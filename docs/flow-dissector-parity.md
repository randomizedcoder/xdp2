# Cross-Parser Parity Gate

This document describes the second-level verification that proves
every flow-dissector implementation produces the same answer for the
same packet — not just that it compiles, builds, or runs at the
expected speed.

It complements `docs/flow-dissector-matrix-physical-testbed.md` (the
performance matrix) by adding a **parity gate** that catches
extracted-output divergences across the 14 parser implementations.

## Why this exists

The Phase 0-16 matrix campaign measures `ns/pkt` and `Mpps` per
`(parser, pcap)` cell but does not verify that those parsers produce
identical extracted FlowMeta. Three concrete failure modes the
matrix masks (and the parity gate now catches):

1. **Fall-through is invisible.** `c-bpf-fast` returns
   `BPF_FLOW_DISSECTOR_CONTINUE` on packets outside its 7 fast-path
   chains; the matrix reports "100% accepted" because the kernel's
   slow path silently fills `bpf_flow_keys`. The 18 ns/pkt headline
   in `perf-results/2026-05-06/T5-tma.md` is the fast-path subset's
   wall, not the parser's overall coverage.

2. **Different output structs are silently incomparable.** Kernel
   flowdis populates a 22-field subset (no MACs); XDP2 (C) and
   xdp2-rs populate the full 200 B FlowMeta. The matrix records
   nothing about field-level divergence.

3. **Same-named field, different semantic.** XDP2 C and xdp2-rs both
   declare `thoff` in scope. The C parser reports it relative to the
   etype start; the Rust parser reports absolute frame offset. Phase
   17.B.C's first run caught this on every TCP/IPv4 packet and the
   benchmark.c emitter was fixed to translate.

## Architecture

Three layers:

1. **Schema** — `samples/flow_dissector/parity_scope.json`:
   - 36 canonical fields (addr_type, ip_proto, ipv4_*, ipv6_*,
     ports, MACs, MPLS, GRE, VLAN, ESP/AH, L2TP, ICMP, offsets).
   - 3 reusable scope tiers (`bpf_flow_keys`,
     `kernel_flowdis_extras`, `full_flowmeta_extras`).
   - 14 per-parser scope declarations.
   - 6 expected-divergence entries documenting structural cases
     where parsers cannot agree (verifier rejection, AVX2 absence,
     template miss, fast-path fall-through, MAC out-of-scope, BPF
     scope narrowing).

2. **Dump-meta emitters** — every parser binary gained a flag:
   - `xdp2-bench --dump-meta <path>` (8 Rust modes), per
     `xdp2-rs/crates/xdp2-bench/src/parity.rs` and
     `bench.rs::dump_meta_pass`.
   - `benchmark -D <path>` (3 C userspace modes), per
     `samples/flow_dissector/benchmark.c::dump_meta_pass`.
   - `benchmark_bpf -D <path> -P <parser-id>` (BPF parsers), per
     `samples/flow_dissector/benchmark_bpf.c`. Detects
     `BPF_FLOW_DISSECTOR_CONTINUE` for `c-bpf-fast` and emits
     `accept_path="slow"` + `reject_reason="no-fast-path-chain"`.
   - All emitters write the same `ParityRecord` JSONL schema
     defined in `samples/flow_dissector/parity_schema.h` (C) and
     `xdp2-rs/crates/xdp2-bench/src/parity.rs` (Rust).

3. **Comparator + driver + gate**:
   - `nix/scripts/parity-compare.py` — symmetric all-vs-all
     comparator. Loads scope, ingests JSONL, applies scope masks,
     emits `parity-report.{md,csv}`. Cluster reporting groups
     parsers into agreement classes when ≥3 parsers disagree.
   - `nix run .#flow-dissector-parity-check -- --pcap PATH` —
     orchestrator that runs each parser's dump-meta path and feeds
     the JSONL tree into the comparator.
   - `nix build .#checks.x86_64-linux.parity-gate` — flake check.
     Runs the orchestrator on a small synthetic corpus
     (`tcp_ipv4.pcap`, `icmp_ipv4.pcap`) with 11 of 14 parsers
     (BPF parsers excluded — the Nix sandbox doesn't grant
     CAP_BPF for `BPF_PROG_TEST_RUN`). Asserts zero unexpected
     disagreements.

## Phase 17.C findings (live diagnostics from the gate)

The first runs of the gate against the broader corpus surfaced
**three real issues** that the campaign matrix had silently masked.
These are not blockers for shipping the gate (the gate's corpus is
restricted to exclude them) but each is a real action item.

### Finding 1 — `rust-graph-enum` rejects every IPv6 packet

- **Symptom:** on `tcp_ipv6.pcap` (12 packets) and `icmp_ipv6.pcap`
  (6 packets), `rust-graph-enum` emits
  `accepted=false, reject_reason="parse-error"` for every packet
  while every other Rust mode and every C parser accepts. The 2026-
  05-02 reference reported graph-enum at 12 ns/pkt on combo.pcap;
  the IPv4-dominant combo mix masked this gap.
- **Root cause (suspected, requires triage):**
  `xdp2-rs/crates/xdp2-bench/src/graph_enum.rs` defines a "minimal
  graph (Ether/IPv4/{TCP,UDP,ICMP})" per the cli.rs comment at line
  12-13. IPv6 isn't in graph-enum's table. The **schema scope claims
  full FlowMeta** for `rust-graph-enum`, which is now provably
  wrong.
- **Resolution paths:**
  (a) Extend graph-enum to handle IPv6/VLAN (preferred — the
      headline 12 ns/pkt was for combo.pcap where it works).
  (b) Tighten `parity_scope.json` to declare graph-enum's tier as
      "ipv4-only" and skip it on IPv6 packets.
  (a) is the right answer; the schema declares intent and the
  parser must match.

### Finding 2 — Tunnel-encapsulated packets: kernel-flowdis vs XDP2

- **Symptom:** on `gre-sample.pcap` (11 GRE packets), `c-flowdis-usp`
  vs every Rust mode (and `c-xdp2-*`) disagrees on `sport`, `dport`,
  `ipv4_src`, `ipv4_dst`, `ip_proto`, `thoff` for every packet.
- **Root cause (known design):** kernel flowdis stops at the OUTER
  5-tuple (the GRE header itself), while XDP2 follows the GRE
  tunnel and reports the INNER flow's 5-tuple. The C-side
  benchmark already has this carve-out at
  `samples/flow_dissector/benchmark.c:264-277`:
    ```c
    /* VXLAN (4789) or Geneve (6081) — xdp2 follows tunnel, flowdis
     * doesn't. These are not mismatches — xdp2 extracts inner flow
     * keys intentionally.
     */
    ```
  But this carve-out is **not** in `parity_scope.json:expected_divergences`,
  so the gate flags every tunnel packet.
- **Resolution path:** Add a new expected-divergence entry of the
  form *"on packets where outer ip_proto ∈ {GRE, GRE-PPTP, IPIP,
  IPv6, ESP, AH, UDP/4789, UDP/6081}, c-flowdis-usp's 5-tuple
  fields are out-of-scope vs the rest."* This requires the
  comparator to support per-packet conditional masks (current
  implementation only has per-parser static masks). Phase 17.D
  follow-up; tracked.

### Finding 3 — Already-fixed during 17.B.C: thoff-vs-l4_off semantics

- **Symptom (caught + fixed):** XDP2 C parser reported `l3_off=2`
  while xdp2-rs reported `l3_off=14` on every tcp_ipv4 packet —
  same packet, different reference frame.
- **Root cause:** `benchmark.c` invokes `xdp2_parse` starting at
  the etype field (`data + l3_off - 2`); the metadata's `l*_off`
  fields are relative to that start, not the original frame.
- **Resolution (done in commit `9c7d5a1`):**
  `parity_fill_from_metadata()` now adds the absolute etype offset
  back when emitting. Zero disagreements after the fix.

## Running the gate

```bash
# Fast: synthetic corpus only, ~30 s, runs in `nix flake check`
nix build .#checks.x86_64-linux.parity-gate

# Full: any single PCAP, 11 of 14 parsers (skip BPF on non-CAP_BPF host)
nix run .#flow-dissector-parity-check -- \
    --pcap data/pcaps/<some.pcap> \
    --out /tmp/parity-out

# Full 14-parser run (requires CAP_BPF — typically root or hp2/hp5)
nix run .#flow-dissector-parity-check -- \
    --pcap data/pcaps/<some.pcap> \
    --out /tmp/parity-out
# Output: /tmp/parity-out/{parser_id}.jsonl + parity-report.{md,csv}
```

Reading `parity-report.md`:

- **Acceptance matrix** at top: counts of accepted/total per `(pcap,
  parser)` cell. A row of `11/11` across all parsers means every
  parser parsed every packet. A row like `0/11` flags a parser
  that rejected everything (verifier rejection, missing protocol,
  etc.).
- **Field disagreements** section: pairwise `(parser_a, parser_b,
  field) → count` table, plus first-20 raw-disagreement rows. Zero
  disagreements is the green path.
- **Acceptance disagreements** section: parsers that rejected
  without a `reject_reason` matching `expected_divergences`. If
  this section is non-empty, either the rejection is a parser bug
  OR the divergence catalog needs an entry.
- **Rejection reason distribution**: per-parser × reason counts
  with an "expected?" column flagged ✓ or ✗ against the schema.

## Schema versioning

Bump `schema_version` in `parity_scope.json` AND
`parity_schema.h:PARITY_SCHEMA_VERSION` AND
`parity.rs:SCHEMA_VERSION` together when:

- Adding a new field name (and to which parser tiers it belongs).
- Renaming an existing field.
- Changing a field's type / serialization format.
- Adding a new `expected_divergences` mechanism (e.g., per-packet
  conditional masks for tunnel handling).

The comparator validates the version on every record; mismatches
are surfaced as harness errors (exit 2), not parity failures.

## What the gate does NOT verify

1. **Performance.** `parity-gate` is correctness-only; the matrix
   campaign covers `ns/pkt` regression detection.
2. **BPF parsers in the flake-check sandbox.** `nix flake check`
   doesn't grant CAP_BPF; the gate explicitly excludes
   `c-bpf-flowdis` and `c-bpf-fast`. Full 14-parser coverage
   requires an out-of-band run on a privileged host.
3. **Per-packet conditional behaviour beyond static scope.**
   Tunnel inner-vs-outer flow extraction (Finding 2) needs schema
   extension; today it manifests as unexpected disagreements on
   tunneled corpus.
4. **Cross-version regression.** The gate catches present-day
   parity, not "did Rust commit X introduce a divergence Y." For
   that, run the gate before/after the change and diff
   `parity-report.csv`.
