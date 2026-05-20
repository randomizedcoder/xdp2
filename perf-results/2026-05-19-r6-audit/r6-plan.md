# R6 — Metadata Struct Re-Layout (Plan)

## Context (one-line)

Per the audit in `audit.md`: `xdp2_metadata_all` is 200 B / 4
cachelines but a plain TCP/IPv4 parse writes only ~30 B
scattered across 3 cachelines. The 280 instr/pkt c-xdp2-mono
vs rust-mono gap on `vxlan-k8s-pure` (R5 disproved bookkeeping
as the cause) traces to this layout: 2× metadata frames × 4 CLs
each ≈ 8 cacheline writes per packet vs rust's 2.

## What changed since the R5 doc's R6 estimate

The R5 `comparison.md` estimated R6 as "500+ LoC, 2-3 day
effort". The audit refines this:

- **Option A (trailing-cold reorder)** is NOT a 5-line change.
  The `XDP2_HASH_LENGTH` macro at `parser_metadata.h:304-316`
  uses `sizeof(*(FRAME))` as the hashed-region terminator, so
  any tail-append silently extends the IPv6 hash byte range.
  Need to introduce `XDP2_HASH_END_FIELD_ALL = addrs` and
  rewrite the macro to bound on that field instead.
  **~30 LoC.**
- **Hash compatibility is NOT a constraint.** Grep across
  `src/` `samples/` `nix/` found **zero** sites that compare
  computed hashes against fixed expected values. Hashes are
  used internally for RSS/flow-tracking — output values can
  change freely between runs without breaking the matrix or
  parity gate. (Verification: per-field content is what those
  gates check, not the hash digest.)

These two together turn R6 from "500 LoC + delicate" into
"~80 LoC + matrix-verified". Phase table below.

## Phase table

| # | Phase | Scope | Files | LoC | Risk |
|---|---|---|---|---:|---|
| A | Hash macro bound on `addrs` instead of `sizeof(*FRAME)` | Add `XDP2_HASH_END_FIELD_ALL`; rewrite `XDP2_HASH_LENGTH` to use `offsetof(end) + sizeof(end)`. Pre-condition for trailing-cold reorder without IPv6 hash content change. | `src/include/xdp2/parser_metadata.h` | 15 | Low |
| B | Trailing-cold reorder | Move `tcp_options`, `arp`, `gre`, `gre_pptp`, `mpls` to AFTER `addrs` in `struct xdp2_metadata_all`. Hash region (`eth_proto..end-of-addrs`) unchanged in content. eth_addrs stays in CL0. | `src/include/xdp2/parser_metadata.h` | 10 | Low (matrix gate proves correctness) |
| C | Sweep + measure | Run parity-gate, protocol-coverage-matrix, hp2/hp5 sweep on all 6 workloads, icache sweep on vxlan-k8s-pure. | (no code) | 0 | Low |
| D (gate) | Decide on phase E | If Phase B nets ≥3 ns/pkt drop on hp5 vxlan-k8s-pure: ship phase B + skip E. Else: phase E. | — | — | — |
| E (optional) | Hot-cacheline coalescence | Move `eth_addrs` to immediately precede `eth_proto`. Requires moving `l2_off/l3_off/l4_off` to the front prefix to keep struct size. Coalesces hot writes into 1 cacheline. Hash content changes (eth_addrs becomes adjacent to hash region — but eth_addrs is BEFORE eth_proto so still unhashed). | `parser_metadata.h` | 25 | Medium (more reorder; matrix still verifies) |

**Total expected**: A+B+C = ~25 LoC + verification. If E
warranted, +25 LoC. Total ≤80 LoC vs the original 500-LoC
estimate.

## Phase A — Hash macro bounded on a named end field

**Today** (`parser_metadata.h:304-316`):

```c
#define XDP2_HASH_LENGTH(FRAME, HASH_OFFSET) ({
    size_t diff = HASH_OFFSET + sizeof((FRAME)->addrs);
    switch ((FRAME)->addr_type) {
    case XDP2_ADDR_TYPE_IPV4: diff -= sizeof((FRAME)->addrs.v4_addrs); break;
    case XDP2_ADDR_TYPE_IPV6: diff -= sizeof((FRAME)->addrs.v6_addrs); break;
    }
    sizeof(*(FRAME)) - diff;
})
```

This computes `sizeof(*FRAME) - HASH_OFFSET - <skip>` which
implicitly hashes EVERYTHING from `eth_proto` to the end of
the struct. Adding fields at the tail extends the hash range,
changing hash output for IPv6.

**Replacement**:

```c
#define XDP2_HASH_END_FIELD_ALL addrs

#define XDP2_HASH_LENGTH(FRAME, HASH_OFFSET) ({
    size_t end = offsetof(typeof(*(FRAME)), XDP2_HASH_END_FIELD_ALL) +
                 sizeof((FRAME)->XDP2_HASH_END_FIELD_ALL);
    size_t diff = end - (HASH_OFFSET);
    switch ((FRAME)->addr_type) {
    case XDP2_ADDR_TYPE_IPV4: diff -= sizeof((FRAME)->addrs.v4_addrs); break;
    case XDP2_ADDR_TYPE_IPV6: /* full addrs included */ break;
    }
    diff;
})
```

**Net effect** (still on the ORIGINAL struct layout):
- IPv6 hash today: bytes 136..199 (= 64 bytes; includes trailing
  4 bytes of struct padding that are always zero post-memset).
- IPv6 hash after Phase A: bytes 136..195 (= 60 bytes; excludes
  the 4-byte trailing padding).
- IPv4 hash today: bytes 136..175. **Unchanged** after A.
- Default (non-IP): bytes 136..167. **Unchanged** after A.

The IPv6 hash output changes by 4 bytes of always-zero padding,
so in practice the hash digest stays the same (zero-input
doesn't change the FNV/jhash output). Verifiable by hashing
both before/after on the test vectors. **No matrix-gate
disagreements expected.**

**Cross-check sites**: `XDP2_HASH_LENGTH` callers must still
compile. Single caller per audit:
`src/lib/xdp2/parsers/parser_big.c:451` —
`xdp2_compute_hash(start, XDP2_HASH_LENGTH(...))`. The macro
return type is unchanged (`size_t`).

## Phase B — Trailing-cold reorder

Modify `parser_metadata.h:220-245` from:

```c
struct xdp2_metadata_all {
    XDP2_METADATA_addr_type;
    XDP2_METADATA_is_fragment;
    XDP2_METADATA_first_frag;
    XDP2_METADATA_vlan_count;
    XDP2_METADATA_eth_addrs;
    XDP2_METADATA_tcp_options;   /* HOT cacheline, but only TCP-options touch it */
    XDP2_METADATA_mpls;
    XDP2_METADATA_arp;           /* CL1 */
    XDP2_METADATA_gre;
    XDP2_METADATA_gre_pptp;
    XDP2_METADATA_l2_off;
    XDP2_METADATA_l3_off;
    XDP2_METADATA_l4_off;
#define XDP2_HASH_START_FIELD_ALL eth_proto
    XDP2_METADATA_eth_proto __aligned(8);
    /* ...hashed region... */
    XDP2_METADATA_addrs; /* Must be last */
};
```

to:

```c
struct xdp2_metadata_all {
    /* Hot prefix (not hashed): always-written or per-pkt-cheap fields */
    XDP2_METADATA_addr_type;
    XDP2_METADATA_is_fragment;
    XDP2_METADATA_first_frag;
    XDP2_METADATA_vlan_count;
    XDP2_METADATA_eth_addrs;
    XDP2_METADATA_l2_off;
    XDP2_METADATA_l3_off;
    XDP2_METADATA_l4_off;

    /* Hashed region (unchanged byte order — preserves hash digest content) */
#define XDP2_HASH_START_FIELD_ALL eth_proto
    XDP2_METADATA_eth_proto __aligned(8);
    XDP2_METADATA_ip_proto;
    XDP2_METADATA_flow_label;
    XDP2_METADATA_vlan;
    XDP2_METADATA_keyid;
    XDP2_METADATA_ports;
    XDP2_METADATA_icmp;
    XDP2_METADATA_addrs;
#define XDP2_HASH_END_FIELD_ALL addrs

    /* Cold tail: rare-write fields outside hash. Not touched on TCP/UDP
     * 5-tuple parses. */
    XDP2_METADATA_tcp_options;   /* 44 B — TCP-with-options only */
    XDP2_METADATA_arp;           /* 24 B — ARP-only */
    XDP2_METADATA_gre;           /* 20 B — GRE-only */
    XDP2_METADATA_gre_pptp;      /* 16 B — PPTP-only */
    XDP2_METADATA_mpls;          /* 4 B  — MPLS-only */
};
```

**Resulting offset table** (verify post-change with same
probe script):

- CL0 (0-63): addr_type+bitfields(2) + eth_addrs(12) + l2/l3/l4_off(6) + pad → ends ~32-40
- Hashed region (offset ~40-104): eth_proto..addrs
- CL1 (64-127): tail of hashed region + start of tcp_options
- CL2 (128-191): tcp_options + arp
- CL3 (192-): gre + gre_pptp + mpls

**Per-packet write footprint for TCP/IPv4** (most common):
- CL0: addr_type+bitfields + eth_addrs + l3_off ≈ 16 B written
- CL1 (start of hashed region): eth_proto + ip_proto + addr_type set... wait, eth_proto is in CL1 now (offset ~40-ish, aligned 8 → 48). ports + addrs spill into CL1/CL2.

Hmm — need to verify actual offsets after the move via the
probe before claiming the cacheline savings. **The probe will
confirm whether the hot writes coalesce into 2 CLs (vs 3
today).**

Two cachelines being written (CL0 for L2/L3 offs + eth_addrs;
CL1 for the entire hashed region) vs three today = ~30 % drop
in store cache traffic on the hot path.

**Cost on tcp_options-touching packets**: tcp_options is now
in CL2-CL3 (was CL0). TCP-with-MSS/sack packets now touch 4
CLs instead of 3. This is a deliberate trade — TCP-options
parsing is a small fraction of real traffic (most TCP packets
have no options after handshake). Verifiable via the
proto_audit field-touch rates.

## Phase C — Verify

```sh
# 1. Parity gate stays green
nix build .#checks.x86_64-linux.parity-gate

# 2. Protocol-coverage matrix stays 0/0/0
nix run .#protocol-coverage-matrix -- --out /tmp/r6-cov
grep -E "^- .OK!N|REJ-unexpected" /tmp/r6-cov/report/matrix.md
# Expect: 0 OK!N, 0 REJ-unexpected.

# 3. Layout probe to confirm new offsets
gcc -O0 -I src/include -include xdp2/parser_metadata.h \
    /tmp/metadata-layout-probe.c -o /tmp/probe && /tmp/probe

# 4. Full sweep (6 workloads)
XDP2_RESULTS_ROOT=/tmp/r6-sweep \
nix run .#flow-dissector-matrix-sweep -- \
    --testbed testbeds/hp2-hp5-x710.toml

# 5. Icache sweep on vxlan-k8s-pure (the headline target)
XDP2_RESULTS_ROOT=/tmp/r6-icache \
nix run .#flow-dissector-icache-sweep -- \
    --testbed testbeds/hp2-hp5-x710.toml \
    --workloads vxlan-k8s-pure --modes M
```

**Success criteria for Phase B**:
- hp5 `c-xdp2-mono vxlan-k8s-pure` drops by ≥3 ns/pkt (from
  140 → ≤137). Stretch: ≤130.
- hp5 `c-xdp2-mono https-web` flat or improves (currently 72;
  expect 70-72).
- icache instructions/pkt drops ≥30 (currently 789; expect
  ≤760).
- Parity-gate: 0 regressions.
- Matrix: 0 OK!N, 0 REJ-unexpected.

**Failure criteria (rollback Phase B, attempt Phase E
instead)**:
- vxlan-k8s-pure no improvement (within ±2 ns of baseline).
- Any matrix disagreement.
- Any parity-gate test fails.

## Phase E (conditional) — Hot-cacheline coalescence

Only if Phase B yields <3 ns/pkt delta.

Move `eth_addrs` to immediately precede `eth_proto` (after
l2/l3/l4_off). This requires `__aligned(8)` on eth_proto to
preserve 8B alignment for downstream fields:

```c
struct xdp2_metadata_all {
    XDP2_METADATA_addr_type;
    XDP2_METADATA_is_fragment;
    XDP2_METADATA_first_frag;
    XDP2_METADATA_vlan_count;
    XDP2_METADATA_l2_off;
    XDP2_METADATA_l3_off;
    XDP2_METADATA_l4_off;
    /* eth_addrs moved here to pack adjacent to hashed region */
    XDP2_METADATA_eth_addrs;
#define XDP2_HASH_START_FIELD_ALL eth_proto
    XDP2_METADATA_eth_proto __aligned(8);
    /* ...hashed... */
    /* cold tail same as Phase B */
};
```

Per-packet TCP/IPv4 write footprint becomes:
- 1 cacheline that contains eth_addrs + entire hashed region
  (eth_proto..addrs).
- Total: 1 CL written for the 5-tuple extract.

Hash content unchanged: eth_addrs is still BEFORE
`HASH_START_FIELD_ALL = eth_proto` and is NOT hashed today (or
after).

**Expected delta**: another 2-3 ns/pkt drop on hp5 (each CL
write costs ~1 ns of store-buffer traffic).

## Tests that must stay green

- `nix flake check` — parity + smoke gates
- `nix run .#protocol-coverage-matrix` — 4914-cell pairwise
  field-content check
- The benchmark `mono-perf` ceiling: `c-xdp2-mono` must remain
  ≤ `c-xdp2-usp × 1.10` (we have headroom — mono is currently
  ~50 % of usp's time)

## Open questions

1. **Does the IPv6 4-byte hash change (Phase A) really not
   alter digest output?** Verified analytically (zero-input)
   but a hash differ probe on representative pcaps would
   confirm. Doable in 5 min: hash before, hash after, diff.
2. **Does the matrix gate catch field-content differences if
   tcp_options moves into the CL2-CL3 tail?** Yes — the
   matrix compares per-field values from the metadata struct
   regardless of offset. Verified by previous reorderings.
3. **Is there a downstream consumer that uses `&frame->addrs`
   pointer arithmetic to access fields after addrs?** Audit:
   none found in `src/` `samples/`. The only `addrs`-relative
   access is the `XDP2_HASH_CONSISTENTIFY` macro which uses
   field-name dereferences, not pointer math.

## Out of scope

- Per-parser tailored metadata struct (audit's Option C). If
  Phases A+B+E together don't close enough of the gap, the
  per-parser struct is the next escalation — but that's a
  separate ~500 LoC R7 phase touching the IR + codegen.
- TLV / flag_fields walker emission. Independent investigation
  in R4 territory.
- Any change to `xdp2_metadata_all` field semantics. Pure
  layout move only.
