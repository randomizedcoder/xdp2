# 2026-05-19 hp2/hp5 sweep — `-O3 -march=native -flto -fno-plt`

Re-run of the post-R3.4 sweep after patching the
`samples/flow_dissector/Makefile` `CFLAGS` from `-O2` to
`-O3 -march=native -flto -fno-plt`. Same testbed (hp2-hp5-x710),
same 6 workloads, same smoke iteration count. Goal: validate
hypothesis H4 from `../2026-05-19-r3.4-complete/investigation-mono-vs-rust.md`
that the c-xdp2-mono vs rust-mono gap on tunneled workloads was
caused by build-flag asymmetry.

## TL;DR

**H4 disproved.** Aggressive compile flags moved every
c-xdp2-mono cell by ≤3 ns (= measurement noise). The vxlan-k8s-pure
gap to rust-mono remains 49 ns. The codebase was already well-
tuned for `-O2`; gcc's `-O3 -march=native -flto` adds nothing
measurable on this parsing workload.

## c-xdp2-mono — O2 vs O3 across all 6 workloads (hp5)

| workload | O2 (eee56ea) | O3 (this run) | Δ |
|---|---:|---:|---:|
| https-web | 73 | **71** | -2 |
| nfs-server | 69 | **72** | +3 |
| k8s-microservices | 137 | **136** | -1 |
| pppoe-isp | 72 | **73** | +1 |
| vlan-tcp-mix | 70 | **70** | 0 |
| **vxlan-k8s-pure** | **141** | **141** | **0** |

All deltas within ±3 ns. The Mono perf-ceiling gate stayed clean
across both runs (0 violations).

## c-xdp2-mono vs rust-mono — gap on vxlan-k8s-pure (hp5)

| build | c-xdp2-mono | rust-mono | gap |
|---|---:|---:|---:|
| -O2 (eee56ea) | 141 | 93 | **48 ns** |
| -O3 -march=native -flto (this) | 141 | 92 | **49 ns** |

Unchanged. The gap is structural, not a build-tuning artifact.

## Why didn't -O3 -march=native -flto help?

Pre-flag-change inspection showed:

1. **gcc -O2 already devirtualises** the indirect `ops.next_proto`
   / `ops.extract_metadata` / `ops.handler` calls when the
   `proto_def` / `parse_node` structs are `static const`. The
   generated asm has 0 `call *<reg>` indirect instructions in
   `xdp2_parser_flow_dissector_l2_xdp2_parse_mono`.

2. **`__mono_check_pkt_len` is fully inlined** at `-O2` already
   (no symbol in the binary; no references in the function asm).

3. **`-march=native`** on Zen 1 enables BMI2 / AVX, but the
   parsing loop is dominated by branchy control flow + 8-byte
   field stores. There's no vectorisable hot loop for the
   vectoriser to exploit; the BMI2 instructions (PEXT/PDEP) aren't
   used by the bit-twiddling in the parsers.

4. **`-flto` cross-TU inlining**: the parser is already in a
   single TU (parser.mono.c) compiled together with benchmark.c
   and parser.p.c. Cross-TU inlining doesn't have meaningful
   work to do.

5. **`-fno-plt`**: small effect; the parse loop barely calls
   shared-library functions (`libpcap` is invoked once at startup,
   not per packet).

The codebase is already at the local minimum gcc -O2 can produce
for this code shape. The remaining 49 ns gap to rust-mono is
something else.

## What the gap probably IS

Re-examining the hypotheses from the previous investigation:

- **NOT** compile flags (now disproved with this run).
- **NOT** indirect-call overhead (gcc devirtualises).
- **NOT** per-node `__mono_check_pkt_len` overhead (inlined).
- **NOT** less-work-asymmetry (rust extracts MORE fields).

Remaining candidate causes, in rough order of plausibility:

### A. Code size / icache pressure

The L2 mono entry function is **10,388 asm instructions ≈ 62 KB**
(estimated, 6 B/instr avg). Zen 1's L1i is **32 KB** — the
function is *2× too big to fit*. Different packet shapes hit
different ~200-line slices of this giant function. Cold paths
take icache-miss penalties (≈10s of ns at full memory latency
on first hit).

Rust's monomorphic dispatch produces **N small functions** (one
per protocol parse_*). Each fits comfortably in L1i. Branch
predictor + icache stay warm even across cold-start paths.

This is structural. -O3 doesn't change it.

### B. Per-node bookkeeping store

Every node body emits:

```c
ctrl->var.last_node = parse_node;
```

That's an unconditional store-to-memory per node. On a 7-node
vxlan walk that's 7 extra stores. Each is a few cycles
(store-buffer write). Rust's monomorphic dispatch doesn't have
a parallel concept.

Cost estimate: ~7 × 2 cycles = 14 cycles ≈ 4 ns. Small but real.

### C. Metadata struct cacheline footprint

`struct xdp2_metadata_all` is ~200 bytes (~3 cachelines).
Rust's `FlowMeta` is smaller (~100 bytes based on field count).
Memcpy-style metadata extraction (the R3.3.4 devirt) touches
more cachelines on the C side.

Cost estimate: ~1-2 extra cacheline writebacks/reads = ~5-10 ns.
Measurable but not the whole gap.

### D. encap / overlay / len bookkeeping in node body

Each generated node body has:
```c
if (!proto_def->overlay) {
    hdr = (char *)hdr + hlen;
    len -= hlen;
}
```

Plus encap-depth checks per encap layer. Rust's monomorphic
dispatch has equivalents but pulls them outside the per-protocol
function where possible.

Cost estimate: ~5-10 ns total across the walk.

### Sum-check

A+B+C+D ≈ 25-40 ns. The remaining gap is 49 ns. Within the
ballpark; the structural icache effect (A) is likely the
single biggest contributor.

## Recommendation

**Keep the new compile flags.** They don't hurt, and they remove
"build tuning" as a confounding variable in future investigations
(any remaining gap to rust IS architectural, not build).

**Investigate (A) code-size / icache** as the next step. Concrete
experiment: split `xdp2_parser_flow_dissector_l2_xdp2_parse_mono`
into per-chain entry functions, measure icache misses with
`perf stat -e l1-icache-load-misses` on the vxlan workload. If
the miss count drops significantly, the structural code-size
issue is confirmed and we can plan a codegen change.

That's a larger investigation — out of scope for this perf
question, but worth a follow-up R6 phase ("code-size / icache
trimming").

## Note on the kernel-team comparison framing

The new flags make C BEST-CASE perf comparable. But the kernel
itself is compiled with:

  - `CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE=y` → `-O2`
  - `CONFIG_LTO_NONE=y` → no LTO
  - `CONFIG_FORTIFY_SOURCE=y` → fortify overhead
  - generic x86_64 (no `-march=native`)

So when presenting numbers to the kernel team:

- **"Fair comparison to kernel flowdis at the same build flags"**
  → use the -O2 baseline numbers (eee56ea). c-xdp2-mono 73 ns/pkt
  on https-web; ~140 ns/pkt on tunneled.
- **"Best-case XDP2 perf with aggressive build flags"**
  → use this run's numbers. c-xdp2-mono 71 ns/pkt on https-web;
  ~140 ns/pkt on tunneled.

Per-workload, the spread between O2 and O3-aggressive is ≤3 ns.
The framing matters less than expected because the codebase is
already well-tuned.

## Files

- `summary.md` / `summary.csv` — full matrix (6 workloads × 14
  parsers × 2 hosts)
- `mono-perf.md` — c-xdp2-mono parity-ceiling gate (0 violations)
- `INDEX.json` — testbed metadata
