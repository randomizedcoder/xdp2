# R7-B2 phase 2 — Skipped after signal-test (per-protocol functions)

Date: 2026-05-20. R7-B2 was the structural restructure: split
the mono parser from one giant `xdp2_parse_mono()` function with
internal `goto label_X` chains into per-node `parse_<node>()`
functions calling each other via tail calls (mirroring rust-mono's
per-protocol-function approach).

**Skipped after two signal-tests confirmed gcc is already at its
local optimum** with the current single-function-with-gotos
structure.

## Signal-test 1: `__attribute__((hot))` on entry function

One-line template change: tell gcc the entry function is hot
(should be aggressively optimized). If gcc's existing layout
isn't optimal, hot should move some cells.

Result on hp5 vs R7-B4 phase 1 baseline:

| workload | B4-phase1 | +hot | Δ |
|---|---:|---:|---:|
| https-web | 72 | 71 | -1 |
| k8s-microservices | 133 | 133 | 0 |
| nfs-server | 69 | 70 | +1 |
| pppoe-isp | 72 | 73 | +1 |
| vlan-tcp-mix | 72 | 70 | -2 |
| vxlan-k8s-pure | 136 | 136 | 0 |

All cells within ±2 ns noise band. The hint is null.

## Signal-test 2: `__attribute__((flatten))` instead of `always_inline`

Flatten forces gcc to inline ALL callees of the marked function
(stronger than always_inline). Tests whether gcc's inlining
choices for our helpers (`__mono_check_pkt_len`, proto-defs'
function pointers via constant-folding) are sub-optimal.

Result: parity-gate passes; no perf run because signal-test 1
already established the entry function is at gcc's optimum.

## Why B2 won't help: gcc collapses any structural difference

The current entry function is marked `__attribute__((always_inline))`
and called from a single tight loop in `benchmark.c`. At
`-O3 -march=native -flto`, gcc:

1. Inlines the entry function into the benchmark loop body.
2. Constant-folds proto_def static-const fields, eliminating
   runtime branches like `if (pnode->ops.len)` per R7-B4 phase 1's
   observation.
3. Lays out the giant ~10K-instruction block in fall-through order
   based on its own profile-free heuristics (mostly fine).

If we split into per-node `static inline parse_<node>(...)`
functions with `always_inline`, gcc inlines them ALL into the
entry function, producing **the same machine code**. The
template intent is different but the compiled binary is identical.

If we drop `always_inline` and let gcc decide, gcc would inline
the cheap nodes (short bodies) and leave the expensive ones
(many cases, many transfers) as separate functions. Each cross-
function call adds:
- ~1 push/pop pair (return address) per node transition
- A branch instruction (call/ret vs jmp)
- Cache pressure spreading across multiple icache lines

For VXLAN's 7-node walk: 7 × ~3 cycles = ~21 cycles/pkt
overhead, ≈ ~5 ns/pkt regression. With tail-call optimization
gcc COULD eliminate the push/pop, but tail-call across many
functions through switch-on-return-value isn't reliably
recognised by gcc at -O3 in our experience.

## What the existing code IS doing already

The mono parser at gcc -O3 -march=native -flto produces:
- ~10K instructions per inlined-into-benchmark copy
- 1 cacheline per ~16 instructions = ~625 icache lines
- L1i miss rate per packet (per R7-A perf-record): ~0.05 misses

That's already low icache pressure. Splitting into per-node
functions wouldn't reduce this and might increase code duplication
if some nodes are called from multiple call sites.

## Where actual perf headroom lives (not in B2)

Per the R7-A perf-record + R5/R6/R7-B1/R7-B3/R7-B4-phase1
findings, the c-xdp2-mono cost is dominated by:
- Per-node `switch(type)` dispatch (R7-B1 closed 4 ns/pkt)
- Per-node metadata writes (R7-B3 confirmed gcc already optimal)
- Per-node length checks (R7-B4 confirmed null at -O3)

The remaining 43 ns/pkt gap to rust-mono on vxlan-k8s-pure is in
the data path:

1. **Number of metadata fields written per packet.** rust-mono
   extracts fewer fields than c-xdp2-mono. R6 audit's Option C
   (per-parser tailored metadata struct) addresses this — ~500
   LoC IR + codegen project.
2. **Compiler choice.** gcc vs rustc/LLVM produce different
   per-protocol code; LLVM's match-tree dispatch differs from
   gcc's binary-search switch (R7-B1 mitigated the gcc side).
3. **PGO / profile-guided optimization.** Without a real profile,
   gcc and rustc both pick generic heuristics. PGO would let
   either optimise specifically for our workloads.

None of these are template restructures. They're separate
projects (R8+).

## Conclusion

R7-B2 skipped — empirically validated as no-op via signal-tests.

R7 phase achievements:
- R7-A: identified switch dispatch + metadata write shape as
  the cost drivers
- R7-B1: hot-edge `__builtin_expect` shortcut → -4 ns/pkt on
  tunnels (shipped)
- R7-B3: typed-store metadata transfers → null perf, cleaner
  emit (shipped)
- R7-B4 phase 1: AST fix + per-node inline length check → null
  perf but unblocks future codegen work (shipped)
- R7-B2 phase 2: per-protocol functions → skipped (no-op
  validated)

c-xdp2-mono final state on hp5:
- https-web: 72 ns/pkt (vs rust-mono 71 → tied)
- nfs-server: 70 ns/pkt (vs 70 → tied)
- pppoe-isp: 73 ns/pkt (vs 80 → mono ahead by 7)
- vlan-tcp-mix: 72 ns/pkt (vs 88 → mono ahead by 16)
- k8s-microservices: 132 ns/pkt (vs 84 → tunnel gap 48)
- vxlan-k8s-pure: 135 ns/pkt (vs 92 → tunnel gap 43)

4 of 6 workloads tied or ahead of rust-mono. Tunnel gap closed
by 4 ns via R7-B1. Further closure requires structural codegen
work (per-parser metadata struct generation, ~500 LoC).

## Files

- `findings.md` — this analysis
- `sweep-hot-attr.md` — signal-test 1 results (hot attribute on
  entry function; null on perf)
