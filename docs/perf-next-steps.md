# XDP2 perf — next steps after R8

Last updated: 2026-05-20 (post-R8, branch
`merge/matrix-physical-testbed` at `766f8d8`).

## Current state

c-xdp2-mono is at gcc's local optimum on Zen 1:
- 4/6 sweep workloads tied or ahead of rust-mono
- 35-42 % faster than kernel C flow_dissector on flat workloads
- Tunnel gap to rust-mono on vxlan-k8s-pure: 36 ns (closed from
  +46 at end of R6 via R7-B1 + R8)
- Correctness: parity-gate 32/32, matrix 4914/4914 cells clean,
  mono-perf ceiling 0 violations
- 16 commits ahead of `origin/merge/matrix-physical-testbed`
  (pushed 2026-05-20)

Remaining 36 ns gap on tunnels is structural per R7-A: different
codegen shape between gcc's binary-search switch and rustc/LLVM's
match-tree dispatch.

## Options ranked by impact vs effort

| # | option | effort | expected impact | risk |
|---|---|---|---|---|
| A | Polish kernel-team deliverable | 2-4 h | high (communication) | low |
| B | Try building with clang/LLVM | 4-8 h | unknown (could be ±15 ns) | medium |
| C | R6 audit Option C: per-parser metadata struct | 2-3 days | 5-10 ns on tunnels | medium |
| D | R4: TLV / flag_fields walker emission | 1-2 days | unblocks more parsers, null on current sweep | medium |
| E | PGO infrastructure | 1-2 days | 5-15 ns potential | medium |
| F | R9: more fast-path chains for new workloads | small per chain | depends on workload | low |

## Option A — Polish kernel-team deliverable (recommended next)

The perf work has reached a defensible state. The next-most-
valuable artifact is a clean writeup for kernel review.

Sub-options:
1. **Executive summary** `docs/perf-summary.md` — single-page
   distillation of the 6-workload comparison, key findings,
   and reproduction commands. Suitable for an LWN.net article
   or LSF/MM presentation.
2. **Methodology section** added to
   `docs/kernel-vs-xdp2-comparison.md` covering benchmark
   harness, BPF_PROG_TEST_RUN mechanics, smoke-vs-full iter
   counts, and noise band estimates.
3. **Visualisation** — gnuplot / asciigraph chart of the
   6-cell comparison table. Visual impact for slides.

## Option B — Compiler swap (clang instead of gcc)

R7-A noted that rustc/LLVM emits match-tree dispatch differently
from gcc's binary-search switch. Building XDP2 with clang would
test whether the 36 ns vxlan gap is gcc-specific or fundamental.

Steps:
1. Modify the nix build to use `clangStdenv` instead of
   `stdenv` for the mono parser binary.
2. Verify parity-gate + matrix.
3. Sweep hp2/hp5; compare cells with current gcc build.

Risk: clang's optimisation choices differ from gcc; could
regress on the flat-workload wins. BPF-side build already uses
clang, so toolchain support is present.

## Option C — R6 audit Option C: per-parser metadata struct

The R6 audit identified per-parser tailored metadata struct
generation as the only template-level lever that could reduce
the NUMBER of metadata writes per packet (vs R7-B1/B3/B4 which
all addressed write SHAPE, not count).

Estimated 500 LoC IR + codegen:
1. Add `__u64 used_field_mask` to `xdp2_parser_def`.
2. Each parser declares which metadata fields it actually uses.
3. Codegen emits a tailored struct (e.g. ~57 B for
   flow-dissector-l2 vs 192 B universal struct).
4. Metadata write template gates each field-write on the mask.
5. API: consumers of `struct xdp2_metadata_all *` adapt to
   `void *` + parser-provided struct type.

Risk: large API surface change. May still be null on Zen 1 if
gcc was already constant-folding unused writes.

## Option D — R4: TLV / flag_fields walker emission

R4 was deferred during R3 because the mono-eligibility validator
rejected parsers using TLV / flag_fields walkers. Adding proper
walker emission would unblock parsers that use these features
(GRE-PPTP, SRv6-end_dx2, etc.) without affecting current sweep
workloads.

Estimated 1-2 days. Increases protocol coverage; null on perf
numbers for the current 6 workloads.

## Option E — PGO (profile-guided optimization)

gcc PGO collects a profile from a benchmark run and recompiles
with that data. Could reorder hot paths better than gcc's
heuristic-driven choices.

Steps:
1. Modify build to add `-fprofile-generate` pass.
2. Run benchmark to collect `.gcda` files.
3. Rebuild with `-fprofile-use`.
4. Sweep + compare.

Risk: PGO infrastructure adds build complexity. Profile must
be representative; data from one workload may not help (or
hurt) another.

## Option F — R9: more fast-path chains for new workloads

The R8.1 IPIP attempt showed each new chain has a layout-shift
cost on existing chains; only worth adding chains for shapes
that hit >10% of target pcap traffic. Without new workloads
that have specific dominant tunnel shapes, additional chain
extensions risk null-or-regression.

Marginal at this point. Reactivate IF a new workload arrives
with a clear miss-tail pattern.
