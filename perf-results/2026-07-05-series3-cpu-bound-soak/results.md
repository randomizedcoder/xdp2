# Series4 counters — no-regression A/B (pristine net-next vs gate-off vs gate-on)

**Date**: 2026-07-05
**Question**: Do the series4 per-shape counters (`/proc/net/flow_dissector_stats`,
  always-on `this_cpu_inc` on the dissector classification path) add a measurable
  per-packet regression vs pristine net-next? Predicted: non-zero but very small.
**Method**: Kernel-level cyc/pkt gold standard — pktgen TX + receiver-side
  ksoftirqd `perf stat`, cycles / packets-received. 2 pktgen threads, 64 B frames,
  `DUR=25 REPLICATES=5` per cell (`nix run .#series3-cpu-bound-soak`).
**Pair**: l (gen, 10.10.4.2) ↔ l2 (DUT, 10.10.4.5), back-to-back on
  `enp35s0f0np0` (mlx5_core ConnectX, 25 GbE), xdp2.testbed pair #4.
**Scenario**: `eth_ip` (plain Ethernet/IPv4, no encap) — the byte-identical
  fast-path's cheapest shape.
**Kernels** (net-next 7.2-rc1, base b73bc9ca3686):
  - **baseline**: pristine `netnext-baseline` (b73bc9ca3686) — no series4, no
    counters. Measured on its own boot, n=10 (two 5-rep cells, both gate-less).
  - **series4**: `series4-send` (9efb44752a0c) — 12 patches incl. the counters.
    gate-off / gate-on toggled live via `sysctl net.flow_dissector.eth_ip`.
  Both built by overriding nixpkgs `linux_testing` on the identical base, so the
  only delta baseline→gate-off is the counters + framework (all static_branches
  NOP'd when off).

## TL;DR

**No measurable regression from the counters.** Series4 with gates off is
performance-identical to pristine net-next within measurement resolution.

- **Counter overhead** (gate-off − baseline) = **+15.8 cyc/pkt (+0.74%)**, at
  **+0.44σ** — well inside the ~3.8% CV / ±80 cyc/pkt noise floor, i.e.
  statistically indistinguishable from zero. The ~16 cyc/pkt point estimate is
  consistent with a few `this_cpu_inc`s on the already-hot classification path.
- **Fast-path effect for eth_ip** (gate-on − gate-off) = +6.6 cyc/pkt, also
  within noise — expected, since plain eth/IP is the shortest slow path and the
  byte-identical fast-path has the least to save here. The real fast-path wins
  are on the deeper shapes (vlan/qinq/mpls/encap), quantified in the microbenches.
- All three distributions overlap heavily: baseline [2049–2209],
  gate-off [2087–2203], gate-on [2120–2182].

## Results

| Configuration | cyc/pkt (mean ± sd) | n | vs baseline |
|---|---:|---:|---:|
| Pristine baseline (net-next, no series4) | 2129.0 ± 80.0 | 10 | — |
| Series4, **gate OFF** (counters run, fast-path NOP'd) | 2144.8 ± 57.9 | 5 | +15.8 (+0.44σ) |
| Series4, **gate ON** (fast-path active) | 2151.4 ± 31.0 | 5 | +22.3 |

Noise floor (baseline CV): 3.8%. Counter overhead as a fraction of baseline: +0.74%.

### Raw per-rep cyc/pkt

- **baseline** (net-next, separate boot): 2040.59, 2152.95, 2159.70, 2071.56,
  2133.79, 2124.05, 2129.76, 2319.59, 2121.80, 2036.57
- **series4 gate-off** (sysctl=0): 2059.96, 2176.91, 2139.50, 2132.28, 2215.43
- **series4 gate-on** (sysctl=1): 2156.73, 2128.61, 2192.39, 2165.37, 2113.81

Full per-cell metrics (pps, cycles, instructions, branch-misses, recv_soft%) in
`matrix.csv` and `l-l2/eth_ip/cell-*-rep*/`.

## Notes / caveats

- eth_ip is the **least favourable shape for the fast-path** (cheapest slow path),
  so gate-on≈gate-off here is expected — this run targets the *counter overhead*
  question, not the fast-path benefit.
- Baseline and series4 were separate boots of the same net-next base on the same
  host (l2); the receiver was otherwise idle (llama CPU instances present but not
  loaded). ~3.8% run-to-run CV is the pktgen/ksoftirqd measurement floor on this
  Zen box, dominated by cache/scheduling jitter, not the code under test.
- Companion evidence: userspace A/B ≈ 3 ns/pkt upper bound (l, Zen2); RISC-V
  bpi-f3 gate-flip verified. Together: counters ≤ noise on x86 and consistent
  across arches.

## Conclusion

The always-on per-shape counters meet the "non-zero but low" bar: overhead is
below the measurement noise floor (<1%, <0.5σ) at kernel-call granularity. Safe
to keep counters unconditional; no gate needed for the observability layer.
Fold the +0.74% / <1% figure into `PERFORMANCE.md`'s counting-overhead note.
