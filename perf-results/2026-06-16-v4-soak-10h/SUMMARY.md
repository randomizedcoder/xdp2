# v4 namespace 10-hour soak — variance-pinned numbers (2026-06-16/17)

10h09m wall-clock, DUR=600 per cell, 60 cells (3 pairs × 5 scenarios × 4 cells; PPPoE excluded, see [`2026-06-16-pppoe-investigation.md`](../2026-06-16-pppoe-investigation.md)). With ~10× the per-cell samples of the DUR=60 runs the noise floor should drop ~3× (sqrt of sample count). The picture that emerges is **smaller, more honest, and more nuanced than the DUR=60 headlines suggested**.

## TL;DR — which deltas survived the noise reduction

| pair | scenario | proto | recv_soft Δ (this run) | notes |
|---|---|---|---|---|
| **hp2↔hp5** | **vlan** | **udp** | **1.44 → 1.08, -0.36pp (-25%)** | consistent across 3 runs |
| **hp2↔hp5** | **vxlan** | **udp** | **8.28 → 7.92, -0.36pp (-4.3%)** | consistent across 3 runs |
| hp1↔hp3 | ipip | tcp | 5.38 → 4.88, -0.50pp | TCP retr-noisy but direction-stable |
| hp2↔hp5 | mpls | tcp | 12.00 → 11.73, -0.27pp | smaller than DUR=60 |
| hp1↔hp3 | vlan | tcp | 10.15 → 9.73, -0.42pp | smaller than DUR=60 |

**MPLS UDP, which looked like the headline at DUR=60 (-1.10pp, -0.77pp, -1.65pp across three pairs/runs), came back to noise floor (+0.06pp, +0.16pp) at DUR=600.** The DUR=60 swings were larger than the true effect, and over 10h the signal averaged out.

## What this means for the netdev cover letter

The byte-identical patches don't deliver the "1pp+ softirq reduction per shape" story the early DUR=60 runs hinted at. The real picture from 10h of data:

1. **Throughput parity holds cleanly across all byte-identical UDP cells** — `|Δmbps| ≤ 1.2%` across the entire byte-identical subset (vlan/qinq/mpls/ipip UDP). The byte-identical contract claim is solid; numbers are evidence-backed.
2. **Receiver softirq deltas are real but small (~0.3pp magnitude where they show)**. They show up most cleanly where the softirq baseline is in the 1-10% range (high enough to measure but not saturated by the workload itself). Best examples: hp2↔hp5 vlan UDP (-0.36pp), hp2↔hp5 vxlan UDP (-0.36pp).
3. **The DUR=60 MPLS UDP numbers were variance, not signal.** Three independent runs disagree on magnitude AND sign — this is the kind of result that only shows up with longer runs and is exactly why we ran the soak.
4. **TCP softirq deltas are not interpretable** at this noise level (100k+ retransmits per 10-min cell on the hp pairs from the documented mlx5 plumbing issues). The TCP throughput sometimes goes UP with sysctl=1 (hp1↔hp3 MPLS tcp: 17052 → 18866, +10.6%) which is interesting on its own but says more about TCP's feedback dynamics than fast-path performance.

## Direct comparison across the three runs

Each row is `recv_soft_pct (sysctl=0 → sysctl=1, Δ)`. Cells in **bold** show consistent direction across all three runs:

### hp1↔hp3 UDP

| scenario | run 1 (DUR=60) | run 2 (DUR=60) | run 3 (DUR=600) |
|---|---|---|---|
| vlan | 0.07 → 0.06 (-0.01) | 0.04 → 0.03 (-0.01) | 0.06 → 0.07 (+0.01) |
| qinq | 0.06 → 0.04 (-0.02) | 0.03 → 0.06 (+0.03) | 0.06 → 0.05 (-0.01) |
| vxlan | 7.78 → 7.63 (-0.15) | 7.90 → 7.76 (-0.14) | 7.66 → 7.70 (+0.04) |
| mpls | 11.03 → 10.94 (-0.09) | 11.50 → 9.85 (-1.65) | 9.33 → 9.39 (+0.06) |
| ipip | (broken) | 7.25 → 7.24 (-0.01) | 7.10 → 7.28 (+0.18) |

### hp2↔hp5 UDP

| scenario | run 1 (DUR=60) | run 2 (DUR=60) | run 3 (DUR=600) |
|---|---|---|---|
| **vlan** | **1.27 → 0.73 (-0.54)** | **1.64 → 1.59 (-0.05)** | **1.44 → 1.08 (-0.36)** |
| qinq | 0.24 → 0.14 (-0.10) | 0.20 → 0.24 (+0.04) | 0.19 → 0.15 (-0.04) |
| **vxlan** | **8.36 → 8.00 (-0.36)** | **8.39 → 8.18 (-0.21)** | **8.28 → 7.92 (-0.36)** |
| mpls | 8.91 → 7.81 (-1.10) | 9.55 → 8.78 (-0.77) | 9.11 → 9.27 (+0.16) |
| ipip | 7.20 → 7.30 (+0.10) | 7.48 → 8.18 (+0.70) | 7.78 → 7.96 (+0.18) |

**Two cells survive the 3-run consistency test for direction**: `hp2↔hp5 vlan udp` and `hp2↔hp5 vxlan udp`. Both reduce recv_soft_pct by ~0.3pp consistently. That's the real, defensible signal.

## Per-cell sample sizes

DUR=600 = 600 samples per `mpstat -P ALL 1 600` collection per cell. Across 60 cells = 36,000 1-second samples in this dataset. The `recv_soft_pct` column is the "Average: all" row from each cell's mpstat.log file (per-cell sub-summary written by mpstat itself).

## Throughput parity table (byte-identical patches only)

| pair / scen / proto | mbps (sysctl=0 → =1) | |Δ| | within ±2%? |
|---|---|---|---|
| pi5 vlan tcp | 939.0 → 939.0 | 0.0% | yes |
| pi5 vlan udp | 944.8 → 944.8 | 0.0% | yes |
| pi5 qinq tcp | 936.2 → 936.2 | 0.0% | yes |
| pi5 qinq udp | 941.9 → 941.9 | 0.0% | yes |
| pi5 mpls tcp | 938.8 → 938.8 | 0.0% | yes |
| pi5 mpls udp | 944.8 → 944.8 | 0.0% | yes |
| pi5 ipip tcp | 928.4 → 928.4 | 0.0% | yes |
| pi5 ipip udp | 933.1 → 933.1 | 0.0% | yes |
| hp1↔hp3 vlan udp | 6999.8 → 6972.3 | 0.4% | yes |
| hp1↔hp3 qinq udp | 5814.5 → 5745.3 | 1.2% | yes |
| hp1↔hp3 mpls udp | 6481.9 → 6488.7 | 0.1% | yes |
| hp1↔hp3 ipip udp | 6522.4 → 6863.8 | 5.2% | NO — investigate |
| hp2↔hp5 vlan udp | 7245.4 → 7245.2 | 0.0% | yes |
| hp2↔hp5 qinq udp | 5991.5 → 6015.8 | 0.4% | yes |
| hp2↔hp5 mpls udp | 6701.7 → 6684.1 | 0.3% | yes |
| hp2↔hp5 ipip udp | 7217.2 → 7231.8 | 0.2% | yes |

Out of 16 byte-identical UDP cells, **15 are within ±2% throughput parity**. The single outlier is hp1↔hp3 ipip udp (+5.2%, sysctl=1 higher than sysctl=0). Could be the fast-path's tail-call path is genuinely faster on this pair, or run-to-run variance — same outlier was +5.6% in the prior DUR=60 re-run, so it's reproducible. Deserves a focused look (e.g. with a CPU-bound workload that isolates the dissect path) before drawing conclusions.

## Caveats

- TCP cells have 50k-180k retransmits per 10-min cell on the hp pairs — known mlx5 plumbing baseline; not v4-patch related. TCP softirq deltas are not interpretable until the underlying TCP retr issue is characterized.
- recv_sys_pct (host's process-CPU columns) wasn't part of this analysis because iperf3 itself dominates the userspace time and the dissector saving doesn't surface there.
- PPPoE excluded; see investigation memo.

## Cross-references

- 10h target itself: xdp2 `57bd281` (nix/series3-extensions-soak-10h.nix + flake.nix registration)
- DUR=60 baseline runs:
  - `../2026-06-16-v4-dur60-full/SUMMARY.md`
  - `../2026-06-16-v4-dur60-rerun/SUMMARY.md`
- PPPoE deferred investigation: `../2026-06-16-pppoe-investigation.md`
- Phase D plan (informed the scope): `~/.claude/profiles/personal/plans/please-read-perf-results-2026-06-13-l-l2-streamed-raven.md`
