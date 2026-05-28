# Series 3 Phase 5 — 30-min sustained per pair

**Date**: 2026-05-28
**Patched kernel**: 7.1.0-rc4-flowdis-fastpath (series 3 v1 RFC)
**Pairs**: hp2↔hp5 i40e 10 GbE, hp1↔hp3 mlx5_core 25 GbE
**TCP profile**: tuned (rto_min=5ms, no_metrics_save,
  no slow_start_after_idle, no autocorking)

## TL;DR

Both rounds (30-min iperf3, then 30-min iperf2) ran cleanly on
both pairs in parallel. No regression vs Phase 4 60-s numbers
or B.1 24h baseline. No new dmesg alerts on any host.

## Results

| pair | round 1 (iperf3 30 min) | round 2 (iperf2 30 min) | comparison |
|---|---:|---:|---:|
| **i40e 10 GbE** | **9.414 Gbit/s** | **9.414 Gbit/s** | iperf3 == iperf2, near link rate |
| **mlx5 25 GbE** | **16.017 Gbit/s** | **16.226 Gbit/s** | matches B.1 baseline 16.023 |

### mlx5 stability

The mlx5 round 1 (iperf3, 30-min) result of 16.017 Gbit/s is
within **0.04 %** of the B.1 24-h soak mean of 16.023 Gbit/s.
This is well below the B.1 CV of 1.27 % and confirms that the
series 3 patches do not change the steady-state throughput at
30-min duration.

### i40e stability

iperf3 round 1 (9.414 Gbit/s) matches iperf2 round 2
(9.414 Gbit/s) **exactly** to 3 decimals. This is the first
30-min sustained measurement on the i40e pair; near link rate
on a 10 GbE link.

## Post-round 2 cake stats

mlx5 (hp3 dut):

```
qdisc cake 8001: root bandwidth 25Gbit diffserv3 triple-isolate ...
 Sent 22468737299 bytes 337332530 pkt (dropped 0, overlimits 0 requeues 22195)
 backlog 0b 0p requeues 22195
 memory used: 260162b of 15140Kb
```

i40e (hp5 dut):

```
qdisc cake 8001: root bandwidth 10Gbit diffserv3 triple-isolate ...
 Sent 16457150113 bytes 246390003 pkt (dropped 0, overlimits 0 requeues 15627)
 backlog 0b 0p requeues 15627
 memory used: 129600b of 15140Kb
```

**0 dropped, 0 overlimits, low requeues, tiny memory footprint
(260 KB on mlx5, 130 KB on i40e).** Same shape as B.1 baseline.

## Dmesg

Both DUTs show 8 dmesg WARN/BUG/oops matches (the 8 pre-existing
boot-time entries: AMD Zen1 DIV0/FPDSS, ACPI firmware bug,
amdgpu drm init). **0 new alerts** introduced by 1 hour of
sustained load.

## What this confirms

- Patched kernel sustains both server models (iperf3
  single-threaded + iperf2 thread-per-stream) without
  degradation over 30 min.
- 0 cake drops, 0 overlimits across both 30-min rounds on
  both pairs.
- 0 new dmesg alerts.
- The patched kernel's behaviour at 30-min duration is
  indistinguishable from the 60-s Phase 4 measurements.

## Files

- `round1_iperf3.log`, `round2_iperf2.log` — wrapper banners
- `round1_{i40e,mlx5}.json` — iperf3 30-min JSON outputs
- `round2_{i40e,mlx5}.txt` — iperf2 30-min text outputs
- `round{1,2}_pre_snapshot.txt`, `round{1,2}_post_snapshot.txt`
  — pre and post state snapshots

## Next

Phase 6: 24h soaks (i40e iperf3 + mlx5 iperf2 in parallel).
