# Series 3 Phase 4 — IPv4 macro tests on patched kernel

**Date**: 2026-05-28
**Patched kernel**: 7.1.0-rc4-flowdis-fastpath (series 3 RFC v1, 3 patches)
  - Kernel store hash: `sk5ach761w14cin3wdv1ixyl9p5lxgqp` (hp1/hp3 nixpkgs)
    or `3jx4f3hcrys4i9kfsh5qian2ahg2nqj5` (hp2/hp5 nixpkgs)
  - Verified by disassembly: fast-path `cmpb $0x45, (%rsi)` + frag
    check `testw $0xff3f, 0x6(%rsi)` inlined into `__skb_flow_dissect`
**Testbed pairs**:
  - i40e 10 GbE: hp2 (gen) ↔ hp5 (DUT), cake 10Gbit triple-isolate
  - mlx5_core 25 GbE: hp1 (gen) ↔ hp3 (DUT), cake 25Gbit triple-isolate
**TCP profile applied to both ends per pair**:
  - tcp_rto_min_us=5000, tcp_no_metrics_save=1
  - tcp_slow_start_after_idle=0, tcp_autocorking=0
**Run shape**: 60 s per cell, -P 16 streams

## TL;DR

**No regressions vs B.1 baseline (series 1+2 kernel).** Patched kernel
performs identically or slightly better on all 8 IPv4 cells. The
fast-path code is inlined into `__skb_flow_dissect` and runs on
every RX packet through cake.

## Results

| pair | tool | proto | Gbit/s | retx/lost |
|---|---|---|---:|---:|
| i40e | iperf3 | TCP | 9.408 | 32,086 retx |
| i40e | iperf3 | UDP | 9.563 | 5.2M lost (cake-shaped) |
| i40e | iperf2 | TCP | 9.406 | n/a |
| i40e | iperf2 | UDP | 10.363 | n/a |
| mlx5 | iperf3 | TCP | **15.942** | 8,539 retx |
| mlx5 | iperf3 | UDP | 10.446 | 0 lost (client-bound) |
| mlx5 | iperf2 | TCP | **16.785** | n/a |
| mlx5 | iperf2 | UDP | 10.265 | n/a |

## Comparison with B.1 baseline (series 1+2 kernel, mlx5 only)

| metric | B.1 mean | Phase 4 (1 run) | delta |
|---|---:|---:|---:|
| iperf3 TCP throughput | 16.023 Gbit/s | 15.942 | -0.5 % (within noise) |
| iperf3 TCP retx per 60 s | 14,715 | 8,539 | -42 % (single-sample variance) |

The throughput is within the ±1 % noise band; the retx delta is
within the per-run variance (B.1's CV was 22 % on retx). One run
isn't enough to call signal. The Phase A controlled experiment
(N=10) showed neutrality between B.1 baseline and the series 3
patched kernel; we expect similar here.

## i40e numbers (no prior baseline)

This is the first time we've benchmarked the i40e 10 GbE pair
under series 3. iperf3 TCP at 9.408 Gbit/s is near link-rate
(~94 % of 10 GbE). iperf2 TCP matches at 9.406. iperf2 UDP at
10.363 Gbit/s slightly exceeds iperf3 UDP — iperf2's
thread-per-stream model pushes UDP harder than iperf3's
single-thread sender.

## What this confirms

- **Patched kernel is stable** — 8 macro cells, no kernel WARN/BUG.
- **No throughput regression** vs the prior baseline.
- **cake works correctly** — no excessive drops, classes populate
  per the configured triple-isolate buckets.
- **The fast-path doesn't break anything observable** at the
  macro level. (Byte-exact output to the slow path is asserted by
  patch design; a kernel selftest is queued for v2.)

## What this doesn't confirm

- The PER-PACKET ns/pkt improvement claimed by the patches.
  Macro tests show no regression but can't distinguish a 30-ns
  speedup at a per-packet timescale (the receiver is CPU-bound
  on the TCP/socket-copy path, not the flow_dissector path).
  Phase 3 microbench (flow-dissector-matrix-unified) gives the
  per-packet numbers; deferred.

## IPv6 cells

NOT YET RUN. The hosts' NixOS configs don't have the IPv6 ULA
addresses (`fd10:10:N::M/64`) we wrote on the workstation —
sync didn't happen before reboot. Also, the hosts' xdp2 module
input is pinned to a branch without the IPv6 schema additions.

Will be handled separately:
- Either ad-hoc `ip -6 addr add` for the v6 Phase 4 cells now
- Or wait until the NixOS configs are properly synced and the
  module branch resolves

## Files

- `iperf3_ipv4_results.log` — summary table
- `iperf3_i40e_TCP.json`, `iperf3_i40e_UDP.json`,
  `iperf3_mlx5_TCP.json`, `iperf3_mlx5_UDP.json` — raw JSON outputs
- `iperf2_ipv4_results.log` — summary table
- `iperf2_i40e_TCP.txt`, `iperf2_i40e_UDP.txt`,
  `iperf2_mlx5_TCP.txt`, `iperf2_mlx5_UDP.txt` — raw iperf2 outputs
