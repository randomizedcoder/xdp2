# Dual-sender stress to the RISC-V bpi-f3 (both 1 GbE ports)

**Date**: 2026-06-25
**Setup**: pi5-1 (6.12.87) kernel-pktgen → bpi-f3 end0 (172.16.40.205);
pi5-2 (6.12.87) kernel-pktgen → bpi-f3 end1 (172.16.40.206); both 64 B
UDP, randomized flows, 2 threads; RPS on bpi-f3 cores 1-7 (CPU0 reserved
for management). Goal: CPU-saturate the 8-core K1 so a *macro*
flow-dissector A/B becomes visible (the single 1 GbE port couldn't).

## Result — no macro A/B, and the K1 is NOT CPU-bound

| net.flow_dissector.eth_ip | cyc/pkt (system-wide, N=2) |
|---|---|
| 0 (slow path) | 3286.5, 3289.7 |
| 1 (fast path) | 3316.7, 3279.0 |

Within noise — no measurable fast-path effect.

**Why:** received only ~682k pps total (the two pis offer ~3 Mpps; the
K1 drops the rest), at **~17% total CPU**. The bottleneck is the
**single-RX-queue `k1_emac` + NAPI**, not the CPU: packets are dropped at
the NIC ring before the RPS/dissect stage, and the per-packet RX overhead
(~3288 cyc/pkt of NAPI/ring/RPS/drop handling) dwarfs the flow-dissector
cost. Flooding cannot CPU-saturate the dissect path on this single-queue
NIC — it queue-saturates first.

## Takeaway

This reinforces why the **userland microbench** is the right tool for the
flow-dissector A/B: it isolates the dissector from NIC-ring / queue /
NAPI bottlenecks that dominate (and mask it) in a live small-packet
flood. It is also consistent with the Phase F/G macro results (link- or
queue-bound, dissector saving below noise). The per-packet dissector win
is real and large in isolation (~47-55%, see the cross-arch microbench),
but in a full RX flood it is a small fraction of total RX cost; it shows
up as CPU headroom on qdisc/RPS paths (e.g. the WireGuard/cake scenario),
not as throughput on a queue-bound receiver.

Note: a true CPU-bound macro demonstration would need a multi-queue NIC
(NAPI spread across cores) or the qdisc-side path; the K1's in-tree
k1_emac is single-queue.
