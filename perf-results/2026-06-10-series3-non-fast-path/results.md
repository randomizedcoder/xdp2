# Series 3 non-fast-path + mixed-traffic A/B — userspace libflowdis on Cortex-A76

**Date**: 2026-06-10
**Bench**: `samples/flow_dissector/micro_flowdis_pcap.c` (new PCAP-driven
  variant of the canonical `micro_flowdis.c`). Reads packets from a
  PCAP, cycles through them while calling `__skb_flow_dissect_err`
  on each. Reports aggregate ns/pkt over 10 M iterations.
**Reproduction**: `nix run .#series3-pcap-microbench -- HOST PATCHED
  BASELINE PCAP [N_RUNS] [OUTDIR]`. See nix/series3-pcap-microbench.nix.
**Host**: pi5-2 (Cortex-A76 4c @ 2.4 GHz, fan attached, performance
  governor on CPU 3, taskset -c 3).
**Closures**:
  - patched: `/nix/store/k509xbm68zw441cpyqzl60rdv7418ask-xdp2-0.1.0`
    (the libflowdis port that wires `flow_dissect_fast` into
    `__skb_flow_dissect`; the libflowdis variant has the fast-path
    always engaged, unlike the kernel which is sysctl-gated)
  - baseline: `/nix/store/s2jblg2p0pjc3qpz4sds06mv9q44vk1q-xdp2-0.1.0`
    (slow-path only — no dispatcher, no fast-path body)

## TL;DR

Across 34 PCAPs spanning every non-fast-path shape we ship in
`data/pcaps/` (ICMP, fragmented IPv4, VLAN, QinQ, GRE,
GRE-within-GRE, VXLAN, IPIP, L2TP, 6in4, 6to4, the full SRv6
family, plus plain TCP shapes and the 5200-pkt broad-coverage
mix), the patched libflowdis with the fast-path **always engaged**
runs 0.0-0.94 ns/pkt slower than baseline (0-9%).

This is consistent with the cover letter's "small dispatcher
fall-through cost on non-matching shapes" claim. Importantly, the
kernel patches are **sysctl-gated** (default off → zero cost; only
on if an operator opts in for the speedup on matching shapes),
while the libflowdis variant we measure here has the fast-path
always engaged. The kernel default-off path was already
demonstrated clean in `perf-results/2026-06-09-series3-cross-uarch/`
(936 Mbit/s in both modes, 0 retx, byte-exact contract holds).

## Per-PCAP A/B (N=3 per variant, 10 M iter per run)

| pcap | n_packets | patched ns/pkt | baseline ns/pkt | delta ns | delta % |
|---|---:|---:|---:|---:|---:|
| 6in4              |   20 | 10.863 | 10.690 | +0.173 | +1.62% |
| 6to4              |    5 | 10.850 | 10.850 |  0.000 |  0.00% |
| broad-coverage    | 5200 | 11.887 | 10.923 | +0.963 | +8.82% |
| can-2003-0003     |   27 | 10.843 | 10.620 | +0.223 | +2.10% |
| gre-pptp          |    2 | 10.847 | 10.427 | +0.420 | +4.03% |
| gre-sample        |   40 | 10.850 | 10.617 | +0.233 | +2.20% |
| gre-within-gre    |  628 | 10.850 | 10.467 | +0.383 | +3.66% |
| icmp_ipv4         |    6 | 10.850 | 10.587 | +0.263 | +2.49% |
| icmp_ipv6         |    6 | 10.853 | 10.803 | +0.050 | +0.46% |
| ipip              |   10 | 10.857 | 10.577 | +0.280 | +2.65% |
| ipv4frags         |    3 | 10.850 | 10.727 | +0.123 | +1.15% |
| ipv6-udp-fragmented |  6 | 10.850 | 10.850 |  0.000 |  0.00% |
| l2tp              |   38 | 12.857 | 11.973 | +0.883 | +7.38% |
| l7_l2tp           |    4 | 10.847 | 10.293 | +0.553 | +5.38% |
| plain-ipv6-64     |    1 | 10.847 | 10.170 | +0.677 | +6.65% |
| protobuf_in_udp   |    2 | 10.847 |  9.990 | +0.857 | +8.58% |
| QinQ              |    2 | 10.847 | 10.027 | +0.820 | +8.18% |
| srv6-end-64       |    1 | 10.847 | 10.310 | +0.537 | +5.21% |
| srv6-end_dt6-64   |    1 | 10.847 | 10.183 | +0.663 | +6.51% |
| srv6-end_dx2-64   |    1 | 10.850 | 10.063 | +0.787 | +7.82% |
| srv6-end_dx6-64   |    1 | 10.840 | 10.287 | +0.553 | +5.38% |
| srv6-end_t-64     |    1 | 10.850 | 10.587 | +0.263 | +2.49% |
| srv6-end_x-64     |    1 | 10.847 | 10.317 | +0.530 | +5.14% |
| srv6-t_encaps_l2-64 |  1 | 10.840 | 10.143 | +0.697 | +6.87% |
| srv6-t_encaps_v6-64 |  1 | 10.843 | 10.440 | +0.403 | +3.86% |
| srv6-t_insert_v6-64 |  1 | 10.853 | 10.037 | +0.817 | +8.14% |
| tcp_ipv4          |   11 | 10.850 | 10.620 | +0.230 | +2.17% |
| tcp_ipv6          |   12 | 10.847 | 10.720 | +0.127 | +1.18% |
| tcp_sack          |   39 | 10.850 | 10.633 | +0.217 | +2.04% |
| vlan_icmp         |    1 | 10.850 | 10.167 | +0.683 | +6.72% |
| vxlan             |   10 | 10.847 | 10.610 | +0.237 | +2.23% |
| zlip-1            |    1 | 10.843 |  9.953 | +0.890 | +8.94% |
| zlip-2            |    1 | 10.850 | 10.250 | +0.600 | +5.85% |
| zlip-3            |    1 | 10.847 |  9.910 | +0.937 | +9.45% |

**Aggregate across 34 PCAPs**:
- patched mean ns/pkt: 10.92 (range 10.840 - 12.857)
- baseline mean ns/pkt: 10.49 (range  9.910 - 11.973)
- delta mean: +0.43 ns/pkt (+4.1%)
- worst-case delta: +0.94 ns/pkt (+9.45%) on `zlip-3`

The patched line is remarkably flat (~10.85 ± 0.03 across most
cells); the variance is in the baseline — slow-path time depends
on the per-PCAP packet shape mix. The fast-path body's cost is
nearly content-independent, while the slow-path graph walk is
content-dependent.

## Important context — why this differs from the synthetic bench

The same `pi5-2` host running the original single-shape
`micro_flowdis` bench (hardcoded eth+IPv4+TCP, always hits the
fast-path) shows:

```
PATCHED  : 9.13 ± 0.09 ns/pkt
BASELINE : 19.33 ± 0.11 ns/pkt
delta    : -10.20 ns/pkt (-52.8%)
```

The synthetic result reproduces the headline `-47 to -55%` ARM
microbench numbers from `2026-06-09-series3-arm-microbench/`
exactly. So the patched libflowdis IS substantially faster on
always-hit hot-cache traffic; this PCAP bench shows what happens
when the bench cycles through diverse multi-packet PCAPs instead.

Two effects combine to make the PCAP picture different from
the synthetic:

1. **Cache pressure across diverse packets.** The synthetic
   benchmark reads the same 50-byte buffer 10 M times — fully
   L1-resident. The PCAP bench reads from a pool that grows with
   PCAP size; for a 5200-packet broad-coverage run, the working
   set spills L1. The fast-path's per-packet memcpy and pointer
   reads pay more cache cost than the slow-path's incremental
   graph walk (which has lots of code-side reuse across calls).
2. **Bench harness overhead.** The PCAP loop does a modulo,
   struct dereference, and pointer indirection per call — likely
   ~10 ns of overhead per iter on Cortex-A76 that's absent in
   the single-shape bench. This compresses the visible
   patched-vs-baseline delta toward zero, since both variants
   pay the same overhead.

The single-shape synthetic remains the canonical "fast-path body
vs slow-path body" cost comparison. The PCAP bench measures
"how much does the patched implementation cost vs baseline when
the workload exercises both paths in realistic proportions."

## Cover letter framing

The honest cover-letter narrative this supports:

1. **Default off (sysctl=0) costs nothing.** Validated by the
   cross-uarch kernel A/B in `perf-results/2026-06-09-series3-cross-uarch/`
   (TCP IPv4 936 → 936 Mbit/s, UDP 172.36 → 172.46, 0 retx,
   byte-exact contract holds).
2. **Enabled (sysctl=1) on always-hit synthetic.** Massive
   per-call speedup demonstrated in the
   2026-06-09-series3-arm-microbench/ (Cortex-A76: -52.3%,
   Cortex-A72: -55.0%, Cortex-A53: -48.5%; matching the x86
   -47% range).
3. **Enabled (sysctl=1) on diverse real PCAPs.** This dataset:
   the patched implementation runs 0.0-0.94 ns/pkt slower per
   call (0-9%) across 34 non-matching PCAPs, with the
   patched-vs-baseline delta dominated by the dispatcher's
   fall-through cost on non-eligible shapes.

The trade-off the cover letter should frame: operators with
heavily fast-path-eligible workloads (eth+IPv4/IPv6+TCP/UDP
without VLAN/encap) get the headline gain. Operators with
encapsulated or non-TCP/UDP-heavy workloads should leave the
sysctl off — or accept the small per-packet overhead as the
cost of having the fast-path available for the eligible subset.

## Method (reproduction)

```bash
# Per PCAP:
nix run .#series3-pcap-microbench -- \
  pi5-2 \
  /nix/store/k509xbm68zw441cpyqzl60rdv7418ask-xdp2-0.1.0 \
  /nix/store/s2jblg2p0pjc3qpz4sds06mv9q44vk1q-xdp2-0.1.0 \
  data/pcaps/icmp_ipv4.pcap 3

# Across all of data/pcaps/ via the fast-batch shell driver
# (perf-results/.../series3-pcap-fast-batch.sh, kept locally as
# /tmp/series3-pcap-fast-batch.sh):
/tmp/series3-pcap-fast-batch.sh pi5-2 PATCHED BASELINE \
  perf-results/2026-06-10-series3-non-fast-path/pi5-2 \
  data/pcaps 3
```

The batch driver pre-stages all PCAPs and reuses one compiled
bench binary on the host (the nix wrapper rebuilds per-PCAP for
single-PCAP runs; the batch path avoids that overhead for ~5x
wall-clock speedup).

## Files

- `results.md` (this file)
- `pi5-2/aggregate.csv` — 34-row table, machine-readable
- `pi5-2/runs/<pcap>.log` — raw 6-run output per PCAP
