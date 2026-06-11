# Series 3 PCAP A/B — Cortex-A53 (Pi 3) cross-uarch confirmation

**Date**: 2026-06-10
**Bench**: same `samples/flow_dissector/micro_flowdis_pcap.c` +
  `nix run .#series3-pcap-microbench` used for the pi5-2 (Cortex-A76)
  runs in `2026-06-10-series3-non-fast-path/` and
  `2026-06-10-series3-mixed-traffic/`.
**Host**: pi3-1 (BCM2837 / Cortex-A53 4c @ 1.2 GHz in-order,
  performance governor on CPU 3, taskset -c 3, 40.8 °C at start,
  no throttle).
**Kernel**: `6.12.87 #1-NixOS aarch64` (linux_rpi3 with the
  three series-3 patches applied; sysctl
  `net.core.flow_dissector_fastpath` present and toggleable —
  not exercised here since the libflowdis bench is always-on).
**Closures**: same as the pi5-2 runs.
  - patched: `/nix/store/k509xbm68zw441cpyqzl60rdv7418ask-xdp2-0.1.0`
  - baseline: `/nix/store/s2jblg2p0pjc3qpz4sds06mv9q44vk1q-xdp2-0.1.0`

## TL;DR

Seven PCAPs spanning the variance range observed on pi5-2
(Cortex-A76) re-run on pi3-1 (Cortex-A53). The dispatcher
fall-through cost on an in-order ARM core is ~7-10 ns/pkt
(10-15%), against ~0.2-1.0 ns/pkt (2-9%) on the A76. The
cost-per-cycle scales linearly with host slowness, as the
single-shape synthetic microbench numbers from
`2026-06-09-series3-arm-microbench/` already showed for the
fast-path body itself.

## Per-PCAP A/B (N=5 per variant, 10 M iter per run)

| pcap | n_packets | patched ns/pkt | baseline ns/pkt | delta ns | delta % |
|---|---:|---:|---:|---:|---:|
| broad-coverage  |  5200 | 74.886 ± 0.22 | 65.068 ± 0.04 | +9.82 | +15.09% |
| gre-within-gre  |   628 | 69.960 ± 0.09 | 63.236 ± 0.06 | +6.72 | +10.63% |
| l2tp            |    38 | 74.342 ± 0.00 | 67.354 ± 0.06 | +6.99 | +10.38% |
| tcp_ipv4        |    11 | 71.278 ± 0.02 | 64.564 ± 0.01 | +6.71 | +10.40% |
| vlan-tcp-mix    | 20000 | 73.576 ± 0.15 | 63.682 ± 0.58 | +9.89 | +15.54% |
| vxlan-k8s-pure  | 20000 | 69.354 ± 0.16 | 62.518 ± 0.10 | +6.84 | +10.93% |
| vxlan           |    10 | 71.288 ± 0.04 | 64.600 ± 0.08 | +6.69 | +10.35% |

**Aggregate across 7 PCAPs**:
- patched mean ns/pkt: 71.96
- baseline mean ns/pkt: 64.43
- delta mean: +7.52 ns/pkt (+11.91%)

The picture matches the pi5-2 data qualitatively. Two regimes:

- **Pure-encap workloads** (vxlan, vxlan-k8s-pure, gre-within-gre,
  l2tp): all 7 ns/pkt delta. Every packet declines the fast-path;
  this is the dispatcher fall-through cost on a 1.2 GHz in-order
  A53 — measured here at ~9 cycles per call.
- **Mixed-shape workloads** (broad-coverage, vlan-tcp-mix): ~10
  ns/pkt delta. Higher cache footprint amplifies the cost of
  the per-call dispatcher chain.

## Cross-uarch comparison (A53 vs A76)

The same 7 PCAPs side by side. Numbers in ns/pkt:

| pcap            | A53 patched | A53 baseline | A53 Δ | A76 patched | A76 baseline | A76 Δ |
|-----------------|------------:|-------------:|------:|------------:|-------------:|------:|
| broad-coverage  |       74.89 |        65.07 |  9.82 |       11.89 |        10.92 |  0.96 |
| gre-within-gre  |       69.96 |        63.24 |  6.72 |       10.85 |        10.47 |  0.38 |
| l2tp            |       74.34 |        67.35 |  6.99 |       12.86 |        11.97 |  0.88 |
| tcp_ipv4        |       71.28 |        64.56 |  6.71 |       10.85 |        10.62 |  0.23 |
| vlan-tcp-mix    |       73.58 |        63.68 |  9.89 |       10.89 |        10.34 |  0.55 |
| vxlan-k8s-pure  |       69.35 |        62.52 |  6.84 |       10.88 |        10.38 |  0.50 |
| vxlan           |       71.29 |        64.60 |  6.69 |       10.85 |        10.61 |  0.24 |

Ratio (A53 ns / A76 ns):
- patched body cost: 6.4x - 6.8x
- baseline body cost: 5.9x - 6.2x
- dispatcher fall-through cost (delta): 8.8x - 26.2x

The dispatcher cost ratio is larger than the body cost ratio — an
in-order pipeline pays disproportionately more per branch than an
out-of-order one. That's expected: the dispatcher is a short chain
of dependent loads + compares, exactly the workload pattern that
benefits most from out-of-order execution.

## Implications for the cover letter

This data point reinforces, doesn't change, the existing operator
guidance:

1. **The fast-path savings are real and substantial** on the
   eligible subset of any workload — even on a 1.2 GHz in-order
   A53, the always-hit synthetic microbench showed a -48.5%
   gain (per `2026-06-09-series3-arm-microbench/pi3-1/`).
2. **The dispatcher fall-through cost is workload-dependent** —
   ~7 ns/pkt on A53, ~0.5 ns/pkt on A76, ~0.3 ns/pkt on x86_64
   Comet Lake-H. The breakeven hit fraction (cost-balanced
   point) is therefore architecture-dependent too: on an A53,
   the operator needs a higher fast-path-eligible share before
   sysctl=1 is net-positive.
3. The default `sysctl=0` remains a strict zero-cost — the
   static_branch NOP-skip is uniform across uarchs.

Operators on small ARM cores (CPE, low-end embedded, edge
appliances) should be more conservative about enabling the
sysctl than operators on large x86 datacenter cores. The cover
letter's existing guidance ("DC east-west, HTTP edge" yes; "PPPoE
CPE, VXLAN overlays" no) already captures most of this; the
Cortex-A53 numbers here are the empirical backing for the
warning that ARM CPE devices have higher per-packet dispatcher
cost.

## Method (reproduction)

```bash
# Pre-conditions: closures present on pi3-1 via nix-copy-closure;
# libpcap materialized on pi3-1 (nix build --no-link nixpkgs#libpcap
# nixpkgs#libpcap.lib).
nix-copy-closure --to root@pi3-1 \
  /nix/store/k509xbm68zw441cpyqzl60rdv7418ask-xdp2-0.1.0 \
  /nix/store/s2jblg2p0pjc3qpz4sds06mv9q44vk1q-xdp2-0.1.0

ssh root@pi3-1 'nix build --no-link --print-out-paths \
  nixpkgs#libpcap nixpkgs#libpcap.lib'

ssh root@pi3-1 'echo performance > \
  /sys/devices/system/cpu/cpu3/cpufreq/scaling_governor'

# Stage the 7-PCAP subset and run the batch:
mkdir -p /tmp/pi3-pcaps
cp data/pcaps/{tcp_ipv4,broad-coverage,l2tp,vxlan,gre-within-gre}.pcap \
   /tmp/pi3-pcaps/
cp /tmp/phase-d-pcaps/{vlan-tcp-mix,vxlan-k8s-pure}.pcap /tmp/pi3-pcaps/

# Single-PCAP smoke run via nix wrapper (builds the bench binary
# under /root/microbench/ on pi3-1):
nix run .#series3-pcap-microbench -- \
  pi3-1 \
  /nix/store/k509xbm68zw441cpyqzl60rdv7418ask-xdp2-0.1.0 \
  /nix/store/s2jblg2p0pjc3qpz4sds06mv9q44vk1q-xdp2-0.1.0 \
  /tmp/pi3-pcaps/tcp_ipv4.pcap 1 \
  perf-results/2026-06-10-series3-pi3-pcap-microbench/pi3-1

# Then the fast-batch driver for the rest:
/tmp/series3-pcap-fast-batch.sh \
  pi3-1 \
  /nix/store/k509xbm68zw441cpyqzl60rdv7418ask-xdp2-0.1.0 \
  /nix/store/s2jblg2p0pjc3qpz4sds06mv9q44vk1q-xdp2-0.1.0 \
  perf-results/2026-06-10-series3-pi3-pcap-microbench/pi3-1 \
  /tmp/pi3-pcaps 5
```

## Files

- `results.md` (this file)
- `pi3-1/aggregate.csv` — 7-row table, machine-readable
- `pi3-1/runs/<pcap>.log` — raw 10-run output per PCAP
- `pi3-1/micro_flowdis_pcap_tcp_ipv4.log` — smoke-run log
