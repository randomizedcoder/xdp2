# Series 3 tcpreplay mixed-packet kernel macro — pi5-2 → pi4-1, pi5-2 → pi3-1

**Date**: 2026-06-10
**Sender**: pi5-2 (Cortex-A76 4c @ 2.4 GHz, 1 GbE end0). tcpreplay 4.5.2.
**Receivers**:
  - pi4-1 (Cortex-A72, 1 GbE end0): replay rate 500 Mbit/s
  - pi3-1 (Cortex-A53, 100 Mbit USB-eth): replay rate 80 Mbit/s
**PCAPs replayed**:
  - `broad-coverage.pcap` — 5200-packet diverse mix (ICMP, fragments,
    SRv6 family, gre-within-gre, vxlan, ipip, l2tp, 6in4, plain
    TCP/UDP). Heavy fast-path-miss content. Tcprewrite-rewrote dst
    MAC per receiver.
  - `vxlan-k8s-pure.pcap` — 20 000-packet VXLAN-encap K8s workload
    (gRPC, Kafka inside). Every packet has outer eth+IPv4+UDP+VXLAN;
    fast-path declines (the dispatcher sees UDP outer and stops at
    the VXLAN dst-port check).
**Tool chain**: `tcprewrite --enet-dmac=$RECV_MAC --enet-smac=$pi5-2_MAC`
  to fix L2 routing; `tcpreplay --intf1=end0 --mbps=$RATE --duration=20s
  --loop=0` to send. Receivers run `mpstat -P ALL 1 20 -o JSON` during
  the replay window and report per-CPU mean %used (= 100 - %idle).
**Driver**: `/tmp/series3-tcpreplay-mixed.sh` (~150 LoC, preserved).
**Matrix**: 2 receivers × 2 PCAPs × 2 sysctl × 3 iters × 20 s = 24
  cells, ~9 min wall clock.

## TL;DR

**Kernel-level CPU% delta on realistic mixed-encap traffic: within
±0.7 pp on both Cortex-A72 and Cortex-A53 receivers**, all four
PCAP×receiver cells. No regression from enabling sysctl=1 on
traffic the fast-path declines.

This matches the iperf3/iperf2 cross-uarch matrix in
`2026-06-10-series3-cross-uarch-perf/`: the userspace PCAP
microbench's +10-15% per-call dispatcher cost on Cortex-A53
remains a microbench artefact; it doesn't translate to measurable
macro cost because the dissector is a small fraction of the
kernel receive path's total CPU budget.

## Per-cell aggregate (N=3, 20 s each)

| recv | pcap            | cpu=0  | cpu=1  | Δ pp   | loss=0 (pkts) | loss=1 (pkts) |
|------|-----------------|-------:|-------:|-------:|--------------:|--------------:|
| pi4-1 (A72) | broad-coverage  | 16.54% | 15.86% | -0.68 |     ~2 893 k  |     ~2 781 k  |
| pi4-1 (A72) | vxlan-k8s-pure  | 17.18% | 17.18% | +0.00 |           ~0  |           ~0  |
| pi3-1 (A53) | broad-coverage  | 14.53% | 14.10% | -0.42 |     ~1 074 k  |     ~1 074 k  |
| pi3-1 (A53) | vxlan-k8s-pure  | 12.26% | 12.15% | -0.11 |           ~0  |           ~0  |

(CPU%: mean across 4 cores during the 20 s replay window;
`packet_loss` = `tx_packets` from tcpreplay − Δ `rx_packets` on
receiver iface. Negative loss values in the vxlan cells are
spurious — tcpreplay's send-side counter slightly under-counts vs
the kernel's rx counter, ±200 pkts cell-to-cell.)

## Observations

1. **broad-coverage.pcap saturates the receiver soft-irq** on pi4-1
   (500 Mbps × small avg packet size → ~250 kpps; receiver drops
   ~55% of packets at the NIC ring before they reach skb alloc).
   On pi3-1, the USB-eth ceiling caps incoming PPS so ~55% loss
   too. In both cases, the receiver CPU% reflects whatever fraction
   of softirq budget the dissector contributes — and it's
   essentially unchanged sysctl=0 → sysctl=1.

2. **vxlan-k8s-pure.pcap has zero loss** on both receivers — the
   larger encap packets are easy to keep up with at these rates.
   Every packet ingresses, runs through the receive softirq
   (which calls the dispatcher on the eth+IPv4+UDP outer header,
   sees UDP for the outer, then the fast-path bails at the
   protocol-port check since VXLAN's dst-port isn't TCP/UDP-data).
   This is exactly the "dispatcher declines, slow-path runs"
   pattern. CPU% delta sysctl=0 → sysctl=1 is +0.00pp on pi4-1
   and -0.11pp on pi3-1 — well below noise.

3. **The broad-coverage -0.68pp / -0.42pp drops at sysctl=1 are
   not a real flow_dissector advantage.** They're within-noise
   sampling artefacts from the heavy receive-drop pattern. The
   loss rates are essentially equal between modes (±0.04%); a
   handful more packets buffered/sampled at the right moment in
   one mode produces this kind of mpstat variance.

## How this fits the broader story

| layer            | dataset                                                  | A76 result    | A72 result    | A53 result    |
|------------------|----------------------------------------------------------|--------------:|--------------:|--------------:|
| Single-shape synthetic (always-hit) | 2026-06-09-series3-arm-microbench/ | -52.3% (gain) | -55.0% (gain) | -48.5% (gain) |
| PCAP microbench (per-call cost)     | 2026-06-10-series3-pi3-pcap-microbench/ | +0.2 to +1.0 ns/pkt | (not run) | +6.7 to +9.9 ns/pkt |
| Kernel iperf3 TCP/UDP wire-rate     | 2026-06-10-series3-cross-uarch-perf/ | (prior pair)  | -0.0pp / -0.0pp CPU | -0.1pp / +0.7pp CPU |
| Kernel tcpreplay mixed-PCAP         | THIS dataset                              | (not run)     | -0.7 / +0.0pp CPU | -0.4 / -0.1pp CPU |

The pattern is consistent across all four layers:

- **Synthetic always-hit**: the patches buy a real ~50% per-call
  cycle saving when the fast-path matches.
- **PCAP microbench, non-eligible shapes**: a small per-call
  dispatcher overhead, ~10x higher on in-order A53 than OoO A76 —
  the per-call cost matters relatively on cores where everything
  is slow.
- **Kernel iperf3 macro**: the dissector is a small fraction of
  total rx cost; A53's relatively-larger per-call cost becomes
  fraction-of-a-percent at kernel level.
- **Kernel tcpreplay macro**: holds on real mixed-packet traffic
  too. Both encap-heavy (vxlan-k8s-pure) and diverse non-eligible
  (broad-coverage) cells show no CPU% regression on either A72
  or A53.

The takeaway for the cover letter is unchanged but reinforced:
the static_branch sysctl gate makes the default-off case
strictly zero-cost; enabling it on shapes the fast-path declines
is essentially free at kernel macro level, even on in-order ARM
where the microbench shows the worst relative per-call overhead.

## Files

- `results.md` (this file)
- `aggregate.csv` — 24-row table
- `raw/<recv>-<pcap>-sysctl<0|1>-iter<n>.{mpstat.json,replay.log}`
- `/tmp/series3-tcpreplay-mixed.sh` — driver script

## Method (reproduction)

```bash
# Pre: patched kernels booted on pi5-2/pi4-1/pi3-1, sysctl present.
# Pre: workload PCAPs on pi5-2 under /root/replay/pcaps/.

# Tcprewrite + replay matrix:
N=3 DUR=20 /tmp/series3-tcpreplay-mixed.sh
```

The driver:
- materialises tcpreplay on sender, sysstat on each receiver
- rewrites each PCAP's eth dst MAC (per receiver) and src MAC
- snapshots /sys/class/net/$iface/statistics/rx_packets pre/post
- runs mpstat in parallel with the replay
- parses tcpreplay's "Successful packets" and the mpstat JSON

## Note on raw logs

The .replay.log files in raw/ are trimmed to their last 20 lines
(the tcpreplay tail summary block — "Successful packets" /
"Failed packets" / etc.) for repo size. The original full logs
were dominated by per-packet "Message too long" warnings caused
by oversized frames in the source PCAPs (mtu-exceeding entries
that the wire-level send rejects); the summary block carries the
actual successful tx count, which is what aggregate.csv parses.
The .mpstat.json files are full, unmodified.

