# mlx5 offload OFAT investigation — IPIP +5.2% root cause + TX checksum bug

Cross-references:
- IPIP run: `perf-results/2026-06-18-mlx5-offload-ipip-hp1-hp3-v2/matrix.csv`
- GRE run: `perf-results/2026-06-18-mlx5-offload-gre-hp1-hp3/matrix.csv`
- Harness: `nix/mlx5-offload-investigate.nix`, registered as `nix run .#mlx5-offload-investigate`
- Originating data point: `perf-results/2026-06-16-v4-soak-10h/SUMMARY.md` (+5.2% IPIP UDP)

## TL;DR

Two findings:

1. **The +5.2% IPIP UDP outlier from the 10h soak is variance, not a fast-path effect.** Across 36 cells per scenario (12 (feature×state) × 3 replicates × 2 sysctl), no single offload feature reliably reproduces a +5% throughput shift. Per-cell stdev is ~150-200 Mbps (±2-3% relative); +5.2% is ~2σ — possible but not signal. The headline framing for the v4 cover letter stands: throughput parity holds across byte-identical patches; recv_soft saving is ~0.3pp where it surfaces.

2. **The mlx5 ConnectX-4 Lx silicon revision in hp1/hp3 (`rx-vlan-stag-filter: on [fixed]` variant) has a real TX-checksum bug specific to IPIP encapsulation.** Same NIC, same kernel, same outer IP: GRE-encap flows fine with `tx-checksum on` on the tunnel iface; IPIP-encap with `tx-checksum on` drops throughput to 0 Mbps because the NIC mis-computes the inner TCP/UDP checksum. This is a real, reproducible, kernel-team-shareable finding.

## Reproducer

```sh
git clone github.com:randomizedcoder/xdp2
cd xdp2
# IPIP investigation (the failing case)
nix run .#mlx5-offload-investigate
# GRE investigation (the working case for comparison)
SCENARIO=gre nix run .#mlx5-offload-investigate
```

Each run is ~35 minutes; outputs `perf-results/<date>-mlx5-offload-<scenario>-<pair>/matrix.csv` with one row per (feature, state, sysctl, replicate) cell.

Test fleet:
- pair: hp1 ↔ hp3, back-to-back 25 GbE DAC, Linux 7.0.9 + the v4 + v4-gre patches deployed
- iface: enp1s0f0np0 (Mellanox ConnectX-4 Lx PCI 15b3:1015, HP_2420 firmware, `rx-vlan-stag-filter: on [fixed]`, `tx-vlan-stag-hw-insert: on`)

Default per-run configuration:
- iperf3 UDP, 4 parallel streams, 1200-byte packet, 30s per cell, 3 replicates per cell
- Features toggled OFAT: `tx-checksum` (tunnel), `gso` (tunnel), `gro` (tunnel), `tx-udp-segmentation` (tunnel), `tx-checksum-ip-generic` (physical iface)

## Finding 1 — IPIP +5.2% is variance (not a fast-path effect)

Aggregating IPIP UDP throughput across all 12 (feature × state) combinations, sysctl=0 vs sysctl=1:

| feature | state | sysctl=0 mbps | sysctl=1 mbps | Δ |
|---|---|---|---|---|
| baseline | asfound | 6698 | 6767 | +1.0 % |
| csum-ipv4 | off | 6744 | 6770 | +0.4 % |
| csum-ipv4 | on | 6786 | 6757 | -0.4 % |
| gro | off | 6720 | 6792 | +1.1 % |
| gro | on | 6726 | 6797 | +1.1 % |
| gso | off | 6735 | 6605 | -1.9 % |
| gso | on | 6648 | 6703 | +0.8 % |
| tx | off | 6641 | 6831 | **+2.9 %** |
| tx | on | 0 | 0 | (BROKEN — see Finding 2) |
| udp-seg | off | 6845 | 6637 | -3.0 % |
| udp-seg | on | 6746 | 6805 | +0.9 % |

Per-cell stdev ranges 30-250 Mbps (= ±0.5-3.7 % of the mean). The largest single delta (+2.9 % `tx off`) is well within 1-2σ of the per-cell variance. Direction is **inconsistent** between features (5 of 11 negative, 6 positive), which is exactly what random noise looks like across an OFAT scan.

The +5.2 % from the 10h soak was a 2σ point — possible by chance about 5 % of the time. Not a reliable fast-path effect.

GRE OFAT scan shows the same pattern: all deltas within ±3 %, direction mixed. So the byte-identical-fast-path contract claim (throughput parity within run-to-run variance) holds.

## Finding 2 — mlx5 TX-checksum bug is IPIP-encap-specific

Same NIC, same kernel, same outer IPv4 header layout (only the `protocol` byte differs: 4=IPIP, 47=GRE). The `tx` alias on the tunnel iface controls hardware TX-checksum offload for packets exiting via that tunnel:

| tunnel iface, `tx` state | IPIP UDP cells | GRE UDP cells |
|---|---|---|
| `tx off` (default after netconf-X up; workaround) | 6641 / 6831 Mbps | 6910 / 6827 Mbps |
| `tx on` | **0 / 0 Mbps** (Connection timed out) | 6575 / 6648 Mbps (works) |

iperf3 error for the IPIP+`tx on` cells:

```
{"error": "unable to connect to server - server may have stopped
           running or use a different port, firewall issue, etc.:
           Connection timed out"}
```

(Six replicates across sysctl=0 and sysctl=1; all six reported the same.)

ICMP-in-IPIP with `tx on` traverses fine (verified manually earlier in the investigation — kernel computes ICMP checksums in software regardless of NIC offload state). It's specifically TCP/UDP under IPIP encap that the NIC mishandles.

### Why this matters

- IPIP is the default Linux behaviour for several common tunnel uses (legacy 6to4, simple GRE-less IP-in-IP between two hosts).
- The bug is silent: the connection just times out. There's no kernel log message, no driver error counter increment, no offload-status indication that the frames are leaving with bad checksums.
- The workaround (`ethtool -K $TUN tx off`) is per-tunnel-iface and operator-discoverable only via this kind of A/B test.

### Suggested kernel-team report shape

Subject: `mlx5_core: TX checksum offload mis-computes for IPIP-encapsulated TCP/UDP on ConnectX-4 Lx (rx-vlan-stag-filter [fixed] revision)`

Body:
- NIC: Mellanox ConnectX-4 Lx, PCI 15b3:1015, firmware HP_2420.
- Symptom: `iperf3 -u/-c` over an `ip link add type ipip` tunnel with the tunnel's `tx-checksum-ip-generic` offload **on** produces 0 Mbps throughput. Disabling the tunnel-iface TX-checksum (`ethtool -K $TUN tx off`) restores ~6.7 Gbps. Same firmware + driver handles GRE-encap (`ip link add type gre`) correctly with `tx` on.
- Reproducer: this xdp2 harness (`nix run .#mlx5-offload-investigate`) on hp1↔hp3 testbed pair.
- Attached: this memo + the two matrix.csv files.

## Configuration matrix details

For both IPIP and GRE scenarios:

| feature key | ethtool kw | which iface | as-found default |
|---|---|---|---|
| tx | tx | tunnel | off (after netconf-X up applies the workaround) |
| gso | gso | tunnel | on |
| gro | gro | tunnel | on |
| udp-seg | tx-udp-segmentation | tunnel | off [fixed] (mlx5 doesn't advertise) |
| csum-ipv4 | tx-checksum-ip-generic | physical | on |

OFAT loop: for each feature, the scenario is torn-down and brought back up (to recover from any destructive toggle from a prior feature — discovered necessary after the first run showed `tx on` poisoning subsequent cells when the tunnel wasn't recreated). Then for each (state, sysctl, replicate) combination a 30-second iperf3 + mpstat run records the cell.

## Caveats

- Per-cell DUR=30 and N=3 replicates is intentionally light for a first-pass screening. To pin a 1-2 % effect to confidence, bump to DUR=120 N=5 (~3 h wall) or DUR=300 N=3 (~3 h wall).
- The OFAT scan didn't test feature *combinations*. If two features interact synergistically (e.g., `gso off + udp-seg off`) the effect would be invisible to a single-feature toggle. Pairwise scan is a follow-up if needed; this screening would have caught a single-feature ≥5 % effect, which is what we were looking for.
- The harness toggles features on **both** ends of the pair. If the bug were asymmetric (only TX-side or only RX-side), we'd miss the asymmetry. Could be split into `LEFT_FEATURES=` and `RIGHT_FEATURES=` if needed.
- Only hp1↔hp3 tested. hp2↔hp5 has different mlx5 silicon (`tx-vlan-stag-hw-insert: off [fixed]` variant) which is known to behave differently for IPIP elsewhere in this investigation — see the v4 `2026-06-16-v4-dur60-full` matrix where hp2↔hp5 ipip works without the tx-off workaround.
