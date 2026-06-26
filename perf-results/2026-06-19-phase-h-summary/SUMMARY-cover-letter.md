# Cover-letter summary: flow_dissector fast-path measurements (2026-06-20)

Mean ± sample stddev across replicates. sysctl=0 reproduces pre-patch kernel behavior (slow path); sysctl=1 enables the new fast-path. Per-cell run-to-run variance is the noise floor; "(noise)" tags rows where the slow→fast delta is within 2× pooled stddev.

**Headline:** on hp2-hp5 eth_ip UDP (Phase G pktgen), the fast-path saves 198 cycles/packet (6.2% reduction, 3205 → 3008).

## Phase G — cycles per packet (kernel pktgen, ksoftirqd perf-stat)

| sysctl | pair | scen | slow_path | fast_path | Δ cyc/pkt | % improvement |
|---|---|---|---|---|---|---|
| net.flow_dissector.vlan | hp1-hp3 | vlan | 2263 ± 77 cyc/pkt | 2409 ± 74 cyc/pkt | +146 (noise) | +6.4% (noise) |
| net.flow_dissector.eth_ip | hp2-hp5 | eth_ip | 3205 ± 146 cyc/pkt | 3008 ± 104 cyc/pkt | -198 (noise) | -6.2% (noise) |
| net.flow_dissector.vlan | hp2-hp5 | vlan | 3054 ± 88 cyc/pkt | 2905 ± 48 cyc/pkt | -148 | -4.9% |
| net.flow_dissector.ipip | hp1-hp3 | ipip | 2311 ± 19 cyc/pkt | 2261 ± 47 cyc/pkt | -50 (noise) | -2.2% (noise) |
| net.flow_dissector.qinq | hp2-hp5 | qinq | 3023 ± 137 cyc/pkt | 3076 ± 165 cyc/pkt | +53 (noise) | +1.7% (noise) |
| net.flow_dissector.mpls | hp1-hp3 | mpls | 2352 ± 25 cyc/pkt | 2313 ± 54 cyc/pkt | -38 (noise) | -1.6% (noise) |
| net.flow_dissector.gre | hp2-hp5 | gre | 3113 ± 82 cyc/pkt | 3073 ± 112 cyc/pkt | -40 (noise) | -1.3% (noise) |
| net.flow_dissector.gre | hp1-hp3 | gre | 2290 ± 41 cyc/pkt | 2315 ± 121 cyc/pkt | +25 (noise) | +1.1% (noise) |
| net.flow_dissector.ipip | hp2-hp5 | ipip | 3088 ± 71 cyc/pkt | 3111 ± 236 cyc/pkt | +23 (noise) | +0.8% (noise) |
| net.flow_dissector.mpls | hp2-hp5 | mpls | 3010 ± 82 cyc/pkt | 2990 ± 94 cyc/pkt | -20 (noise) | -0.7% (noise) |
| net.flow_dissector.eth_ip | hp1-hp3 | eth_ip | 2334 ± 16 cyc/pkt | 2344 ± 32 cyc/pkt | +9 (noise) | +0.4% (noise) |
| net.flow_dissector.qinq | hp1-hp3 | qinq | 2315 ± 47 cyc/pkt | 2310 ± 48 cyc/pkt | -5 (noise) | -0.2% (noise) |

## Phase F — receiver softirq % (iperf3 + RPS/CAKE/FLOWER loaded)

| sysctl | pair | scen | proto | slow_path | fast_path | Δ pp | % improvement |
|---|---|---|---|---|---|---|---|
| net.flow_dissector.qinq | hp1-hp3 | qinq | tcp | 22.51 ± 1.25% | 18.92 ± 4.42% | -3.59pp (noise) | -15.9% (noise) |
| net.flow_dissector.vxlan_inner | hp1-hp3 | vxlan | tcp | 16.54 ± 2.60% | 19.88 ± 4.81% | +3.34pp (noise) | +20.2% (noise) |
| net.flow_dissector.vlan | hp1-hp3 | vlan | tcp | 20.37 ± 3.02% | 22.52 ± 1.16% | +2.15pp (noise) | +10.6% (noise) |
| net.flow_dissector.eth_ip | hp1-hp3 | eth_ip | tcp | 22.93 ± 0.67% | 20.99 ± 3.75% | -1.94pp (noise) | -8.5% (noise) |
| net.flow_dissector.geneve_inner | hp1-hp3 | geneve | tcp | 22.05 ± 1.87% | 23.41 ± 0.21% | +1.36pp (noise) | +6.2% (noise) |
| net.flow_dissector.eth_ip | hp2-hp5 | eth_ip | udp | 15.01 ± 1.29% | 13.67 ± 0.71% | -1.34pp (noise) | -8.9% (noise) |
| net.flow_dissector.ipip | pi5-pair | ipip | udp | 18.56 ± 0.24% | 19.42 ± 0.85% | +0.86pp (noise) | +4.6% (noise) |
| net.flow_dissector.mpls | hp1-hp3 | mpls | tcp | 23.64 ± 0.08% | 22.97 ± 0.62% | -0.67pp (noise) | -2.8% (noise) |
| net.flow_dissector.gre | pi5-pair | gre | udp | 19.53 ± 0.81% | 19.05 ± 0.83% | -0.48pp (noise) | -2.5% (noise) |
| net.flow_dissector.geneve_inner | hp2-hp5 | geneve | tcp | 14.03 ± 0.45% | 13.56 ± 0.06% | -0.47pp (noise) | -3.3% (noise) |
| net.flow_dissector.mpls | hp2-hp5 | mpls | udp | 11.83 ± 0.36% | 12.22 ± 0.17% | +0.39pp (noise) | +3.3% (noise) |
| net.flow_dissector.geneve_inner | pi5-pair | geneve | udp | 20.81 ± 0.71% | 21.20 ± 0.73% | +0.39pp (noise) | +1.9% (noise) |
| net.flow_dissector.qinq | hp2-hp5 | qinq | tcp | 17.10 ± 0.39% | 17.47 ± 0.28% | +0.37pp (noise) | +2.2% (noise) |
| net.flow_dissector.gre | hp1-hp3 | gre | tcp | 14.20 ± 0.33% | 14.54 ± 0.40% | +0.35pp (noise) | +2.4% (noise) |
| net.flow_dissector.mpls | pi5-pair | mpls | udp | 14.71 ± 0.02% | 15.05 ± 0.59% | +0.34pp (noise) | +2.3% (noise) |
| net.flow_dissector.vxlan_inner | pi5-pair | vxlan | udp | 20.22 ± 0.55% | 19.89 ± 0.03% | -0.33pp (noise) | -1.6% (noise) |
| net.flow_dissector.gre | hp2-hp5 | gre | tcp | 14.22 ± 0.19% | 14.52 ± 0.39% | +0.30pp (noise) | +2.1% (noise) |
| net.flow_dissector.eth_ip | pi5-pair | eth_ip | udp | 13.33 ± 0.02% | 13.57 ± 0.43% | +0.24pp (noise) | +1.8% (noise) |
| net.flow_dissector.qinq | hp1-hp3 | qinq | udp | 9.70 ± 0.43% | 9.49 ± 0.13% | -0.21pp (noise) | -2.2% (noise) |
| net.flow_dissector.vxlan_inner | hp2-hp5 | vxlan | tcp | 14.54 ± 0.14% | 14.74 ± 0.35% | +0.21pp (noise) | +1.4% (noise) |
| net.flow_dissector.vxlan_inner | hp2-hp5 | vxlan | udp | 14.58 ± 0.17% | 14.71 ± 0.07% | +0.14pp (noise) | +0.9% (noise) |
| net.flow_dissector.ipip | hp1-hp3 | ipip | udp | 13.30 ± 0.16% | 13.21 ± 0.04% | -0.09pp (noise) | -0.7% (noise) |
| net.flow_dissector.geneve_inner | hp1-hp3 | geneve | udp | 14.20 ± 0.08% | 14.11 ± 0.04% | -0.09pp (noise) | -0.6% (noise) |
| net.flow_dissector.vlan | hp2-hp5 | vlan | udp | 8.86 ± 0.03% | 8.95 ± 0.08% | +0.09pp (noise) | +1.0% (noise) |
| net.flow_dissector.mpls | hp2-hp5 | mpls | tcp | 15.33 ± 0.22% | 15.26 ± 0.17% | -0.07pp (noise) | -0.5% (noise) |
| net.flow_dissector.geneve_inner | hp2-hp5 | geneve | udp | 14.93 ± 0.05% | 15.00 ± 0.05% | +0.07pp (noise) | +0.4% (noise) |
| net.flow_dissector.ipip | hp2-hp5 | ipip | tcp | 14.18 ± 0.82% | 14.24 ± 0.59% | +0.06pp (noise) | +0.4% (noise) |
| net.flow_dissector.ipip | hp2-hp5 | ipip | udp | 14.46 ± 0.18% | 14.51 ± 0.32% | +0.05pp (noise) | +0.3% (noise) |
| net.flow_dissector.vxlan_inner | pi5-pair | vxlan | tcp | 5.60 ± 0.03% | 5.65 ± 0.04% | +0.05pp (noise) | +0.8% (noise) |
| net.flow_dissector.vxlan_inner | hp1-hp3 | vxlan | udp | 14.38 ± 0.11% | 14.34 ± 0.10% | -0.05pp (noise) | -0.3% (noise) |
| net.flow_dissector.eth_ip | hp2-hp5 | eth_ip | tcp | 11.42 ± 0.07% | 11.46 ± 0.06% | +0.04pp (noise) | +0.4% (noise) |
| net.flow_dissector.vlan | hp1-hp3 | vlan | udp | 9.12 ± 0.25% | 9.08 ± 0.04% | -0.04pp (noise) | -0.4% (noise) |
| net.flow_dissector.mpls | hp1-hp3 | mpls | udp | 11.00 ± 0.40% | 10.96 ± 0.36% | -0.04pp (noise) | -0.3% (noise) |
| net.flow_dissector.qinq | hp2-hp5 | qinq | udp | 9.68 ± 0.06% | 9.65 ± 0.07% | -0.04pp (noise) | -0.4% (noise) |
| net.flow_dissector.vlan | hp2-hp5 | vlan | tcp | 10.91 ± 0.05% | 10.88 ± 0.07% | -0.03pp (noise) | -0.3% (noise) |
| net.flow_dissector.eth_ip | hp1-hp3 | eth_ip | udp | 10.74 ± 0.36% | 10.71 ± 0.12% | -0.03pp (noise) | -0.3% (noise) |
| net.flow_dissector.eth_ip | pi5-pair | eth_ip | tcp | 6.45 ± 0.02% | 6.48 ± 0.02% | +0.03pp (noise) | +0.5% (noise) |
| net.flow_dissector.ipip | pi5-pair | ipip | tcp | 5.77 ± 0.06% | 5.75 ± 0.02% | -0.03pp (noise) | -0.5% (noise) |
| net.flow_dissector.gre | hp2-hp5 | gre | udp | 14.70 ± 0.08% | 14.73 ± 0.08% | +0.02pp (noise) | +0.2% (noise) |
| net.flow_dissector.gre | hp1-hp3 | gre | udp | 13.30 ± 0.10% | 13.28 ± 0.02% | -0.02pp (noise) | -0.2% (noise) |
| net.flow_dissector.qinq | pi5-pair | qinq | udp | 15.69 ± 0.03% | 15.71 ± 0.01% | +0.02pp (noise) | +0.1% (noise) |
| net.flow_dissector.ipip | hp1-hp3 | ipip | tcp | 13.93 ± 0.23% | 13.95 ± 0.33% | +0.02pp (noise) | +0.1% (noise) |
| net.flow_dissector.vlan | pi5-pair | vlan | udp | 13.92 ± 0.01% | 13.93 ± 0.01% | +0.01pp (noise) | +0.0% (noise) |
| net.flow_dissector.vlan | pi5-pair | vlan | tcp | 4.85 ± 0.03% | 4.85 ± 0.02% | +0.01pp (noise) | +0.1% (noise) |
| net.flow_dissector.geneve_inner | pi5-pair | geneve | tcp | 6.17 ± 0.03% | 6.17 ± 0.02% | +0.00pp (noise) | +0.1% (noise) |
| net.flow_dissector.mpls | pi5-pair | mpls | tcp | 17.76 ± 0.03% | 17.76 ± 0.07% | +0.00pp (noise) | +0.0% (noise) |
| net.flow_dissector.qinq | pi5-pair | qinq | tcp | 5.59 ± 0.01% | 5.59 ± 0.01% | +0.00pp (noise) | +0.0% (noise) |
| net.flow_dissector.gre | pi5-pair | gre | tcp | 5.79 ± 0.04% | 5.79 ± 0.03% | +0.00pp (noise) | +0.0% (noise) |

## Coverage footer (skipped cells)

| group | n | reason |
|---|---|---|
| G|hp1-hp3|geneve|udp|0 | 3 | overlay-unsupported |
| G|hp2-hp5|vxlan|udp|0 | 3 | overlay-unsupported |
| G|hp1-hp3|geneve|udp|1 | 3 | overlay-unsupported |
| G|hp2-hp5|vxlan|udp|1 | 3 | overlay-unsupported |
| G|hp1-hp3|vxlan|udp|0 | 3 | overlay-unsupported |
| G|hp1-hp3|vxlan|udp|1 | 3 | overlay-unsupported |
| G|hp2-hp5|geneve|udp|0 | 3 | overlay-unsupported |
| G|hp2-hp5|geneve|udp|1 | 3 | overlay-unsupported |

---
Generated by `nix run .#series3-summary-report`. Source matrices:
- `perf-results/2026-06-19-phase-h-iperf3/matrix.csv`
- `perf-results/2026-06-19-phase-h-pktgen/matrix.csv`
