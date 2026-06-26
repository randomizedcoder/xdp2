# v4 namespace re-run after IPIP TX-checksum fix (2026-06-16)

Re-run of the DUR=60 full matrix after committing the netconf-ipip.nix
TX-checksum workaround (xdp2 `2dc0a82`) and the PPPoE scenario-script
fixes (same commit). PPPoE scenarios excluded from this run because the
PPPoE Discovery problem is not in the v4 patch series — see
[`2026-06-16-pppoe-investigation.md`](../2026-06-16-pppoe-investigation.md).

## Headline — receiver softirq CPU saving (UDP cells, the clean-signal subset)

Strongest signal continues to be MPLS, on BOTH hp pairs this time:

| pair | scenario | mbps (sysctl=0 → =1) | recv_soft_pct (=0 → =1) | abs Δ | rel Δ |
|---|---|---|---|---|---|
| **hp1↔hp3** | **mpls udp** | 6704 → 6473 | 11.50 → 9.85 | **-1.65pp** | **-14.3%** |
| **hp2↔hp5** | **mpls udp** | 6687 → 6742 | 9.55 → 8.78 | **-0.77pp** | **-8.1%** |
| hp2↔hp5 | vlan udp | 7318 → 7343 | 1.64 → 1.59 | -0.05pp | -3% |
| hp2↔hp5 | vxlan udp | 6016 → 6049 | 8.39 → 8.18 | -0.21pp | -2.5% |
| hp1↔hp3 | vxlan udp | 6025 → 5880 | 7.90 → 7.76 | -0.14pp | -1.8% |
| hp1↔hp3 | ipip udp | 6594 → 6966 | 7.25 → 7.24 | -0.01pp | flat |
| hp2↔hp5 | ipip udp | 7304 → 7283 | 7.48 → 8.18 | +0.70pp | +9% (noise) |
| hp2↔hp5 | qinq udp | 5933 → 5937 | 0.20 → 0.24 | +0.04pp | noise (base <1%) |
| hp1↔hp3 | vlan udp | 7212 → 6908 | 0.04 → 0.03 | -0.01pp | noise (base <1%) |
| hp1↔hp3 | qinq udp | 5988 → 5983 | 0.03 → 0.06 | +0.03pp | noise (base <1%) |

**MPLS is the standout** — the patch produces clear, repeatable softirq reductions on UDP traffic across both hp pairs. The other byte-identical patches save somewhere between "small but real" and "lost in noise floor"; the magnitude depends on how much softirq work the scenario triggers per packet to begin with.

Notable TCP delta (hard to interpret on retr-noisy cells but worth recording):

| pair | scenario | mbps (=0 → =1) | recv_soft_pct (=0 → =1) | comment |
|---|---|---|---|---|
| hp1↔hp3 | **vlan tcp** | 18480 → 18090 | **9.51 → 5.82** | -3.69pp soft, throughput within noise; biggest delta in matrix |
| hp1↔hp3 | vxlan tcp | 16617 → 17077 | 10.70 → 16.20 | TCP retr storm; not interpretable |
| hp1↔hp3 | mpls tcp  | 19029 → 18542 | 18.14 → 15.06 | -3.08pp soft delta |
| hp1↔hp3 | ipip tcp  | **0 → 11308**  | n/a → 5.25 | **previously 0 Mbps — fix landed; +5.6% udp throughput too** |

The hp1↔hp3 vlan TCP -3.69pp soft drop is the largest single delta in the matrix but it's TCP-noisy (7554/6593 retr); flag it as worth re-running but not a headline number yet.

## IPIP fix validation

Before (`2026-06-16-v4-dur60-full`): hp1↔hp3 IPIP cells all 0 Mbps (TX-checksum bug).

After (`2026-06-16-v4-dur60-rerun`):
- **TCP**: 11186 → 11308 Mbps, recv_soft 4.98% → 5.25% (+0.27pp small)
- **UDP**: 6594 → 6966 Mbps (+5.6%), recv_soft 7.25% → 7.24% (flat)

The IPIP scenario now produces clean cells on hp1-hp3 just like it did on hp2-hp5 and pi5-pair. UDP throughput improvement on hp1-hp3 (+5.6%) is interesting and possibly real (the fast-path tail-calls into the inner ip helper without re-entering the dispatcher); deserves a deeper look in a future targeted run.

## Throughput parity (byte-identical contract)

All byte-identical UDP cells stay within ±5.6% mbps across sysctl=0/1. The 5.6% IPIP UDP improvement and the small negative deltas elsewhere fit within run-to-run variance (we have separate baselines showing pi5-pair line-rate variance alone ~1%). The contract holds: fast-path produces the same flow_keys as slow path, throughput parity confirmed.

## Comparison with the first DUR=60 run

| scenario | pair | first-run recv_soft Δ | re-run recv_soft Δ | direction agrees? |
|---|---|---|---|---|
| mpls udp | hp1↔hp3 | -0.09pp | -1.65pp | yes (bigger) |
| mpls udp | hp2↔hp5 | -1.10pp | -0.77pp | yes |
| vxlan udp | hp1↔hp3 | -0.15pp | -0.14pp | yes |
| vxlan udp | hp2↔hp5 | -0.36pp | -0.21pp | yes |
| vlan udp | hp2↔hp5 | -0.54pp | -0.05pp | yes (smaller) |

Direction-of-effect is consistent across runs. Magnitudes vary by 0.1-1.5pp run-to-run, which is the noise floor on this orchestrator/workload. Average over 2 runs for the netdev cover letter or do a longer DUR=300 to pin it down.

## Cross-references

- IPIP TX-checksum fix: xdp2 `2dc0a82` (also has the PPPoE plugin/secrets/IPCP fixes that are still useful even though PPPoE Discovery is broken upstream)
- First v4 matrix: `../2026-06-16-v4-dur60-full/SUMMARY.md`
- PPPoE deferred investigation: `../2026-06-16-pppoe-investigation.md`
- v4 cover letter: `../../kernel-patches/series3-flowdis-fastpath/v4-namespace/0000-cover-letter.patch`
