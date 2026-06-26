# v3 namespace cross-testbed smoke results (2026-06-15)

First end-to-end validation of the v3 per-shape sysctl design after refactoring `net.core.flow_dissector_fastpath` (single umbrella knob) into `/proc/sys/net/flow_dissector/{eth_ip,vlan,qinq,vxlan_inner}` (one knob per shape). Companion to `2026-06-15-extensions-cross-testbed-summary.md` (the v1+extensions baseline that v3 supersedes).

## Test fleet

| host | kernel | role |
|---|---|---|
| pi5-1, pi5-2 | linux_rpi5 6.12.87 | aarch64 paired |
| hp1, hp3 | linuxPackages_latest 7.0.9 | x86_64 paired (this smoke) |
| hp2, hp5 | linuxPackages_latest 7.0.0 | x86_64 paired (next) |

All six booted on v3 patches (`kernel-patches/series3-flowdis-fastpath/v3-namespace/` at xdp2 commit `f951da4`). All four sysctls present at default 0 on every host.

## Live sysctl namespace + behaviour validation (hp1)

```
$ sysctl -w net.flow_dissector.qinq=1
$ sysctl -n net.flow_dissector.vlan      # auto-toggle: also became 1
1
$ sysctl -w net.flow_dissector.vlan=0
$ sysctl -n net.flow_dissector.qinq      # sibling-clear: also became 0
0
$ sysctl -w net.flow_dissector.eth_ip=1
$ sysctl -n net.flow_dissector.vlan      # eth_ip independent of vlan/qinq
0
```

Custom `proc_set_vlan_key` / `proc_set_qinq_key` proc_handlers wire the qinq↔vlan dependency exactly as designed in [`v3-namespace/0003-…QinQ`](../../kernel-patches/series3-flowdis-fastpath/v3-namespace/0003-net-flow_dissector-extend-VLAN-fast-path-to-QinQ-dep.patch).

## hp1↔hp3 smoke matrix

`PAIRS=hp1-hp3 SCENARIOS=vlan,qinq DUR=10 nix run .#series3-extensions-soak`

| scenario | proto | sysctl=0 | sysctl=1 | delta |
|---|---|---|---|---|
| vlan | tcp | 18262 Mbps | 18180 Mbps | -0.5 % (line-rate-bound, retr noise) |
| vlan | udp | 6979 Mbps | 7115 Mbps | **+1.9 %** |
| qinq | tcp | 0 Mbps¹ | 0 Mbps¹ | — (unrelated MTU plumbing bug) |
| qinq | udp | 5820 Mbps | 5946 Mbps | **+2.2 %** |

¹ QinQ TCP on hp1↔hp3 carries the mlx5 plumbing failure from the 2026-06-13 session (28+ retransmits, no throughput). UDP path is unaffected and confirms the fast-path works. Not a v3-patch issue.

## Cross-references

- Per-shape design rationale: `kernel-patches/series3-flowdis-fastpath/v3-namespace/0000-cover-letter.patch`
- Patch-context-drift gotcha (`flow_keys_dissector_symmetric` forward decl): xdp2 commit `f951da4`
- v1+extensions baseline (what v3 replaces): `perf-results/2026-06-15-extensions-cross-testbed-summary.md`
- matrix.csv (this run): `matrix.csv` next to this file

## Next runs queued

- Full hp1↔hp3, hp2↔hp5, pi5-1↔pi5-2 matrix with DUR=60 (run when machines are quiet).
- QinQ TCP MTU plumbing investigation (separate from v3; tracked).
- VXLAN inner descent (patch 4 / RFC EXPERIMENT) opt-in A/B once the byte-identical paths are settled.
