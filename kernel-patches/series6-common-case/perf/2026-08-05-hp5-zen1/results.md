# flow-menu-bench — hp5 (x86 Zen 1) microbench

Date: 2026-08-05. Host: **hp5** (AMD Ryzen 5 PRO 2400G, Zen 1) — DUT of the
hp2↔hp5 X710 back-to-back pair. Same `flow-menu-bench` harness as the l2 run
(`BPF_PROG_TEST_RUN`, `BPF_REPEAT=1000`, per-shape corpus). `results.csv` is raw.

## Results (ns/pkt, lower is better)

| shape | fast | in-tree | speedup | parity |
|---|---:|---:|---|---|
| eth_ip | 23 | 82 | 3.6× | **GOLD** |
| vlan   | 21 | 77 | 3.7× | **GOLD** |
| qinq   | 18 | 79 | 4.4× | **GOLD** |
| ipip   | 25 | 87 | 3.5× | **GOLD** |
| gre    | 31 | 92 | 3.0× | **GOLD** |
| mpls   | 21 | 71 | — (in-tree stub) | c-dissector |
| pppoe  | 18 | 70 | — (in-tree drops) | series2 |
| vxlan  | 27 | 84 | descends³ | c-dissector |
| geneve | 26 | 86 | descends³ | c-dissector |
| gtpu   | 28 | 81 | descends³ | c-dissector |

³ descends to the inner flow the in-tree dissector never reaches, still faster.

## Cross-uarch summary (microbench)

| shape | l2 fast/in-tree (Zen 2) | hp5 fast/in-tree (Zen 1) | parity |
|---|---|---|---|
| eth_ip | 22 / 64 | 23 / 82 | GOLD |
| vlan   | 16 / 60 | 21 / 77 | GOLD |
| qinq   | 16 / 58 | 18 / 79 | GOLD |
| ipip   | 23 / 70 | 25 / 87 | GOLD |
| gre    | 25 / 76 | 31 / 92 | GOLD |

Both x86 uarches: **GOLD parity on all five in-tree-oracle shapes**, ~2–4×
faster than the in-tree BPF dissector. The relative win is larger on Zen 1
(the older core spends more on the graph walk). Next: pktgen soak (authoritative
in-RX-path cyc/pkt) on hp2→hp5, and cross-ISA (ARM/RISC-V) when those DUTs are up.
