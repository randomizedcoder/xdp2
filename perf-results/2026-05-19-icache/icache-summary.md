# Icache / branch sweep — perf counters per parser mode

Source: `flow-dissector-icache-sweep`. One row per
(host, workload, mode) cell. Counters are TOTAL across the
benchmark loop (iters x packets); divide by iters x packets
for per-packet equivalents.

Headers:
  ns/pkt        XDP2 parser line from benchmark output
  icache-miss   L1 icache load misses (total)
  branch-miss   branch misses (total)
  cycles        cycles (total)
  instr         instructions retired (total)
  iTLB-miss     iTLB load misses (total)
  IPC           instr/cycles
  miss/Mi       icache-miss per million instructions

| host | workload | mode | ns/pkt | icache-miss | branch-miss | cycles | instr | iTLB-miss | IPC | miss/Mi |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| hp2 | https-web | -M | 70 | 1,420,812 | 2,656,729 | 2,506,496,295 | 892,701,531 | 234 | 0.36 | 1592 |
| hp2 | https-web | -O | 128 | 1,424,669 | 7,361,830 | 3,412,163,492 | 1,445,123,339 | 242 | 0.42 | 986 |
| hp2 | https-web | -S | 176 | 1,482,928 | 6,846,758 | 4,160,279,993 | 2,835,480,902 | 370 | 0.68 | 523 |
| hp2 | vxlan-k8s-pure | -M | 137 | 1,584,371 | 2,543,158 | 3,442,786,568 | 1,575,013,811 | 294 | 0.46 | 1006 |
| hp2 | vxlan-k8s-pure | -O | 156 | 1,553,735 | 2,889,001 | 3,702,179,085 | 2,126,593,943 | 264 | 0.57 | 731 |
| hp2 | vxlan-k8s-pure | -S | 234 | 1,502,993 | 5,269,793 | 4,873,977,731 | 4,426,925,908 | 250 | 0.91 | 340 |
| hp5 | https-web | -M | 72 | 1,382,480 | 2,672,850 | 2,460,219,164 | 893,981,423 | 246 | 0.36 | 1546 |
| hp5 | https-web | -O | 131 | 1,471,456 | 7,341,353 | 3,356,560,600 | 1,447,445,495 | 234 | 0.43 | 1017 |
| hp5 | https-web | -S | 177 | 1,296,707 | 6,770,536 | 4,089,800,224 | 2,829,594,277 | 229 | 0.69 | 458 |
| hp5 | vxlan-k8s-pure | -M | 140 | 1,409,346 | 2,571,444 | 3,406,859,106 | 1,578,004,677 | 280 | 0.46 | 893 |
| hp5 | vxlan-k8s-pure | -O | 160 | 1,418,035 | 2,897,796 | 3,662,298,462 | 2,125,817,044 | 272 | 0.58 | 667 |
| hp5 | vxlan-k8s-pure | -S | 239 | 1,603,432 | 5,239,199 | 4,800,596,204 | 4,415,998,518 | 232 | 0.92 | 363 |
