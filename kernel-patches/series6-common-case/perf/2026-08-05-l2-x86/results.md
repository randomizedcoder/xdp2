# flow-menu-bench — first hardware run (l2, x86 Zen 2)

Date: 2026-08-05. Host: **l2** (AMD Threadripper PRO 3945WX, Zen 2), the
only testbed DUT reachable this session (hp5/hp2 down; ARM pi5-2 / RISC-V
bpi-f3 / Intel `t` unreachable). x86-only; cross-ISA pending those hosts.

Harness: `nix run .#flow-menu-bench` closure copied to l2, run as root
(`BPF_PROG_TEST_RUN` needs CAP_BPF). Each menu object benchmarked on its
per-shape corpus pcap vs the in-tree `bpf_flow.kern.o` dissector on the same
pcap; `parity_test` Gold gate where an in-tree BPF oracle exists.
`BPF_REPEAT=1000` (kernel-reported avg ns/invocation of the JITed program).

## Results (ns/pkt, lower is better; two runs)

| shape | fast (r1/r2) | in-tree (r1/r2) | ~speedup | parity |
|---|---|---|---|---|
| eth_ip | 33 / 22 | 63 / 64 | ~2–3× | **GOLD** |
| vlan   | 16 / 16 | 60 / 60 | ~3.8× | **GOLD** |
| qinq   | 16 / 16 | 57 / 58 | ~3.6× | **GOLD** |
| ipip   | 22 / 23 | 70 / 70 | ~3.1× | **GOLD** |
| gre    | 26 / 25 | 74 / 76 | ~2.9× | **GOLD** |
| mpls   | 22 / 17 | 56 / 56 | n/a¹ | c-dissector² |
| pppoe  | 16 / 16 | 54 / 54 | n/a¹ | series2² |
| vxlan  | 26 / 24 | 64 / 62 | descends³ | c-dissector² |
| geneve | 24 / 24 | 64 / 64 | descends³ | c-dissector² |
| gtpu   | 23 / 25 | 64 / 64 | descends³ | c-dissector² |

¹ in-tree "cost" isn't comparable: its MPLS handler is a stub (no inner
  5-tuple) and it drops PPPoE — our object does strictly more.
² parity oracle isn't the stock in-tree BPF dissector (see ebpf-menu.md):
  mpls + vxlan/geneve/gtpu need the descent-/single-label-patched C dissector;
  pppoe needs the series2-patched oracle. Bench-only here; Gold gate pending.
³ vxlan/geneve/gtpu **descend to the inner flow** (which the in-tree dissector
  never reaches) and are still faster than the in-tree outer-only parse — the
  inner-flow hash is the whole point (fixes outer-5-tuple hash collapse /
  reordering).

## Takeaways

- **Correctness:** all five in-tree-oracle shapes (eth_ip, vlan, qinq, ipip,
  gre) are **byte-identical (GOLD)** to the in-tree BPF dissector.
- **Performance:** every menu object is ~2–4× faster than the in-tree BPF
  dissector on its shape, consistent across two runs.
- These are `BPF_PROG_TEST_RUN` microbench numbers (JITed program, single host,
  mostly single-packet templates) — a strong relative signal, not the
  authoritative pktgen-soak cyc/pkt. Next: pktgen soak + cross-ISA + the
  c-dissector/series2 Gold gates for the remaining shapes.

`results.csv` holds the raw second run.
