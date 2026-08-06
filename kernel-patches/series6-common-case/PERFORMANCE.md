# Performance — per-encapsulation eBPF flow-dissector menu

Consolidated results + analysis for the loadable `fast_flow_<encap>` menu
(design in [`ebpf-menu.md`](ebpf-menu.md)). Raw per-run data lives under
[`perf/`](perf/). Two instruments:

1. **Microbench** — `BPF_PROG_TEST_RUN` (kernel-reported avg ns per JITed
   invocation), one object per shape on its corpus pcap, vs the in-tree
   `bpf_flow.kern.o`. Harness: `nix run .#flow-menu-bench`. Isolates the
   dissector's own cost; also runs the byte-identical (GOLD) parity gate.
2. **Soak** — real object attached on the DUT (`xdp2-flow-loader --hold`), live
   64 B pktgen from the back-to-back generator, RPS on, whole-box cyc/pkt. The
   authoritative in-RX-path cost.

## Correctness (parity)

The five shapes whose oracle is the stock in-tree BPF dissector —
**eth_ip, vlan, qinq, ipip, gre** — are **byte-identical (GOLD)** to it on both
x86 uarches tested (`parity_test` exit 0, `bpf_flow_keys` memcmp over the
corpus). mpls/pppoe/vxlan/geneve/gtpu need their own oracles (series2-patched /
descent-patched C dissector — see `ebpf-menu.md`); Gold gates for those are TODO.

## Microbench — ns/pkt (lower is better)

| shape | l2 fast/in-tree (Zen 2) | hp5 fast/in-tree (Zen 1) | speedup | parity |
|---|---|---|---|---|
| eth_ip | 22 / 64 | 23 / 82 | ~2–3× | GOLD |
| vlan   | 16 / 60 | 21 / 77 | ~3–4× | GOLD |
| qinq   | 16 / 58 | 18 / 79 | ~3–4× | GOLD |
| ipip   | 23 / 70 | 25 / 87 | ~3× | GOLD |
| gre    | 25 / 76 | 31 / 92 | ~3× | GOLD |
| mpls   | 17 / 56 | 21 / 71 | — (in-tree stub) | c-dissector |
| pppoe  | 16 / 54 | 18 / 70 | — (in-tree drops) | series2 |
| vxlan  | 24 / 62 | 27 / 84 | descends³ | c-dissector |
| geneve | 24 / 64 | 26 / 86 | descends³ | c-dissector |
| gtpu   | 25 / 64 | 28 / 81 | descends³ | c-dissector |

³ descends to the inner flow the in-tree dissector never reaches, still faster.
Every menu object is ~2–4× faster than the in-tree BPF dissector; the win is
larger on the older Zen 1 core (more graph-walk cost to skip).

## Soak — cyc/pkt (hp2→hp5 X710, Zen 1, net-next 7.2.0-rc1, 3 runs)

| flow dissector | mean cyc/pkt | vs native C path |
|---|---:|---|
| none (kernel C dissector) | 7356 | baseline |
| in-tree BPF `bpf_flow.kern.o` | 12029 | **+4673 (+64%)** |
| our `fast_flow_eth_ip` | 7514 | **+158 (+2%)** |

The in-tree BPF flow dissector costs **~30× more per packet than ours** in the
live RX softirq (per-packet BPF invocation + tail-call dispatch); attaching it
pushed the DUT toward RX drops (~10.6M vs ~13.8M pkts/window under equal load).
Our object is nearly free over the kernel's own C dissector.

## Analysis — what this says for the upstream discussion

1. **The in-kernel eth+IP+TCP/UDP fast path is the one non-subjective win**, and it
   stays in-kernel (reduced series, patches 1–2, +377/−50 LoC).
2. **Everything subjective belongs in loadable BPF** — Willem's own suggestion.
   But the *reference* in-tree BPF dissector is +64% cyc/pkt vs the C path, so
   "just use the BPF dissector" is only *performant* with a fast object. Our
   per-shape objects (~1080 LoC, out of tree) are byte-identical where an oracle
   exists and ~30× cheaper than the in-tree BPF dissector in the live path.
3. **Descent (vxlan/geneve/gtpu)** is a hashing-policy change (inner-flow hash),
   so it is exactly a "load it when you want it" object — the fix for the
   production reordering case where outer-5-tuple hashing collapses inner flows.
   Its payoff is measured as hash distribution, not cyc/pkt (TODO below).

## Coverage / TODO

- [x] Parity GOLD: eth_ip, vlan, qinq, ipip, gre (x86 ×2 uarch)
- [x] Microbench ns/pkt: all 10 shapes, x86 Zen 2 + Zen 1
- [x] Soak cyc/pkt: eth_ip, hp2→hp5
- [ ] Cross-ISA microbench: ARM Cortex-A76 (pi5-2), RISC-V X60 (bpi-f3)
- [ ] Soak on the mlx5 pair (hp1→hp3) — second NIC/pair confirmation
- [ ] Descent hash-distribution demo (vxlan/gtpu) via encap-pcap replay
- [ ] Gold gates: mpls (C dissector), pppoe (series2), tunnels (descent-patched C)
