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

## Microbench — ns/pkt, fast / in-tree (lower is better)

| shape | l2 (x86 Zen 2) | hp5 (x86 Zen 1) | pi5-2 (ARM A76) | parity |
|---|---|---|---|---|
| eth_ip | 22 / 64 | 23 / 82 | 42 / 123 | GOLD |
| vlan   | 16 / 60 | 21 / 77 | 36 / 111 | GOLD |
| qinq   | 16 / 58 | 18 / 79 | 35 / 146 | GOLD |
| ipip   | 23 / 70 | 25 / 87 | 49 / 163 | GOLD |
| gre    | 25 / 76 | 31 / 92 | 64 / 197 | GOLD |
| mpls   | 17 / 56 | 21 / 71 | 38 / 154 | c-dissector |
| pppoe  | 16 / 54 | 18 / 70 | 36 / 136 | series2 |
| vxlan  | 24 / 62 | 27 / 84 | 57 / 157 | c-dissector³ |
| geneve | 24 / 64 | 26 / 86 | 59 / 137 | c-dissector³ |
| gtpu   | 25 / 64 | 28 / 81 | 56 / 167 | c-dissector³ |

³ descends to the inner flow the in-tree dissector never reaches, still faster.
Every menu object is ~2–4× faster than the in-tree BPF dissector across **two x86
uarches + ARM Cortex-A76**, GOLD parity on all five in-tree-oracle shapes on every
one. The ARM/RISC-V builds are cross-compiled on `l` (flake `pkgsCross*`, no qemu).

**RISC-V (bpi-f3):** cross build succeeds, but the board's kernel (7.2.0-rc1
riscv, `CONFIG_BPF_JIT` absent) rejects *every* flow_dissector BPF program at
verify time — including the kernel's own `bpf_flow.kern.o`, and the x86-built
copy of our object. A DUT-kernel limitation, not our bytecode; needs a bpi-f3
kernel rebuilt with `CONFIG_BPF_JIT=y`. See
`perf/2026-08-05-bpi-f3-riscv/results.md`.

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

- [x] Parity GOLD: eth_ip, vlan, qinq, ipip, gre — x86 Zen 2, x86 Zen 1, ARM A76
- [x] Microbench ns/pkt: all 10 shapes on x86 Zen 2 + Zen 1 + ARM Cortex-A76
- [x] Soak cyc/pkt: eth_ip, hp2→hp5
- [~] Cross-ISA: ARM done; **RISC-V blocked** by bpi-f3 kernel (no CONFIG_BPF_JIT;
      rejects all flow_dissector BPF progs incl. in-tree) — needs a kernel rebuild
- [ ] Soak on the mlx5 pair (hp1→hp3) — second NIC/pair confirmation
- [ ] Descent hash-distribution demo (vxlan/gtpu) via encap-pcap replay
- [ ] Gold gates: mpls (C dissector), pppoe (series2), tunnels (descent-patched C)
