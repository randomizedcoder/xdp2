# pktgen soak — hp2 → hp5 (X710 10GbE, Zen 1), eth_ip

Date: 2026-08-05. The **authoritative in-RX-path** measurement (vs the
`BPF_PROG_TEST_RUN` microbench): a real BPF flow dissector attached on the DUT,
exercised by live traffic, measured as whole-box active cycles per received
packet.

## Setup

- **Generator hp2** → **DUT hp5**, back-to-back Intel X710 10GbE, `enp1s0f0np0`,
  underlay 10.10.0.2 → 10.10.0.5 (MAC f8:f2:1e:38:ab:80). hp5 = AMD Ryzen 5 PRO
  2400G (Zen 1), net-next 7.2.0-rc1.
- **Traffic:** kernel pktgen, 64-byte UDP, dst port 8080 (closed), 2 threads,
  ~1.3–1.7 Mpps (`samples/flow_dissector/pktgen_ntuple_template.sh`).
- **DUT:** RPS enabled (`rps_cpus=0xfc`, CPUs 2–7) so `skb_get_hash()` runs the
  flow dissector on every RX packet. The BPF object is attached with
  `xdp2-flow-loader --bpf <obj> --hold` (init netns; attach verified via
  `bpftool net show` flow_dissector id). Metric: `perf stat -a -e cycles` over a
  fixed window ÷ `rx_packets` delta. Idle cores halt (cycles counter stops), so
  whole-box active cycles ≈ RX-path work.
- **A/B:** the flow dissector is the only thing that changes —
  none (kernel C dissector) / in-tree `bpf_flow.kern.o` / our `fast_flow_eth_ip`.

## Results (cyc/pkt, 3 runs)

| config | r0 | r1 | r2 | mean | vs C path |
|---|---:|---:|---:|---:|---|
| none (kernel C dissector) | 7387 | 7337 | 7344 | **7356** | baseline |
| in-tree BPF (`bpf_flow.kern.o`) | 12016 | 12044 | 12027 | **12029** | **+4673 (+64%)** |
| our `fast_flow_eth_ip` | 7487 | 7542 | 7513 | **7514** | **+158 (+2%)** |

(ins/pkt tracked the same shape: none 6353, in-tree 8512, ours 6478.)

## Takeaways

- **The in-tree BPF flow dissector is far more expensive in the live RX path than
  the native C dissector** — +4673 cyc/pkt (+64%). Per-packet BPF invocation +
  tail-call dispatch dominates. Under the same load the DUT delivered fewer
  packets with it attached (~10.6M vs ~13.8M per window), i.e. it pushed the box
  toward RX drops.
- **Our loadable fast BPF dissector is nearly free** — +158 cyc/pkt over the C
  path, ~**30× cheaper than the in-tree BPF dissector** (158 vs 4673). Attaching
  it costs essentially nothing versus the kernel's own C dissector.
- **Reply consequence:** "if you want a linear fast path, the BPF dissector offers
  that" holds *only with a fast object like ours*. The reference in-tree BPF
  dissector is markedly slower than the C path it would replace; our per-shape
  objects make the BPF route actually performant while keeping the subjective
  shapes out of the kernel.

## Caveats

- The ~7356 cyc/pkt baseline is dominated by the UDP-to-closed-port RX +
  ICMP-unreachable path, not the dissector; the **delta** (attach on/off) isolates
  the dissector cost, and that delta is stable and large for the in-tree BPF case.
- Single DUT/uarch (hp5 Zen 1), eth_ip only. Next: the descent objects need
  VXLAN/GTP-U traffic (pktgen can't craft it — replay the encap-flow-distribution
  pcaps), where the payoff is inner-flow **hash distribution** (RSS/RPS spread),
  not cyc/pkt; and cross-ISA when the ARM/RISC-V DUTs are up.

Raw runs are inline above; orchestration was `xdp2-flow-loader --hold` +
`perf stat -a -e cycles` on hp5 with pktgen on hp2 (RPS on).
