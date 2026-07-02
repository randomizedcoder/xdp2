# series4 — testing methodology

Coverage: **3 ISAs** (x86, ARM, RISC-V), **8 microarchitectures** (x86 Zen1,
Zen2, Skylake, Haswell; ARM Cortex-A53/A72/A76; RISC-V SpacemiT X60), N=3
replicates on the in-kernel runs, byte-identical verification per shape, and
months of runs. Each method below is one instrument; they are complementary
(isolated cost, in-kernel cost, macro behaviour, flow identity, worst case,
no-regression).

| method | what it measures | source dir under `perf-results/` |
|---|---|---|
| userspace A/B microbench | isolated dissector ns/pkt, one synthetic shape, patched vs baseline `.so` | `2026-06-09-series3-arm-microbench`, `2026-06-25-series3-riscv-microbench`, `2026-06-03-series3-phase3-haswell` |
| allshapes microbench | per-shape ns/pkt with all fast-paths compiled in (icache-representative); byte-identical check per shape | `2026-06-25-series3-allshapes-microbench` |
| kernel-pktgen cycles/pkt (Phase G/H) | in-kernel per-packet cost via ksoftirqd `perf stat`, 64B UDP, sysctl 0/1, N=3 — the clean CPU signal | `2026-06-19-phase-h-*`, `2026-06-30-phase-h-l-l2-*` |
| iperf3 wire-saturated macro (Phase F/H) | receiver softirq % under RSS/RPS/RFS + tc-flower load | `2026-06-19-phase-h-iperf3`, `2026-06-30-phase-h-l-l2-iperf3` |
| **encap flow-hash distribution (NEW)** | real `flow_hash_from_keys` distribution, outer vs inner descent, honest sport variants | `2026-07-01-encap-flow-distribution` |
| 10-hour soaks | stability + drift over long runs; throughput parity | `2026-06-16/18-v4-soak-10h`, `2026-06-11-series3-soak` |
| tcpreplay mixed real traffic | no-regression on a diverse non-eligible encap mix | `2026-06-10-series3-tcpreplay-mixed` |
| PCAP miss-cost microbench | worst-case dispatcher fall-through on non-eligible shapes | `2026-06-10-series3-pi3-pcap-microbench` |
| flow_keys consumer/field audit | which consumers read which flow_keys fields; hash-region bias | `2026-05-23-flow-keys-consumer-audit` |
| mlx5 offload OFAT | isolate NIC-offload variance; found a real IPIP tx-checksum bug (workaround documented) | `2026-06-18-mlx5-offload-investigation.md` |
| 25 GbE line-rate characterisation | confirmed the MTU-1500 ceiling is a NIC packet-rate wall, not CPU (jumbo hits line rate) | `2026-06-30-phase-h-l-l2-summary/FINDINGS.md` |
| cross-uarch macro | iperf3/iperf2 TCP+UDP A/B on ARM receivers; no regression | `2026-06-09-series3-cross-uarch`, `2026-06-10-series3-cross-uarch-perf` |
| RISC-V dual-sender stress | proves the K1 macro is queue-bound (why the microbench is the right instrument there) | `2026-06-25-bpif3-dual-sender-stress` |
| WireGuard live bpftrace | call frequency in a real deployment: 1.1M `__skb_flow_dissect` / 10s @ 902 Mbit/s | `2026-06-25-wireguard-flowdis` |
| NEON SIMD port bench | aarch64 vectorised dissect path (companion xdp2-rs work) | `2026-06-14-rust-neon-pi5` |

## Honesty conventions used throughout
- `(noise)` = slow->fast delta within 2x pooled stddev at N=3. Only two Phase G
  rows clear it cleanly (see `PERFORMANCE.md` §3); we report those and label the rest.
- Absolute ns/pkt are per-arch baselines; the cross-arch *ratios* are the claim.
- The descent shapes are ~net-zero on CPU; their benefit is flow identity
  (`PERFORMANCE.md` §4), and the kernel-sourced-VXLAN spreading case is shown, not hidden.
