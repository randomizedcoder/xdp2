# series4 — performance data (full tables)

Every figure below is quoted from a file under `perf-results/` in this repo; the
cover letter carries only the headlines. Rows within the N=3 noise floor (2x
pooled stddev) are tagged `(noise)`.

## 1. Isolated dissector cost — userspace A/B microbench

eth + IPv4 + TCP, ns/pkt (baseline -> patched). Same dissector source compiled
two ways; distinct SHA256 confirms A/B.
Source: v3 cover letter; `perf-results/2026-06-09-series3-arm-microbench/`,
`2026-06-03-series3-phase3-haswell/`, `2026-06-25-series3-riscv-microbench/`.

| uarch | ISA | base -> fast | reduction |
|---|---|---|---|
| Zen 2 (TR PRO 3945WX) | x86 | 12.4 -> 6.6 | -47% |
| Skylake (i9-10885H) | x86 | 10.6 -> 5.6 | -47% |
| Haswell (Celeron 2955U) | x86 | 35.9 -> 18.0 | -50% |
| Cortex-A53 | ARM | 119.0 -> 61.3 | -48% |
| Cortex-A72 | ARM | 42.4 -> 19.1 | -55% |
| Cortex-A76 | ARM | 19.4 -> 9.3 | -52% |
| SpacemiT X60 | RISC-V | 98.2 -> 49.3 | -50% |
| Zen 1 (2400G) | x86 | 20.50 -> 20.53 | not measurable @ p50 |

IPv6 (same gate, byte-identical): x86 -39%, RISC-V -25% (inner loop is
address-copy-bound; RISC-V deep-dive `2026-06-25-riscv-deep-dive/analysis.md`:
instr/pkt 220.4 -> 111.8, IPC ~1.40 flat).

## 2. Per-shape — allshapes microbench (all fast-paths compiled in)

% reduction in dissector ns/pkt, the kernel-representative case (icache footprint
of the full set present). Source:
`perf-results/2026-06-25-series3-allshapes-microbench/results.md`.

| uarch | eth_ip | vlan | qinq | pppoe | mpls | ipip |
|---|---|---|---|---|---|---|
| Zen2 | -23.1 | -38.5 | -36.5 | -27.0 | -10.5 | -41.1 |
| Skylake | -30.6 | -26.8 | -19.9 | -24.5 | -11.6 | -41.7 |
| Zen1 | -4.7 | -18.1 | -16.1 | -8.6 | -9.7 | -36.8 |
| A76 | -21.8 | -31.3 | -39.8 | -24.9 | -15.0 | -46.2 |
| A72 | -21.2 | -32.1 | -38.6 | -25.6 | -12.2 | -47.0 |
| A53 | -23.2 | -32.8 | -37.3 | -23.2 | -6.7 | -39.4 |
| X60 | -31.6 | -34.3 | -34.5 | -28.0 | -11.4 | -46.7 |

IP-in-IP is the biggest win everywhere (slow path re-runs the full parser for the
inner IP); MPLS the smallest.

## 3. In-kernel — pktgen cycles/pkt (Phase G/H, N=3)

64B UDP random src-port, ksoftirqd `perf stat`, sysctl 0/1 A/B. Sources:
`perf-results/2026-06-19-phase-h-summary/SUMMARY.md`,
`2026-06-30-phase-h-l-l2-summary/SUMMARY.md`.

| pair | uarch / NIC | shape | slow -> fast | Δ | note |
|---|---|---|---|---|---|
| hp2-hp5 | Zen1 / mlx5 25G | vlan UDP | 3054 -> 2905 | **-148 (-4.9%)** | above noise |
| l-l2 | Zen2 / mlx5 25G | eth_ip | 2303 -> 2191 | **-112 (-4.9%)** | above noise |
| hp2-hp5 | Zen1 | eth_ip UDP | 3205 -> 3008 | -198 (-6.2%) | (noise, ~1.6σ) |

N=1 -> N=3 flipped several signs (hp1-hp3 vlan -128 -> +146) — why replicates were
needed. All Phase F (iperf3+consumers) hp rows are noise (TCP-with-cake variance
dwarfs the effect); pi5 Phase G PMU returns 0 (ARM 6.x perf-event-name gap);
RISC-V macro is queue-bound (K1 single RX queue), so the userland microbench is
the right instrument there.

## 4. NEW — encapsulation flow-hash distribution (inner descent)

Real `flow_hash_from_keys` (`test_parser -c flowdis -H`), single tunnel-endpoint
pair, 2000 distinct inner flows, 20000 packets. distinct = flow-identity
resolution; occ@256 = RSS-table occupancy; entropy normalised.
Source: `perf-results/2026-07-01-encap-flow-distribution/` (`ANALYSIS.md`,
`results.txt`).

| scenario | outer distinct | inner distinct | outer occ@256 / entropy | inner occ@256 / entropy |
|---|---|---|---|---|
| GTP-U (fixed) | **1** | 2000 | 1/256 · 0.000 | 256/256 · 0.986 |
| VXLAN fixed-sport | **1** | 2000 | 1/256 · 0.000 | 256/256 · 0.985 |
| Geneve fixed-sport | **1** | 1999 | 1/256 · 0.000 | 256/256 · 0.986 |
| VXLAN kernel-sport | 1883 | 2000 | 255/256 · 0.984 | 256/256 · 0.986 |
| Geneve kernel-sport | 1883 | 2000 | 256/256 · 0.985 | 256/256 · 0.986 |

Honest reading: GTP-U and fixed-sport tunnels collapse 2000 flows -> 1 bucket;
descent restores full spread. Kernel-sourced VXLAN/Geneve already spreads for
RSS/ECMP (outer sport = f(inner)); descent's value there is inner-flow *identity*
for classifiers (tc-flower/CT/policy), which the outer sport cannot provide.

Comprehensive follow-up (`ANALYSIS2.md`, `results2.txt`): the result holds across
inner/outer IPv4 **and** IPv6; the hot-bucket imbalance for the collapse cases is
up to **512x** (all flows on one queue/path) vs ~1.4x with descent; fixed-sport
outer resolves only **#VTEP-pairs** (1/4/16), not #flows; and a **flow-count
sweep** shows kernel-sourced VXLAN hits the 14-bit outer source-port ceiling at
scale (50k flows: outer resolves 14.4k vs inner 34.9k). The inner-stripped method
was **validated byte-identical to the real ported descent** (`VALIDATION.md`).

## 5. Worst case + no-regression

- PCAP miss-cost microbench (`2026-06-10-series3-pi3-pcap-microbench/`): A53
  non-eligible tcp_ipv4 +6.67 ns/pkt (+10.3%) dispatcher fall-through — the
  worst case. Translates to +0.5-1.0% total RX CPU, below macro noise.
- mixed real-traffic tcpreplay (`2026-06-10-series3-tcpreplay-mixed/`): Δ within
  ±0.7pp; no regression on the diverse non-eligible mix.
- v4 10h soak (`2026-06-18-v4-soak-10h/`): |Δmbps| ≤ 3.3% across 84 cells;
  throughput parity (per-packet CPU saving, not a throughput change).
- **Counters overhead A/B** (`2026-07-05-series3-cpu-bound-soak/results.md`):
  pktgen cyc/pkt gold standard, l→l2 mlx5 25 GbE, eth_ip, net-next 7.2-rc1.
  Pristine baseline (no series4) 2129.0 ± 80.0 cyc/pkt (n=10); series4
  gate-off (counters run, fast paths NOP'd) 2144.8 ± 57.9 (n=5). Counter
  overhead = **+15.8 cyc/pkt (+0.74%, +0.44σ)** — within the ~3.8% CV noise
  floor, statistically indistinguishable from zero. The always-on per-shape
  `this_cpu_inc` counters add no measurable regression, matching the
  userspace A/B upper bound (~3 ns/pkt, Zen 2).
