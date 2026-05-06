# Performance by Platform

Cross-platform benchmark results for the XDP2 Rust packet parser.

## Standard Methodology

All measurements follow this procedure:

1. **PCAP:** `data/pcaps/tcp_ipv4.pcap` (11 packets, Ethernet/IPv4/TCP)
2. **Warmup:** 3 iterations (discarded)
3. **Iterations:** 500 (minimum for stable ns/pkt at sub-10ns timescales)
4. **Modes:** graph, mono, mono-x4, compiled, simd, template, template-simd (all via `--mode both`)
5. **Perf counters:** Enabled for single-threaded runs (`--perf`)
6. **Build:** `cargo build -p xdp2-bench --release` (fat LTO, `target-cpu=native`)
7. **Isolation:** Pinned to one core via `taskset` where possible; no other CPU-heavy processes

### Quick Run

```bash
cd xdp2-rs
cargo run -p xdp2-bench --release -- \
  --pcap ../data/pcaps/tcp_ipv4.pcap \
  --iterations 500 --mode both --perf
```

### Full Sweep (JSON output)

```bash
cd xdp2-rs
./scripts/perf-sweep.sh ../data/pcaps/tcp_ipv4.pcap 500 perf-results/
```

## Results

### AMD Ryzen Threadripper 3945WX (Zen 2, 12c/24t)

Measured 2026-04-14 (post feature-parity: 28 ethertypes, 14 IPv4 protos,
17 IPv6 protos, 31 metadata extractors — matching C flow_dissector scope).

**Single-threaded (combo.pcap, 445K mixed-protocol packets, full parse + metadata, 200 iterations):**

All parser modes perform identical metadata extraction (MACs, IPs, ports,
VLAN tags, GRE fields, MPLS labels, ESP/AH SPIs, ICMP, TIPC, L2TP, etc.).

| Mode | ns/pkt | Mpps | cycles/pkt | ins/pkt | IPC | branch-miss% | cache-miss% |
|------|--------|------|-----------|---------|-----|-------------|------------|
| graph | 174 | 6 | 583.8 | 1065.7 | 1.83 | 1.00% | 2.85% |
| mono | 38 | 26 | 129.5 | 189.7 | 1.46 | 6.13% | 2.51% |
| mono-x4 | 51 | 19 | 173.7 | 188.3 | 1.08 | 6.23% | 2.82% |
| compiled | 36 | 27 | 122.5 | 160.0 | 1.31 | 6.54% | 2.80% |
| simd | 44 | 22 | 148.8 | 186.6 | 1.25 | 6.76% | 6.68% |

**Template modes (classify + extract for template-matched, compiled fallback for rest):**

| Mode | ns/pkt | Mpps | Template match rate | Notes |
|------|--------|------|---------------------|-------|
| template | 39 | 25 | 29% (128,859/445,178) | Software classification + compiled fallback |
| template-simd | 44 | 22 | 29% | Batch variant, same match rate |

Note: 29% template match rate reflects this PCAP's extreme protocol diversity
(1371 unique stacks including MPLS, IPv6+EH, L2TP, ESP/AH). Production traffic
(80-95% TCP/UDP) would see much higher template match rates and proportionally
faster template performance. 63 templates cover plain, VLAN, QinQ, GRE,
double-GRE, VLAN+GRE, QinQ+GRE, IP-in-IP, VLAN+IPIP, QinQ+IPIP stacks.

**C vs Rust (mixed-protocol PCAP, 445K packets):**

| Engine | ns/pkt | Mpps | Notes |
|--------|--------|------|-------|
| C (xdp2-compiler, `-O2 -march=native`) | 174 | 6 | Full parse + metadata |
| Rust graph (fat LTO + `#[inline]`) | 158 | 6 | Full parse + FlowMeta |

Rust/C ratio: **0.91x (Rust ~9% faster)** on identical filtered workload (445K packets).
Filter pass rate: **89.0%** (445,178/500,000 — Rust parses 89% of gen_test_pcap output).

**Multi-threaded (4 threads, tcp_ipv4.pcap):**

| Mode | ns/pkt | Mpps | Mpps/thread |
|------|--------|------|-------------|
| graph-mt | 69 | 14.5 | 3.6 |
| mono-mt | 29 | 34.1 | 8.5 |
| mono-x4-mt | 25 | 39.3 | 9.8 |
| compiled-mt | 22 | 44.5 | 11.1 |
| simd-mt | 21 | 46.6 | 11.7 |
| template-mt | 19 | 50.6 | 12.7 |
| template-simd-mt | 23 | 42.1 | 10.5 |

Note: MT numbers use tcp_ipv4.pcap (11 packets) — small dataset means
per-thread workloads are sub-optimal. Re-measure with larger PCAPs for
production sizing. Previous pre-parity measurements showed near-linear
scaling to 16 threads; expect similar shape with lower per-thread throughput.

### AMD Ryzen 5 PRO 2400G (Zen 1, 4c/8t)

Measured 2026-05-06 on the dedicated `hp2-hp5-x710` lab testbed
(2× Ryzen 5 PRO 2400G hosts, Intel X710 10 GbE, NixOS 26.05 / kernel
7.0.1, `mitigations=off` + `isolcpus=2-7` + `nohz_full=2-7`). Full
narrative: `perf-results/2026-05-06-physical-testbed-summary.md`.
Regression-gated baseline:
[`testbeds/hp2-hp5-x710.baseline.csv`](../../testbeds/hp2-hp5-x710.baseline.csv).

**Single-threaded headline (combo.pcap, 500K mixed-protocol packets,
matrix runner with 100 iterations × 5 reps), hp5 medians:**

| Mode | ns/pkt | Mpps | IPC | branch-miss% |
|------|-------:|-----:|----:|-------------:|
| **graph-enum** | **12** | **81** | 2.55* | 0.4%* |
| compiled       | 47     | 21    | 1.22  | 6.19% |
| mono           | 50     | 20    | 1.28  | 5.91% |
| template       | 51     | 20    | 1.09  | 6.50% |
| mono-x4        | 55     | 18    | 1.16  | 6.16% |
| template-simd  | 56     | 18    | 0.84  | 7.98% |
| simd           | 57     | 18    | 1.18  | 6.62% |
| graph          | 289    | 3     | 1.31  | 3.89% |

\* graph-enum's PMU breakdown is from a separate `xdp2-bench --mode
graph-enum --perf` run captured 2026-05-02 (perf-sweep's `--mode both`
doesn't iterate graph-enum); the 12 ns/pkt headline is independently
reproduced by the matrix runner (Phase 12, c070ca9 baseline).

**Cross-pcap (hp5 medians, ns/pkt; smallest = winner per row):**

| Mode               | tcp_ipv4 (11) | https-web (20K) | mixed-real (~870) | combo (500K) |
|--------------------|--------------:|----------------:|------------------:|-------------:|
| **graph-enum**     | **22**        | 78              | **18**            | **12**       |
| compiled           | 22            | 82              | 53                | 47           |
| mono               | 24            | 82              | 48                | 50           |
| template           | **17**        | 77              | 21                | 51           |
| template-simd      | 19            | **74**          | 19                | 56           |
| simd               | 29            | 42              | 65                | 57           |
| graph (vtable)     | 218           | 266             | 464               | 289          |
| c-bpf-fast         | 24            | 23              | 21                | **18**       |
| c-flowdis-usp      | 26            | 122             | 67                | 162          |

graph-enum is the **strongest mode on heterogeneous traffic**
(combo, mixed-real); template variants win on small or single-stack
pcaps where match rate approaches 100 %. graph (trait-object dynamic
dispatch) is 6× slower than graph-enum across the board — vtable
overhead is a significant tax that enum-tag dispatch removes.

**Cross-host reproducibility (combo.pcap, hp2 vs hp5):**
mean delta 1.6 %, max 4.4 % (c-bpf-flowdis); graph-enum, compiled,
c-bpf-fast all read **identical** between the two hosts.

**Comparison vs Threadripper Zen 2:** the 2026-05-06 Zen 1 data
isn't directly comparable to the Zen 2 numbers above because the
2026-04-14 Zen 2 sweep used per-mode `xdp2-bench` invocations on a
different filtered pcap (the 89%-acceptance pre-22d3448 filter
left ~445K packets), while the 2026-05-06 matrix uses 100% of
combo.pcap (post-22d3448). For directly-comparable Zen 1 vs Zen 2,
re-run the matrix on the Zen 2 host with the same pipeline.

### (placeholder) AMD EPYC

_Not yet measured._

### (placeholder) Intel Xeon

_Not yet measured._

### (placeholder) AWS Graviton (ARM)

_Not yet measured._

## Notes

- **C vs Rust comparison:** With feature-parity (same protocol coverage,
  same metadata extraction), Rust graph mode is ~9% faster than C at scale
  (158 vs 174 ns/pkt on 445K filtered packets). The gap is driven by code
  compactness (Rust stays L2-resident while C's inlined code exceeds L2).
- **graph vs mono/compiled:** The ~4.6x gap (158 vs 34-36 ns) is due to
  `&dyn` dispatch overhead (vtable indirection, opaque pointers blocking
  inlining, ProtoTable lookups). All modes now perform identical metadata
  extraction — the gap is purely dispatch overhead.
- **mono vs compiled:** Nearly identical (38 vs 36 ns) — the ProtocolOps
  trait overhead is negligible when monomorphized. Compiled uses direct byte
  reads instead of zerocopy `ref_from_prefix`, producing fewer instructions
  (160 vs 190).
- **simd vs compiled:** SIMD is slower (44 vs 36 ns) — AVX2 gather overhead
  doesn't pay off with scattered PCAP pointers. Expect improvement with
  contiguous AF_XDP UMEM buffers.
- **template vs compiled:** Template mode classifies each packet, dispatches
  to a fixed-offset extractor (63 templates), and falls back to compiled parsing
  for untemplatable packets. On this diverse PCAP, 71% of packets fall back
  so template ≈ compiled speed. With production traffic (80-95% TCP/UDP),
  template would be significantly faster due to NIC hardware classification
  (zero CPU classification cost) and higher template match rates.
- **simd:** Batch SIMD parser with multi-stage AVX2 classification pipeline
  and scalar metadata extraction. Slower than compiled (44 vs 36 ns) because
  gather overhead doesn't amortize with scattered PCAP pointers.
- **Multi-threaded scaling:** Near-linear up to physical core count, then
  drops due to SMT sharing. The parser is purely CPU-bound with no shared
  state, so scaling is limited only by hardware resources.
- **All modes now extract FlowMeta:** Every mode (graph, mono, compiled, simd,
  template, template-simd) performs the same metadata extraction (MACs, IPs,
  ports, VLAN, GRE, etc.). The ~4.5x gap between graph and compiled is purely
  `&dyn` dispatch overhead.
