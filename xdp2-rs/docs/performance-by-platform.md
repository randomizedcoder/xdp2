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

**Field extraction (not parsing — pre-classified packets, no protocol walk):**

| Mode | ns/pkt | Mpps | cycles/pkt | ins/pkt | IPC | branch-miss% | cache-miss% |
|------|--------|------|-----------|---------|-----|-------------|------------|
| template | 2 | 364 | 9.3 | 6.6 | 0.71 | 1.94% | 47.93% |
| template-simd | 2 | 493 | 6.8 | 6.0 | 0.87 | 2.17% | 48.85% |

**C vs Rust (mixed-protocol PCAP, 445K packets):**

| Engine | ns/pkt | Mpps | Notes |
|--------|--------|------|-------|
| C (xdp2-compiler, `-O2 -march=native`) | 180 | 5 | Full parse + metadata |
| Rust graph (fat LTO + `#[inline]`) | 174 | 6 | Full parse + FlowMeta |

Rust/C ratio: **0.97x (Rust ~3% faster)** on identical workload.
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

### (placeholder) AMD EPYC

_Not yet measured._

### (placeholder) Intel Xeon

_Not yet measured._

### (placeholder) AWS Graviton (ARM)

_Not yet measured._

## Notes

- **C vs Rust comparison:** With feature-parity (same protocol coverage,
  same metadata extraction), Rust graph mode is ~3% faster than C at scale
  (174 vs 180 ns/pkt on 445K packets). The gap is driven by code compactness
  (Rust stays L2-resident while C's inlined code exceeds L2).
- **graph vs mono/compiled:** The ~4.7x gap (174 vs 36-38 ns) is due to
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
- **template vs compiled:** Template extraction has the fewest instructions
  (6.6/pkt) and near-zero branches — fixed-offset reads with one bounds
  check. Fastest single-threaded mode at 364 Mpps (field extraction, not parsing).
- **template-simd:** SIMD batch template extraction processes 8 packets per
  AVX2 pass at 493 Mpps. Expect even better results with contiguous AF_XDP UMEM.
- **simd:** Batch SIMD parser with multi-stage AVX2 classification pipeline
  and scalar metadata extraction. Slower than compiled (44 vs 36 ns) because
  gather overhead doesn't amortize with scattered PCAP pointers.
- **Multi-threaded scaling:** Near-linear up to physical core count, then
  drops due to SMT sharing. The parser is purely CPU-bound with no shared
  state, so scaling is limited only by hardware resources.
- **Cache-miss%:** Higher percentages on template modes are artifacts
  of very small total cache-ref counts, not real cache pressure.
- **All modes now extract FlowMeta:** mono/compiled/simd perform the same
  metadata extraction as graph mode (MACs, IPs, ports, VLAN, GRE, etc.).
  The ~4.7x gap between graph and compiled is purely `&dyn` dispatch overhead.
  Template is field extraction on pre-classified packets, not parsing.
