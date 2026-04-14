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

Measured 2026-04-13.

**Single-threaded:**

| Mode | ns/pkt | Mpps | cycles/pkt | ins/pkt | IPC | branch-miss% | cache-miss% |
|------|--------|------|-----------|---------|-----|-------------|------------|
| graph | 86 | 12 | 334.2 | 543.1 | 1.63 | 0.12% | 0.00% |
| mono | 5 | 168 | 24.8 | 68.9 | 2.78 | 0.05% | 0.00% |
| mono-x4 | 6 | 165 | 25.3 | 72.5 | 2.87 | 0.06% | 0.00% |
| compiled | 3 | 251 | 16.8 | 47.9 | 2.85 | 0.07% | 15.85% |
| simd | 5 | 172 | 24.2 | 55.6 | 2.29 | 0.00% | 62.68% |
| template | 3 | 261 | 15.9 | 35.8 | 2.25 | 0.00% | 24.39% |
| template-simd | 4 | 200 | 20.8 | 43.5 | 2.10 | 0.00% | 48.14% |

**Multi-threaded (4 threads):**

| Mode | ns/pkt | Mpps | Mpps/thread |
|------|--------|------|-------------|
| graph-mt | 59 | 16.7 | 4.17 |
| mono-mt | 19 | 51.1 | 12.78 |
| mono-x4-mt | 28 | 35.2 | 8.79 |
| compiled-mt | 17 | 56.4 | 14.11 |
| simd-mt | 20 | 49.5 | 12.37 |
| template-mt | 17 | 58.8 | 14.69 |
| template-simd-mt | 20 | 48.0 | 12.01 |

**Multi-threaded scaling (mono, peak):**

| Threads | Mpps | Mpps/thread |
|---------|------|-------------|
| 1 | 100 | 100.0 |
| 4 | 366 | 91.5 |
| 8 | 671 | 83.9 |
| 16 | 1195 | 74.7 |

### (placeholder) AMD EPYC

_Not yet measured._

### (placeholder) Intel Xeon

_Not yet measured._

### (placeholder) AWS Graviton (ARM)

_Not yet measured._

## Notes

- **graph vs mono:** The 7x gap is due to dynamic dispatch (`&dyn`) overhead
  (vtable indirection, opaque pointers blocking inlining). Mono eliminates
  all indirection via monomorphization.
- **mono vs compiled:** The compiled parser uses direct byte reads instead of
  zerocopy `ref_from_prefix`, producing fewer instructions (47.9 vs 68.9).
- **template vs compiled:** Template extraction has the fewest instructions
  (35.8/pkt) and zero branches — fixed-offset reads with one bounds check.
  Fastest single-threaded mode at 261 Mpps.
- **template-simd:** SIMD batch template extraction processes 8 packets per
  AVX2 pass. With only 11 packets (1 batch of 8 + 3 scalar tail), the
  gather + horizontal sum overhead doesn't fully amortize. Expect better
  results with larger packet counts and contiguous AF_XDP UMEM.
- **simd:** Batch SIMD parser with multi-stage classification pipeline.
  Zero branches but higher instruction count due to gather-compare stages.
- **Multi-threaded scaling:** Near-linear up to physical core count, then
  drops due to SMT sharing. The parser is purely CPU-bound with no shared
  state, so scaling is limited only by hardware resources.
- **Cache-miss%:** Higher percentages on simd/template modes are artifacts
  of very small total cache-ref counts (0.06-0.09 refs/pkt), not real
  cache pressure.
