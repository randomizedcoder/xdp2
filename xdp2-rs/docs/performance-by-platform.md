# Performance by Platform

Cross-platform benchmark results for the XDP2 Rust packet parser.

## Standard Methodology

All measurements follow this procedure:

1. **PCAP:** `data/pcaps/tcp_ipv4.pcap` (11 packets, Ethernet/IPv4/TCP)
2. **Warmup:** 3 iterations (discarded)
3. **Iterations:** 500 (minimum for stable ns/pkt at sub-10ns timescales)
4. **Modes:** graph, mono, mono-x4, compiled (all via `--mode both`)
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
| graph | 56 | 17 | 226.2 | 542.0 | 2.40 | 0.08% | 0.00% |
| mono | 4 | 250 | 18.2 | 68.9 | 3.79 | 0.04% | 0.00% |
| mono-x4 | 4 | 250 | 18.8 | 72.7 | 3.87 | 0.05% | 0.00% |
| compiled | 2 | 500 | 11.9 | 47.9 | 4.04 | 0.06% | 0.00% |

**Multi-threaded (mono, peak):**

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

- **graph vs mono:** The 14x gap is due to dynamic dispatch (`&dyn`) overhead
  (vtable indirection, opaque pointers blocking inlining). Mono eliminates
  all indirection via monomorphization.
- **mono vs compiled:** The compiled parser uses direct byte reads instead of
  zerocopy `ref_from_prefix`, producing fewer instructions (47.9 vs 68.9)
  and hitting IPC 4.04 — the Zen 2 superscalar ceiling.
- **Multi-threaded scaling:** Near-linear up to physical core count, then
  drops due to SMT sharing. The parser is purely CPU-bound with no shared
  state, so scaling is limited only by hardware resources.
