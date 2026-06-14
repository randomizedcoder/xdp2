# xdp2-rs NEON port — pi5-1 (Cortex-A76) microbench

**Date**: 2026-06-14
**Host**: pi5-1 (Raspberry Pi 5, Cortex-A76 4c @ 2.4 GHz, 7.9 GiB RAM)
**Kernel**: 6.12.87 aarch64
**Governor**: schedutil (sudo unavailable to switch — variance reflects this)
**Toolchain**: rustc 1.91.1 / cargo 1.91.0 (via `nix shell nixpkgs#cargo nixpkgs#rustc`)
**Binary**: `xdp2-bench` built from `/tmp/xdp2-rs-neon/` (rsync'd from
`flow-keys-compat-reorder` HEAD with the NEON port applied to
`xdp2-rs/crates/xdp2-bench/src/simd_batch.rs`)
**CPU pin**: `taskset -c 3` for every run

## What this measures

The xdp2-rs `simd_batch.rs` historically had only an x86_64 AVX2 path;
this session added a NEON equivalent for aarch64 (`vceqq_u32` over two
4-lane Q registers replacing the AVX2 8-lane `_mm256_cmpeq_epi32`).
The remaining 5 stages of the 6-stage pipeline are scalar code shared
by both backends.

This bench compares `rust-simd` (which now means NEON on pi5-1) against
the other Rust modes on two workloads with very different fast-path
hit rates.

## Results (median of 5 trials per cell)

### tcp_ipv4.pcap — 11 packets, 100% fast-path eligible (Eth + IPv4 + TCP)

5000 iterations per trial. The pcap is the cleanest possible
fast-path-eligible workload — every packet matches the SIMD
classifier's narrow shape (IPv4 IHL=5, TCP, no fragments).

| mode | min | **median** | max | Mpps @ median |
|---|---:|---:|---:|---:|
| rust-template | 12 | **18** | 20 | 55.6 |
| rust-mono | 25 | **26** | 50 | 38.5 |
| rust-compiled | 17 | **26** | 28 | 38.5 |
| **rust-simd (NEON)** | 27 | **39** | 41 | **25.6** |
| rust-graph-enum | 65 | **74** | 79 | 13.5 |
| rust-graph | 209 | **261** | 290 | 3.8 |

### broad-coverage.pcap — 5200 packets, mixed shapes (VLAN/IPv6/encap)

500 iterations per trial. Most packets do NOT match the SIMD
classifier's narrow shape, so every batch falls through to scalar.
Useful for measuring the SIMD path's setup overhead on
fast-path-ineligible traffic.

| mode | min | **median** | max | Mpps @ median |
|---|---:|---:|---:|---:|
| rust-graph-enum | 21 | **22** | 23 | 45.5 |
| rust-template-simd | 42 | **43** | 44 | 23.3 |
| rust-mono | 46 | **46** | 47 | 21.7 |
| rust-compiled | 45 | **46** | 46 | 21.7 |
| rust-template | 48 | **49** | 50 | 20.4 |
| **rust-simd (NEON)** | 56 | **56** | 57 | **17.9** |
| rust-graph | 316 | **317** | 319 | 3.2 |

## Interpretation

**Functional success**: `rust-simd` runs on aarch64, produces correct
output (`cargo test --release -p xdp2-bench` → **93 passed, 0 failed,
0 ignored**), and tracks the AVX2 behavior pattern.

**Workload-dependent win**:
- On tcp_ipv4 (fast-path eligible), NEON SIMD beats rust-graph-enum
  by **1.9× (39 vs 74 ns/pkt)**, beats rust-graph by **6.7× (39 vs
  261 ns/pkt)**.
- On broad-coverage (mixed shapes), rust-graph-enum's tight
  enum-dispatch loop beats rust-simd by **2.5× (22 vs 56 ns/pkt)** —
  the SIMD batch setup cost is unrecovered on workloads that fall
  through to scalar.

**Versus per-packet hand-tuned scalar** (`rust-template`, `rust-mono`,
`rust-compiled`): SIMD is *not* the fastest mode on either workload.
- On the small-pcap fast-path workload, the per-batch setup cost
  (loading 8 pointers + 8 lengths) is amortized over only one batch
  per iteration. Modes like rust-template (18 ns/pkt) win here.
- On broad-coverage, the SIMD fallback bookkeeping is pure overhead.

This matches the AVX2 / x86 picture documented in the file's own
comments: SIMD wins where every batch lights up, and is dead weight
otherwise. The headline cross-arch claim — "the SIMD batch parser
ports to NEON and delivers the same shape of win where it applies" —
is supported.

## Comparison to the x86_64 AVX2 baseline

From the existing perf-results matrix, the AVX2 `rust-simd` on x86
showed:

| workload | x86 AVX2 (hp5 Zen2, ns/pkt) | aarch64 NEON (pi5-1 A76, ns/pkt) |
|---|---:|---:|
| fast-path eligible (tcp_ipv4 / fast workload) | 40 | 39 |
| broad-coverage | n/a in earlier matrix | 56 |

The 40 ns x86 number was on a different but similar small fast-path
workload (per `perf-results/2026-05-19-r6-layout/sweep-full.md`).
That a Pi 5 A76 — a ~10× slower CPU in absolute terms — produces a
similar absolute ns/pkt for SIMD code suggests the SIMD path is
dominated by memory access latency more than ALU throughput. That's
expected for a parser that gathers per-packet bytes rather than
crunching long vectors.

## Files

- `summary.md` (this file)
- `pi5-1/aggregate.log` — raw run output (85 lines, all 5 trials × all
  modes × both pcaps)

## Reproduction

```bash
# on l:
rsync -a --exclude=target/ /home/das/Downloads/xdp2/xdp2-rs/ pi5-1:/tmp/xdp2-rs-neon/
rsync -a data/pcaps/tcp_ipv4.pcap data/pcaps/broad-coverage.pcap pi5-1:/tmp/pcaps/

# on pi5-1:
cd /tmp/xdp2-rs-neon
nix shell nixpkgs#cargo nixpkgs#rustc nixpkgs#gcc \
  --command cargo build --release -p xdp2-bench --bin xdp2-bench
for pcap in tcp_ipv4 broad-coverage; do
  for mode in graph graph-enum mono compiled simd template template-simd; do
    taskset -c 3 ./target/release/xdp2-bench \
      --pcap /tmp/pcaps/${pcap}.pcap --mode $mode \
      --iterations 5000 --warmup 50
  done
done
```
