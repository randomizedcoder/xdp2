# Performance Maximization Plan

This document captures the roadmap for maximizing packet parsing performance
in the Rust XDP2 implementation, beyond the current optimized baseline of
**59 ns/pkt (16 Mpps)** achieved through fat LTO + `#[inline]` hints.

See [performance-optimization.md](./performance-optimization.md) for the
optimizations already applied.

## Current State

**Baseline: 500K filtered packets, single-threaded, AMD Ryzen / Intel Core class CPU**

| Engine | ns/pkt | Mpps | Ratio to C |
|--------|--------|------|------------|
| C (xdp2-compiler, `-O2 -march=native`) | 182 | 5 | 1.00x |
| Rust (fat LTO + `#[inline]`) | 59 | 16 | **0.32x (3.1x faster)** |

The Rust engine outperforms C at scale due to a more compact code footprint
that stays hot in L1/L2 instruction cache. However, we're still flying blind
on microarchitectural behavior — we don't know whether the remaining time is
spent on compute, memory, or branch misprediction.

## Strategy

The plan is to maximize performance through a mix of **measurement** (to guide
optimization decisions) and **targeted architectural changes** (to eliminate
fundamental overheads). Every step begins with measurement and ends with
re-measurement to confirm impact.

## Steps

### Step 1: CPU Performance Counter Instrumentation

**Goal:** Expose cycles-per-packet, IPC, cache miss rate, and branch misprediction
rate so we can attribute time to root causes.

**Why first:** Every subsequent optimization is a guess until we measure.
Knowing whether we are memory-bound vs compute-bound changes which direction
to push.

**Approach:**

- Add `--perf` flag to `xdp2-bench` using the [`perf-event` crate]
  (https://crates.io/crates/perf-event), which wraps Linux's `perf_event_open`.
- Measure per-packet:
  - Cycles and instructions (IPC)
  - L1-dcache-load-misses, L1-icache-load-misses
  - LLC-load-misses (last-level cache)
  - Branch-misses (indicator of unpredictable indirect dispatch)
  - Context switches (should be zero during the tight benchmark loop)
- Report results alongside ns/pkt so every benchmark run produces a full
  profile, not just a single number.
- Optional: emit a `perf stat`-compatible one-line summary for easy diffing
  across changes.

**Example target output:**

```text
--- Performance (500000 packets x 100 iterations) ---
Rust parser:     59 ns/pkt,  16 Mpps
  cycles/pkt:          180
  instructions/pkt:    420   (IPC 2.33)
  L1-dcache-misses:    0.8/pkt
  L1-icache-misses:    0.15/pkt
  LLC-misses:          0.02/pkt
  branch-misses:       0.15/pkt  (3.1%)
```

**Prerequisites:**

- `perf_event_open` syscall access. Typical production setups require
  `kernel.perf_event_paranoid <= 2` (can be set in the dev shell).
- Add `perf-event` to `xdp2-bench` dependencies.
- Nix: `perf-event` is a pure-Rust crate; no extra system deps.

**Deliverables:**

- `crates/xdp2-bench/src/perf.rs` — counter abstraction.
- New `--perf` CLI flag in `main.rs`.
- Sample output captured in the performance docs.
- Benchmark re-run with the flag; results recorded as the "measurement
  baseline" for all subsequent steps.

### Step 2: Monomorphized Parse Graph (Compile-Time Specialization)

**Goal:** Eliminate `&dyn ParseNodeDyn` vtable dispatch entirely by generating
a bespoke Rust function per parse graph topology at compile time. This is
what the C `xdp2-compiler` does, and why the C parser wins at small scale.

**Approach:**

- Phase 4 of the Rust port already plans an `xdp2-compiler` crate using
  `petgraph` and `tera`.
- For each declared parse graph, generate a monomorphic function:
  ```rust
  fn parse_eth_ipv4_tcp(hdr: &[u8]) -> Result<Metadata, ParseError> {
      // All header checks inlined, zero indirect calls, zero table lookups.
  }
  ```
- Alternatively, use const generics / `TypeId`-keyed dispatch in the
  parse engine to let LLVM fully devirtualize without a separate codegen
  pass. This is more ergonomic but less predictable than template codegen.

**Expected impact:** Another 2-3x speedup. Targeting **~20-30 ns/pkt**.

**Risk:** Code size explosion if many graph topologies are instantiated.
Mitigate with `#[inline(never)]` on cold paths.

### Step 3: SIMD Header Parsing

**Goal:** Exploit data parallelism in header field validation and extraction.

**Targets:**

- MAC address compare (6 bytes) — single AVX instruction.
- IPv4 header checksum — SSE2-accelerated one's-complement sum.
- Parsing multiple port / flag fields in a single SIMD load.
- IPv6 address comparison (16 bytes) — single SSE/AVX load+compare.

**Approach:**

- Start with `std::arch::x86_64` intrinsics (stable) for hot paths.
- Consider `std::simd` (portable, nightly) if we need ARM NEON too.
- Measure against Step 1 baseline before committing — SIMD often wins
  less than expected for tiny buffers due to setup cost.

**Expected impact:** 5-15% on compute-bound paths. Only worth it if
Step 1 shows IPC headroom (meaning we are not already stalling on memory).

### Step 4: Branchless / Table-Driven Protocol Dispatch

**Goal:** Eliminate branch mispredicts on indirect protocol-number dispatch.

**Approach:**

- For dense protocol spaces (8-bit IP protocol, some ethertypes):
  replace `match` with a 256-entry function-pointer lookup table.
- For sparse spaces (full ethertype range): consider a perfect hash
  (e.g., [`phf`](https://crates.io/crates/phf)) — zero branches, one hash + load.
- The parse graph currently uses a linear-search `ProtoTable`. A
  hash-based table with perfect hashing would eliminate the search
  entirely at static-graph construction time.

**Expected impact:** Only meaningful if Step 1 reveals high branch-miss
rate. Otherwise skip.

### Step 5: Metadata Layout and Allocation

**Goal:** Eliminate any per-packet allocation or cache-unfriendly layout
in the metadata struct.

**Approach:**

- Audit the metadata struct size — if larger than 64 bytes it straddles
  cache lines; try to pack hot fields into the first cache line.
- Replace per-packet `Metadata::default()` (zeroing) with
  `MaybeUninit` and touch only the fields that matter.
- Run `cargo flamegraph` / `heaptrack` to confirm no heap allocs in
  the parse loop.

**Expected impact:** 5-10% if any of these issues exist; zero if already
clean.

### Step 6: Multi-Core Parallelism

**Goal:** Linear throughput scaling across cores.

**Approach:**

- Packet parsing is embarrassingly parallel. Partition the packet stream
  across N cores with per-core metadata buffers.
- Use `rayon` or a custom work-stealing scheduler.
- The hard part: avoiding cross-core cache-line bouncing on shared
  counters / output buffers.

**Expected impact:** ~Nx throughput multiplier. Does not improve
per-packet latency — different axis of improvement.

**Note:** This is a throughput win, not a latency win. Whether to pursue
depends on use case. For single-flow low-latency parsing (e.g., intrusion
detection on a single stream), stick with Steps 1-5. For aggregate
throughput (all-flow analysis), multi-core is the biggest knob.

### Step 7: Kernel-Bypass I/O Integration

**Goal:** Feed the parser at line rate from a real NIC.

**Approach:**

- Integrate with `AF_XDP`, DPDK, or `io_uring` for zero-copy packet
  ingress.
- This is a separate problem from the parser itself — the parser is
  already fast enough that I/O becomes the bottleneck around 10-25 Gbps.

**Expected impact:** Enables the parser to run at production line rates.
Zero improvement to parser microbenchmarks.

## Measurement Discipline

Every step follows the same pattern:

1. **Measure first** — capture `--perf` counters for the current state.
2. **Make the change** — one focused change at a time.
3. **Measure again** — diff counters, not just ns/pkt.
4. **Commit with data** — include before/after counters in the commit
   message so we can later reconstruct which change did what.
5. **Update this doc** — record actual results vs expected.

This avoids the classic trap of stacking optimizations and then wondering
which one actually helped.

## Tracking Table

| Step | Status | ns/pkt | Mpps | Notes |
|------|--------|--------|------|-------|
| Baseline (pre-optimization) | done | 109 | 9 | Default release profile |
| LTO + `#[inline]` | done | 59 | 16 | Current baseline |
| Step 1: CPU counters | in progress | — | — | Measurement infrastructure |
| Step 2: Monomorphized graph | not started | target ~25 | target ~40 | Biggest expected win |
| Step 3: SIMD header parsing | not started | — | — | Only if Step 1 shows compute headroom |
| Step 4: Branchless dispatch | not started | — | — | Only if Step 1 shows branch-miss |
| Step 5: Metadata layout | not started | — | — | Only if flamegraph shows issue |
| Step 6: Multi-core | not started | — | — | Throughput, not latency |
| Step 7: AF_XDP / DPDK | not started | — | — | I/O, not parser |

## Non-Goals

- Micro-optimizing code that doesn't show up in `--perf` output.
- Architectural rewrites without measurement justification.
- Performance "improvements" that sacrifice code clarity or safety for
  marginal gains. The Rust implementation should remain readable and
  idiomatic; this is a primary advantage over the C version.
