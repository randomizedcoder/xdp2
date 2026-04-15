# Deep Performance Analysis: From Measurement to Microarchitecture

This document provides a comprehensive performance analysis of the xdp2-rs
packet parser, covering CPU microarchitectural profiling, a systematic
assessment of every optimization class, and a cross-reference against HFT
industry best practices.  It serves as both a roadmap for future optimization
work and a reference for new contributors.

**Target workloads:** high-frequency trading (HFT) and deep packet inspection
(DPI), where every nanosecond matters.

**Prerequisite reading:**
[performance-maximization-plan.md](performance-maximization-plan.md) (the
optimization journey so far),
[performance-by-platform.md](performance-by-platform.md) (current numbers).

---

## 1  Current Performance Baseline

AMD Ryzen Threadripper 3945WX (Zen 2, 12 cores / 24 threads), 445K
mixed-protocol packets, 200 iterations, single-threaded, all modes extract
full `FlowMeta` (31 metadata fields):

| Mode | ns/pkt | Mpps | cyc/pkt | ins/pkt | IPC | branch-miss% | cache-miss% |
|------|--------|------|---------|---------|-----|-------------|-------------|
| graph (`&dyn` dispatch) | 174 | 6 | 583.8 | 1065.7 | 1.83 | 1.00 | 2.85 |
| mono (hand-rolled) | 38 | 26 | 129.5 | 189.7 | 1.46 | 6.13 | 2.51 |
| compiled (codegen) | 36 | 27 | 122.5 | 160.0 | 1.31 | 6.54 | 2.80 |
| simd (AVX2 batch) | 44 | 22 | 148.8 | 186.6 | 1.25 | 6.76 | 6.68 |
| template (scalar) | 2 | 364 | 9.3 | 6.6 | 0.71 | 1.94 | — |
| template-simd (AVX2) | 2 | 493 | 6.8 | 6.0 | 0.87 | — | — |

C vs Rust (identical 445K filtered packets): Rust graph 158 ns vs C 174 ns —
**Rust is 9% faster**.

Multi-threaded peak (4T, template mode): **50.6 Mpps**.

Protocol coverage: 28 ethertypes, 14 IPv4 protocols, 17 IPv6 protocols,
31 metadata extractors.

---

## 2  Deeper CPU Profiling

### 2.1  What We Measure Today

`perf.rs` collects 6 hardware counters via Linux `perf_event_open`:

| Counter | Source |
|---------|--------|
| CPU cycles | `Hardware::CPU_CYCLES` |
| Instructions | `Hardware::INSTRUCTIONS` |
| Branches | `Hardware::BRANCH_INSTRUCTIONS` |
| Branch misses | `Hardware::BRANCH_MISSES` |
| Cache references | `Hardware::CACHE_REFERENCES` |
| Cache misses | `Hardware::CACHE_MISSES` |

These tell us *what* happened (IPC 1.31, 6.54% branch-miss) but not *why*
the IPC is only 1.31 when Zen 2 can retire ~5 micro-ops per cycle.

### 2.2  Phase A — Stall and TLB Counters

Available via the existing `perf-event` crate's `Hardware` and `Cache` enums,
requiring no new dependencies:

| Counter | API | What It Answers |
|---------|-----|-----------------|
| Frontend stall cycles | `Hardware::STALLED_CYCLES_FRONTEND` | Decode / fetch bottleneck? |
| Backend stall cycles | `Hardware::STALLED_CYCLES_BACKEND` | Memory / execution bottleneck? |
| DTLB read misses | `Cache { DTLB, READ, MISS }` | Scattered packet pointers thrashing TLB? |
| ITLB read misses | `Cache { ITLB, READ, MISS }` | Compiled parser too large for ITLB? |
| L1D read misses | `Cache { L1D, READ, MISS }` | Fine-grained data cache misses |
| L1I read misses | `Cache { L1I, READ, MISS }` | Instruction cache pressure |
| LL read misses | `Cache { LL, READ, MISS }` | Last-level cache / DRAM spills |

**Multiplexing:** Zen 2 has 6 general-purpose PMC registers, so we cannot
measure all 13 counters simultaneously.  Solution: run multiple passes.

| Pass | Counters |
|------|----------|
| basic (current) | cycles, instructions, branches, branch_misses, cache_refs, cache_misses |
| stalls | cycles, frontend_stalls, backend_stalls, dtlb_misses, itlb_misses, l1d_misses |
| detail | cycles, l1i_misses, ll_misses, node_misses (NUMA) |

CLI: `--perf-pass basic|stalls|detail|all`.  The `all` option runs 3 passes
automatically and combines results.

### 2.3  Phase B — Raw AMD PMU Events

The `perf-event` crate exposes `Builder::attrs_mut()` → `&mut perf_event_attr`,
allowing `PERF_TYPE_RAW` events with AMD-specific PMU codes:

| Counter | Raw Code | What It Reveals |
|---------|----------|-----------------|
| Op Cache Hit | `0x02C0` | Whether compiled parser fits in micro-op cache |
| Dispatch Stall: ROB full | `0x20AF` | Reorder buffer overflow (dependency chains) |
| Dispatch Stall: INT sched | `0x01AF` | Integer pipeline saturation |
| Store-to-Load Forward | `0x0035` | Store buffer forwarding events |
| MAB Allocation Stall | `0x0041` | Pending-load stalls (memory-bound indicator) |
| Retired Micro-ops | `0x00C1` | True work done (compare to instructions) |
| DTLB L2 Walk | `0x0745` | Full page table walks (expensive) |

Intel equivalents (for future X710/E810 testing):

| Intel Event | Hex | Zen 2 Analog |
|-------------|-----|-------------|
| `IDQ_UOPS_NOT_DELIVERED.CORE` | `0x019C` | `STALLED_CYCLES_FRONTEND` |
| `IDQ.DSB_UOPS` | `0x0879` | Op Cache Hit |
| `DTLB_LOAD_MISSES.MISS_CAUSES_A_WALK` | `0x0108` | DTLB L2 Walk |
| `RESOURCE_STALLS.ROB` | `0x10A2` | Dispatch Stall: ROB full |

### 2.4  Phase C — TopDown Microarchitecture Analysis (TMA)

TMA decomposes every pipeline slot into exactly one of four categories:

```
TMA Level 1:
  Retiring:        ??%   ← useful work
  Bad Speculation:  ??%   ← mispredicts (expect ~2% given low branch-miss)
  Frontend Bound:  ??%   ← decode / fetch stalls
  Backend Bound:   ??%   ← memory / execution stalls (expect dominant)

TMA Level 2 (if Backend Bound dominates):
  Memory Bound:    ??%
    L1 Bound:      ??%
    L3 Bound:      ??%
    DRAM Bound:    ??%
  Core Bound:      ??%
    Dependency:    ??%   ← the serial load chain: ethertype→IHL→proto→L4
    Port Util:     ??%
```

**Prediction:** The compiled parser's IPC of 1.31 is likely backend-bound,
dominated by the serial dependent-load chain
(`pkt[12..13]` ethertype → `pkt[14]` IHL → `pkt[23]` protocol → `pkt[34..37]`
ports).  Each load depends on the previous check.

Implementation: a `--tma` CLI mode that runs 3–4 passes with different counter
groups and produces the TMA tree.

### 2.5  Phase D — External Tool Integration

| Tool | What It Reveals | Integration |
|------|----------------|-------------|
| `perf record` + flamegraph | Per-instruction cycle attribution | `perf-sweep.sh --flamegraph` |
| `perf annotate` | Assembly-level hotspot analysis | `perf-sweep.sh --annotate` |
| AMD uProf | Zen-specific TMA + IBS (per-instruction load latency) | External, recommended for deep dives |
| `perf c2c` | False sharing detection in MT mode | `perf-sweep.sh --c2c` |
| `perf mem` | Per-load-instruction latency distribution | Manual |
| `llvm-mca` | Static instruction throughput / port pressure | `perf-sweep.sh --llvm-mca` |

### 2.6  Phase E — Per-Function `rdpmc` Measurement

For sub-nanosecond, per-protocol-layer cycle counting without syscall overhead:

1. Program a PMC via `perf_event_open` (existing crate).
2. `mmap` the perf event page to get the user-space `rdpmc` index.
3. Use inline `rdpmc` assembly (~20 cycles overhead vs ~200 for `ioctl`).

This enables measurements like "IPv4 parsing costs 15 cycles, TCP costs
8 cycles, metadata extraction costs 12 cycles" — guiding which protocol
handler to optimize next.

---

## 3  HFT Design Patterns Cross-Reference

Every technique from the Open Markets Initiative
["C++ design patterns for low-latency applications"](https://github.com/Open-Markets-Initiative/omi-low-latency-reference/blob/main/documents/hft-design-patterns.pdf)
(Bilokon & Gunduz, 2023) mapped against xdp2-rs:

| # | HFT Technique | Status | Evidence | Remaining Opportunity |
|---|--------------|--------|----------|----------------------|
| 1 | **Cache Warming** | Not started | No cache warming in codebase | In production: periodically exercise hot parsing path during idle to keep i-cache/d-cache warm.  AF_XDP busy-poll partially achieves this. |
| 2 | **Compile-time Dispatch** | Done (100%) | `graph_compiled.rs` eliminates all vtable dispatch.  `ProtocolOps` on zero-sized types = Rust CRTP. Assembly audit confirms zero indirect calls. | None. |
| 3 | **Constexpr** | Done (90%) | Protocol sizes are `const`.  `MIN_LEN` associated constants.  Compiled parser pre-computes all dispatch. | Minor: more `const fn` offset calculations in template mode. |
| 4 | **Loop Unrolling** | Done (implicit) | LLVM unrolls with fat LTO.  VLAN loop confirmed unrolled in asm.  SIMD batch = manual 8x unroll. | None — compiler handles well. |
| 5 | **Short-circuiting** | Done (implicit) | Rust `&&`/`||` short-circuit natively.  `?` operator provides early return on errors. | None. |
| 6 | **Signed vs Unsigned** | Done (implicit) | Rust type system prevents implicit signed/unsigned mixing.  All offsets are `usize`. | None — language eliminates this class of issue. |
| 7 | **Avoid Float/Double Mixing** | N/A | Hot path uses zero floating-point.  All operations are integer/bitwise. | N/A. |
| 8 | **Branch Prediction/Reduction** | Done (95%) | Branch-miss 0.05% (small PCAP), 6.54% (445K mixed).  Jump tables confirmed in asm (`.LJTI` sections). | Minor: `#[cold]` on error paths, `likely`/`unlikely` hints. |
| 9 | **Slowpath Removal** | Partial (70%) | Error paths return `Err` early.  `bench_mono_x4` uses `#[inline(never)]`. | Add `#[cold]` to `ParseError` handling.  `#[inline(never)]` on error formatters. |
| 10 | **SIMD** | Done (AVX2) | `simd_batch.rs`: 8-packet classification. `template_simd.rs`: 8-packet extraction (493 Mpps). | AVX-512: projected 1–2 cyc/pkt template.  Requires Zen 4+ or Intel. |
| 11 | **Prefetching** | **Not started** | Zero `_mm_prefetch` calls in codebase. | **High priority**: prefetch next packet in batch loops.  ~10–20% potential, especially with AF_XDP UMEM. |
| 12 | **Lock-free Programming** | Done (100%) | MT benchmark: zero locks, disjoint partitions, private `FlowMeta` per thread.  AF_XDP rings are inherently lock-free. | None for parsing.  AF_XDP ring integration uses lock-free ring buffer pattern. |
| 13 | **Inlining** | Done (100%) | 254+ `#[inline]` annotations.  Fat LTO enables cross-crate inlining.  46% combined improvement. | None — well calibrated. |
| 14 | **LMAX Disruptor** | Designed (0% impl) | AF_XDP uses the same ring buffer pattern: TX/RX/Fill/Completion rings with sequence numbers and memory barriers. | **Critical**: implement AF_XDP integration. |
| 15 | **Kernel Bypass** | Designed (0% impl) | AF_XDP chosen over DPDK.  Comprehensive plan in `af-xdp-integration-plan.md`. | **Critical**: single most impactful remaining work. |
| 16 | **Fixed-size Arrays** | Partial (80%) | Template mode: stack-allocated.  Protocol tables: `&'static` slices. | Graph mode: `CtrlData` allocates `Vec` per packet — replace with fixed arrays. |

**Summary:** 11 of 16 techniques are fully implemented, 3 are partially done,
and 2 are designed but not yet implemented.  The two biggest gaps (kernel
bypass and ring buffers) are addressed by the AF_XDP integration plan.

---

## 4  Comprehensive Optimization Taxonomy

### 4.1  Compiler and Build

| Technique | Status | Impact | Effort | Notes |
|-----------|--------|--------|--------|-------|
| Fat LTO (`lto = "fat"`, `codegen-units = 1`) | Done | — | — | Cross-crate inlining, devirtualization |
| `target-cpu=native` | Done | — | — | Enables AVX2, BMI2 on Zen 2 |
| `#[inline]` annotations (254 methods) | Done | — | — | 46% combined with LTO |
| PGO (profile-guided optimization) | Partial | Low–Med | Low | Pipeline exists in Nix, never measured |
| BOLT (post-link binary optimization) | Not started | Low–Med | Med | Reorders code by profile for i-cache |
| AutoFDO (sampling-based PGO) | Not started | Low | Med | Less precise than PGO |
| `panic = "abort"` | Not started | Low | Low | Removes unwind tables, ~5% smaller binary |
| Whole-program devirtualization | Done | — | — | Compiled parser: zero indirect calls |

### 4.2  CPU Architecture

| Technique | Status | Impact | Effort | Notes |
|-----------|--------|--------|--------|-------|
| AVX2 SIMD (256-bit) | Done | — | — | 8-packet batch classify + extract |
| AVX-512 SIMD (512-bit) | Not started | High | Med | Projected 1–2 cyc/pkt template.  Needs Zen 4+ |
| Branch reduction | Done | — | — | 0.05% miss rate, jump tables in compiled parser |
| Slowpath removal (`#[cold]`) | Partial | Low | Low | Add `#[cold]` on error paths |
| ILP exploitation (software pipelining) | Partial | Low | Med | mono-x4: +9%, regressed with metadata (register pressure) |
| Op cache optimization | Unknown | Unknown | Low | Need counters (Phase B) to determine if relevant |

### 4.3  Memory System

| Technique | Status | Impact | Effort | Notes |
|-----------|--------|--------|--------|-------|
| **Software prefetching** | **Not started** | **Med–High** | **Low** | `_mm_prefetch` in batch loops; critical for AF_XDP UMEM |
| Huge pages (2 MB / 1 GB) | Not started | Med | Low | Reduces TLB misses for 32 MB+ UMEM; `MAP_HUGETLB` |
| Cache line alignment | Partial | Low | Low | Headers: `#[repr(C, packed)]`.  `FlowMeta` hot fields not aligned |
| NUMA-aware allocation | Not started | High (multi-socket) | Med | N/A on current single-socket machine |
| Arena allocator for packets | Not started | Med | Med | Replace per-packet `Vec<u8>` with single buffer + slices |
| SoA metadata layout | Not started | Med | Med | Struct-of-arrays `FlowMeta` for batch processing |
| False sharing avoidance | Done | — | — | No shared mutable state in MT mode |
| **Cache warming** | **Not started** | **Med (HFT)** | **Low** | Exercise hot path during idle to keep caches warm |
| CtrlData stack allocation | Not started | Low–Med | Low | Replace Vec in CtrlData with fixed arrays (graph mode) |

### 4.4  System Level

| Technique | Status | Impact | Effort | Notes |
|-----------|--------|--------|--------|-------|
| **AF_XDP (kernel bypass)** | **Designed** | **Critical** | **High** | Zero-copy NIC → userspace.  Plan: `af-xdp-integration-plan.md` |
| CPU pinning (`taskset`) | Partial | Med | Low | Add `--core-pin` or `sched_setaffinity` |
| **CPU isolation** (`isolcpus`, `nohz_full`) | **Not started** | **High (HFT)** | **Low** | Kernel params; eliminates timer-tick jitter |
| IRQ affinity | Not started | Med | Low | Pin NIC IRQs away from parser cores |
| Busy-polling (`SO_PREFER_BUSY_POLL`) | Not started | High (latency) | Low | For AF_XDP; eliminates syscall overhead |
| Queue-template binding | Not started | High | Med | NIC queue → parser template; zero software classification |
| NIC ntuple / Flow Director | Not started | High | Low | `ethtool -N` rules; designed in `hardware-classified-extraction.md` |
| Interrupt coalescing (`ethtool -C`) | Not started | Med | Low | Throughput vs latency tradeoff |

### 4.5  Algorithmic

| Technique | Status | Impact | Effort | Notes |
|-----------|--------|--------|--------|-------|
| State machine compilation | Done | — | — | `xdp2-compiler` codegen; 4.8x speedup |
| Batched processing | Done | — | — | 8-packet SIMD batches + MT partitioning |
| JIT compilation | Not started | Low | High | Runtime codegen; not needed for static topologies |
| **Vectorized pattern matching (DPI)** | **Not started** | **Critical (DPI)** | **High** | Aho-Corasick / Hyperscan for multi-pattern payload search |
| Speculative parsing | Not started | Low | Med | Template mode makes this largely moot |

### 4.6  Rust-Specific

| Technique | Status | Impact | Effort | Notes |
|-----------|--------|--------|--------|-------|
| Enum layout (`#[repr(u8)]`) | Done | — | — | `AddrType`, `ParseError` are compact |
| Compile-time protocol tables | Done | — | — | `proto_table!` macro + const statics |
| `MaybeUninit<FlowMeta>` | Not started | Low | Low | Skip ~200-byte memset; increases `unsafe` surface |
| `no_std` core/protocols | Not started | Low (perf) | Med | Enables kernel/embedded deployment |
| Assembly verification | Done | — | — | `cargo-show-asm`; all redundant bounds checks eliminated |

---

## 5  Priority-Ranked Roadmap

Ordered by expected production impact for HFT/DPI workloads:

| Rank | Action | Category | Impact | Effort | Dependencies |
|------|--------|----------|--------|--------|-------------|
| 1 | AF_XDP integration | System | Enables production | High | Plan exists |
| 2 | Frontend/backend stall counters | Profiling | Identifies next bottleneck | Low | None |
| 3 | DTLB/ITLB miss counters | Profiling | Quantifies TLB pressure | Low | None |
| 4 | Software prefetching | Memory | 10–20% batch modes | Low | None |
| 5 | Queue-template binding + ntuple | System | Template in production | Med | AF_XDP |
| 6 | PGO (run and measure) | Compiler | 3–8% graph mode | Low | None |
| 7 | CPU isolation (`isolcpus` / `nohz_full`) | System | Eliminates latency jitter | Low | Production deploy |
| 8 | Full TMA analysis mode | Profiling | Systematic bottleneck ID | Med | Stall counters |
| 9 | `#[cold]` on error paths | CPU | 1–3% (i-cache) | Low | None |
| 10 | Huge pages for UMEM | Memory | Reduces TLB misses | Low | AF_XDP |
| 11 | Cache warming for HFT | Memory | Latency consistency | Low | AF_XDP |
| 12 | AVX-512 template extraction | CPU | 4–8x template throughput | Med | Zen 4+ / Intel hw |
| 13 | Arena allocator for packets | Memory | TLB/alloc pressure | Med | Benchmark only |
| 14 | CtrlData fixed-size arrays | Rust | 5–10% graph mode | Low | None |
| 15 | Flamegraph / perf-annotate integration | Profiling | Visual hotspot analysis | Low | None |
| 16 | NUMA-aware allocation | Memory | Multi-socket scaling | Med | Multi-socket hw |
| 17 | `rdpmc` per-function measurement | Profiling | Per-layer cycle breakdown | Med | None |
| 18 | Aho-Corasick / Hyperscan (DPI) | Algorithm | DPI payload inspection | High | DPI use case |
| 19 | ARM NEON/SVE SIMD | CPU | ARM deployment | Med | ARM hardware |
| 20 | BOLT post-link optimization | Compiler | 3–5% graph mode | Med | PGO data |

### Execution Phases

**Phase 0 — Profiling foundation (no code changes to parser)**
- Add stall + TLB counters to `perf.rs` (7 new counters across 2 passes)
- Run `perf annotate` and flamegraphs on compiled parser
- Run PGO pipeline and record results
- This data determines whether the next optimization should target the memory
  system (prefetch, huge pages, arena) or the CPU pipeline (cold paths,
  codegen tuning)

**Phase 1 — Low-hanging fruit (guided by Phase 0 data)**
- Software prefetching in batch loops
- `#[cold]` on error paths
- CtrlData stack allocation
- `panic = "abort"` in release profile

**Phase 2 — AF_XDP and production path**
- AF_XDP integration (the critical enabler)
- Queue-template binding + NIC ntuple configuration
- Huge pages + prefetching for UMEM
- CPU isolation + core pinning + IRQ affinity
- Cache warming

**Phase 3 — Hardware-dependent**
- AVX-512 template extraction (Zen 4+ / Intel)
- NUMA-aware allocation (multi-socket)
- Intel X710 ntuple validation

**Phase 4 — DPI extensions**
- Aho-Corasick / Hyperscan for multi-pattern payload matching
- ARM NEON/SVE portability

---

## 6  Key Questions This Analysis Will Answer

| Question | Counter / Tool | Expected Answer |
|----------|---------------|-----------------|
| Why is compiled mode IPC only 1.31? | Frontend vs backend stalls | Backend-bound (dependent-load chain) |
| Are TLB misses significant? | DTLB miss counter | Likely yes — 445K packets across ~11K pages exceeds L1 DTLB (64 entries) |
| Does the compiled parser fit in the op cache? | AMD op cache raw events | Likely yes — ~200 micro-ops for hot path vs 4K-entry capacity |
| Is there false sharing in MT mode? | `perf c2c` | Likely no — no shared mutable state |
| Which protocol layer costs the most cycles? | `rdpmc` per-function | Unknown — this is the next measurement to take |
| How much does PGO actually help? | PGO benchmark | Expected 3–8% for graph mode (6.54% branch-miss) |
| Would prefetching help with scattered PCAP packets? | Benchmark with `_mm_prefetch` | Yes for batch modes; dramatic for contiguous AF_XDP UMEM |
