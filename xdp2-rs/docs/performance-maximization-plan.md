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
| Rust graph (fat LTO + `#[inline]`) | 59 | 16 | **0.32x (3.1x faster)** |
| Rust mono (hand-rolled, Step 2) | 10 | 100 | **0.055x (18x faster)** |
| Rust compiled (IR codegen, Step 9) | 2 | 500 | **0.011x (91x faster)** |
| Rust mono × 16 threads (Step 6) | — | 1195 | **239x C throughput** |

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

**Actual measured baseline** (500K packets × 10 iterations on AMD Ryzen-class CPU):

```text
--- Performance (500000 packets x 10 iterations) ---
Rust parser:     62 ns/pkt,  16 Mpps
  cycles/pkt:             200.3
  instructions/pkt:       449.2   (IPC 2.24)
  branches/pkt:           111.8
  branch-misses/pkt:      0.525   (0.47% miss rate)
  cache-refs/pkt:         2.909
  cache-misses/pkt:       0.055   (1.87% miss rate)
```

**What this tells us:**

- **IPC 2.24** out of ~4 theoretical max — the core is doing real work but
  has headroom. Some fraction of cycles is spent on indirect calls the
  compiler could not devirtualize.
- **Branch-miss rate 0.47%** — extremely low. Step 4 (branchless dispatch)
  will not move the needle; skip it.
- **Cache-miss rate 1.87%** — low. We are not memory-bound. Step 5
  (metadata layout) unlikely to help.
- **Conclusion:** Remaining cost is compute + vtable dispatch. Step 2
  (monomorphized parse graph) is the correct next target — it directly
  attacks the indirect-call overhead that is eating IPC headroom.

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

**Actual impact (hand-rolled PoC in `graph_mono.rs`):**

```text
Rust graph    : 64 ns/pkt,  15 Mpps   (206 cyc, 450 ins, IPC 2.18)
Rust mono     : 10 ns/pkt, 100 Mpps   ( 35 cyc,  52 ins, IPC 1.47)
Correctness: graph ok=500000/500000, mono ok=500000/500000
```

- **6.4x faster** than the graph-dispatched engine
- **18x faster** than C (was 182 ns/pkt)
- 10x fewer instructions per packet — vtable dispatch and the linear
  `ProtoTable::lookup` were generating real work, not just indirect
  branches
- IPC drops from 2.18 → 1.47 because the remaining sequence is too
  short for the OOO core to find ILP; we are now slightly load-latency
  bound inside the tiny hot loop
- Branch-misses per packet stay roughly constant in absolute terms
  (0.530 → 0.547); the higher *rate* (4.65% vs 0.47%) is just the same
  mispredicts divided by a much smaller total

**Conclusion:** The `xdp2-compiler` codegen pass is strongly justified.
A hand-written monomorphic parser for this protocol set closes the gap
entirely and then some — the question now is only how to produce one
automatically from a `.xdp2` graph definition.

**Risk:** Code size explosion if many graph topologies are instantiated.
Mitigate with `#[inline(never)]` on cold paths.

### Step 3: SIMD Header Parsing

SIMD splits into two very different ideas that share an instruction set
but not a use case. We dismissed one and deferred the other.

#### Step 3a — Per-packet SIMD (skip)

**Goal:** Use vector instructions to process a *single* packet's header
faster — MAC compare (6 B), IPv6 address compare (16 B), IPv4 checksum,
multi-field extraction.

**Verdict after Step 2:** skip.

- After monomorphization the hot loop is 52 instructions / 35 cycles per
  packet with IPC 1.47. The critical path is a dependent-load chain:
  ethertype → protocol byte → next_proto branch → next header's fields.
  Each load feeds the next branch. You cannot vectorize a pointer chase.
- This benchmark does not extract IPv6 addresses, compute checksums, or
  compare MACs — there is no bulk header data to put through SIMD lanes.
- For a full-metadata parser that does extract addresses or checksums,
  per-packet SIMD would matter again. Revisit when metadata extraction
  is enabled.

#### Step 3b — Cross-packet (batch) SIMD (deferred, not skipped)

**Goal:** Process **N packets in parallel** within one thread, using
SIMD lanes to hide the dependent-load latency that limits single-packet
throughput.

**Sketch:** load ethertype for packets 0..7 into one AVX2 register,
test against 0x0800 / 0x86DD / 0x8100 in parallel, gather the
next headers, and so on. DPDK's vector PMDs and several flow-dissector
forks use this technique.

**Why it could win big:** the single-packet parser is limited by
dependent-load latency, not compute. Batching amortizes those loads
across N packets — we stop waiting on any individual chain. A 2-4x
single-thread throughput improvement is plausible on uniform-path
traffic.

**The lane-divergence problem (and why it does not block us in practice):**

A naive batch parser falls off a cliff when packets in the batch take
different paths (one TCP, one UDP, one IPv6-EH chain) — the SIMD lanes
have to fall back to scalar per-lane execution, and you end up slower
than the mono parser. On arbitrary mixed internet traffic this kills
most of the gain.

**But** modern NICs already sort packets for us, so this is a solved
problem for deployments that control the NIC configuration:

- **Intel Flow Director / RSS hash tuning** can steer same-5-tuple or
  same-protocol flows to dedicated receive queues.
- **nFlow / ntuple rules** (`ethtool -N`) let you pin e.g. "IPv4 TCP
  port 443" to queue 3, "VXLAN" to queue 7, etc.
- **Mellanox / Nvidia ConnectX** has similar steering primitives.

So in a deployment where operators configure the NIC to stream a small
number of dominant packet types to dedicated queues — and the parser
reads from one queue at a time — batches are naturally homogeneous and
the lane-divergence problem disappears.

**Concrete scenario where this pays off:**

Mobile / cellular packet core (5G UPF, GTP-U termination, etc.) —
typical traffic mix is dominated by a handful of encapsulations:
GTP-U / IPv4+TCP (browsing), GTP-U / IPv4+UDP (QUIC, video), GTP-U /
IPv6+{TCP,UDP}, and control-plane PFCP. Four to eight NIC queues,
each bound to a CPU running a batch-SIMD parser specialized for that
queue's dominant path, covers ~80-90% of traffic with fully uniform
batches. The long tail falls through to a scalar fallback. This is
exactly the topology where batch SIMD stops being a theoretical
exercise and starts being 2-4x of real throughput on top of Step 6's
1 Gpps per host.

**Approach (when pursued):**

- Restructure the parser into a stage-based pipeline (`parse_eth_stage`,
  `parse_ipv4_stage`, ...) that operates on arrays of N packet cursors.
- Start with AVX2 (256-bit, 8×32 or 4×64 lanes) using
  `std::arch::x86_64` intrinsics.
- Consider `std::simd` (portable, nightly) for ARM NEON / SVE if the
  parser ships on non-x86 platforms (edge / telco ARM SoCs are
  increasingly relevant here).
- Provide a scalar fallback path and a "batch size 1" degenerate mode
  so lane-divergent traffic still gets the Step 2 mono performance.
- Measure against the Step 6 baseline (per-core throughput) with
  homogeneous synthetic PCAPs first, then with realistic NIC-steered
  mixes.

**Expected impact (on uniform batches, single-threaded):** 2-4x vs the
mono parser. Stacks multiplicatively with Step 6's multi-core scaling.
On a 16-thread host that currently does 1 Gpps, this could push per-host
throughput toward 2-4 Gpps on favorable deployments.

**Expected impact (on arbitrary mixed traffic, no NIC steering):** near
zero or slightly negative. Do not pursue without the steering story.

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

**Measured scaling (AMD Ryzen Threadripper PRO 3945WX, 12c/24t,
500K filtered packets × 50 iterations, mono parser, `black_box` on
each worker's slice to prevent LLVM LICM):**

| Threads | Mpps (mono) | Mpps / thread | Notes |
|---------|-------------|---------------|-------|
| 1       |    100      |  100          | Single-core baseline |
| 4       |    370      |   93          | Near-linear |
| 8       |    713      |   89          | Near-linear |
| 12      |    959      |   80          | All physical cores busy |
| 16      | **1195**    |   75          | **Peak — 1.2 Gpps** |
| 24      |   1094      |   46          | SMT contention, net negative |

Earlier short runs (10 iterations) reported 1046 Mpps at this same
configuration — that was undersampled, not inflated. Use ≥50 iterations
for stable numbers.

**These numbers are specific to this machine.** The 3945WX is a
12-core / 24-thread workstation CPU with 8-channel DDR4-3200 and 64 MB
L3. On a server-class box, the scaling shape will shift:

- A 64-core EPYC 9xxx or 128-core Altra Max will likely keep near-linear
  scaling further than 12 cores, because (a) per-core bandwidth is
  comparable or higher, and (b) L3 is larger per socket, so the
  packet buffer stays resident longer.
- At ~75 Mpps per physical core and 64-128 cores, per-socket throughput
  should land in the 5-10 Gpps range on current-generation servers —
  but memory-bandwidth saturation will eventually dominate just like it
  does here, just at a higher knee.
- Multi-socket (2P EPYC, 2P Xeon SP) adds NUMA. Without packet-buffer
  replication per socket, cross-socket L3 traffic will cap scaling
  well before 2x per-socket. This is worth testing before deploying.
- SMT behavior differs by generation: Zen 3+ and Sapphire Rapids have
  larger execution resources and may tolerate SMT better than Zen 2.
  Re-measure — the "stop at N_physical_cores" rule is empirical, not
  theoretical.

**Action item:** re-run `--threads 1,2,4,8,16,32,64,128 --mode both`
on every production-candidate CPU before pinning a deployment sizing
recommendation. Add results to a new `performance-by-platform.md`
once we have data from more than one box.

At 16 threads we exceed **1 billion packets per second** on a single host.
The packet set is ~72 MB, so each thread's slice fits comfortably in L2
on the first pass and the remaining passes are L3-resident — this is why
per-thread throughput stays so high even at 12 threads.

The 24-thread regression is not a bug: at that point each SMT pair is
competing for the same core's L1 and execution ports, and the parser is
already issue-bound (IPC 1.47 → lower under contention). For this
workload, stop at ~N_physical_cores; SMT is not a win.

**Implementation:** `run_mt` in `xdp2-bench/src/main.rs`:
partitions packets into equal chunks, spawns one `std::thread::scope`
worker per chunk, each running `iterations` full passes with a
black-box-fed accumulator. No synchronization in the inner loop — every
byte read is from a shared read-only buffer.

### Step 7: Kernel-Bypass I/O Integration

**Goal:** Feed the parser at line rate from a real NIC.

**Approach:**

- Integrate with `AF_XDP`, DPDK, or `io_uring` for zero-copy packet
  ingress.
- This is a separate problem from the parser itself — the parser is
  already fast enough that I/O becomes the bottleneck around 10-25 Gbps.

**Expected impact:** Enables the parser to run at production line rates.
Zero improvement to parser microbenchmarks.

### Step 6a — Software-Pipelined Scalar (x4)

**Goal:** Test whether the out-of-order engine has spare scheduling
headroom on a single packet. If so, interleaving 4 independent parse
chains per loop iteration should shorten wall-time by fanning out
dependent-load chains across the OoO window.

**Approach:** `bench_mono_x4` in `xdp2-bench/src/main.rs` — process
packets in groups of 4 with 4 fully independent `parse_packet_mono`
calls per iteration. No new parser; just a restructured outer loop.

**Result:**

| Config | Mpps | cycles/pkt | IPC |
|--------|------|------------|-----|
| mono (1T)    | 100  | 36.6 | 1.44 |
| mono-x4 (1T) | 100  | 35.0 | 1.49 |
| mono-mt (16T)    | 1195 | — | — |
| mono-x4-mt (16T) | 1180 | — | — |

Single-thread: ~4% fewer cycles and ~3% higher IPC. Real, but at the
measurement-noise boundary for a wall-clock ns/pkt number.

Multi-thread: no benefit. At 16 threads the L3 and core-private memory
paths saturate; adding software-level interleaving on top does not
extract more because the system is already bandwidth-limited rather
than OoO-window-limited.

**Conclusion (on this machine):** the Zen 2 OoO engine is already nearly
saturated on a single packet. To extract meaningfully more per-thread
throughput here we need either (a) a shorter per-packet critical path,
or (b) true SIMD to issue batched loads across packets (Step 3b).

**Do not generalize this to "x4 is a dead end everywhere."** The 3945WX
is workstation-class: 12 cores, 8-channel DDR4-3200 per-socket
bandwidth, Zen 2 OoO width of 10-way dispatch. The result could look
very different on other hardware:

- **Wider server cores (EPYC 9004 / Intel Sapphire Rapids / Graviton 3/4):**
  bigger ROBs, more load/store ports, higher per-core memory bandwidth.
  Software pipelining may matter even less here (the OoO engine already
  handles more packets in flight) — or more (if the critical path stays
  fixed while the window grows). Needs to be measured.
- **Narrower cores (cloud-edge ARM, embedded Xeon-D, older chips):**
  smaller OoO window, shorter pipelines. x4 pipelining could
  plausibly give 20-30% here because the single-packet chain does not
  fit in the window.
- **Many-core servers (EPYC 9754 128c, Altra Max 128c):** multi-thread
  scaling is a different problem. At 16T on the 3945WX we are L3-
  and memory-bandwidth-limited; on a 128-core system with 12-channel
  DDR5 and 256 MB L3 per socket, the scaling ceiling is far higher
  and the per-thread ceiling may also shift. The "stop at 16 threads"
  guidance is specific to the test machine, not general.
- **Multi-socket systems:** NUMA adds a new axis entirely — pin workers
  to local memory, duplicate the read-only packet buffer per socket, etc.

The `mono-x4` mode is kept in `xdp2-bench` for exactly this reason:
it is cheap infrastructure for characterizing new hardware. Re-run
`--mode both --threads N` on any target of interest before deciding
whether to ship the vanilla `mono` loop or the pipelined one.

**Lesson — LLVM LICM can invalidate pure-function benchmarks.** The
first x4 run reported 4x multi-thread speedups that turned out to be
fake: `bench_mono_x4` is `#[inline(never)]` and pure, so LLVM hoisted
the call out of the worker's `for _ in 0..iterations` loop and
effectively divided the work by `iterations`. Fix: `black_box` the
input slice at the top of the function (and at the top of every MT
worker closure) so the compiler must assume each call has a distinct
input and cannot reuse the previous result. This is now standard
practice in `xdp2-bench`.

### Step 8: Bounds-Check Audit (Assembly Verification)

**Goal:** Determine whether the `hdr_len<P>()` wrapper's redundant bounds
checks survive into the final binary, and if so, eliminate them.

**Analysis:** The `hdr_len` helper (graph_mono.rs:57-66) performs three
checks for every protocol layer:

1. `hdr.len() < P::MIN_LEN` — early length gate
2. `proto.header_len(hdr, hdr.len())` — calls the ProtocolOps impl
3. `hlen < P::MIN_LEN || hlen > hdr.len()` — validates the result

For fixed-length protocols (Ethernet, VLAN, QinQ, UDP, ARP, ICMP, SCTP),
`header_len()` uses the default impl returning `Ok(MIN_LEN)`, making
check (3) provably false after check (1). For variable-length protocols
(IPv4, TCP), `header_len()` internally calls `ref_from_prefix(hdr)`
which re-validates the length — redundant with check (1). IPv4's
`next_proto()` does yet another `ref_from_prefix` — redundant with
`header_len()`.

**Method:** Added `cargo-show-asm` to the Nix dev shell (`nix/packages.nix`)
and inspected the release-mode assembly for all five emitted functions:
`parse_eth`, `parse_vlan`, `parse_qinq`, `parse_ipv6`, `dispatch_ipv4`.

**Result: LLVM eliminates all redundancies.** No code changes needed.

Key observations from the assembly:

- **Fixed-length protocols (Ethernet, VLAN, QinQ, IPv6, UDP, ARP):**
  LLVM reduces the three-check `hdr_len` wrapper to a single
  `cmp reg, <MIN_LEN>` / `jb error`. The `header_len()` call and
  check (3) are completely eliminated — they do not appear in the
  binary at all.

- **Ethertype / next-proto reads:** LLVM inlines `next_proto()` to
  direct byte reads at compile-time-known offsets. Ethernet becomes
  `movzx eax, word ptr [rdi + 12]; rol ax, 8` (read + byte-swap).
  No `ref_from_prefix` frame or error-path code survives.

- **Variable-length protocols (IPv4, AH, IPv6 EH):** IHL extraction
  becomes `shl ecx, 2; and ecx, 60` (one instruction for
  `(byte & 0x0F) * 4`). The two bounds checks (`ihl < 20` and
  `ihl > remaining`) are combined branchlessly via `setb + or`.

- **VLAN recursion fully unrolled:** `parse_vlan` (507 bytes) contains
  no recursion — LLVM unrolled all 8 iterations of the `MAX_ETH_DEPTH`
  loop into straight-line code with direct offset reads at
  `[rdi + 6]`, `[rdi + 10]`, ..., `[rdi + 26]`.

- **Jump tables for dispatch:** Both `dispatch_ipv4` and `dispatch_ipv6`
  use hardware jump tables (`.LJTI` sections), confirming the `match`
  statements compile to optimal O(1) dispatch.

- **Leaf nodes:** Fixed-length leaves compile to
  `cmp reg, <MIN_LEN>; setae al; shl al, 4; inc al` — a single
  branchless comparison packed into the return value.

**Conclusion:** The ProtocolOps zero-cost abstractions are working exactly
as intended. The readable, type-safe source code (with `EthernetOps`,
`hdr_len<P>()`, etc.) produces assembly indistinguishable from hand-written
byte-offset code. **Do not replace the trait-based code with manual byte
reads** — it would sacrifice readability for zero performance benefit.

This validates the approach for the `xdp2-compiler` codegen (Step 2):
the generated code can use the same ProtocolOps abstractions and trust
LLVM to produce optimal output.

**Tool added:** `cargo-show-asm` (`pkgs.cargo-show-asm`) added to the Nix
dev shell for future assembly inspection. Usage:

```bash
nix develop --command cargo asm -p xdp2-bench --release "xdp2_bench::graph_mono::parse_eth"
```

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
| Step 1: CPU counters | done | 62 | 16 | IPC 2.24, branch-miss 0.47%, cache-miss 1.87% |
| Step 2: Monomorphized graph (PoC) | done | **10** | **100** | Hand-rolled mono parser: 6.4x faster, 35 cycles/pkt, 52 ins/pkt |
| Step 3a: Per-packet SIMD | skip | — | — | No bulk data in hot path; critical path is a dependent-load chain |
| Step 3b: Cross-packet (batch) SIMD | deferred | — | — | High ROI on uniform-path traffic (NIC-steered queues); requires pipeline rewrite |
| Step 4: Branchless dispatch | skip | — | — | Branch-miss already 0.47%, nothing to gain |
| Step 5: Metadata layout | skip | — | — | Cache-miss already 1.87%, not memory-bound |
| Step 6: Multi-core (mono) | done | — | **1195** | 16 threads, Threadripper 3945WX (12c/24t), 50 iterations |
| Step 6a: Software-pipelined x4 | done on 3945WX | 35 (−1) | 100 (0) | Marginal here (Zen 2, wide OoO); may matter more on narrower cores — re-measure per target |
| Step 7: AF_XDP / DPDK | not started | — | — | I/O, not parser |
| Step 8: Bounds-check audit | done | — | — | LLVM eliminates all redundancies; zero-cost abstractions verified via `cargo asm` |
| Step 9: Compiler codegen (IR → Rust) | done | **2** | **500** | Auto-generated mono parser from bench-graph.json; 11.9 cycles/pkt, 47.9 ins/pkt, IPC 4.04; 28x graph, ~2x hand-rolled mono |
| Step 10: Cross-platform perf harness | done | — | — | `--report` JSON output, `perf-sweep.sh`, `performance-by-platform.md` |
| Step 11: Batch SIMD prototype (AVX2) | done | 4 | 208 | Eth/IPv4/TCP fast path in SIMD, scalar fallback; ~2x slower than compiled (gather overhead); validates approach for AF_XDP batches |

## Non-Goals

- Micro-optimizing code that doesn't show up in `--perf` output.
- Architectural rewrites without measurement justification.
- Performance "improvements" that sacrifice code clarity or safety for
  marginal gains. The Rust implementation should remain readable and
  idiomatic; this is a primary advantage over the C version.
