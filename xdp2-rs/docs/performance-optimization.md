# Performance Optimization: Rust Parse Engine

## 1. Overview

The Rust XDP2 parse engine uses `&dyn ParseNodeDyn<M>` trait objects for protocol
dispatch, enabling a flexible parse graph where protocol nodes are looked up at
runtime via protocol tables. This design mirrors the C implementation's function
pointer dispatch through `struct xdp2_parse_ops`, but introduces vtable overhead:
each protocol node requires up to 7 indirect function calls per packet layer
(min_len, header_len, extract_metadata, handler, sub_parse, post_handler,
next_proto/proto_table).

For a typical Ethernet -> IPv4 -> TCP packet (3 protocol nodes), that's 21
indirect calls per packet. Each protocol method is only 5-15 instructions,
so call overhead dominates the hot loop.

The C implementation avoids this entirely: the optimizing compiler
(`xdp2-compiler`) inlines all protocol functions directly into the parse loop,
producing a single monolithic function with no indirect dispatch.

This document describes the compiler-level and code-level optimizations applied
to close the performance gap.

## 2. Optimization Strategy

### 2.1 Compiler-Level: Link-Time Optimization (LTO)

The XDP2 Rust workspace splits protocol definitions (`xdp2-protocols`) from the
parse engine (`xdp2-core`) and the benchmark binary (`xdp2-bench`) into separate
crates. Without LTO, the Rust compiler cannot inline protocol methods across
crate boundaries -- each crate is compiled as an independent codegen unit.

**Workspace `Cargo.toml`:**

```toml
[profile.release]
lto = "fat"         # Full cross-crate optimization
codegen-units = 1   # Single codegen unit for maximum optimization
```

- **`lto = "fat"`** enables full link-time optimization. The compiler merges
  LLVM IR from all crates before code generation, allowing cross-crate inlining.
  This is the single most important optimization: without it, protocol methods
  in `xdp2-protocols` cannot be inlined into the parse loop in `xdp2-core`.

- **`codegen-units = 1`** forces the compiler to use a single codegen unit
  instead of the default 16. Multiple codegen units enable parallel compilation
  but prevent some optimizations because each unit is optimized independently.
  With a single unit, LLVM has full visibility for inlining, constant
  propagation, and dead code elimination.

Trade-off: compilation is slower (no parallel codegen), but runtime performance
is maximized. This is appropriate for release builds.

### 2.2 Compiler-Level: Target CPU

```toml
# In nix/xdp2-rs.nix
RUSTFLAGS = "-C target-cpu=native";
```

This tells LLVM to emit instructions for the specific CPU on the build machine,
enabling AVX2, BMI2, and other instruction set extensions. Equivalent to
`-march=native` for GCC/Clang.

For Nix builds, this is set in `nix/xdp2-rs.nix` via the `RUSTFLAGS`
environment variable in `commonArgs`. The C benchmark in
`nix/parser-benchmark.nix` uses `-march=native` for a fair comparison.

### 2.3 Code-Level: `#[inline]` Annotations

While LTO enables cross-crate inlining, the compiler still uses heuristics to
decide which functions to inline. For small protocol methods (5-15 instructions),
the `#[inline]` attribute provides a strong hint that inlining is worthwhile.

**Where applied:**

| Location | Methods | Count |
|----------|---------|-------|
| `xdp2-core/src/parse_node.rs` | All 13 `ParseNodeDyn` impl methods | 13 |
| `xdp2-core/src/proto_def.rs` | `ProtocolOps::header_len` default impl | 1 |
| `xdp2-protocols/src/**/*.rs` | All `header_len()` and `next_proto()` implementations | 240 |

The 240 protocol method annotations span 62 files across all protocol families
(ethernet, ip, transport, tunnel, security, bluetooth, etc.).

**Why `#[inline]` matters with trait objects:**

Normally, `&dyn Trait` dispatch goes through a vtable and cannot be inlined.
However, with LTO + `#[inline]`, LLVM can sometimes **devirtualize** -- when
the compiler can prove the concrete type at a call site (e.g., through constant
propagation from a static parse graph), it replaces the indirect call with a
direct call and then inlines the function body.

Even when devirtualization doesn't apply, `#[inline]` ensures the function body
is available in the LLVM IR for any optimization pass that might benefit from it.

## 3. Nix Integration

### 3.1 Rust Build (`nix/xdp2-rs.nix`)

The `RUSTFLAGS` environment variable is set in the `commonArgs` attribute set,
so it applies to all Nix build targets (production build, tests, clippy, etc.):

```nix
commonArgs = {
  pname = "xdp2-rs";
  version = "0.1.0";
  inherit src cargoHash;
  nativeBuildInputs = [ pkgs.pkg-config ];
  RUSTFLAGS = "-C target-cpu=native";
  # ...
};
```

The `[profile.release]` settings in `Cargo.toml` are picked up automatically
by `cargo build --release` during the Nix build.

### 3.2 C Benchmark (`nix/parser-benchmark.nix`)

The C benchmark compiles with `-O2 -march=native` for a fair comparison:

```bash
gcc -I${xdp2}/include -I${pkgs.libpcap}/include -g -O2 -march=native \
    -o benchmark benchmark.c parser.p.c \
    -lpcap -lxdp2 -lcli -lflowdis -lsiphash
```

### 3.3 Running the Benchmark

```bash
# Full C vs Rust benchmark (generates PCAP, builds C, runs both)
nix build .#parser-benchmark
./result/bin/xdp2-parser-benchmark 100 500000

# Quick Rust-only benchmark (local development)
cargo build --release -p xdp2-bench
./target/release/xdp2-bench --pcap test.pcap --iterations 100 --warmup 3
```

The benchmark automatically filters packets to the Rust-parseable subset,
ensuring both C and Rust benchmark identical work. As protocols are added to
the Rust parse graph, more packets pass the filter automatically.

## 4. Results

### 4.1 C vs Rust: Fair Comparison (Post Feature-Parity)

As of 2026-04-14, the Rust benchmark has full feature-parity with the C
flow_dissector: 28 ethertypes, 14 IPv4 protocols, 17 IPv6 protocols, 31
metadata extractors, GRE flag-field sub-parsing, VXLAN/Geneve tunnel
decapsulation, LLC/SNAP, FCoE, L2TP. Both benchmarks parse 445K
mixed-protocol packets (89.0% pass rate from gen_test_pcap.py's 500K output).

| Engine | ns/pkt | Mpps | Notes |
|--------|--------|------|-------|
| C (xdp2-compiler, `-O2 -march=native`) | 180 | 5 | Full parse + metadata |
| Rust graph (fat LTO + `#[inline]`) | 174 | 6 | Full parse + FlowMeta |

**Rust/C ratio: 0.97x (Rust ~3% faster)** on identical workload.

The Rust graph engine's advantage at scale comes from code compactness:
the C compiler inlines all protocol functions into a single large function
that exceeds L2 at 445K packets, while Rust's vtable dispatch produces more
compact code that stays cache-resident.

### 4.2 Optimization History

**Before optimization** (default release profile, no LTO, no `#[inline]`,
limited protocol coverage, no metadata extraction):

| Engine | ns/pkt | Mpps | Notes |
|--------|--------|------|-------|
| C (xdp2_parse) | 180 | 5 | `-O2`, compiler-inlined parse loop |
| Rust graph | 109 | 9 | Default release profile (~15 protos, no metadata) |

**After LTO + `#[inline]`** (`lto = "fat"`, `codegen-units = 1`, `#[inline]`
on all 254 protocol and dispatch methods):

| Engine | ns/pkt | Mpps | Notes |
|--------|--------|------|-------|
| Rust graph | 174 | 6 | Fat LTO + `#[inline]` + full feature-parity (445K mixed packets) |

**Note:** The pre-parity number was 59 ns/pkt because the Rust parser only
handled ~15 protocol nodes with no metadata extraction. Intermediate numbers
(95 ns on small PCAPs) reflected partial coverage. Post feature-parity with
28 ethertypes, 31 metadata extractors, and 445K mixed-protocol packets, the
graph mode is 174 ns/pkt — reflecting the real cost of full protocol
coverage and metadata extraction comparable to the C implementation.

### 4.3 Optimization Breakdown

| Change | Expected Impact | Actual Impact |
|--------|----------------|---------------|
| `lto = "fat"` + `codegen-units = 1` | 10-20% | ~0% alone (vtable barrier) |
| `#[inline]` on all protocol methods (with LTO) | 5-10% | **46% combined with LTO** |

The key insight: LTO alone had no measurable effect because it cannot inline
through `&dyn` vtable boundaries. However, `#[inline]` combined with LTO
enables LLVM's devirtualization passes to replace indirect vtable calls with
direct calls where the concrete type can be inferred -- and then inline those
direct calls. Neither optimization is effective alone; **together they produce
a multiplicative effect**.

## 5. Cache Effects and Scale Sensitivity

Benchmark results are sensitive to dataset size due to CPU cache effects:

| Dataset | C ns/pkt | Rust graph ns/pkt | Winner |
|---------|----------|-------------------|--------|
| Small (fits L1/L2) | ~100 | ~95 | Comparable |
| 445K packets (~57 MB PCAP) | 180 | 174 | Rust (marginal) |

Post feature-parity, both engines do comparable work. The Rust advantage at
scale comes from code compactness.

**Why Rust wins at scale:**

- The C parser's optimizing compiler inlines all protocol functions into a single
  large function. This maximizes instruction-level parallelism but increases code
  size. At small scale, the entire working set fits in cache and the inlined code
  runs at full speed.

- At large scale, the inlined C code exceeds the L2 instruction cache, causing
  frequent cache misses. The Rust vtable dispatch, while adding per-call overhead,
  produces more compact code that stays hot in cache.

- The Rust `#[inline]` + LTO optimization is selective: LLVM devirtualizes only
  where profitable, keeping the code compact. The C compiler inlines everything
  unconditionally.

## 6. Profile-Guided Optimization (PGO)

### 6.1 Overview

PGO uses runtime profiling data to guide compiler optimizations: branch
prediction, hot/cold code splitting, and function layout. The benchmark
supports PGO for both C and Rust via the `--pgo` flag.

### 6.2 How It Works

PGO is a two-pass compilation process:

1. **Pass 1 (Instrument):** Build the binary with profiling instrumentation.
   Every branch, function call, and loop counter is recorded at runtime.

2. **Profile:** Run the instrumented binary on a representative workload
   (the same filtered PCAP used for benchmarking). This produces raw
   profiling data (`.profraw` files for Rust/LLVM, `.gcda` files for GCC).

3. **Pass 2 (Optimize):** Rebuild with the profiling data. The compiler uses
   the data to:
   - Optimize branch prediction (likely/unlikely paths)
   - Arrange hot code together for better instruction cache locality
   - Inline functions that are frequently called on hot paths
   - Split cold code to separate pages

### 6.3 Rust PGO Pipeline

Rust PGO is stable since Rust 1.71 and uses LLVM's instrumentation under
the hood. The benchmark copies the `xdp2-rs` source tree to a temp directory
and runs two full `cargo build --release` passes:

```bash
# Pass 1: Build with instrumentation
RUSTFLAGS="-Cprofile-generate=$PGO_DATA_DIR -C target-cpu=native" \
  cargo build --release -p xdp2-bench

# Run representative workload (10 iterations)
./target/release/xdp2-bench --pcap filtered.pcap --iterations 10 --warmup 1

# Merge profiling data
llvm-profdata merge -o merged.profdata $PGO_DATA_DIR/

# Pass 2: Build with profile data
RUSTFLAGS="-Cprofile-use=merged.profdata -C target-cpu=native" \
  cargo build --release -p xdp2-bench
```

The instrumented build produces `.profraw` files during the profiling run.
`llvm-profdata merge` combines them into a single `.profdata` file that the
second pass reads to guide optimization decisions.

### 6.4 C PGO Pipeline (GCC)

GCC's PGO uses `-fprofile-generate` (pass 1) and `-fprofile-use` (pass 2).
The `-fprofile-correction` flag handles minor inconsistencies between the
profiling run and the optimized build:

```bash
# Pass 1: Build with instrumentation
gcc -O2 -march=native -fprofile-generate -o benchmark-pgo1 benchmark.c ...
./benchmark-pgo1 -p -n 10 filtered.pcap

# Pass 2: Build with profile data
gcc -O2 -march=native -fprofile-use -fprofile-correction -o benchmark benchmark.c ...
```

### 6.5 Running PGO Benchmarks

```bash
# Standard benchmark (no PGO)
nix build .#parser-benchmark
./result/bin/xdp2-parser-benchmark 100 500000

# PGO benchmark (two-pass build for both C and Rust)
./result/bin/xdp2-parser-benchmark 100 500000 --pgo
```

The `--pgo` flag adds significant time (two full cargo builds + profiling run)
but produces binaries optimized for the actual packet mix being benchmarked.

### 6.6 Nix Integration

The PGO pipeline requires the Rust toolchain and LLVM tools at runtime
(not just the pre-built binary). The benchmark's `runtimeInputs` include:

- `cargo` and `rustc` -- for building from source during PGO passes
- `llvmPackages.bintools-unwrapped` -- provides `llvm-profdata` for merging
  Rust profiling data

The Rust source tree (`xdp2-rs/`) is copied to a writable temp directory
for the PGO build, preserving the Nix store's immutability.

## 7. Beyond Graph Mode: Specialized Parsers

The graph engine (174 ns/pkt at scale) is the general-purpose parser. For
higher throughput, specialized modes eliminate different overheads while
performing the **same work** (full parse + metadata extraction):

| Mode | ns/pkt | Mpps | What it eliminates | Speedup vs graph |
|------|--------|------|--------------------|------------------|
| mono | 38 | 26 | Vtable dispatch (monomorphized calls) | 4.6x |
| compiled | 36 | 27 | Vtable + zerocopy overhead (direct byte reads) | 4.8x |
| simd | 44 | 22 | Scalar classification (AVX2 batch fast path) | 4.0x |

All modes above extract identical FlowMeta (MACs, IPs, ports, VLAN, GRE,
MPLS, ESP, AH, ICMP, TIPC, L2TP, etc.). The `&dyn` dispatch + ProtoTable
overhead accounts for the ~4.7x difference.

Template mode is **not a parser** — it performs fixed-offset field extraction
on NIC-pre-classified packets (2 ns/pkt, 7 ins/pkt). It belongs in a
different category; see [hardware-classified-extraction.md](./hardware-classified-extraction.md).

The Rust `xdp2-compiler` crate (Phase 4, planned) will auto-generate the
compiled parser from the graph IR, replacing the current hand-maintained
`graph_compiled.rs`.
