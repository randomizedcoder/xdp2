# C++ High-Performance Backport: Design Plan

## 1. Motivation

The Rust port of the XDP2 parse engine demonstrated 20--90x speedups over
the original C graph-dispatch implementation. These speedups come from
techniques that are all available in C++:

| Technique | Rust Mechanism | C++ Equivalent |
|---|---|---|
| Static dispatch | Monomorphized trait impls | CRTP / C++ templates |
| Whole-program inlining | `lto = "fat"` + `#[inline]` | `-flto=full` + `always_inline` |
| Compiler codegen | `xdp2-compiler` -> Rust source | `xdp2-compiler` -> C++ source |
| Batch SIMD | `std::arch::x86_64::*` intrinsics | `<immintrin.h>` (same intrinsics) |
| Template extraction | `const` structs + fixed-offset reads | `constexpr` structs + fixed-offset reads |

In theory, C++ should match or slightly exceed Rust performance because
both target the same LLVM backend (when using Clang), and C++ avoids Rust's
crate-boundary visibility limitations for inlining. This document plans a
new high-performance C++ implementation that applies the same optimizations.

**Important context:** The Rust benchmark numbers (2--3 ns/pkt) were
measured on a **reduced-scope parser** -- 15 protocol types with no
metadata extraction, no TLV/flag-field processing, and no tunnel
decapsulation. The C flow_dissector parser being compared handles ~40+
nodes with 18 active metadata extractors, GRE flag-fields, and VXLAN/Geneve
tunnels. Part of the Rust speedup is doing less work per packet, not just
doing the same work faster. See `performance-lecture.md` Section "Scope and
Fair Comparison" for details. The C++ backport should target feature parity
with the C flow_dissector, not just the reduced Rust benchmark scope.

## 2. Goals and Non-Goals

### Goals

- **Match Rust performance:** 2--3 ns/pkt single-thread, 1+ Gpps multi-thread
- **Preserve the parse graph abstraction:** the graph definition remains the
  single source of truth
- **Coexist with original code:** new code in `src/high-perf/`, original C
  in `src/lib/xdp2/` remains untouched
- **Reuse existing protocol definitions:** `src/include/xdp2/proto_defs/`
  headers are C-compatible and can be included directly
- **Benchmark parity:** same PCAPs, same packet filtering, same perf counters
  as the Rust benchmark for apples-to-apples comparison

### Non-Goals

- Replacing the original C implementation
- Rewriting protocol definitions (reuse existing C headers)
- Matching Rust's memory safety guarantees (correctness ensured by testing
  and sanitizers)
- Supporting eBPF/XDP targets (the existing C compiler already handles those)

---

## 3. Architecture Overview

### 3.1 Directory Structure

New code lives in `src/high-perf/`, completely separate from the original
`src/lib/xdp2/`:

```
src/high-perf/
├── CMakeLists.txt                  # Build system
├── include/
│   └── xdp2hp/
│       ├── protocol_traits.hpp     # CRTP base + C++20 concepts
│       ├── protocols/
│       │   ├── ethernet.hpp        # Wraps proto_defs/ethernet/
│       │   ├── ipv4.hpp
│       │   ├── ipv6.hpp
│       │   ├── tcp.hpp
│       │   ├── udp.hpp
│       │   └── ...
│       ├── parse_engine.hpp        # Template-based parse engine
│       ├── graph_compiler.hpp      # Compile-time graph specialization
│       ├── simd_batch.hpp          # AVX2/AVX-512 batch parser
│       └── template_extract.hpp    # Fixed-offset template extraction
├── src/
│   ├── parse_engine.cpp
│   └── simd_batch.cpp
├── bench/
│   ├── main.cpp                    # Benchmark harness (mirrors xdp2-bench)
│   ├── perf_counters.hpp           # perf_event_open wrapper
│   └── pcap_reader.hpp             # PCAP loading
└── test/
    ├── parse_test.cpp              # Correctness tests
    └── golden_test.cpp             # Cross-validate vs C and Rust parsers
```

### 3.2 Dependency on Existing Code

The high-perf implementation includes existing C protocol definition headers
directly:

```cpp
// xdp2hp/protocols/ethernet.hpp
#include "xdp2/proto_defs/ethernet/ethernet.h"  // existing C header

struct EthernetProtocol : ProtocolBase<EthernetProtocol> {
    static constexpr size_t MIN_LEN = sizeof(struct ethhdr);  // from C header
    // ...
};
```

This ensures protocol definitions remain in one place. When the C headers
are updated, the C++ wrappers automatically pick up the changes.

---

## 4. Optimization Mapping: Rust to C++

This is the core of the design. Each subsection maps a Rust optimization
technique to its C++ equivalent and explains any differences.

### 4.1 Trait Objects -> CRTP (Static Dispatch)

**Rust approach:**

The generic graph engine uses `&dyn ParseNodeDyn<M>` trait objects --
indirect dispatch through a vtable, exactly like C++ virtual functions.
The monomorphized version uses zero-sized structs implementing `ProtocolOps`
directly, allowing the compiler to inline everything.

**C++ equivalent -- Phase 1 (virtual, baseline):**

```cpp
struct ParseNode {
    virtual ssize_t header_len(const uint8_t* hdr, size_t len) const = 0;
    virtual int next_proto(const uint8_t* hdr) const = 0;
    virtual ~ParseNode() = default;
};

struct EthernetNode : ParseNode {
    ssize_t header_len(const uint8_t*, size_t) const override { return 14; }
    int next_proto(const uint8_t* hdr) const override {
        return (hdr[12] << 8) | hdr[13];
    }
};
```

This mirrors the original C function-pointer dispatch and establishes the
baseline for benchmarking.

**C++ equivalent -- Phase 2 (CRTP, static dispatch):**

```cpp
template <typename Derived>
struct ProtocolBase {
    size_t header_len(const uint8_t* hdr, size_t len) const {
        return static_cast<const Derived*>(this)->header_len_impl(hdr, len);
    }
    int next_proto(const uint8_t* hdr) const {
        return static_cast<const Derived*>(this)->next_proto_impl(hdr);
    }
};

struct EthernetProtocol : ProtocolBase<EthernetProtocol> {
    static constexpr size_t MIN_LEN = 14;

    size_t header_len_impl(const uint8_t*, size_t) const { return 14; }
    int next_proto_impl(const uint8_t* hdr) const {
        return (hdr[12] << 8) | hdr[13];
    }
};
```

CRTP eliminates the vtable. The compiler resolves `header_len()` to a
direct call to `header_len_impl()` at compile time and inlines it.

**C++20 concepts** can enforce the protocol interface:

```cpp
template <typename T>
concept Protocol = requires(const T& p, const uint8_t* hdr, size_t len) {
    { T::MIN_LEN } -> std::convertible_to<size_t>;
    { p.header_len_impl(hdr, len) } -> std::convertible_to<size_t>;
    { p.next_proto_impl(hdr) } -> std::convertible_to<int>;
};
```

This gives compile-time errors similar to Rust's trait bounds, instead of
C++ template error novels.

### 4.2 Monomorphization via C++ Templates

**Rust approach:**

Generic functions like `hdr_len<P: ProtocolOps>()` are monomorphized --
the compiler generates a separate copy for each concrete type `P`. This
is what allows LLVM to inline everything.

**C++ equivalent:**

```cpp
template <Protocol P>
[[gnu::always_inline]]
inline size_t hdr_len(const P& proto, const uint8_t* pkt, size_t len) {
    if (len < P::MIN_LEN) return 0;  // error
    size_t hlen = proto.header_len_impl(pkt, len);
    if (hlen < P::MIN_LEN || hlen > len) return 0;
    return hlen;
}
```

C++ template instantiation is fundamentally the same mechanism as Rust
monomorphization. The compiler generates `hdr_len<EthernetProtocol>`,
`hdr_len<Ipv4Protocol>`, etc., each fully specialized and inlineable.

The monomorphized parse function:

```cpp
inline int parse_eth(const uint8_t* pkt, size_t len, uint32_t depth) {
    if (depth >= MAX_ETH_DEPTH) return -1;
    EthernetProtocol proto;
    size_t hlen = hdr_len(proto, pkt, len);
    if (!hlen) return -1;
    int next = proto.next_proto_impl(pkt);
    const uint8_t* rest = pkt + hlen;
    size_t rest_len = len - hlen;

    switch (next) {
        case 0x0800: return parse_ipv4(rest, rest_len, depth + 1);
        case 0x86DD: return parse_ipv6(rest, rest_len, depth + 1);
        case 0x8100: return parse_vlan(rest, rest_len, depth + 1);
        case 0x88A8: return parse_qinq(rest, rest_len, depth + 1);
        case 0x0806: return parse_arp(rest, rest_len);
        default:     return -1;
    }
}
```

### 4.3 LTO and Inline Hints

**Rust:**
```toml
[profile.release]
lto = "fat"
codegen-units = 1
opt-level = 3
```
Plus `#[inline]` annotations on hot functions.

**C++ equivalent:**

| Rust | C++ (GCC) | C++ (Clang) |
|---|---|---|
| `lto = "fat"` | `-flto` | `-flto=full` |
| `codegen-units = 1` | (default with `-flto`) | (default with `-flto=full`) |
| `opt-level = 3` | `-O3` | `-O3` |
| `target-cpu = native` | `-march=native` | `-march=native` |
| `#[inline]` | `inline` (hint) | `inline` (hint) |
| `#[inline(always)]` | `__attribute__((always_inline))` | `[[gnu::always_inline]]` |
| `#[inline(never)]` | `__attribute__((noinline))` | `[[gnu::noinline]]` |

**C++ advantage:** With header-only protocol definitions and template
functions, everything is visible in a single translation unit. The compiler
can inline without LTO. This avoids the crate-boundary problem that Rust's
`lto = "fat"` specifically solves.

**Recommended flags:**
```
-std=c++20 -O2 -march=native -flto=full -fno-exceptions -fno-rtti
```

Exceptions and RTTI are disabled because:
- The parser uses return codes, not exceptions (matching C behavior)
- RTTI is unused (CRTP replaces virtual dispatch)
- Both add binary size and prevent certain optimizations

### 4.4 Compiler Codegen (IR to C++)

**Rust approach:**

The `xdp2-compiler` crate reads a Parser IR JSON file (`bench-graph.json`)
and generates Rust source code (`graph_compiled.rs`) using Tera templates.
The generated code is straight-line `if/match` chains with no abstraction
overhead.

**C++ approach:**

Extend the existing `src/tools/compiler/` (which already generates optimized
C code) to emit a C++ target. The generated code would look like:

```cpp
// Auto-generated from Parser IR — do not edit
namespace xdp2hp::generated {

inline int parse_ipv4(const uint8_t* pkt, size_t len, uint32_t depth) {
    if (depth >= MAX_DEPTH) return -1;
    if (len < 20) return -1;
    size_t hlen = (pkt[0] & 0x0F) * 4;  // IHL extraction
    if (hlen < 20 || hlen > len) return -1;
    int next = pkt[9];                    // protocol byte
    switch (next) {
        case 51:  return parse_ah(pkt + hlen, len - hlen, depth + 1);
        case 4:   return parse_ip_in_ip(pkt + hlen, len - hlen, depth + 1);
        case 132: return parse_sctp(pkt + hlen, len - hlen);
        case 1:   return parse_icmpv4(pkt + hlen, len - hlen);
        case 17:  return parse_udp(pkt + hlen, len - hlen);
        case 6:   return parse_tcp(pkt + hlen, len - hlen);
        default:  return -1;
    }
}

} // namespace xdp2hp::generated
```

This is structurally identical to the generated Rust code. The same LLVM
backend (when using Clang) will produce the same assembly.

### 4.5 AVX2/AVX-512 SIMD Intrinsics

**Rust:**
```rust
#[target_feature(enable = "avx2")]
unsafe fn parse_8_avx2(chunk: &[&StoredPacket]) -> u64 {
    let ethertypes = _mm256_i32gather_epi32(base_ptr, offsets, 1);
    let is_ipv4 = _mm256_cmpeq_epi32(ethertypes, _mm256_set1_epi32(0x0800));
    // ...
}
```

**C++ equivalent:**
```cpp
#include <immintrin.h>

__attribute__((target("avx2")))
uint64_t parse_8_avx2(const StoredPacket* chunk[8]) {
    __m256i ethertypes = _mm256_i32gather_epi32(
        reinterpret_cast<const int*>(base_ptr), offsets, 1);
    __m256i is_ipv4 = _mm256_cmpeq_epi32(
        ethertypes, _mm256_set1_epi32(0x0800));
    // ...
}
```

The intrinsics are **identical** -- both languages use the same Intel
intrinsic names from `<immintrin.h>`. The C++ version has two small
advantages:

1. **No `unsafe` blocks.** C++ treats SIMD intrinsics as regular function
   calls. There is no syntactic overhead for using them.

2. **`reinterpret_cast` is natural.** SIMD intrinsics frequently require
   casting between pointer types. C++ makes this idiomatic.

The stage pipeline (length check -> gather ethertypes -> compare -> gather
protocols -> classify -> scalar fallback) is identical to the Rust
implementation in `simd_batch.rs`.

### 4.6 Template Extraction (Fixed-Offset)

**Rust:**
```rust
pub const ETH_IPV4_TCP: PacketTemplate = PacketTemplate {
    name: "eth_ipv4_tcp",
    min_length: 54,
    fields: &[ /* ... */ ],
};
```

**C++ equivalent:**
```cpp
struct EthIpv4TcpTemplate {
    static constexpr size_t MIN_LENGTH = 54;
    static constexpr size_t ETH_DST_OFFSET     = 0;
    static constexpr size_t ETH_SRC_OFFSET      = 6;
    static constexpr size_t ETHERTYPE_OFFSET    = 12;
    static constexpr size_t IP_PROTO_OFFSET     = 23;
    static constexpr size_t IP_SRC_OFFSET       = 26;
    static constexpr size_t IP_DST_OFFSET       = 30;
    static constexpr size_t TCP_SRC_PORT_OFFSET = 34;
    static constexpr size_t TCP_DST_PORT_OFFSET = 36;
    static constexpr size_t TCP_FLAGS_OFFSET    = 47;
};

template <typename T>
[[gnu::always_inline]]
inline uint64_t extract(const uint8_t* pkt, size_t len) {
    if (len < T::MIN_LENGTH) return 0;  // single bounds check
    uint64_t acc = 0;
    acc ^= read_u32(pkt + T::ETH_DST_OFFSET);
    acc ^= read_u16(pkt + T::ETH_SRC_OFFSET + 4);
    acc ^= read_u32(pkt + T::IP_SRC_OFFSET);
    acc ^= read_u32(pkt + T::IP_DST_OFFSET);
    acc ^= read_u16(pkt + T::TCP_SRC_PORT_OFFSET);
    acc ^= read_u16(pkt + T::TCP_DST_PORT_OFFSET);
    acc ^= pkt[T::TCP_FLAGS_OFFSET];
    return acc;
}
```

The `constexpr` offsets are resolved at compile time. The compiler generates
the same sequence of `mov`/`movzx` instructions with literal offsets as the
Rust version.

**AVX-512 shuffle extraction** (future optimization):
```cpp
// Extract all key fields from a 42-byte UDP packet in 2 instructions
__m512i shuffle_mask = _mm512_loadu_si512(udp_field_shuffle_table);
__m512i pkt_data = _mm512_loadu_si512(pkt);
__m512i fields = _mm512_permutexvar_epi8(shuffle_mask, pkt_data);
```

### 4.7 Bounds-Check Behavior

**Rust:**

Rust inserts automatic bounds checks on slice indexing. LLVM eliminates
redundant checks (verified by assembly audit in the Rust implementation).
This provides safety-by-default with zero runtime cost for the common case.

**C++:**

C++ raw pointer arithmetic has no automatic bounds checks. This is both an
advantage and a risk:

| Aspect | Rust | C++ |
|---|---|---|
| Default safety | Bounds-checked slices | Raw pointers (unchecked) |
| Release performance | Zero-cost (LLVM eliminates redundant checks) | Zero-cost (no checks to eliminate) |
| Debug safety | Panics on out-of-bounds | Undefined behavior |
| Mitigation | Built-in | `-fsanitize=address,undefined` |

**Recommended approach for the C++ backport:**

- **Release builds:** Raw `uint8_t*` arithmetic. One manual bounds check
  per protocol layer (e.g., `if (len < 20) return -1;`). This matches the
  existing C implementation.

- **Debug builds:** Use `std::span` (C++20) for bounds-checked access:
  ```cpp
  #ifdef NDEBUG
  #define PKT_SPAN(ptr, len) (ptr)  // raw pointer in release
  #else
  #define PKT_SPAN(ptr, len) std::span(ptr, len)  // checked in debug
  #endif
  ```

- **CI builds:** Always run with `-fsanitize=address,undefined` to catch
  memory errors and UB.

---

## 5. Phased Implementation Plan

### Phase 1: Baseline Port (Weeks 1--3)

**Goal:** Establish the benchmark harness and virtual-dispatch baseline.

**Deliverables:**
- `bench/main.cpp` -- PCAP reader, timing framework, `perf_event_open`
  counters, CLI matching `xdp2-bench` flags
- `include/xdp2hp/protocol_traits.hpp` -- virtual `ParseNode` base class
- Protocol wrappers for the benchmark set: Ethernet, VLAN, QinQ, IPv4,
  IPv6, TCP, UDP, ICMP, ICMPv6, SCTP, ARP, AH, IPv6 EH, IPv6 Frag,
  IP-in-IP
- `src/parse_engine.cpp` -- generic graph-walk loop (mirrors
  `__xdp2_parse()`)
- Nix build integration: `nix/high-perf-bench.nix`

**Target:** ~180 ns/pkt (validates the harness against the C baseline)

**Verification:** Run on the same PCAP as the Rust benchmark. Success
counts must match exactly. ns/pkt should be within 10% of the C parser.

### Phase 2: Static Dispatch (Weeks 3--5)

**Goal:** Eliminate virtual dispatch using CRTP and templates.

**Deliverables:**
- `include/xdp2hp/protocols/*.hpp` -- CRTP protocol wrappers
- `include/xdp2hp/parse_engine.hpp` -- template-based `parse_packet()`
  with `switch` dispatch
- Compiler flags: `-O2 -march=native -flto=full`
- Benchmark comparison: virtual vs CRTP

**Target:** 5--10 ns/pkt (match Rust monomorphized)

**Verification:** Same success counts as Phase 1. Assembly inspection via
`objdump -d` to verify inlining and jump table generation.

### Phase 3: Compiler Codegen (Weeks 5--7)

**Goal:** Auto-generate optimized C++ parsers from Parser IR.

**Deliverables:**
- Extend `src/tools/compiler/` with a C++ output backend (template-based
  code generator)
- Generated `parse_*.hpp` files from `bench-graph.json`
- Benchmark: generated vs hand-written template code

**Target:** 2--3 ns/pkt (match Rust compiled)

**Verification:** Generated code produces identical parse results to the
template-based parser. IPC should reach ~4.0 on Zen 2.

### Phase 4: Multi-Core (Week 7--8)

**Goal:** Linear throughput scaling across CPU cores.

**Deliverables:**
- Multi-threaded benchmark using `std::jthread` (C++20) or `std::thread`
- Per-thread packet slices, no shared mutable state
- Thread-count sweep automation (1, 2, 4, 8, 12, 16, 24 threads)

**Target:** 1+ Gpps at 12--16 threads on the Threadripper 3945WX

**Anti-optimization note:** C++ has no `std::hint::black_box()` equivalent
in the standard library. Use `benchmark::DoNotOptimize()` from Google
Benchmark, or:
```cpp
template <typename T>
[[gnu::noinline]] void do_not_optimize(T& value) {
    asm volatile("" : "+r"(value) : : "memory");
}
```

### Phase 5: SIMD Batch (Weeks 8--10)

**Goal:** Process 8 packets in parallel using AVX2.

**Deliverables:**
- `include/xdp2hp/simd_batch.hpp` -- AVX2 batch parser
- Fast path: Eth -> IPv4 (IHL=5) -> TCP/UDP/ICMP
- Scalar fallback for divergent packets (VLAN, IPv6, variable IHL)
- Runtime AVX2 detection via `__builtin_cpu_supports("avx2")`

**Target:** 4 ns/pkt on scattered PCAP data (matching Rust SIMD)

**AVX-512 extension (optional):** If running on E810 or EPYC 9004:
- `vpgatherdd` with 512-bit vectors: 16 packets per batch
- `vpermb` for single-instruction field extraction

### Phase 6: Template Extraction (Weeks 10--11)

**Goal:** Fixed-offset extraction for NIC-classified packets.

**Deliverables:**
- `include/xdp2hp/template_extract.hpp` -- `constexpr` template definitions
  and specialized extractors for Tier 1 templates
- Benchmark mode: `--mode template`
- AVX-512 shuffle extraction prototype (if hardware available)

**Target:** 2--3 ns/pkt scalar, 1--2 ns/pkt AVX-512 batch

---

## 6. Performance Predictions

Both Rust and C++ use the same LLVM backend (when C++ is compiled with
Clang). The generated assembly should be nearly identical for equivalent
source patterns.

| Phase | C++ Predicted ns/pkt | Rust Actual ns/pkt | Confidence | Notes |
|---|---|---|---|---|
| Virtual dispatch | ~180 | 86 | High | C++ matches C baseline; Rust is faster due to partial devirtualization |
| CRTP / template | 5--10 | 5--10 | High | Same monomorphization mechanism |
| Compiler codegen | 2--3 | 2--3 | High | Same LLVM backend, same IR patterns |
| Multi-core (16T) | 1+ Gpps | 1.2 Gpps | Medium | OS scheduling and NUMA effects may differ |
| Template extraction | 2--3 | 3 | Medium-High | C++ may slightly beat Rust (no bounds-check to eliminate) |
| Template + AVX-512 | 1--2 | (projected) | Medium | Hardware-dependent; untested in Rust |

**Where C++ may be faster:**

1. **No bounds-check overhead at all.** Rust relies on LLVM to eliminate
   redundant checks. C++ never inserts them. In edge cases where LLVM
   cannot prove a check is redundant, C++ wins by default.

2. **Header-only templates.** C++ template definitions in headers are fully
   visible to the compiler without LTO. Rust requires `lto = "fat"` to
   achieve cross-crate inlining, which increases compile time.

3. **SIMD ergonomics.** No `unsafe` blocks, no `target_feature` annotations
   (use `__attribute__((target(...)))` instead). Less friction for writing
   and maintaining SIMD code.

**Where Rust may be faster:**

1. **`enum` return types.** Rust's `Result<(), ParseError>` compiles to
   efficient tagged unions. C++ uses integer return codes, which are
   equivalent but less type-safe.

2. **`#[inline]` + LTO synergy.** Rust's `#[inline]` is a stronger hint
   than C++ `inline`. Combined with fat LTO, rustc can make better
   inlining decisions across module boundaries.

3. **`black_box` is built-in.** C++ requires a custom `DoNotOptimize`
   helper (see Phase 4), which may behave differently across compilers.

---

## 7. Build System Integration

### CMake

```cmake
cmake_minimum_required(VERSION 3.20)
project(xdp2-high-perf CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Performance flags
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -march=native -flto=full -fno-exceptions -fno-rtti")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -fsanitize=address,undefined")

# Include existing XDP2 protocol headers
include_directories(${CMAKE_SOURCE_DIR}/../include)
include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(xdp2hp-bench
    bench/main.cpp
    src/parse_engine.cpp
)

target_link_libraries(xdp2hp-bench PRIVATE pcap)
```

### Nix Integration

New derivation in `nix/high-perf-bench.nix`:

```nix
{ pkgs, ... }:
pkgs.stdenv.mkDerivation {
  pname = "xdp2-high-perf-bench";
  src = ../src/high-perf;
  nativeBuildInputs = [ pkgs.cmake pkgs.clang_16 ];
  buildInputs = [ pkgs.libpcap ];
  cmakeFlags = [ "-DCMAKE_C_COMPILER=clang" "-DCMAKE_CXX_COMPILER=clang++" ];
}
```

### Compiler Requirements

| Feature | Minimum Version |
|---|---|
| C++20 concepts | GCC 12+ or Clang 15+ |
| `<immintrin.h>` (AVX2) | GCC 4.8+ or Clang 3.3+ |
| `-flto=full` | Clang 4+ (GCC: `-flto`) |
| `std::jthread` | GCC 10+ or Clang 11+ |
| `std::span` | GCC 10+ or Clang 7+ |

**Recommended:** Clang 16+ for best LLVM codegen parity with rustc.

---

## 8. Risk Analysis

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| C++ template error messages obscure real issues | Developer velocity | High | Use C++20 concepts for clear constraints; `static_assert` for compile-time checks |
| Memory bugs in SIMD code (no borrow checker) | Correctness | Medium | ASan/UBSan builds in CI; fuzzing with AFL++/libFuzzer |
| LTO behaves differently across GCC and Clang | Performance portability | Medium | Benchmark both compilers; standardize on Clang for parity with Rust |
| Code size explosion from template instantiation | Binary size, I-cache pressure | Low | Monitor with `size` command and I-cache miss counters; `[[gnu::noinline]]` on cold paths |
| Maintaining two implementations (Rust + C++) | Engineering cost | High | Share the Parser IR format; code-generate both from the same JSON source |
| `DoNotOptimize` behaves differently than `black_box` | Benchmark accuracy | Low | Validate with assembly inspection; test on both GCC and Clang |

---

## 9. Benchmark Methodology

### Apples-to-Apples Comparison

The C++ benchmark must produce directly comparable results to the Rust
benchmark:

1. **Same PCAPs.** Use the same test packet files.
2. **Same filtering.** Apply the same packet filter (only packets the
   parser can handle). Use the Rust benchmark's `--output-pcap` to
   generate the filtered PCAP.
3. **Same iteration counts.** Default 100 iterations with 3 warmup.
4. **Same perf counters.** Use `perf_event_open` directly (same syscall,
   same counter set: cycles, instructions, branches, branch-misses,
   cache-references, cache-misses).
5. **Same output format.** JSON `--report` mode with identical schema.

### Unified Comparison Script

A comparison script runs all three implementations (C, Rust, C++) on the
same PCAP and produces a unified table:

```bash
#!/usr/bin/env bash
PCAP="test/tcp_ipv4.pcap"

echo "=== C baseline ==="
./src/test/parser/xdp2-test --pcap "$PCAP" --core xdp2 --out null

echo "=== Rust (all modes) ==="
cargo run --release -p xdp2-bench -- --pcap "$PCAP" --perf --report

echo "=== C++ (all modes) ==="
./src/high-perf/build/xdp2hp-bench --pcap "$PCAP" --perf --report
```

### Anti-Cheating Measures

Matching the Rust benchmark's methodology:

- `DoNotOptimize` on loop accumulators to prevent DCE
- Success counts printed and verified against the Rust parser
- Warmup iterations (3 default) to warm icache/TLB/branch predictor
- Minimum 500 iterations for sub-10ns measurements (statistical stability)

---

## 10. Summary

The Rust optimization journey from 86 ns/pkt to 2--3 ns/pkt used
techniques that are all available in C++. The key mappings are:

```
Rust trait objects        →  C++ virtual functions (baseline)
Rust monomorphization     →  C++ templates + CRTP (static dispatch)
Rust #[inline] + fat LTO →  C++ always_inline + -flto=full
Rust xdp2-compiler        →  Extend existing C++ compiler
Rust std::arch SIMD       →  C++ <immintrin.h> (identical intrinsics)
Rust const templates      →  C++ constexpr templates
Rust black_box            →  C++ DoNotOptimize / asm volatile
```

C++ should achieve performance parity with Rust (both target LLVM) and may
have small advantages in SIMD ergonomics and inlining visibility. The
primary cost is losing Rust's memory safety guarantees, mitigated by
sanitizer builds and testing.

The phased approach (6 phases over ~11 weeks) allows incremental validation
at each step, with benchmark comparisons against both the original C code
and the Rust implementation.
