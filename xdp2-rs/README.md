# XDP2-RS: Rust Reimplementation of XDP2

This is the Rust reimplementation of the [XDP2](../README.md) packet parsing
framework. XDP2 is a high-performance, declarative packet parser built around
a **parse graph** abstraction -- a directed graph of protocol nodes that
replaces hand-written if/else chains with a composable, compiler-optimizable
data structure.

## Reference Documentation

The complete technical specification of XDP2 is documented as a 12-lecture
series designed for 3rd-year CS students:

**[XDP2 Technical Lectures](../documentation/lectures/)**

| Lecture | Topic |
|---------|-------|
| [0](../documentation/lectures/lecture00-xdp2-overview.md) | Orientation and Motivation |
| [1](../documentation/lectures/lecture01-protocol-definitions.md) | Protocol Definitions -- The Vocabulary of Parsing |
| [2](../documentation/lectures/lecture02-parse-graph.md) | Parse Nodes, Protocol Tables, and Parsers -- Building the Graph |
| [3](../documentation/lectures/lecture03-runtime-engine.md) | The Runtime Parsing Engine -- Walking the Graph |
| [4](../documentation/lectures/lecture04-metadata-extraction.md) | Metadata Extraction and Advanced Node Types |
| [5](../documentation/lectures/lecture05-compiler.md) | The Optimizing Compiler -- From Graph to Linear Code |
| [6](../documentation/lectures/lecture06-xdp-ebpf.md) | The XDP/eBPF Target -- Kernel-Space Parsing |
| [7](../documentation/lectures/lecture07-worked-examples.md) | Worked Examples -- Packets Walking the Parse Graph |
| [8](../documentation/lectures/lecture08-testing.md) | Testing and Clean-Room Reimplementation Guide |
| [9](../documentation/lectures/lecture09-rust-runtime.md) | Porting the Runtime -- C to Rust |
| [10](../documentation/lectures/lecture10-rust-compiler.md) | Porting the Compiler and XDP Target -- C++ to Rust |
| [11](../documentation/lectures/lecture11-performance.md) | High-Performance Parsing -- From 158 ns/pkt to 2 ns/pkt |

Lectures 8-11 are the primary design references for this Rust reimplementation.

## Documentation

| Document | Description |
|----------|-------------|
| [detailed-implementation-plan.md](./detailed-implementation-plan.md) | Phased implementation strategy, C-to-Rust mapping tables, Nix integration |
| [docs/adding-protocol-support.md](./docs/adding-protocol-support.md) | How to add a new protocol across all four parser variants |
| [docs/deep-performance-analysis.md](./docs/deep-performance-analysis.md) | CPU profiling data, optimization taxonomy, HFT design pattern cross-reference |
| [docs/performance-optimization.md](./docs/performance-optimization.md) | Trait object dispatch overhead and optimization techniques |
| [docs/performance-by-platform.md](./docs/performance-by-platform.md) | Cross-platform benchmark results |
| [docs/performance-maximization-plan.md](./docs/performance-maximization-plan.md) | Optimization roadmap from graph engine baseline (158 ns/pkt) |
| [Lecture 11](../documentation/lectures/lecture11-performance.md) | Measurement-driven optimization walkthrough (95 ns/pkt to 3 ns/pkt) |
| [docs/hardware-classified-extraction.md](./docs/hardware-classified-extraction.md) | NIC hardware classification and fixed-offset template extraction |
| [docs/af-xdp-integration-plan.md](./docs/af-xdp-integration-plan.md) | AF_XDP integration for line-rate NIC parsing via shared memory |
| [docs/cpp-backport-plan.md](./docs/cpp-backport-plan.md) | Plan to backport Rust performance gains to C++ |

## Performance (2026-04-15)

Feature-parity with C flow_dissector: 28 ethertypes, 14 IPv4 protocols,
17 IPv6 protocols, 31 metadata extractors, GRE flag-field sub-parsing,
VXLAN/Geneve tunnel decapsulation, LLC/SNAP, FCoE, L2TP.

**All parser modes (445K mixed-protocol packets, full parse + metadata, AMD Ryzen Threadripper 3945WX):**

| Engine | ns/pkt | Mpps | What it measures |
|--------|--------|------|------------------|
| C (xdp2-compiler, `-O2 -march=native`) | 174 | 6 | Full parse + metadata |
| Rust graph (`&dyn` dispatch + ProtoTable) | 149 | 7 | Full parse + FlowMeta |
| Rust mono (monomorphized) | 36 | 28 | Same work, no vtable dispatch |
| Rust compiled (inline byte reads) | 33 | 29 | Same work, no trait overhead |
| Rust simd (AVX2 batch classify) | 38 | 26 | Same work, SIMD classification |
| Rust template (classify + extract + fallback) | 39 | 25 | 29% template, 71% compiled fallback |
| Rust template-simd (batch + fallback) | 44 | 22 | Same as template, batch processing |

All modes produce identical `FlowMeta` output (31 metadata fields: MACs, IPs,
ports, VLAN, GRE, fragments, etc.). The `&dyn` dispatch + ProtoTable overhead
costs ~4.5x (149 vs 33 ns).

### Protocol coverage and template extraction

All parser modes (graph, mono, compiled) support identical protocol coverage.
The template mode adds 63 fixed-offset extraction templates covering:
plain, VLAN (802.1Q), QinQ (802.1ad), GRE, double-GRE, VLAN+GRE, QinQ+GRE,
IP-in-IP, VLAN+IP-in-IP, and QinQ+IP-in-IP header stacks.

Packets with variable-length headers (IPv6 extension headers, MPLS, L2TP, ESP/AH)
cannot use templates and fall back to the compiled parser automatically. On this
PCAP (extremely diverse, 1371 unique protocol stacks), 29% of packets match
templates and 71% fall back. On typical production traffic (predominantly
TCP/UDP), template match rates would be 80-95%.

See [docs/deep-performance-analysis.md](./docs/deep-performance-analysis.md) for
CPU profiling data, optimization taxonomy, and HFT design pattern cross-reference.

## Architecture

This is a Cargo workspace with three crates:

```
xdp2-rs/
├── crates/
│   ├── xdp2-core/          # Parse engine: types, traits, main loop, TLV/flag/array
│   ├── xdp2-protocols/     # 205 protocol definitions (Ethernet, IPv4, TCP, GRE, etc.)
│   ├── xdp2-bench/         # Benchmark harness (7 parser modes, perf counters)
│   └── xdp2-compiler/      # Optimizing compiler (Phase 4, stub for now)
├── Cargo.toml              # Workspace root
└── README.md
```

- **xdp2-core** reimplements `src/lib/xdp2/parser.c` and the core types from
  `src/include/xdp2/parser_types.h`
- **xdp2-protocols** reimplements the 205 protocol definitions from
  `src/include/xdp2/proto_defs/`
- **xdp2-compiler** will reimplement `src/tools/compiler/` using `petgraph`
  and `tera` (Phase 4)

## Cross-Reference Convention

Every Rust source file documents which C/C++ files it reimplements. Module-level
doc comments include a mapping table; function-level comments include inline
references. Example:

```rust
/// Reimplements: `lookup_node()` in `src/lib/xdp2/parser.c:38-48`
///
/// Differences from C:
/// - Returns `Option<&ParseNode>` instead of `struct xdp2_parse_node *` (NULL → None)
pub fn lookup_node<M>(proto: i32, table: &ProtoTable<M>) -> Option<&ParseNode<M>> {
    // ...
}
```

## Quick Start

### Using Nix (recommended)

```bash
# Build
nix build .#xdp2-rs

# Run all checks
nix build .#xdp2-rs-check       # cargo check
nix build .#xdp2-rs-test        # cargo test
nix build .#xdp2-rs-clippy      # cargo clippy -D warnings
nix build .#xdp2-rs-fmt-check   # cargo fmt --check
nix build .#xdp2-rs-doc         # cargo doc
nix build .#xdp2-rs-golden      # compare output vs C parser
```

### Local development

```bash
cd xdp2-rs
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## License

BSD-2-Clause-FreeBSD, matching the XDP2 C codebase.
