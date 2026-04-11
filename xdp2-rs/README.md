# XDP2-RS: Rust Reimplementation of XDP2

This is the Rust reimplementation of the [XDP2](../README.md) packet parsing
framework. XDP2 is a high-performance, declarative packet parser built around
a **parse graph** abstraction -- a directed graph of protocol nodes that
replaces hand-written if/else chains with a composable, compiler-optimizable
data structure.

## Reference Documentation

The complete technical specification of XDP2 is documented as an 11-lecture
series designed for 3rd-year CS students:

**[XDP2 Technical Lectures](../documentation/xdp2-lectures.md)**

| Lecture | Topic |
|---------|-------|
| 0 | Orientation and Motivation |
| 1 | Protocol Definitions (`xdp2_proto_def`, `ops.len`, `ops.next_proto`) |
| 2 | Parse Nodes, Protocol Tables, and Parsers (macro API) |
| 3 | The Runtime Parsing Engine (`__xdp2_parse()` main loop) |
| 4 | Metadata and Advanced Node Types (TLVs, flag-fields, arrays) |
| 5 | The Optimizing Compiler (Clang AST → Boost Graph → codegen) |
| 6 | The XDP/eBPF Target (tail-call architecture, verifier constraints) |
| 7 | Worked Examples (byte-by-byte packet traces) |
| 8 | Testing and Clean-Room Reimplementation Guide |
| 9 | Porting the Runtime -- C to Rust |
| 10 | Porting the Compiler and XDP Target -- C++ to Rust |

Lectures 8-10 are the primary design references for this Rust reimplementation.

## Implementation Plan

See **[detailed-implementation-plan.md](./detailed-implementation-plan.md)** for
the full phased implementation strategy, C-to-Rust mapping tables, verification
approach, and Nix integration.

## Architecture

This is a Cargo workspace with three crates:

```
xdp2-rs/
├── crates/
│   ├── xdp2-core/          # Parse engine: types, traits, main loop, TLV/flag/array
│   ├── xdp2-protocols/     # Protocol definitions (Ethernet, IPv4, TCP, etc.)
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
