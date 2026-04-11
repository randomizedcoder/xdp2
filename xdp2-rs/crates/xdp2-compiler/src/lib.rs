//! # xdp2-compiler — XDP2 Optimizing Compiler
//!
//! Reimplements the C++ XDP2 compiler (`src/tools/compiler/`) in Rust.
//! Reads Parser IR (JSON), builds a protocol parse graph, and generates
//! optimized C or XDP/eBPF code.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Module | C/C++ Source | Purpose |
//! |------------|-------------|---------|
//! | `ir` | `documentation/parser-ir.md` | JSON IR types (serde) |
//! | `graph` | `include/xdp2gen/graph.h` | Graph types + algorithms (petgraph) |
//! | `codegen` | `src/templates/xdp2/` | Code generation (Tera templates) |
//! | `dot` | `graph.h:dotify()` | Graphviz .dot output |
//!
//! ## Architecture
//!
//! ```text
//! JSON IR ──→ ir::ParserIr (serde)
//!                  │
//!                  ▼
//!          graph::ParseGraph (petgraph)
//!                  │
//!            ┌─────┴─────┐
//!            ▼           ▼
//!     codegen::c    codegen::xdp
//!     (Tera)        (Tera)
//! ```

pub mod ir;
pub mod graph;
pub mod dot;
pub mod codegen;
