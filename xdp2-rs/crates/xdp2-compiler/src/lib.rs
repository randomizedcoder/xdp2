//! # xdp2-compiler — XDP2 Optimizing Compiler (Phase 4)
//!
//! This crate will reimplement the XDP2 optimizing compiler in Rust, replacing
//! the C++ implementation in `src/tools/compiler/`.
//!
//! ## Planned Architecture
//!
//! ```text
//! JSON IR (from C++ compiler)  ──→  Graph Construction (petgraph)
//!                                         │
//!                                    ┌────┴────┐
//!                                    │         │
//!                              C Backend    XDP Backend
//!                            (Tera templates)
//! ```
//!
//! ## C/C++ Cross-Reference
//!
//! | Planned Module | C/C++ Source | Purpose |
//! |---------------|-------------|---------|
//! | `graph` | `src/tools/compiler/include/xdp2gen/graph.h` | Graph construction (Boost → petgraph) |
//! | `ir` | `documentation/parser-ir.md` | JSON IR consumption |
//! | `codegen::c_target` | `src/templates/xdp2/c_def.template.c` | Optimized C output |
//! | `codegen::xdp_target` | `src/templates/xdp2/xdp_def.template.c` | XDP/eBPF output |
//!
//! ## Status
//!
//! This crate is a placeholder. Implementation will begin in Phase 4 after
//! the core parser engine and protocol definitions are complete and verified.
//!
//! See `xdp2-rs/detailed-implementation-plan.md` §6 for the full plan.

// Phase 4 placeholder — no implementation yet.
// Crate compiles cleanly so the workspace builds.
