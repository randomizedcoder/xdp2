//! Experimental enum-dispatch parse engine.
//!
//! This module is an alternative to the default `dyn ParseNodeDyn`-based
//! engine. Instead of storing nodes as trait objects and dispatching through
//! a vtable, the engine is generic over a user-provided node enum `N` that
//! implements [`NodeOps`]. Each dispatch point becomes a `match` which the
//! compiler can inline.
//!
//! ## Motivation
//!
//! Profiling on `mixed-real.pcap` showed the dyn-dispatch graph engine
//! executes ~2028 instructions/pkt vs 242 for the monomorphic compiled
//! parser — a 6.9× overhead that comes almost entirely from the vtable
//! indirection (TMA data: both modes are retirement-bound, not stall-bound;
//! branch-miss and icache costs are negligible). See
//! `docs/performance-next-steps.md` § "Option A".
//!
//! ## Feature flag
//!
//! Gated behind `--features enum-dispatch` so the dyn-dispatch code path
//! remains the default and unchanged. Enabling the feature pulls in this
//! module without disturbing the existing engine.
//!
//! ## Usage
//!
//! 1. Define a node enum. Each variant wraps the node's concrete state
//!    (typically `&'static ParseNode<M, P>` or bespoke ops).
//! 2. Implement [`NodeOps<M>`] for the enum; each method `match`es on
//!    `self` and delegates.
//! 3. Build static [`ProtoTableEnum`] instances whose entries hold
//!    `&'static N`.
//! 4. Call [`parse_enum`] with the root node and packet bytes.
//!
//! See `xdp2-bench/src/graph_enum.rs` for a working example.

#![cfg(feature = "enum-dispatch")]

pub mod engine;
pub mod node;
pub mod table;

pub use engine::parse_enum;
pub use node::NodeOps;
pub use table::{ProtoTableEntryEnum, ProtoTableEnum};
