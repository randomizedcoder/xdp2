//! # xdp2-protocols — XDP2 Protocol Definitions
//!
//! Protocol definitions for the XDP2 parse graph framework. Each protocol
//! implements the [`xdp2_core::ProtocolOps`] trait, providing header length
//! calculation and next-protocol extraction.
//!
//! ## C/C++ Cross-Reference
//!
//! | Crate Module | C/C++ Source Directory |
//! |-------------|----------------------|
//! | `ethernet` | `src/include/xdp2/proto_defs/ethernet/` |
//! | `ip` | `src/include/xdp2/proto_defs/ip/` |
//! | `transport` | `src/include/xdp2/proto_defs/transport/` |
//!
//! ## Protocol Coverage
//!
//! Phase 2 implements the core protocol path: Ethernet → IPv4 → TCP/UDP.
//! Additional protocols (IPv6, GRE, VXLAN, etc.) will be added incrementally.

pub mod bluetooth;
pub mod can;
pub mod ethernet;
pub mod infiniband;
pub mod ip;
pub mod legacy;
pub mod management;
pub mod netlink;
pub mod other;
pub mod security;
pub mod storage;
pub mod trading;
pub mod transport;
pub mod tunnel;
pub mod wireless;
