//! Netlink protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/netlink/`

pub mod netlink;
pub mod misc;

pub use netlink::{NetlinkHeader, NetlinkOps};
pub use misc::{GenlmsghdrHeader, GenlmsghdrOps, NlattrHeader, NlattrOps};
