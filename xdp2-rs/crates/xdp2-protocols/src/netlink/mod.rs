//! Netlink protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/netlink/`

pub mod misc;
pub mod netlink;

pub use misc::{GenlmsghdrHeader, GenlmsghdrOps, NlattrHeader, NlattrOps};
pub use netlink::{NetlinkHeader, NetlinkOps};
