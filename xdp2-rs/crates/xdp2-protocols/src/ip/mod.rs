//! IP protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/ip/`

pub mod ipv4;
pub mod ipv6;

pub use ipv4::{Ipv4CheckOps, Ipv4Header, Ipv4Ops};
pub use ipv6::{Ipv6CheckOps, Ipv6Header, Ipv6Ops, Ipv6StopFlowLabelOps};
