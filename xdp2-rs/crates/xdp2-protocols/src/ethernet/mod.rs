//! Ethernet protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/ethernet/`

pub mod ether;
pub mod vlan;

pub use ether::{EthernetHeader, EthernetOps};
pub use vlan::{VlanHeader, VlanOps};
