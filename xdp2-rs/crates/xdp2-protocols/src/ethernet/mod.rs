//! Ethernet protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/ethernet/`

pub mod edsa;
pub mod ether;
pub mod llc;
pub mod pbb;
pub mod ppoed;
pub mod qinq;
pub mod sll;
pub mod vlan;

pub use edsa::{EdsaHeader, EdsaOps};
pub use ether::{EthernetHeader, EthernetOps};
pub use llc::{LlcHeader, LlcOps, LlcSnapHeader, LlcSnapOps};
pub use pbb::{PbbHeader, PbbOps};
pub use ppoed::{PpoedHeader, PpoedOps};
pub use qinq::QinQOps;
pub use sll::{Sll2Header, Sll2Ops, SllHeader, SllOps};
pub use vlan::{VlanHeader, VlanOps};
