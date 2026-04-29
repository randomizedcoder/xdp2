//! CAN bus protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/can/`

pub mod can_variants;
pub mod canxl;
pub mod misc;

pub use can_variants::{CanJ1939Ops, CanObd2Ops, CanTpOps};
pub use canxl::{CanXlHeader, CanXlOps};
pub use misc::{CanFdFrame, CanFdOps, CanFrame, CanOps};
