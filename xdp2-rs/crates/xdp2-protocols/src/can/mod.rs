//! CAN bus protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/can/`

pub mod canxl;
pub mod misc;

pub use canxl::{CanXlHeader, CanXlOps};
pub use misc::{CanFdFrame, CanFdOps, CanFrame, CanOps};
