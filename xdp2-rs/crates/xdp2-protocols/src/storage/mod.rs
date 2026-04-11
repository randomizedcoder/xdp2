//! Storage protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/storage/`

pub mod fc;
pub mod misc;

pub use fc::{FcHeader, FcOps};
pub use misc::{
    AoeHeader, AoeOps, EthercatHeader, EthercatOps, IscsiHeader, IscsiOps, IserHeader, IserOps,
    NvmeHeader, NvmeOps, ScsiHeader, ScsiOps,
};
