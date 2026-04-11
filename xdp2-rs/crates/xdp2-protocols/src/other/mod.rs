//! Other/miscellaneous protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/other/`

pub mod misc;

pub use misc::{
    ErfHeader, ErfOps, MpegTsHeader, MpegTsOps, SrtHeader, SrtOps, TplinkSmarthomeHeader,
    TplinkSmarthomeOps,
};
