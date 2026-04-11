//! Legacy protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/legacy/`

pub mod batman;
pub mod misc;

pub use batman::{BatmanHeader, BatmanOps};
pub use misc::{
    AppletalkHeader, AppletalkOps, AtmHeader, AtmOps, DsaHeader, DsaOps, Ieee802154Header,
    Ieee802154Ops, MctpHeader, MctpOps, PhonetHeader, PhonetOps, ProtobufHeader, ProtobufOps,
    X25Header, X25Ops,
};
