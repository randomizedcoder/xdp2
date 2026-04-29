//! Legacy protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/legacy/`

pub mod batman;
pub mod misc;
pub mod x25;

pub use batman::{BatmanHeader, BatmanOps};
pub use misc::{
    AppletalkHeader, AppletalkOps, AtmHeader, AtmOps, DsaHeader, DsaOps, FddiHeader, FddiOps,
    Ieee802154Header, Ieee802154Ops, IpxHeader, IpxOps, MctpHeader, MctpOps, PhonetHeader,
    PhonetOps, ProtobufHeader, ProtobufOps, X25Header, X25Ops,
};
pub use x25::X25Ops as X25SilverOps;
