//! Tunnel protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/tunnel/`

pub mod geneve;
pub mod gre;
pub mod gtp;
pub mod ip_in_ip;
pub mod misc;
pub mod mpls;
pub mod nsh;
pub mod vxlan;
pub mod vxlan_gpe;

pub use geneve::{GeneveBaseOps, GeneveHeader, GeneveV0Ops};
pub use gre::{GreBaseOps, GreHeader, GreV0Ops};
pub use gtp::{GtpcHeader, GtpcOps, GtpuHeader, GtpuOps};
pub use ip_in_ip::IpInIpOps;
pub use misc::{
    CapwapHeader, CapwapOps, ErspanHeader, ErspanOps, GrePptpHeader, GrePptpOps, GueHeader,
    GueOps, HsrHeader, HsrOps, LispHeader, LispOps, LwappHeader, LwappOps, NvgreHeader,
    NvgreOps, PppHeader, PppOps, PppoeHeader, PppoeOps, SttHeader, SttOps, TeredoHeader,
    TeredoOps, TzspHeader, TzspOps,
};
pub use mpls::{MplsLabel, MplsOps};
pub use nsh::{NshHeader, NshOps};
pub use vxlan::{VxlanHeader, VxlanOps};
pub use vxlan_gpe::{VxlanGpeHeader, VxlanGpeOps};
