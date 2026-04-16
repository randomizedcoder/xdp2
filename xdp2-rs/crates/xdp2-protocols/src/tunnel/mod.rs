//! Tunnel protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/tunnel/`

pub mod capwap;
pub mod erspan;
pub mod geneve;
pub mod gre;
pub mod gre_pptp;
pub mod gtp;
pub mod gue;
pub mod hsr;
pub mod ip_in_ip;
pub mod lisp;
pub mod lwapp;
pub mod mpls;
pub mod nsh;
pub mod nvgre;
pub mod ppp;
pub mod pppoe;
pub mod stt;
pub mod teredo;
pub mod tzsp;
pub mod vxlan;
pub mod vxlan_gpe;

pub use capwap::{CapwapHeader, CapwapOps};
pub use erspan::{ErspanHeader, ErspanOps};
pub use geneve::{GeneveBaseOps, GeneveHeader, GeneveV0Ops};
pub use gre::{GreBaseOps, GreHeader, GreV0Ops};
pub use gre_pptp::{GrePptpHeader, GrePptpOps};
pub use gtp::{GtpcHeader, GtpcOps, GtpuHeader, GtpuOps};
pub use gue::{GueHeader, GueOps};
pub use hsr::{HsrHeader, HsrOps};
pub use ip_in_ip::IpInIpOps;
pub use lisp::{LispHeader, LispOps};
pub use lwapp::{LwappHeader, LwappOps};
pub use mpls::{MplsLabel, MplsOps};
pub use nsh::{NshHeader, NshOps};
pub use nvgre::{NvgreHeader, NvgreOps};
pub use ppp::{PppHeader, PppOps};
pub use pppoe::{PppoeHeader, PppoeOps};
pub use stt::{SttHeader, SttOps};
pub use teredo::{TeredoHeader, TeredoOps};
pub use tzsp::{TzspHeader, TzspOps};
pub use vxlan::{VxlanHeader, VxlanOps};
pub use vxlan_gpe::{VxlanGpeHeader, VxlanGpeOps};
