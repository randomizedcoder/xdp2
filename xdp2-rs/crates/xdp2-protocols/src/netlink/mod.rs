//! Netlink protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/netlink/`

pub mod diag;
pub mod misc;
pub mod netlink;
pub mod nl_variants;

pub use diag::{
    GenNetlinkOps, NlAttrOps, NlDiagBbrInfoOps, NlDiagDctcpInfoOps, NlDiagMemInfoOps,
    NlDiagSkMemInfoOps, NlDiagTcpInfoOps, NlDiagVegasInfoOps,
};
pub use misc::{GenlmsghdrHeader, GenlmsghdrOps, NlattrHeader, NlattrOps};
pub use netlink::{NetlinkHeader, NetlinkOps};
pub use nl_variants::{
    NlAddrOps, NlBridgePortOps, NlDcbOps, NlDiagInetOps, NlDiagNetlinkOps, NlDiagPragueInfoOps,
    NlDiagReqV2Ops, NlDiagSockIdOps, NlDiagUnixOps, NlIfStatsOps, NlLinkOps, NlNeighOps,
    NlNetfilterOps, NlNexthopOps, NlPrefixOps, NlRouteOps, NlRuleOps, NlTcOps, NlXfrmPolicyOps,
    NlXfrmSaOps,
};
