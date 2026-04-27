//! Storage protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/storage/`

pub mod fc;
pub mod fc_els;
pub mod fc_gs;
pub mod fcp;
pub mod iscsi_pdus;
pub mod misc;
pub mod nvme_rdma;
pub mod nvme_tcp;
pub mod sas;
pub mod srp;

pub use fc::{FcHeader, FcOps, FcoeOps, FCOE_HEADER_LEN};
pub use fc_els::{
    FcElsAdiscOps, FcElsFlogiOps, FcElsLogoOps, FcElsLsAccOps, FcElsLsRjtOps, FcElsPrliOps,
    FcElsRscnOps, FcElsScrOps,
};
pub use fc_gs::{FcCtOps, FcGpnFtRespOps, FcNsGidFtOps};
pub use fcp::{FcpCmndOps, FcpRespOps, FcpSrrOps, FcpTxrdyOps};
pub use iscsi_pdus::{
    IscsiAsyncOps, IscsiDataInOps, IscsiDataOutOps, IscsiLoginReqOps, IscsiLoginRspOps,
    IscsiLogoutReqOps, IscsiLogoutRspOps, IscsiNopInOps, IscsiNopOutOps, IscsiR2tOps,
    IscsiRejectOps, IscsiScsiReqOps, IscsiScsiRspOps, IscsiTextReqOps, IscsiTextRspOps,
    IscsiTmReqOps, IscsiTmRspOps,
};
pub use misc::{
    AoeHeader, AoeOps, EthercatHeader, EthercatOps, IscsiHeader, IscsiOps, IserHeader, IserOps,
    NvmeHeader, NvmeOps, ScsiHeader, ScsiOps,
};
pub use nvme_rdma::{NvmeRdmaCmRejOps, NvmeRdmaCmRepOps, NvmeRdmaCmReqOps};
pub use nvme_tcp::{NvmeTcpIcreqOps, NvmeTcpIcrespOps, NvmeTcpOps, NvmeTcpR2tOps, NvmeTcpRspOps};
pub use sas::{AtaD2hFisOps, AtaH2dFisOps, SasIdentifyOps, SspCommandOps, SspFrameOps};
pub use srp::{
    SrpCmdOps, SrpILogoutOps, SrpLoginReqOps, SrpLoginRspOps, SrpRspOps, SrpTLogoutOps,
    SrpTskMgmtOps,
};
