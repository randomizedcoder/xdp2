//! Fibre Channel Generic Services (FC-GS) — CT header + Name Server queries.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// FC-GS Common Transport header (16 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FcCtHeader {
    pub ct_rev: u8,
    pub ct_in_id: [u8; 3],
    pub ct_fs_type: u8,
    pub ct_fs_subtype: u8,
    pub ct_options: u8,
    pub _ct_resvd1: u8,
    pub ct_cmd: [u8; 2],
    pub ct_mr_size: [u8; 2],
    pub _ct_resvd2: u8,
    pub ct_reason: u8,
    pub ct_explan: u8,
    pub ct_vendor: u8,
}

pub struct FcCtOps;

impl ProtocolOps for FcCtOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "FC_CT";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// FC Name Server GID_FT request (4 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FcNsGidFtHeader {
    pub fn_resvd: u8,
    pub fn_domain_id_scope: u8,
    pub fn_area_id_scope: u8,
    pub fn_fc4_type: u8,
}

pub struct FcNsGidFtOps;

impl ProtocolOps for FcNsGidFtOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "FC_NS_GID_FT";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// FC Name Server GPN_FT response entry (16 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FcGpnFtRespHeader {
    pub fp_flags: u8,
    pub fp_fid: [u8; 3],
    pub fp_resvd: [u8; 4],
    pub fp_wwpn: [u8; 8],
}

pub struct FcGpnFtRespOps;

impl ProtocolOps for FcGpnFtRespOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "FC_GPN_FT_Resp";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fc_gs_all_are_leaves() {
        assert!(FcCtOps.next_proto(&[0u8; 16]).is_err());
        assert!(FcNsGidFtOps.next_proto(&[0u8; 4]).is_err());
        assert!(FcGpnFtRespOps.next_proto(&[0u8; 16]).is_err());
    }
}
