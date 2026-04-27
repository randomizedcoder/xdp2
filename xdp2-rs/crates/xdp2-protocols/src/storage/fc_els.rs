//! Fibre Channel Extended Link Services (FC-ELS).
//!
//! All ELS frames are leaf protocols — they are terminal within the FC frame.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// FC-ELS LS_ACC (4 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FcElsLsAccHeader {
    pub la_cmd: u8,
    pub la_resv: [u8; 3],
}

pub struct FcElsLsAccOps;

impl ProtocolOps for FcElsLsAccOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "FC_ELS_LS_ACC";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// FC-ELS LS_RJT (8 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FcElsLsRjtHeader {
    pub er_cmd: u8,
    pub er_resv: [u8; 4],
    pub er_reason: u8,
    pub er_explan: u8,
    pub er_vendor: u8,
}

pub struct FcElsLsRjtOps;

impl ProtocolOps for FcElsLsRjtOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "FC_ELS_LS_RJT";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// FC-ELS FLOGI (116 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FcElsFlogiHeader {
    pub fl_cmd: u8,
    pub _fl_resvd: [u8; 3],
    pub sp_hi_ver: u8,
    pub sp_lo_ver: u8,
    pub sp_bb_cred: [u8; 2],
    pub sp_features: [u8; 2],
    pub sp_bb_data: [u8; 2],
    pub sp_u: [u8; 4],
    pub sp_e_d_tov: [u8; 4],
    pub fl_wwpn: [u8; 8],
    pub fl_wwnn: [u8; 8],
    pub fl_cssp: [u8; 64],
    pub fl_vend: [u8; 16],
}

pub struct FcElsFlogiOps;

impl ProtocolOps for FcElsFlogiOps {
    const MIN_LEN: usize = 116;
    const NAME: &'static str = "FC_ELS_FLOGI";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// FC-ELS LOGO (12 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FcElsLogoHeader {
    pub fl_cmd: u8,
    pub fl_zero: [u8; 3],
    pub fl_resvd: u8,
    pub fl_n_port_id: [u8; 3],
}

pub struct FcElsLogoOps;

impl ProtocolOps for FcElsLogoOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "FC_ELS_LOGO";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// FC-ELS PRLI (4 bytes common header).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FcElsPrliHeader {
    pub prli_cmd: u8,
    pub prli_spp_len: u8,
    pub prli_len: [u8; 2],
}

pub struct FcElsPrliOps;

impl ProtocolOps for FcElsPrliOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "FC_ELS_PRLI";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// FC-ELS ADISC (28 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FcElsAdiscHeader {
    pub adisc_cmd: u8,
    pub adisc_resv: [u8; 3],
    pub adisc_resv1: u8,
    pub adisc_hard_addr: [u8; 3],
    pub adisc_wwpn: [u8; 8],
    pub adisc_wwnn: [u8; 8],
    pub adisc_resv2: u8,
    pub adisc_port_id: [u8; 3],
}

pub struct FcElsAdiscOps;

impl ProtocolOps for FcElsAdiscOps {
    const MIN_LEN: usize = 28;
    const NAME: &'static str = "FC_ELS_ADISC";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// FC-ELS RSCN (4 bytes common header).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FcElsRscnHeader {
    pub rscn_cmd: u8,
    pub rscn_page_len: u8,
    pub rscn_plen: [u8; 2],
}

pub struct FcElsRscnOps;

impl ProtocolOps for FcElsRscnOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "FC_ELS_RSCN";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// FC-ELS SCR (8 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FcElsScrHeader {
    pub scr_cmd: u8,
    pub scr_resv: [u8; 6],
    pub scr_reg_func: u8,
}

pub struct FcElsScrOps;

impl ProtocolOps for FcElsScrOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "FC_ELS_SCR";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fc_els_all_are_leaves() {
        assert!(FcElsLsAccOps.next_proto(&[0u8; 4]).is_err());
        assert!(FcElsLsRjtOps.next_proto(&[0u8; 8]).is_err());
        assert!(FcElsFlogiOps.next_proto(&[0u8; 116]).is_err());
        assert!(FcElsLogoOps.next_proto(&[0u8; 12]).is_err());
        assert!(FcElsPrliOps.next_proto(&[0u8; 4]).is_err());
        assert!(FcElsAdiscOps.next_proto(&[0u8; 28]).is_err());
        assert!(FcElsRscnOps.next_proto(&[0u8; 4]).is_err());
        assert!(FcElsScrOps.next_proto(&[0u8; 8]).is_err());
    }
}
