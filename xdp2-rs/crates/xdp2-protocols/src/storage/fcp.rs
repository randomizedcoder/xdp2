//! Fibre Channel Protocol for SCSI (FCP) — command, data, response, SRR.
//! All FCP IUs are leaf protocols within FC frames.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// FCP Command IU (32 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FcpCmndHeader {
    pub fc_lun: [u8; 8],
    pub fc_cmdref: u8,
    pub fc_pri_ta: u8,
    pub fc_tm_flags: u8,
    pub fc_flags: u8,
    pub fc_cdb: [u8; 16],
    pub fc_dl: [u8; 4],
}

pub struct FcpCmndOps;

impl ProtocolOps for FcpCmndOps {
    const MIN_LEN: usize = 32;
    const NAME: &'static str = "FCP_CMND";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// FCP Transfer Ready (12 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FcpTxrdyHeader {
    pub ft_data_ro: [u8; 4],
    pub ft_burst_len: [u8; 4],
    pub _ft_resvd: [u8; 4],
}

pub struct FcpTxrdyOps;

impl ProtocolOps for FcpTxrdyOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "FCP_TXRDY";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// FCP Response (12 bytes base).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FcpRespHeader {
    pub _fr_resvd: [u8; 8],
    pub fr_retry_delay: [u8; 2],
    pub fr_flags: u8,
    pub fr_status: u8,
}

pub struct FcpRespOps;

impl ProtocolOps for FcpRespOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "FCP_RSP";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// FCP SRR (16 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FcpSrrHeader {
    pub srr_op: u8,
    pub srr_resvd: [u8; 3],
    pub srr_ox_id: [u8; 2],
    pub srr_rx_id: [u8; 2],
    pub srr_rel_off: [u8; 4],
    pub srr_r_ctl: u8,
    pub srr_resvd2: [u8; 3],
}

pub struct FcpSrrOps;

impl ProtocolOps for FcpSrrOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "FCP_SRR";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fcp_all_are_leaves() {
        assert!(FcpCmndOps.next_proto(&[0u8; 32]).is_err());
        assert!(FcpTxrdyOps.next_proto(&[0u8; 12]).is_err());
        assert!(FcpRespOps.next_proto(&[0u8; 12]).is_err());
        assert!(FcpSrrOps.next_proto(&[0u8; 16]).is_err());
    }
}
