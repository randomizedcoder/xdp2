//! SCSI RDMA Protocol (SRP) — InfiniBand-based SCSI transport.
//! All SRP IUs are leaf protocols.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// SRP Login Request (64 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SrpLoginReqHeader {
    pub opcode: u8,
    pub reserved1: [u8; 7],
    pub tag: [u8; 8],
    pub req_it_iu_len: [u8; 4],
    pub reserved2: [u8; 4],
    pub req_buf_fmt: [u8; 2],
    pub req_flags: u8,
    pub reserved3: u8,
    pub imm_data_offset: [u8; 2],
    pub reserved4: [u8; 2],
    pub initiator_port_id: [u8; 16],
    pub target_port_id: [u8; 16],
}

pub struct SrpLoginReqOps;

impl ProtocolOps for SrpLoginReqOps {
    const MIN_LEN: usize = 64;
    const NAME: &'static str = "SRP_LOGIN_REQ";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// SRP Login Response (52 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SrpLoginRspHeader {
    pub opcode: u8,
    pub reserved1: [u8; 3],
    pub req_lim_delta: [u8; 4],
    pub tag: [u8; 8],
    pub max_it_iu_len: [u8; 4],
    pub max_ti_iu_len: [u8; 4],
    pub buf_fmt: [u8; 2],
    pub rsp_flags: u8,
    pub reserved2: [u8; 25],
}

pub struct SrpLoginRspOps;

impl ProtocolOps for SrpLoginRspOps {
    const MIN_LEN: usize = 52;
    const NAME: &'static str = "SRP_LOGIN_RSP";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// SRP Command (48 bytes base).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SrpCmdHeader {
    pub opcode: u8,
    pub sol_not: u8,
    pub reserved1: [u8; 3],
    pub buf_fmt: u8,
    pub data_out_desc_cnt: u8,
    pub data_in_desc_cnt: u8,
    pub tag: [u8; 8],
    pub reserved2: [u8; 4],
    pub lun: [u8; 8],
    pub reserved3: u8,
    pub task_attr: u8,
    pub reserved4: u8,
    pub add_cdb_len: u8,
    pub cdb: [u8; 16],
}

pub struct SrpCmdOps;

impl ProtocolOps for SrpCmdOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "SRP_CMD";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// SRP Response (36 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SrpRspHeader {
    pub opcode: u8,
    pub sol_not: u8,
    pub reserved1: [u8; 2],
    pub req_lim_delta: [u8; 4],
    pub tag: [u8; 8],
    pub reserved2: [u8; 2],
    pub flags: u8,
    pub status: u8,
    pub data_out_res_cnt: [u8; 4],
    pub data_in_res_cnt: [u8; 4],
    pub sense_data_len: [u8; 4],
    pub resp_data_len: [u8; 4],
}

pub struct SrpRspOps;

impl ProtocolOps for SrpRspOps {
    const MIN_LEN: usize = 36;
    const NAME: &'static str = "SRP_RSP";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// SRP Task Management (48 bytes).
pub struct SrpTskMgmtOps;

impl ProtocolOps for SrpTskMgmtOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "SRP_TSK_MGMT";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// SRP Initiator Logout (16 bytes).
pub struct SrpILogoutOps;

impl ProtocolOps for SrpILogoutOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "SRP_I_LOGOUT";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// SRP Target Logout (16 bytes).
pub struct SrpTLogoutOps;

impl ProtocolOps for SrpTLogoutOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "SRP_T_LOGOUT";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srp_all_are_leaves() {
        assert!(SrpLoginReqOps.next_proto(&[0u8; 64]).is_err());
        assert!(SrpLoginRspOps.next_proto(&[0u8; 52]).is_err());
        assert!(SrpCmdOps.next_proto(&[0u8; 48]).is_err());
        assert!(SrpRspOps.next_proto(&[0u8; 36]).is_err());
        assert!(SrpTskMgmtOps.next_proto(&[0u8; 48]).is_err());
        assert!(SrpILogoutOps.next_proto(&[0u8; 16]).is_err());
        assert!(SrpTLogoutOps.next_proto(&[0u8; 16]).is_err());
    }
}
