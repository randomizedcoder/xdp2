//! iSCSI Protocol Data Units (RFC 7143).
//!
//! All iSCSI PDUs have a 48-byte Basic Header Segment (BHS).
//! The opcode field (byte 0, bits 5:0) identifies the PDU type.
//! All PDU types are leaf protocols from the parser perspective.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// iSCSI SCSI Command (48 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IscsiScsiReqHeader {
    pub opcode: u8,
    pub flags: u8,
    pub rsvd2: [u8; 2],
    pub hlength: u8,
    pub dlength: [u8; 3],
    pub lun: [u8; 8],
    pub itt: [u8; 4],
    pub data_length: [u8; 4],
    pub cmdsn: [u8; 4],
    pub exp_statsn: [u8; 4],
    pub cdb: [u8; 16],
}

pub struct IscsiScsiReqOps;

impl ProtocolOps for IscsiScsiReqOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI_SCSI_Req";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// iSCSI SCSI Response (48 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IscsiScsiRspHeader {
    pub opcode: u8,
    pub flags: u8,
    pub response: u8,
    pub cmd_status: u8,
    pub hlength: u8,
    pub dlength: [u8; 3],
    pub rsvd: [u8; 8],
    pub itt: [u8; 4],
    pub rsvd1: [u8; 4],
    pub statsn: [u8; 4],
    pub exp_cmdsn: [u8; 4],
    pub max_cmdsn: [u8; 4],
    pub exp_datasn: [u8; 4],
    pub bi_residual_count: [u8; 4],
    pub residual_count: [u8; 4],
}

pub struct IscsiScsiRspOps;

impl ProtocolOps for IscsiScsiRspOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI_SCSI_Rsp";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// iSCSI Login Request (48 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IscsiLoginReqHeader {
    pub opcode: u8,
    pub flags: u8,
    pub max_version: u8,
    pub min_version: u8,
    pub hlength: u8,
    pub dlength: [u8; 3],
    pub isid: [u8; 6],
    pub tsih: [u8; 2],
    pub itt: [u8; 4],
    pub cid: [u8; 2],
    pub rsvd3: [u8; 2],
    pub cmdsn: [u8; 4],
    pub exp_statsn: [u8; 4],
    pub rsvd5: [u8; 16],
}

pub struct IscsiLoginReqOps;

impl ProtocolOps for IscsiLoginReqOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI_Login_Req";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// iSCSI Login Response (48 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IscsiLoginRspHeader {
    pub opcode: u8,
    pub flags: u8,
    pub max_version: u8,
    pub active_version: u8,
    pub hlength: u8,
    pub dlength: [u8; 3],
    pub isid: [u8; 6],
    pub tsih: [u8; 2],
    pub itt: [u8; 4],
    pub rsvd3: [u8; 4],
    pub statsn: [u8; 4],
    pub exp_cmdsn: [u8; 4],
    pub max_cmdsn: [u8; 4],
    pub status_class: u8,
    pub status_detail: u8,
    pub rsvd4: [u8; 10],
}

pub struct IscsiLoginRspOps;

impl ProtocolOps for IscsiLoginRspOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI_Login_Rsp";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// iSCSI Data-Out (48 bytes).
pub struct IscsiDataOutOps;

impl ProtocolOps for IscsiDataOutOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI_Data_Out";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// iSCSI Data-In (48 bytes).
pub struct IscsiDataInOps;

impl ProtocolOps for IscsiDataInOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI_Data_In";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// iSCSI R2T (48 bytes).
pub struct IscsiR2tOps;

impl ProtocolOps for IscsiR2tOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI_R2T";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// iSCSI Task Management Request (48 bytes).
pub struct IscsiTmReqOps;

impl ProtocolOps for IscsiTmReqOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI_TM_Req";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// iSCSI Task Management Response (48 bytes).
pub struct IscsiTmRspOps;

impl ProtocolOps for IscsiTmRspOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI_TM_Rsp";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// iSCSI NOP-Out (48 bytes).
pub struct IscsiNopOutOps;

impl ProtocolOps for IscsiNopOutOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI_NOP_Out";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// iSCSI NOP-In (48 bytes).
pub struct IscsiNopInOps;

impl ProtocolOps for IscsiNopInOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI_NOP_In";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// iSCSI Text Request (48 bytes).
pub struct IscsiTextReqOps;

impl ProtocolOps for IscsiTextReqOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI_Text_Req";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// iSCSI Text Response (48 bytes).
pub struct IscsiTextRspOps;

impl ProtocolOps for IscsiTextRspOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI_Text_Rsp";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// iSCSI Logout Request (48 bytes).
pub struct IscsiLogoutReqOps;

impl ProtocolOps for IscsiLogoutReqOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI_Logout_Req";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// iSCSI Logout Response (48 bytes).
pub struct IscsiLogoutRspOps;

impl ProtocolOps for IscsiLogoutRspOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI_Logout_Rsp";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// iSCSI Async Message (48 bytes).
pub struct IscsiAsyncOps;

impl ProtocolOps for IscsiAsyncOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI_Async";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// iSCSI Reject (48 bytes).
pub struct IscsiRejectOps;

impl ProtocolOps for IscsiRejectOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "iSCSI_Reject";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iscsi_pdus_all_are_leaves() {
        let buf = [0u8; 48];
        assert!(IscsiScsiReqOps.next_proto(&buf).is_err());
        assert!(IscsiScsiRspOps.next_proto(&buf).is_err());
        assert!(IscsiLoginReqOps.next_proto(&buf).is_err());
        assert!(IscsiLoginRspOps.next_proto(&buf).is_err());
        assert!(IscsiDataOutOps.next_proto(&buf).is_err());
        assert!(IscsiDataInOps.next_proto(&buf).is_err());
        assert!(IscsiR2tOps.next_proto(&buf).is_err());
        assert!(IscsiTmReqOps.next_proto(&buf).is_err());
        assert!(IscsiTmRspOps.next_proto(&buf).is_err());
        assert!(IscsiNopOutOps.next_proto(&buf).is_err());
        assert!(IscsiNopInOps.next_proto(&buf).is_err());
        assert!(IscsiTextReqOps.next_proto(&buf).is_err());
        assert!(IscsiTextRspOps.next_proto(&buf).is_err());
        assert!(IscsiLogoutReqOps.next_proto(&buf).is_err());
        assert!(IscsiLogoutRspOps.next_proto(&buf).is_err());
        assert!(IscsiAsyncOps.next_proto(&buf).is_err());
        assert!(IscsiRejectOps.next_proto(&buf).is_err());
    }

    #[test]
    fn all_iscsi_pdus_48_bytes() {
        assert_eq!(IscsiScsiReqOps::MIN_LEN, 48);
        assert_eq!(IscsiScsiRspOps::MIN_LEN, 48);
        assert_eq!(IscsiLoginReqOps::MIN_LEN, 48);
        assert_eq!(IscsiLoginRspOps::MIN_LEN, 48);
    }
}
