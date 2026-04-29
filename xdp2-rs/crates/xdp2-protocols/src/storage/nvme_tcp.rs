//! NVMe over TCP (NVMe/TCP Fabrics) protocol definitions.
//!
//! The NVMe/TCP common header (PDU header) dispatches on the `type` field
//! to identify PDU subtypes. PDU subtypes are leaf protocols.
//!
//! Reference: NVM Express TCP Transport Specification 1.0a

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// NVMe/TCP PDU type values.
pub const NVME_TCP_ICREQ: u8 = 0x00;
pub const NVME_TCP_ICRESP: u8 = 0x01;
pub const NVME_TCP_H2C_TERM: u8 = 0x02;
pub const NVME_TCP_C2H_TERM: u8 = 0x03;
pub const NVME_TCP_CMD: u8 = 0x04;
pub const NVME_TCP_RSP: u8 = 0x05;
pub const NVME_TCP_H2C_DATA: u8 = 0x06;
pub const NVME_TCP_C2H_DATA: u8 = 0x07;
pub const NVME_TCP_R2T: u8 = 0x09;

/// NVMe/TCP common PDU header (8 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct NvmeTcpHeader {
    /// PDU type — dispatches to specific PDU format.
    pub pdu_type: u8,
    pub flags: u8,
    /// Header length (variable, includes common header + PDU-specific fields).
    pub hlen: u8,
    /// PDU data offset.
    pub pdo: u8,
    /// Packet length (entire PDU including data).
    pub plen: [u8; 4],
}

impl NvmeTcpHeader {
    pub fn packet_length(&self) -> u32 {
        u32::from_le_bytes(self.plen)
    }
}

pub struct NvmeTcpOps;

impl ProtocolOps for NvmeTcpOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "NVMe/TCP";

    #[inline]
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        if hdr.len() < 8 {
            return Err(ParseError::Length);
        }
        // hlen field specifies actual header length
        Ok(hdr[2] as usize)
    }

    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        if hdr.len() < 8 {
            return Err(ParseError::Length);
        }
        Ok(hdr[0] as i32)
    }
}

/// NVMe/TCP ICReq PDU (128 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NvmeTcpIcreqHeader {
    pub hdr: NvmeTcpHeader,
    pub pfv: [u8; 2],
    pub hpda: u8,
    pub digest: u8,
    pub maxr2t: [u8; 4],
}

pub struct NvmeTcpIcreqOps;

impl ProtocolOps for NvmeTcpIcreqOps {
    const MIN_LEN: usize = 128;
    const NAME: &'static str = "NVMe_TCP_ICReq";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// NVMe/TCP ICResp PDU (128 bytes).
pub struct NvmeTcpIcrespOps;

impl ProtocolOps for NvmeTcpIcrespOps {
    const MIN_LEN: usize = 128;
    const NAME: &'static str = "NVMe_TCP_ICResp";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// NVMe/TCP R2T PDU (24 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NvmeTcpR2tHeader {
    pub hdr: NvmeTcpHeader,
    pub command_id: [u8; 2],
    pub ttag: [u8; 2],
    pub r2t_offset: [u8; 4],
    pub r2t_length: [u8; 4],
}

pub struct NvmeTcpR2tOps;

impl ProtocolOps for NvmeTcpR2tOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "NVMe_TCP_R2T";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// NVMe/TCP CapsuleResp PDU (24 bytes).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NvmeTcpRspHeader {
    pub hdr: NvmeTcpHeader,
    pub result_lo: [u8; 4],
    pub result_hi: [u8; 4],
    pub sq_head: [u8; 2],
    pub sq_id: [u8; 2],
    pub command_id: [u8; 2],
    pub status: [u8; 2],
}

pub struct NvmeTcpRspOps;

impl ProtocolOps for NvmeTcpRspOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "NVMe_TCP_Rsp";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_nvme_tcp(pdu_type: u8, hlen: u8) -> [u8; 8] {
        let mut hdr = [0u8; 8];
        hdr[0] = pdu_type;
        hdr[2] = hlen;
        hdr
    }

    #[test]
    fn nvme_tcp_dispatches_on_type() {
        let hdr = make_nvme_tcp(NVME_TCP_CMD, 72);
        assert_eq!(NvmeTcpOps.next_proto(&hdr).unwrap(), NVME_TCP_CMD as i32);
    }

    #[test]
    fn nvme_tcp_header_len_from_hlen() {
        let hdr = make_nvme_tcp(NVME_TCP_CMD, 72);
        assert_eq!(NvmeTcpOps.header_len(&hdr, 1024).unwrap(), 72);
    }

    #[test]
    fn nvme_tcp_icreq_is_leaf() {
        assert!(matches!(
            NvmeTcpIcreqOps.next_proto(&[0u8; 128]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn nvme_tcp_rsp_is_leaf() {
        assert!(matches!(
            NvmeTcpRspOps.next_proto(&[0u8; 24]),
            Err(ParseError::UnknownProto)
        ));
    }
}
