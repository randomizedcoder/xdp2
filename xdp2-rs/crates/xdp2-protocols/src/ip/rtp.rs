//! RTP and RTCP protocol definitions.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `RtpHeader` | `proto_defs/ip/proto_rtp.h:36-42` | `struct rtphdr` |
//! | `RtpOps` | `proto_rtp.h:52-55` | `xdp2_parse_rtp` |
//! | `RtcpHeader` | `proto_defs/ip/proto_rtcp.h:37-42` | `struct rtcp_hdr` |
//! | `RtcpOps` | `proto_rtcp.h:52-55` | `xdp2_parse_rtcp` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// RTP header (12 bytes).
///
/// Reimplements: `struct rtphdr` in `proto_rtp.h:36-42`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct RtpHeader {
    /// V(2) + P(1) + X(1) + CC(4)
    pub cc_x_p_v: u8,
    /// M(1) + PT(7)
    pub m_pt: u8,
    /// Sequence number
    pub sequence_number: [u8; 2],
    /// Timestamp
    pub timestamp: [u8; 4],
    /// Synchronization source identifier
    pub ssrc: [u8; 4],
}

impl RtpHeader {
    /// RTP version (2 bits).
    pub fn version(&self) -> u8 {
        self.cc_x_p_v >> 6
    }

    /// Payload type (7 bits).
    pub fn payload_type(&self) -> u8 {
        self.m_pt & 0x7F
    }

    /// Marker bit.
    pub fn marker(&self) -> bool {
        (self.m_pt & 0x80) != 0
    }

    /// Sequence number.
    pub fn sequence_number(&self) -> u16 {
        u16::from_be_bytes(self.sequence_number)
    }

    /// SSRC.
    pub fn ssrc(&self) -> u32 {
        u32::from_be_bytes(self.ssrc)
    }
}

/// RTCP header (8 bytes).
///
/// Reimplements: `struct rtcp_hdr` in `proto_rtcp.h:37-42`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct RtcpHeader {
    /// V(2) + P(1) + RC(5)
    pub vprc: u8,
    /// Packet type
    pub pt: u8,
    /// Length in 32-bit words minus one
    pub length: [u8; 2],
    /// Synchronization source
    pub ssrc: [u8; 4],
}

impl RtcpHeader {
    /// RTCP version (2 bits).
    pub fn version(&self) -> u8 {
        self.vprc >> 6
    }

    /// Packet type.
    pub fn packet_type(&self) -> u8 {
        self.pt
    }

    /// Length in bytes (from length field: (length+1)*4).
    pub fn length_bytes(&self) -> usize {
        (u16::from_be_bytes(self.length) as usize + 1) * 4
    }
}

/// RTP protocol operations (leaf node).
///
/// Reimplements: `xdp2_parse_rtp` in `proto_rtp.h:52-55`
pub struct RtpOps;

impl ProtocolOps for RtpOps {
    const MIN_LEN: usize = 12; // sizeof(struct rtphdr)
    const NAME: &'static str = "RTP";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

/// RTCP protocol operations (leaf node).
///
/// Reimplements: `xdp2_parse_rtcp` in `proto_rtcp.h:52-55`
pub struct RtcpOps;

impl ProtocolOps for RtcpOps {
    const MIN_LEN: usize = 8; // sizeof(struct rtcp_hdr)
    const NAME: &'static str = "RTCP";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtp_is_leaf() {
        let ops = RtpOps;
        assert!(ops.next_proto(&[0u8; 12]).is_err());
    }

    #[test]
    fn rtp_fixed_length() {
        let ops = RtpOps;
        assert_eq!(ops.header_len(&[0u8; 12], 100).unwrap(), 12);
    }

    #[test]
    fn rtp_version() {
        let mut hdr = [0u8; 12];
        hdr[0] = 2 << 6; // version = 2
        let rtp = RtpHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(rtp.version(), 2);
    }

    #[test]
    fn rtcp_is_leaf() {
        let ops = RtcpOps;
        assert!(ops.next_proto(&[0u8; 8]).is_err());
    }

    #[test]
    fn rtcp_fixed_length() {
        let ops = RtcpOps;
        assert_eq!(ops.header_len(&[0u8; 8], 100).unwrap(), 8);
    }

    #[test]
    fn rtcp_packet_type() {
        let mut hdr = [0u8; 8];
        hdr[0] = 2 << 6; // version = 2
        hdr[1] = 200; // Sender Report
        let rtcp = RtcpHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(rtcp.version(), 2);
        assert_eq!(rtcp.packet_type(), 200);
    }
}
