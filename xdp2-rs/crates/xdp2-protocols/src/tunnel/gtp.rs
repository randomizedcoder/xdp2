//! GTP (GPRS Tunnelling Protocol) definitions.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `GtpuHeader` | `proto_defs/tunnel/proto_gtp.h:38-43` | `struct gtpuhdr` |
//! | `GtpuOps` | `proto_gtp.h:72-77` | `xdp2_parse_gtpu` |
//! | `GtpuOps::next_proto` | `proto_gtp.h:48-61` | `gtpu_proto()` |
//! | `GtpcHeader` | `proto_defs/tunnel/proto_gtp_c.h:37-42` | `struct gtpchdr` |
//! | `GtpcOps` | `proto_gtp_c.h:52-55` | `xdp2_parse_gtpc` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// EtherType constants for GTP inner protocol dispatch.
const ETH_P_IP: i32 = 0x0800;
const ETH_P_IPV6: i32 = 0x86DD;

/// GTP-U header (8 bytes).
///
/// Reimplements: `struct gtpuhdr` in `proto_gtp.h:38-43`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct GtpuHeader {
    /// Flags
    pub flags: u8,
    /// Message type
    pub message_type: u8,
    /// Total length of payload
    pub length: [u8; 2],
    /// Tunnel Endpoint Identifier
    pub teid: [u8; 4],
}

impl GtpuHeader {
    /// TEID value.
    pub fn teid(&self) -> u32 {
        u32::from_be_bytes(self.teid)
    }

    /// Payload length.
    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }
}

/// GTP-U protocol operations (encap).
///
/// Reimplements: `xdp2_parse_gtpu` in `proto_gtp.h:72-77`
///
/// Encapsulation tunnel. Inner protocol determined by inspecting the
/// first nibble of the payload after the GTP-U header (IPv4=4, IPv6=6).
pub struct GtpuOps;

impl ProtocolOps for GtpuOps {
    const MIN_LEN: usize = 8; // sizeof(struct gtpuhdr)
    const NAME: &'static str = "GTP-U";
    const ENCAP: bool = true;

    /// Determine inner protocol from first nibble of payload.
    ///
    /// Reimplements: `gtpu_proto()` in `proto_gtp.h:48-61`
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        if hdr.len() < 9 {
            return Err(ParseError::Length);
        }
        let version = hdr[8] >> 4;
        match version {
            4 => Ok(ETH_P_IP),
            6 => Ok(ETH_P_IPV6),
            _ => Ok(0),
        }
    }
}

/// GTP-C header (8 bytes).
///
/// Reimplements: `struct gtpchdr` in `proto_gtp_c.h:37-42`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct GtpcHeader {
    /// Flags
    pub flags: u8,
    /// Message type
    pub msg_type: u8,
    /// Length
    pub length: [u8; 2],
    /// TEID
    pub teid: [u8; 4],
}

/// GTP-C protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_gtpc` in `proto_gtp_c.h:52-55`
pub struct GtpcOps;

impl ProtocolOps for GtpcOps {
    const MIN_LEN: usize = 8; // sizeof(struct gtpchdr)
    const NAME: &'static str = "GTP-C";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gtpu_inner_ipv4() {
        let mut hdr = [0u8; 9];
        hdr[8] = 0x45; // IPv4 version nibble = 4
        let ops = GtpuOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), ETH_P_IP);
    }

    #[test]
    fn gtpu_inner_ipv6() {
        let mut hdr = [0u8; 9];
        hdr[8] = 0x60; // IPv6 version nibble = 6
        let ops = GtpuOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), ETH_P_IPV6);
    }

    #[test]
    fn gtpu_inner_unknown() {
        let mut hdr = [0u8; 9];
        hdr[8] = 0x00;
        let ops = GtpuOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0);
    }

    #[test]
    fn gtpu_is_encap() {
        assert!(GtpuOps::ENCAP);
    }

    #[test]
    fn gtpu_teid() {
        let mut hdr = [0u8; 8];
        hdr[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
        let g = GtpuHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(g.teid(), 0x12345678);
    }

    #[test]
    fn gtpc_is_leaf() {
        let ops = GtpcOps;
        assert!(ops.next_proto(&[0u8; 8]).is_err());
    }
}
