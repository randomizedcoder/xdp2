//! MLD (Multicast Listener Discovery) protocol definitions.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `MldHeader` | `proto_defs/ip/proto_mld.h:38-41` | `struct mld_msg` |
//! | `MldOps` | `proto_mld.h:76-79` | `xdp2_parse_mld` |
//! | `Mldv2QueryHeader` | `proto_mld.h:49-58` | `struct mld2_query` |
//! | `Mldv2QueryOps` | `proto_mld.h:85-88` | `xdp2_parse_mldv2_query` |
//! | `Mldv2ReportHeader` | `proto_mld.h:61-66` | `struct mld2_report` |
//! | `Mldv2ReportOps` | `proto_mld.h:94-97` | `xdp2_parse_mldv2_report` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// MLDv1 message header (24 bytes).
///
/// Reimplements: `struct mld_msg` in `proto_mld.h:38-41`
///
/// Carried inside ICMPv6 — 8-byte ICMPv6 header + 16-byte multicast address.
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct MldHeader {
    /// ICMPv6 header (type, code, checksum, max delay, reserved)
    pub icmp6_hdr: [u8; 8],
    /// Multicast address
    pub mca: [u8; 16],
}

/// MLDv2 Query header (28 bytes minimum).
///
/// Reimplements: `struct mld2_query` in `proto_mld.h:49-58`
///
/// Variable length — source IPv6 addresses follow the fixed header.
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Mldv2QueryHeader {
    /// ICMPv6 header
    pub icmp6_hdr: [u8; 8],
    /// Multicast address
    pub mca: [u8; 16],
    /// QRV(3) + S(1) + Resv(4)
    pub misc: u8,
    /// Querier's Query Interval Code
    pub qqic: u8,
    /// Number of sources
    pub nsrcs: [u8; 2],
}

impl Mldv2QueryHeader {
    /// Number of source addresses.
    pub fn num_sources(&self) -> u16 {
        u16::from_be_bytes(self.nsrcs)
    }
}

/// MLDv2 Report header (12 bytes minimum).
///
/// Reimplements: `struct mld2_report` in `proto_mld.h:61-66`
///
/// Variable length — group records follow the fixed header.
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Mldv2ReportHeader {
    /// ICMPv6 header
    pub icmp6_hdr: [u8; 8],
    /// Reserved
    pub reserved: [u8; 2],
    /// Number of group records
    pub ngrec: [u8; 2],
}

impl Mldv2ReportHeader {
    /// Number of group records.
    pub fn num_group_records(&self) -> u16 {
        u16::from_be_bytes(self.ngrec)
    }
}

/// MLDv1 protocol operations (leaf node).
///
/// Reimplements: `xdp2_parse_mld` in `proto_mld.h:76-79`
pub struct MldOps;

impl ProtocolOps for MldOps {
    const MIN_LEN: usize = 24; // sizeof(struct mld_msg) = 8 + 16
    const NAME: &'static str = "MLD";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

/// MLDv2 Query protocol operations (leaf node).
///
/// Reimplements: `xdp2_parse_mldv2_query` in `proto_mld.h:85-88`
pub struct Mldv2QueryOps;

impl ProtocolOps for Mldv2QueryOps {
    const MIN_LEN: usize = 28; // sizeof(struct mld2_query)
    const NAME: &'static str = "MLDv2 Query";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

/// MLDv2 Report protocol operations (leaf node).
///
/// Reimplements: `xdp2_parse_mldv2_report` in `proto_mld.h:94-97`
pub struct Mldv2ReportOps;

impl ProtocolOps for Mldv2ReportOps {
    const MIN_LEN: usize = 12; // sizeof(struct mld2_report) = 8 + 2 + 2
    const NAME: &'static str = "MLDv2 Report";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mld_is_leaf() {
        let ops = MldOps;
        assert!(ops.next_proto(&[0u8; 24]).is_err());
    }

    #[test]
    fn mld_fixed_length() {
        let ops = MldOps;
        assert_eq!(ops.header_len(&[0u8; 24], 100).unwrap(), 24);
    }

    #[test]
    fn mldv2_query_is_leaf() {
        let ops = Mldv2QueryOps;
        assert!(ops.next_proto(&[0u8; 28]).is_err());
    }

    #[test]
    fn mldv2_query_fixed_length() {
        let ops = Mldv2QueryOps;
        assert_eq!(ops.header_len(&[0u8; 28], 100).unwrap(), 28);
    }

    #[test]
    fn mldv2_report_is_leaf() {
        let ops = Mldv2ReportOps;
        assert!(ops.next_proto(&[0u8; 12]).is_err());
    }

    #[test]
    fn mldv2_query_num_sources() {
        let mut hdr = [0u8; 28];
        hdr[26..28].copy_from_slice(&3u16.to_be_bytes());
        let q = Mldv2QueryHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(q.num_sources(), 3);
    }

    #[test]
    fn mldv2_report_num_groups() {
        let mut hdr = [0u8; 12];
        hdr[10..12].copy_from_slice(&7u16.to_be_bytes());
        let r = Mldv2ReportHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(r.num_group_records(), 7);
    }
}
