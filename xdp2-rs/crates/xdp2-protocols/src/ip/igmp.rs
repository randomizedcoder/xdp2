//! IGMP protocol definitions.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `IgmpHeader` | `<linux/igmp.h>` | `struct igmphdr` |
//! | `IgmpOps` | `proto_defs/ip/proto_igmp.h:44-47` | `xdp2_parse_igmp` |
//! | `Igmpv3QueryHeader` | `<linux/igmp.h>` | `struct igmpv3_query` |
//! | `Igmpv3QueryOps` | `proto_igmpv3.h:45-48` | `xdp2_parse_igmpv3_query` |
//! | `Igmpv3ReportHeader` | `<linux/igmp.h>` | `struct igmpv3_report` |
//! | `Igmpv3ReportOps` | `proto_igmpv3.h:55-58` | `xdp2_parse_igmpv3_report` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// IGMP header (8 bytes).
///
/// Reimplements: `struct igmphdr` from `<linux/igmp.h>`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IgmpHeader {
    /// IGMP type
    pub igmp_type: u8,
    /// Max response time
    pub code: u8,
    /// Checksum
    pub csum: [u8; 2],
    /// Group address
    pub group: [u8; 4],
}

/// IGMPv3 Membership Query header (12 bytes minimum).
///
/// Reimplements: `struct igmpv3_query` from `<linux/igmp.h>`
///
/// Variable length — source addresses follow the fixed header.
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Igmpv3QueryHeader {
    /// IGMP type (0x11)
    pub igmp_type: u8,
    /// Max response code
    pub code: u8,
    /// Checksum
    pub csum: [u8; 2],
    /// Group address
    pub group: [u8; 4],
    /// QRV(3) + S(1) + Resv(4)
    pub misc: u8,
    /// Querier's Query Interval Code
    pub qqic: u8,
    /// Number of sources
    pub nsrcs: [u8; 2],
}

impl Igmpv3QueryHeader {
    /// Number of source addresses.
    pub fn num_sources(&self) -> u16 {
        u16::from_be_bytes(self.nsrcs)
    }
}

/// IGMPv3 Membership Report header (8 bytes minimum).
///
/// Reimplements: `struct igmpv3_report` from `<linux/igmp.h>`
///
/// Variable length — group records follow the fixed header.
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Igmpv3ReportHeader {
    /// IGMP type (0x22)
    pub igmp_type: u8,
    /// Reserved
    pub reserved1: u8,
    /// Checksum
    pub csum: [u8; 2],
    /// Reserved
    pub reserved2: [u8; 2],
    /// Number of group records
    pub ngrec: [u8; 2],
}

impl Igmpv3ReportHeader {
    /// Number of group records.
    pub fn num_group_records(&self) -> u16 {
        u16::from_be_bytes(self.ngrec)
    }
}

/// IGMP protocol operations (leaf node).
///
/// Reimplements: `xdp2_parse_igmp` in `proto_igmp.h:44-47`
pub struct IgmpOps;

impl ProtocolOps for IgmpOps {
    const MIN_LEN: usize = 8; // sizeof(struct igmphdr)
    const NAME: &'static str = "IGMP";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

/// IGMPv3 Membership Query operations (leaf node).
///
/// Reimplements: `xdp2_parse_igmpv3_query` in `proto_igmpv3.h:45-48`
pub struct Igmpv3QueryOps;

impl ProtocolOps for Igmpv3QueryOps {
    const MIN_LEN: usize = 12; // sizeof(struct igmpv3_query)
    const NAME: &'static str = "IGMPv3 Query";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

/// IGMPv3 Membership Report operations (leaf node).
///
/// Reimplements: `xdp2_parse_igmpv3_report` in `proto_igmpv3.h:55-58`
pub struct Igmpv3ReportOps;

impl ProtocolOps for Igmpv3ReportOps {
    const MIN_LEN: usize = 8; // sizeof(struct igmpv3_report)
    const NAME: &'static str = "IGMPv3 Report";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn igmp_is_leaf() {
        let ops = IgmpOps;
        assert!(ops.next_proto(&[0u8; 8]).is_err());
    }

    #[test]
    fn igmp_fixed_length() {
        let ops = IgmpOps;
        assert_eq!(ops.header_len(&[0u8; 8], 100).unwrap(), 8);
    }

    #[test]
    fn igmpv3_query_is_leaf() {
        let ops = Igmpv3QueryOps;
        assert!(ops.next_proto(&[0u8; 12]).is_err());
    }

    #[test]
    fn igmpv3_query_fixed_length() {
        let ops = Igmpv3QueryOps;
        assert_eq!(ops.header_len(&[0u8; 12], 100).unwrap(), 12);
    }

    #[test]
    fn igmpv3_report_is_leaf() {
        let ops = Igmpv3ReportOps;
        assert!(ops.next_proto(&[0u8; 8]).is_err());
    }

    #[test]
    fn igmpv3_query_num_sources() {
        let mut hdr = [0u8; 12];
        hdr[10..12].copy_from_slice(&5u16.to_be_bytes());
        let q = Igmpv3QueryHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(q.num_sources(), 5);
    }
}
