//! IPv6 protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `Ipv6Header` | `<linux/ipv6.h>` | `struct ipv6hdr` |
//! | `Ipv6Ops` | `proto_defs/ip/proto_ipv6.h:44-48` | `xdp2_parse_ipv6` |
//! | `Ipv6Ops::next_proto` | `proto_ipv6.h:25-28` | `ipv6_proto()` |
//! | `Ipv6StopFlowLabelOps` | `proto_ipv6.h:50-55` | `xdp2_parse_ipv6_stopflowlabel` |
//! | `Ipv6CheckOps` | `proto_ipv6.h:57-63` | `xdp2_parse_ipv6_check` |
//! | `ip6_flowlabel()` | `proto_ipv6.h:20-23` | `ip6_flowlabel()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// IPv6 header (fixed 40 bytes).
///
/// Reimplements: `struct ipv6hdr` from `<linux/ipv6.h>`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Ipv6Header {
    /// Version (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits)
    /// Stored as 4 bytes: [ver_tc, tc_fl, fl_hi, fl_lo]
    pub ver_tc_fl: [u8; 4],
    /// Payload length (not including the 40-byte fixed header)
    pub payload_len: [u8; 2],
    /// Next header (IP protocol number)
    pub nexthdr: u8,
    /// Hop limit (TTL equivalent)
    pub hop_limit: u8,
    /// Source address (128 bits)
    pub saddr: [u8; 16],
    /// Destination address (128 bits)
    pub daddr: [u8; 16],
}

impl Ipv6Header {
    /// IP version number (should be 6).
    pub fn version(&self) -> u8 {
        self.ver_tc_fl[0] >> 4
    }

    /// Flow label (20-bit field).
    ///
    /// Reimplements: `ip6_flowlabel()` in `proto_ipv6.h:20-23`
    pub fn flow_label(&self) -> u32 {
        // Flow label is the lower 20 bits of the first 4 bytes (big-endian)
        let word = u32::from_be_bytes(self.ver_tc_fl);
        word & 0x000F_FFFF
    }

    /// Traffic class (8-bit field).
    pub fn traffic_class(&self) -> u8 {
        ((self.ver_tc_fl[0] & 0x0F) << 4) | (self.ver_tc_fl[1] >> 4)
    }

    /// Payload length in bytes.
    pub fn payload_len(&self) -> u16 {
        u16::from_be_bytes(self.payload_len)
    }
}

/// IPv6 protocol operations — basic variant.
///
/// Reimplements: `xdp2_parse_ipv6` in `proto_defs/ip/proto_ipv6.h:44-48`
///
/// Fixed 40-byte header. Returns nexthdr field for protocol table lookup.
pub struct Ipv6Ops;

impl ProtocolOps for Ipv6Ops {
    const MIN_LEN: usize = 40; // sizeof(struct ipv6hdr)
    const NAME: &'static str = "IPv6";

    /// Return next header protocol number.
    ///
    /// Reimplements: `ipv6_proto()` in `proto_ipv6.h:25-28`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let iph = Ipv6Header::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(iph.nexthdr as i32)
    }
}

/// IPv6 with flow-label stop — stops parsing if flow label is non-zero.
///
/// Reimplements: `xdp2_parse_ipv6_stopflowlabel` in `proto_ipv6.h:50-55`
///
/// Some deployments use the flow label as a hash key and don't need to
/// parse further into the packet. This variant returns `StopOkay` (-4)
/// when a non-zero flow label is detected.
pub struct Ipv6StopFlowLabelOps;

impl ProtocolOps for Ipv6StopFlowLabelOps {
    const MIN_LEN: usize = 40;
    const NAME: &'static str = "IPv6-stopfl";

    /// Return next header, or stop if flow label is non-zero.
    ///
    /// Reimplements: `ipv6_proto_stopflowlabel()` in `proto_ipv6.h:30-39`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let iph = Ipv6Header::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;

        if iph.flow_label() != 0 {
            // XDP2_STOP_OKAY = -4
            return Ok(-4);
        }

        Ok(iph.nexthdr as i32)
    }
}

/// IPv6 with version check — overlay variant.
///
/// Reimplements: `xdp2_parse_ipv6_check` in `proto_ipv6.h:57-63`
///
/// Same as `Ipv6Ops` but checks that the version field is 6. Used as an
/// overlay node (doesn't consume bytes) for IP version dispatch.
pub struct Ipv6CheckOps;

impl ProtocolOps for Ipv6CheckOps {
    const MIN_LEN: usize = 40;
    const NAME: &'static str = "IPv6-check";
    const OVERLAY: bool = true;

    /// Return header length, checking version is 6.
    ///
    /// Reimplements: `ipv6_length_check()` in `proto_ipv6.h:41-48`
    #[inline]
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        let iph = Ipv6Header::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        if iph.version() != 6 {
            return Err(ParseError::UnknownProto);
        }
        Ok(40)
    }

    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        Ipv6Ops.next_proto(hdr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv6_header(nexthdr: u8, flow_label: u32) -> [u8; 40] {
        let mut hdr = [0u8; 40];
        // Version=6, TC=0, Flow Label
        let word: u32 = (6 << 28) | (flow_label & 0x000F_FFFF);
        let bytes = word.to_be_bytes();
        hdr[0] = bytes[0];
        hdr[1] = bytes[1];
        hdr[2] = bytes[2];
        hdr[3] = bytes[3];
        // payload_len = 0 (for these tests)
        hdr[6] = nexthdr;
        hdr[7] = 64; // hop_limit
        hdr
    }

    #[test]
    fn ipv6_fixed_header_length() {
        let hdr = make_ipv6_header(6, 0);
        let ops = Ipv6Ops;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 40);
    }

    #[test]
    fn ipv6_next_proto_tcp() {
        let hdr = make_ipv6_header(6, 0); // nexthdr=6 (TCP)
        let ops = Ipv6Ops;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 6);
    }

    #[test]
    fn ipv6_next_proto_udp() {
        let hdr = make_ipv6_header(17, 0); // nexthdr=17 (UDP)
        let ops = Ipv6Ops;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 17);
    }

    #[test]
    fn ipv6_flow_label_extraction() {
        let hdr = make_ipv6_header(6, 0xABCDE);
        let iph = Ipv6Header::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(iph.flow_label(), 0xABCDE);
        assert_eq!(iph.version(), 6);
    }

    #[test]
    fn ipv6_stop_flow_label_stops() {
        let hdr = make_ipv6_header(6, 0x12345); // non-zero flow label
        let ops = Ipv6StopFlowLabelOps;
        // Should return XDP2_STOP_OKAY (-4)
        assert_eq!(ops.next_proto(&hdr).unwrap(), -4);
    }

    #[test]
    fn ipv6_stop_flow_label_continues_when_zero() {
        let hdr = make_ipv6_header(6, 0); // zero flow label
        let ops = Ipv6StopFlowLabelOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 6);
    }

    #[test]
    fn ipv6_check_rejects_ipv4() {
        let mut hdr = [0u8; 40];
        hdr[0] = 4 << 4; // version=4
        let ops = Ipv6CheckOps;
        assert_eq!(
            ops.header_len(&hdr, 100).unwrap_err(),
            ParseError::UnknownProto
        );
    }

    #[test]
    fn ipv6_check_accepts_v6() {
        let hdr = make_ipv6_header(6, 0);
        let ops = Ipv6CheckOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 40);
    }

    #[test]
    fn ipv6_traffic_class() {
        let mut hdr = make_ipv6_header(6, 0);
        // Set traffic class to 0xAB (version=6, TC=0xAB)
        // ver_tc_fl[0] = 0x6A (version=6, upper 4 bits of TC=A)
        // ver_tc_fl[1] = 0xB0 (lower 4 bits of TC=B, upper 4 bits of FL=0)
        hdr[0] = 0x6A;
        hdr[1] = 0xB0;
        let iph = Ipv6Header::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(iph.traffic_class(), 0xAB);
    }
}
