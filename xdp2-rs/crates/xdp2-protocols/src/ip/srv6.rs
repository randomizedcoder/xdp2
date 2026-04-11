//! SRv6 (Segment Routing over IPv6) protocol definitions.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `Srv6Header` | `<linux/seg6.h>` | `struct ipv6_sr_hdr` |
//! | `Srv6Ops` | `proto_defs/ip/proto_srv6.h:69-74` | `xdp2_parse_srv6` |
//! | `Srv6Ops::header_len` | `proto_srv6.h:39-42` | `ipv6_srv6_len()` |
//! | `Srv6Ops::next_proto` | `proto_srv6.h:34-37` | `ipv6_srv6_proto()` |
//! | `Srv6SegListArrayOps` | `proto_srv6.h:76-86` | `xdp2_parse_srv6_seg_list` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// SRv6 Segment Routing Header (8 bytes fixed, variable segments follow).
///
/// Reimplements: `struct ipv6_sr_hdr` from `<linux/seg6.h>`
///
/// Uses the same variable-length format as IPv6 extension headers:
/// total length = `(hdrextlen + 1) * 8`.
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Srv6Header {
    /// Next header
    pub nexthdr: u8,
    /// Header extension length (in 8-byte units, minus 1)
    pub hdrextlen: u8,
    /// Routing type (4 for SRv6)
    pub routing_type: u8,
    /// Segments left
    pub segments_left: u8,
    /// First segment index
    pub first_segment: u8,
    /// Flags
    pub flags: u8,
    /// Tag
    pub tag: [u8; 2],
}

impl Srv6Header {
    /// Total header length in bytes.
    ///
    /// Reimplements: `ipv6_optlen()` applied to SRv6 in `proto_srv6.h:39-42`
    pub fn header_length(&self) -> usize {
        (self.hdrextlen as usize + 1) * 8
    }

    /// Number of segments in the segment list.
    ///
    /// Reimplements: `ipv6_srv6_num_els()` in `proto_srv6.h:44-49`
    pub fn num_segments(&self) -> usize {
        self.first_segment as usize + 1
    }

    /// Offset where the segment list begins.
    ///
    /// Reimplements: `ipv6_srv6_seg_list_start_offset()` in `proto_srv6.h:56-59`
    pub fn seg_list_offset() -> usize {
        8 // sizeof(struct ipv6_sr_hdr)
    }
}

/// SRv6 protocol operations.
///
/// Reimplements: `xdp2_parse_srv6` in `proto_srv6.h:69-74`
///
/// Variable-length IPv6 extension header. Length from `(hdrextlen+1)*8`.
/// Next protocol from `nexthdr` field.
pub struct Srv6Ops;

impl ProtocolOps for Srv6Ops {
    const MIN_LEN: usize = 8; // sizeof(struct ipv6_sr_hdr) minimum
    const NAME: &'static str = "SRV6";

    /// Return header length: `(hdrextlen + 1) * 8`.
    ///
    /// Reimplements: `ipv6_srv6_len()` in `proto_srv6.h:39-42`
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        let srv6 = Srv6Header::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(srv6.header_length())
    }

    /// Return next header protocol.
    ///
    /// Reimplements: `ipv6_srv6_proto()` in `proto_srv6.h:34-37`
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let srv6 = Srv6Header::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(srv6.nexthdr as i32)
    }
}

/// Array operations for SRv6 segment list parsing.
///
/// Reimplements: `xdp2_parse_srv6_seg_list` in `proto_srv6.h:76-86`
///
/// The segment list is an array of 16-byte IPv6 addresses starting at
/// offset 8 (after the SRv6 header). Number of elements = `first_segment + 1`.
///
/// In the C implementation this uses `node_type = XDP2_NODE_TYPE_ARRAY`.
/// The array parsing is handled by the array sub-parse system in xdp2-core.
pub struct Srv6SegListArrayOps;

impl Srv6SegListArrayOps {
    /// Size of each segment (IPv6 address = 16 bytes).
    pub const ELEMENT_LENGTH: usize = 16; // sizeof(struct in6_addr)

    /// Get number of segments from header.
    ///
    /// Reimplements: `ipv6_srv6_num_els()` in `proto_srv6.h:44-49`
    pub fn num_elements(hdr: &[u8]) -> Result<usize, ParseError> {
        let srv6 = Srv6Header::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(srv6.num_segments())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_srv6_header(nexthdr: u8, hdrextlen: u8, first_segment: u8) -> [u8; 8] {
        let mut hdr = [0u8; 8];
        hdr[0] = nexthdr;
        hdr[1] = hdrextlen;
        hdr[2] = 4; // routing_type = SRv6
        hdr[3] = first_segment; // segments_left
        hdr[4] = first_segment; // first_segment
        hdr
    }

    #[test]
    fn srv6_header_length() {
        // hdrextlen=3 → (3+1)*8 = 32 bytes
        let hdr = make_srv6_header(6, 3, 1);
        let ops = Srv6Ops;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 32);
    }

    #[test]
    fn srv6_next_proto_tcp() {
        let hdr = make_srv6_header(6, 1, 0); // nexthdr=6 (TCP)
        let ops = Srv6Ops;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 6);
    }

    #[test]
    fn srv6_next_proto_udp() {
        let hdr = make_srv6_header(17, 1, 0); // nexthdr=17 (UDP)
        let ops = Srv6Ops;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 17);
    }

    #[test]
    fn srv6_num_segments() {
        let hdr = make_srv6_header(6, 3, 2);
        let srv6 = Srv6Header::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(srv6.num_segments(), 3); // first_segment + 1
    }

    #[test]
    fn srv6_seg_list_offset() {
        assert_eq!(Srv6Header::seg_list_offset(), 8);
    }

    #[test]
    fn srv6_too_short() {
        let ops = Srv6Ops;
        assert!(ops.header_len(&[0u8; 4], 100).is_err());
    }

    #[test]
    fn srv6_array_num_elements() {
        let hdr = make_srv6_header(6, 5, 3); // 4 segments
        assert_eq!(Srv6SegListArrayOps::num_elements(&hdr).unwrap(), 4);
    }
}
