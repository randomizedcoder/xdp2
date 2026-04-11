//! IPv6 extension header protocol definitions.
//!
//! IPv6 uses a chain of extension headers, each with a `nexthdr` field
//! pointing to the next header type. This module provides parse operations
//! for the generic extension header format, the fragment header, and the
//! routing header.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `Ipv6OptHeader` | `<linux/ipv6.h>` | `struct ipv6_opt_hdr` |
//! | `Ipv6FragHeader` | `proto_defs/ip/proto_ipv6_eh.h:30-35` | `struct ipv6_frag_hdr` |
//! | `Ipv6EhOps` | `proto_ipv6_eh.h:66-71` | `xdp2_parse_ipv6_eh` |
//! | `Ipv6FragOps` | `proto_ipv6_eh.h:73-77` | `xdp2_parse_ipv6_frag_eh` |
//! | `Ipv6RoutingHdrOps` | `proto_ipv6_eh.h:79-85` | `xdp2_parse_ipv6_routing_hdr` |
//! | `ipv6_eh_proto()` | `proto_ipv6_eh.h:37-40` | `ipv6_eh_proto()` |
//! | `ipv6_eh_len()` | `proto_ipv6_eh.h:42-45` | `ipv6_eh_len()` |
//! | `ipv6_frag_proto()` | `proto_ipv6_eh.h:47-56` | `ipv6_frag_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// IPv6 generic extension header (variable length, minimum 2 bytes).
///
/// Reimplements: `struct ipv6_opt_hdr` from `<linux/ipv6.h>`
///
/// Used for Hop-by-Hop options, Destination options, etc.
/// Length is `(hdrlen + 1) * 8` bytes (ipv6_optlen macro).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Ipv6OptHeader {
    /// Next header type
    pub nexthdr: u8,
    /// Header extension length in 8-octet units (not counting first 8)
    pub hdrlen: u8,
}

impl Ipv6OptHeader {
    /// Compute total header length in bytes.
    ///
    /// Reimplements: `ipv6_optlen()` from `<linux/ipv6.h>`
    ///
    /// Formula: `(hdrlen + 1) * 8`
    pub fn opt_len(&self) -> usize {
        (self.hdrlen as usize + 1) * 8
    }
}

/// IPv6 fragment extension header (fixed 8 bytes).
///
/// Reimplements: `struct ipv6_frag_hdr` in `proto_ipv6_eh.h:30-35`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Ipv6FragHeader {
    /// Next header type
    pub nexthdr: u8,
    /// Reserved
    pub reserved: u8,
    /// Fragment offset (13 bits) + reserved (2 bits) + MF flag (1 bit)
    pub frag_off: [u8; 2],
    /// Identification
    pub identification: [u8; 4],
}

/// Fragment offset mask (upper 13 bits).
const IP6_OFFSET: u16 = 0xFFF8;

impl Ipv6FragHeader {
    /// Fragment offset in bytes (multiple of 8).
    pub fn frag_offset(&self) -> u16 {
        u16::from_be_bytes(self.frag_off) & IP6_OFFSET
    }

    /// More Fragments flag.
    pub fn more_fragments(&self) -> bool {
        (u16::from_be_bytes(self.frag_off) & 0x0001) != 0
    }

    /// Check if this is a non-first fragment (offset > 0).
    pub fn is_non_first_fragment(&self) -> bool {
        self.frag_offset() != 0
    }
}

/// IPv6 routing header (variable length, minimum 4 bytes).
///
/// Reimplements: `struct ipv6_rt_hdr` from `<linux/ipv6.h>`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Ipv6RoutingHeader {
    /// Next header type
    pub nexthdr: u8,
    /// Header extension length in 8-octet units
    pub hdrlen: u8,
    /// Routing type (e.g., 0=deprecated, 2=Mobile IPv6, 4=SRv6)
    pub routing_type: u8,
    /// Segments left
    pub segments_left: u8,
}

/// IPv6 generic extension header operations.
///
/// Reimplements: `xdp2_parse_ipv6_eh` in `proto_ipv6_eh.h:66-71`
///
/// Variable-length header using the standard `(hdrlen+1)*8` formula.
/// Used for Hop-by-Hop Options, Destination Options, etc.
pub struct Ipv6EhOps;

impl ProtocolOps for Ipv6EhOps {
    const MIN_LEN: usize = 2; // sizeof(struct ipv6_opt_hdr)
    const NAME: &'static str = "IPv6 EH";

    /// Return header length from hdrlen field.
    ///
    /// Reimplements: `ipv6_eh_len()` in `proto_ipv6_eh.h:42-45`
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        let opt = Ipv6OptHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(opt.opt_len())
    }

    /// Return next header type.
    ///
    /// Reimplements: `ipv6_eh_proto()` in `proto_ipv6_eh.h:37-40`
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let opt = Ipv6OptHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(opt.nexthdr as i32)
    }
}

/// IPv6 fragment header operations.
///
/// Reimplements: `xdp2_parse_ipv6_frag_eh` in `proto_ipv6_eh.h:73-77`
///
/// Fixed 8-byte header. Stops parsing at non-first fragments (matching
/// IPv4 fragment behavior).
pub struct Ipv6FragOps;

impl ProtocolOps for Ipv6FragOps {
    const MIN_LEN: usize = 8; // sizeof(struct ipv6_frag_hdr)
    const NAME: &'static str = "IPv6 Frag EH";

    /// Return next header, stopping at non-first fragments.
    ///
    /// Reimplements: `ipv6_frag_proto()` in `proto_ipv6_eh.h:47-56`
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let frag = Ipv6FragHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;

        if frag.is_non_first_fragment() {
            // XDP2_STOP_OKAY = -4
            return Ok(-4);
        }

        Ok(frag.nexthdr as i32)
    }
}

/// IPv6 fragment header — stops at all fragments (including first).
///
/// Reimplements: `xdp2_parse_ipv6_frag_eh_stop1stfrag` in `proto_ipv6_eh.h:79-84`
pub struct Ipv6FragStopAllOps;

impl ProtocolOps for Ipv6FragStopAllOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "IPv6 Frag EH (stop all)";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        // Always stop — no next_proto defined in C
        Err(ParseError::UnknownProto)
    }
}

/// IPv6 routing header operations (overlay).
///
/// Reimplements: `xdp2_parse_ipv6_routing_hdr` in `proto_ipv6_eh.h:86-92`
///
/// Returns the routing type field as next_proto for sub-type dispatch
/// (e.g., SRv6 Type 4). Uses same length formula as generic EH.
/// Marked as overlay because routing header type dispatch doesn't
/// consume additional bytes.
pub struct Ipv6RoutingHdrOps;

impl ProtocolOps for Ipv6RoutingHdrOps {
    const MIN_LEN: usize = 4; // sizeof(struct ipv6_rt_hdr)
    const NAME: &'static str = "IPv6 RH overlay";
    const OVERLAY: bool = true;

    /// Return header length using standard EH formula.
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        // Uses the same hdrlen field as generic EH
        if hdr.len() < 2 {
            return Err(ParseError::Length);
        }
        Ok((hdr[1] as usize + 1) * 8)
    }

    /// Return routing header type for sub-type dispatch.
    ///
    /// Reimplements: `ipv6_routing_header_proto()` in `proto_ipv6_eh.h:58-61`
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let rh = Ipv6RoutingHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(rh.routing_type as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_eh_length() {
        // hdrlen=0 → (0+1)*8 = 8 bytes
        let hdr = [6, 0, 0, 0, 0, 0, 0, 0]; // nexthdr=6 (TCP), hdrlen=0
        let ops = Ipv6EhOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 8);

        // hdrlen=1 → (1+1)*8 = 16 bytes
        let hdr2 = [17, 1]; // nexthdr=17 (UDP), hdrlen=1
        assert_eq!(ops.header_len(&hdr2, 100).unwrap(), 16);
    }

    #[test]
    fn ipv6_eh_next_proto() {
        let hdr = [6, 0]; // nexthdr=6 (TCP)
        let ops = Ipv6EhOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 6);
    }

    #[test]
    fn ipv6_frag_first_fragment() {
        // nexthdr=6, reserved=0, frag_off=0x0001 (MF=1, offset=0)
        let hdr = [6, 0, 0x00, 0x01, 0, 0, 0, 0];
        let ops = Ipv6FragOps;
        // First fragment — continue parsing
        assert_eq!(ops.next_proto(&hdr).unwrap(), 6);
    }

    #[test]
    fn ipv6_frag_non_first_stops() {
        // nexthdr=6, frag_off=0x0008 (offset=8, MF=0)
        let hdr = [6, 0, 0x00, 0x08, 0, 0, 0, 0];
        let ops = Ipv6FragOps;
        // Non-first fragment — stop
        assert_eq!(ops.next_proto(&hdr).unwrap(), -4); // XDP2_STOP_OKAY
    }

    #[test]
    fn ipv6_frag_no_fragment() {
        // No fragmentation (offset=0, MF=0)
        let hdr = [17, 0, 0x00, 0x00, 0, 0, 0, 0];
        let ops = Ipv6FragOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 17);
    }

    #[test]
    fn ipv6_frag_stop_all() {
        let ops = Ipv6FragStopAllOps;
        assert!(ops.next_proto(&[0; 8]).is_err());
    }

    #[test]
    fn ipv6_routing_hdr_type() {
        // nexthdr=6, hdrlen=0, routing_type=4 (SRv6), segments_left=2
        let hdr = [6, 0, 4, 2, 0, 0, 0, 0];
        let ops = Ipv6RoutingHdrOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 4); // SRv6
        assert!(Ipv6RoutingHdrOps::OVERLAY);
    }

    #[test]
    fn ipv6_routing_hdr_length() {
        // hdrlen=2 → (2+1)*8 = 24 bytes
        let hdr = [6, 2, 0, 3, 0, 0, 0, 0];
        let ops = Ipv6RoutingHdrOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 24);
    }

    #[test]
    fn ipv6_frag_header_fields() {
        // frag_off = 0x0039 → offset=0x0038 (56), MF=1
        let hdr = [6, 0, 0x00, 0x39, 0xDE, 0xAD, 0xBE, 0xEF];
        let frag = Ipv6FragHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(frag.frag_offset(), 0x0038);
        assert!(frag.more_fragments());
        assert!(frag.is_non_first_fragment());
    }
}
