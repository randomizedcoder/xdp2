//! IPv4 protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `Ipv4Header` | `<linux/ip.h>` | `struct iphdr` |
//! | `Ipv4Ops` | `proto_defs/ip/proto_ipv4.h:100-105` | `xdp2_parse_ipv4` |
//! | `Ipv4Ops::header_len` | `proto_ipv4.h:41-44` | `ipv4_len()` |
//! | `Ipv4Ops::next_proto` | `proto_ipv4.h:51-61` | `ipv4_proto()` |
//! | `Ipv4CheckOps` | `proto_ipv4.h:126-132` | `xdp2_parse_ipv4_check` |
//! | `ip_is_fragment()` | `proto_ipv4.h:46-49` | `ip_is_fragment()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// IPv4 header (minimum 20 bytes, variable via IHL).
///
/// Reimplements: `struct iphdr` from `<linux/ip.h>`
///
/// Note: This uses raw byte access rather than bitfield layout because
/// the IHL and version fields share the first byte, and Rust doesn't
/// have native bitfield support.
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Ipv4Header {
    /// Version (4 bits) + IHL (4 bits)
    pub ver_ihl: u8,
    /// Type of Service
    pub tos: u8,
    /// Total length
    pub tot_len: [u8; 2],
    /// Identification
    pub id: [u8; 2],
    /// Fragment offset (includes flags)
    pub frag_off: [u8; 2],
    /// Time to live
    pub ttl: u8,
    /// Protocol (e.g., 6 = TCP, 17 = UDP)
    pub protocol: u8,
    /// Header checksum
    pub check: [u8; 2],
    /// Source address
    pub saddr: [u8; 4],
    /// Destination address
    pub daddr: [u8; 4],
}

impl Ipv4Header {
    /// Internet Header Length in bytes (IHL field * 4).
    ///
    /// Reimplements: `ipv4_len()` in `proto_ipv4.h:41-44`
    pub fn ihl_bytes(&self) -> usize {
        ((self.ver_ihl & 0x0F) as usize) * 4
    }

    /// IP version number.
    pub fn version(&self) -> u8 {
        self.ver_ihl >> 4
    }

    /// Fragment offset field (big-endian, includes flags).
    fn frag_off_be(&self) -> u16 {
        u16::from_be_bytes(self.frag_off)
    }

    /// Check if this packet is a fragment.
    ///
    /// Reimplements: `ip_is_fragment()` in `proto_ipv4.h:46-49`
    pub fn is_fragment(&self) -> bool {
        const IP_MF: u16 = 0x2000;
        const IP_OFFSET: u16 = 0x1FFF;
        (self.frag_off_be() & (IP_MF | IP_OFFSET)) != 0
    }

    /// Check if this is a non-first fragment (offset > 0).
    fn is_non_first_fragment(&self) -> bool {
        const IP_OFFSET: u16 = 0x1FFF;
        self.is_fragment() && (self.frag_off_be() & IP_OFFSET) != 0
    }
}

/// IPv4 protocol operations.
///
/// Reimplements: `xdp2_parse_ipv4` in `proto_defs/ip/proto_ipv4.h:100-105`
///
/// Variable-length header (20-60 bytes via IHL field). Stops parsing at
/// non-first fragments (matching C behavior).
pub struct Ipv4Ops;

impl ProtocolOps for Ipv4Ops {
    const MIN_LEN: usize = 20; // sizeof(struct iphdr)
    const NAME: &'static str = "IPv4";

    /// Return header length from IHL field.
    ///
    /// Reimplements: `ipv4_length()` in `proto_ipv4.h:75-78`
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        let iph = Ipv4Header::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(iph.ihl_bytes())
    }

    /// Return IP protocol number, stopping at non-first fragments.
    ///
    /// Reimplements: `ipv4_proto()` in `proto_ipv4.h:51-61`
    ///
    /// Non-first fragments return `StopOkay` (encoded as a negative value
    /// that the engine interprets as "stop parsing, no error").
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let iph = Ipv4Header::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;

        if iph.is_non_first_fragment() {
            // Stop at non-first fragments (XDP2_STOP_OKAY = -4)
            return Ok(-4);
        }

        Ok(iph.protocol as i32)
    }
}

/// IPv4 with version check — overlay variant.
///
/// Reimplements: `xdp2_parse_ipv4_check` in `proto_ipv4.h:126-132`
///
/// Same as `Ipv4Ops` but checks that the version field is 4. Used as an
/// overlay node (doesn't consume bytes) for IP version dispatch.
pub struct Ipv4CheckOps;

impl ProtocolOps for Ipv4CheckOps {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "IPv4-check";
    const OVERLAY: bool = true;

    /// Return header length, checking version is 4.
    ///
    /// Reimplements: `ipv4_length_check()` in `proto_ipv4.h:80-88`
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        let iph = Ipv4Header::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        if iph.version() != 4 {
            return Err(ParseError::UnknownProto);
        }
        Ok(iph.ihl_bytes())
    }

    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        Ipv4Ops.next_proto(hdr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv4_header(ihl: u8, protocol: u8, frag_off: u16) -> [u8; 20] {
        let mut hdr = [0u8; 20];
        hdr[0] = (4 << 4) | ihl; // version=4, IHL
        hdr[8] = 64; // TTL
        hdr[9] = protocol;
        let frag = frag_off.to_be_bytes();
        hdr[6] = frag[0];
        hdr[7] = frag[1];
        hdr
    }

    #[test]
    fn ipv4_standard_header_length() {
        let hdr = make_ipv4_header(5, 6, 0); // IHL=5 → 20 bytes
        let ops = Ipv4Ops;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 20);
    }

    #[test]
    fn ipv4_with_options() {
        let mut hdr = [0u8; 40];
        hdr[0] = (4 << 4) | 10; // IHL=10 → 40 bytes
        let ops = Ipv4Ops;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 40);
    }

    #[test]
    fn ipv4_next_proto_tcp() {
        let hdr = make_ipv4_header(5, 6, 0); // protocol=6 (TCP)
        let ops = Ipv4Ops;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 6);
    }

    #[test]
    fn ipv4_next_proto_udp() {
        let hdr = make_ipv4_header(5, 17, 0); // protocol=17 (UDP)
        let ops = Ipv4Ops;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 17);
    }

    #[test]
    fn ipv4_non_first_fragment_stops() {
        // MF flag set + offset > 0
        let hdr = make_ipv4_header(5, 6, 0x2000 | 100);
        let ops = Ipv4Ops;
        // Should return XDP2_STOP_OKAY (-4)
        assert_eq!(ops.next_proto(&hdr).unwrap(), -4);
    }

    #[test]
    fn ipv4_first_fragment_continues() {
        // MF flag set but offset = 0 (first fragment)
        let hdr = make_ipv4_header(5, 6, 0x2000);
        let ops = Ipv4Ops;
        // First fragment should still return protocol
        assert_eq!(ops.next_proto(&hdr).unwrap(), 6);
    }

    #[test]
    fn ipv4_check_rejects_ipv6() {
        let mut hdr = [0u8; 20];
        hdr[0] = (6 << 4) | 5; // version=6, IHL=5
        let ops = Ipv4CheckOps;
        assert_eq!(
            ops.header_len(&hdr, 100).unwrap_err(),
            ParseError::UnknownProto
        );
    }

    #[test]
    fn ipv4_check_accepts_v4() {
        let hdr = make_ipv4_header(5, 6, 0);
        let ops = Ipv4CheckOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 20);
    }

    #[test]
    fn ipv4_fragment_detection() {
        let iph_data = make_ipv4_header(5, 6, 0);
        let iph = Ipv4Header::ref_from_prefix(&iph_data).unwrap().0;
        assert!(!iph.is_fragment());

        let iph_data = make_ipv4_header(5, 6, 0x2000); // MF set
        let iph = Ipv4Header::ref_from_prefix(&iph_data).unwrap().0;
        assert!(iph.is_fragment());
    }
}
