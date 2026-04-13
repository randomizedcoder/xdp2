//! ICMP (v4 and v6) protocol definitions.
//!
//! Both ICMPv4 and ICMPv6 are overlay protocols — they consume all
//! remaining packet bytes (`header_len = maxlen`) and return the ICMP
//! type field as the next protocol number for optional sub-type dispatch.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `IcmpHeader` | `<linux/icmp.h>` | `struct icmphdr` |
//! | `Icmp6Header` | `<linux/icmpv6.h>` | `struct icmp6hdr` |
//! | `IcmpV4Ops` | `proto_defs/ip/proto_icmp.h:115-121` | `xdp2_parse_icmpv4` |
//! | `IcmpV6Ops` | `proto_defs/ip/proto_icmp.h:127-133` | `xdp2_parse_icmpv6` |
//! | `icmp_get_type()` | `proto_icmp.h:48-51` | `icmp_get_type()` |
//! | `icmp_all_len()` | `proto_icmp.h:39-42` | `icmp_all_len()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// ICMP echo types that carry an identifier field.
pub const ICMP_ECHO: u8 = 8;
pub const ICMP_ECHOREPLY: u8 = 0;
pub const ICMP_TIMESTAMP: u8 = 13;
pub const ICMP_TIMESTAMPREPLY: u8 = 14;
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;

/// ICMPv4 header (8 bytes).
///
/// Reimplements: `struct icmphdr` from `<linux/icmp.h>`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IcmpHeader {
    /// ICMP type
    pub icmp_type: u8,
    /// ICMP code
    pub code: u8,
    /// Checksum
    pub checksum: [u8; 2],
    /// Type-specific data (echo id+seq, gateway, frag mtu, etc.)
    pub un: [u8; 4],
}

impl IcmpHeader {
    /// Echo identifier (valid for echo request/reply types).
    pub fn echo_id(&self) -> u16 {
        u16::from_be_bytes([self.un[0], self.un[1]])
    }

    /// Echo sequence number (valid for echo request/reply types).
    pub fn echo_seq(&self) -> u16 {
        u16::from_be_bytes([self.un[2], self.un[3]])
    }

    /// Check if this ICMP type carries an identifier field.
    ///
    /// Reimplements: `icmp_has_id()` in `proto_icmp.h:53-64`
    pub fn has_id(&self) -> bool {
        matches!(
            self.icmp_type,
            ICMP_ECHO | ICMP_ECHOREPLY | ICMP_TIMESTAMP | ICMP_TIMESTAMPREPLY
        )
    }
}

/// ICMPv6 header (8 bytes).
///
/// Reimplements: `struct icmp6hdr` from `<linux/icmpv6.h>`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Icmp6Header {
    /// ICMPv6 type
    pub icmp6_type: u8,
    /// ICMPv6 code
    pub icmp6_code: u8,
    /// Checksum
    pub icmp6_cksum: [u8; 2],
    /// Type-specific data
    pub icmp6_data: [u8; 4],
}

impl Icmp6Header {
    /// Check if this ICMPv6 type carries an identifier field.
    pub fn has_id(&self) -> bool {
        matches!(self.icmp6_type, ICMPV6_ECHO_REQUEST | ICMPV6_ECHO_REPLY)
    }
}

/// ICMPv4 protocol operations (overlay node).
///
/// Reimplements: `xdp2_parse_icmpv4` in `proto_icmp.h:115-121`
///
/// ICMP is an overlay that consumes all remaining bytes. The `next_proto`
/// returns the ICMP type field for optional sub-type dispatch tables.
pub struct IcmpV4Ops;

impl ProtocolOps for IcmpV4Ops {
    const MIN_LEN: usize = 8; // sizeof(struct icmphdr)
    const NAME: &'static str = "ICMPv4";
    const OVERLAY: bool = true;

    /// Return remaining packet length (consumes all bytes).
    ///
    /// Reimplements: `icmp_all_len()` in `proto_icmp.h:39-42`
    #[inline]
    fn header_len(&self, _hdr: &[u8], maxlen: usize) -> Result<usize, ParseError> {
        Ok(maxlen)
    }

    /// Return ICMP type for sub-type dispatch.
    ///
    /// Reimplements: `icmp_get_type()` in `proto_icmp.h:48-51`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let icmp = IcmpHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(icmp.icmp_type as i32)
    }
}

/// ICMPv6 protocol operations (overlay node).
///
/// Reimplements: `xdp2_parse_icmpv6` in `proto_icmp.h:127-133`
///
/// Same behavior as ICMPv4 — overlay, consumes all bytes, returns type field.
pub struct IcmpV6Ops;

impl ProtocolOps for IcmpV6Ops {
    const MIN_LEN: usize = 8; // sizeof(struct icmp6hdr)
    const NAME: &'static str = "ICMPv6";
    const OVERLAY: bool = true;

    /// Return remaining packet length.
    #[inline]
    fn header_len(&self, _hdr: &[u8], maxlen: usize) -> Result<usize, ParseError> {
        Ok(maxlen)
    }

    /// Return ICMPv6 type for sub-type dispatch.
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let icmp = Icmp6Header::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(icmp.icmp6_type as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_icmpv4(icmp_type: u8, code: u8) -> [u8; 8] {
        let mut hdr = [0u8; 8];
        hdr[0] = icmp_type;
        hdr[1] = code;
        hdr
    }

    #[test]
    fn icmpv4_echo_request() {
        let hdr = make_icmpv4(ICMP_ECHO, 0);
        let ops = IcmpV4Ops;
        assert_eq!(ops.next_proto(&hdr).unwrap(), ICMP_ECHO as i32);
    }

    #[test]
    fn icmpv4_consumes_all_bytes() {
        let hdr = [0u8; 64];
        let ops = IcmpV4Ops;
        assert_eq!(ops.header_len(&hdr, 64).unwrap(), 64);
        assert_eq!(ops.header_len(&hdr, 32).unwrap(), 32);
    }

    #[test]
    fn icmpv4_is_overlay() {
        assert!(IcmpV4Ops::OVERLAY);
    }

    #[test]
    fn icmpv4_has_id() {
        let echo_hdr = make_icmpv4(ICMP_ECHO, 0);
        let echo = IcmpHeader::ref_from_prefix(&echo_hdr).unwrap().0;
        assert!(echo.has_id());

        let unreach_hdr = make_icmpv4(3, 0);
        let dest_unreach = IcmpHeader::ref_from_prefix(&unreach_hdr).unwrap().0;
        assert!(!dest_unreach.has_id());
    }

    #[test]
    fn icmpv6_echo_request() {
        let mut hdr = [0u8; 8];
        hdr[0] = ICMPV6_ECHO_REQUEST;
        let ops = IcmpV6Ops;
        assert_eq!(ops.next_proto(&hdr).unwrap(), ICMPV6_ECHO_REQUEST as i32);
    }

    #[test]
    fn icmpv6_is_overlay() {
        assert!(IcmpV6Ops::OVERLAY);
    }
}
