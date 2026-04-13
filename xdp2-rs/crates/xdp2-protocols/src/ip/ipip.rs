//! IP-in-IP encapsulation protocol definitions.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `Ipv4InIpOps` | `proto_defs/ip/proto_ipv4ip.h:51-57` | `xdp2_parse_ipv4ip` |
//! | `Ipv4InIpOps::next_proto` | `proto_ipv4ip.h:36-39` | `ipv4_proto_default()` |
//! | `Ipv6InIpOps` | `proto_defs/ip/proto_ipv6ip.h:51-57` | `xdp2_parse_ipv6ip` |
//! | `Ipv6InIpOps::next_proto` | `proto_ipv6ip.h:36-39` | `ipv6_proto_default()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};

/// IPv4-in-IP encapsulation (IP protocol 4).
///
/// Reimplements: `xdp2_parse_ipv4ip` in `proto_ipv4ip.h:51-57`
///
/// Overlay + encap node. Marks an encapsulation boundary for IPv4
/// tunneled inside another IP header. Returns 0 to indicate IPv4.
pub struct Ipv4InIpOps;

impl ProtocolOps for Ipv4InIpOps {
    const MIN_LEN: usize = 20; // sizeof(struct iphdr)
    const NAME: &'static str = "IPv4 in IP";
    const OVERLAY: bool = true;
    const ENCAP: bool = true;

    /// Return 0 indicating IPv4.
    ///
    /// Reimplements: `ipv4_proto_default()` in `proto_ipv4ip.h:36-39`
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(0)
    }
}

/// IPv6-in-IP encapsulation (IP protocol 41).
///
/// Reimplements: `xdp2_parse_ipv6ip` in `proto_ipv6ip.h:51-57`
///
/// Overlay + encap node. Marks an encapsulation boundary for IPv6
/// tunneled inside another IP header. Returns 0 to indicate IPv6.
pub struct Ipv6InIpOps;

impl ProtocolOps for Ipv6InIpOps {
    const MIN_LEN: usize = 40; // sizeof(struct ipv6hdr)
    const NAME: &'static str = "IPv6 in IP";
    const OVERLAY: bool = true;
    const ENCAP: bool = true;

    /// Return 0 indicating IPv6.
    ///
    /// Reimplements: `ipv6_proto_default()` in `proto_ipv6ip.h:36-39`
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_in_ip_is_overlay_encap() {
        assert!(Ipv4InIpOps::OVERLAY);
        assert!(Ipv4InIpOps::ENCAP);
    }

    #[test]
    fn ipv4_in_ip_next_proto() {
        let ops = Ipv4InIpOps;
        assert_eq!(ops.next_proto(&[0u8; 20]).unwrap(), 0);
    }

    #[test]
    fn ipv4_in_ip_min_len() {
        assert_eq!(Ipv4InIpOps::MIN_LEN, 20);
    }

    #[test]
    fn ipv6_in_ip_is_overlay_encap() {
        assert!(Ipv6InIpOps::OVERLAY);
        assert!(Ipv6InIpOps::ENCAP);
    }

    #[test]
    fn ipv6_in_ip_next_proto() {
        let ops = Ipv6InIpOps;
        assert_eq!(ops.next_proto(&[0u8; 40]).unwrap(), 0);
    }

    #[test]
    fn ipv6_in_ip_min_len() {
        assert_eq!(Ipv6InIpOps::MIN_LEN, 40);
    }
}
