//! IP-in-IP tunnel encapsulation (RFC 2003).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `IpInIpOps` | `proto_defs/tunnel/proto_ip_in_ip.h:68-73` | `xdp2_parse_ip_in_ip` |
//! | `IpInIpOps::header_len` | `proto_ip_in_ip.h:52-55` | `ip_in_ip_length()` |
//! | `IpInIpOps::next_proto` | `proto_ip_in_ip.h:47-50` | `ip_in_ip_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};

/// IP-in-IP tunnel protocol operations.
///
/// Reimplements: `xdp2_parse_ip_in_ip` in `proto_ip_in_ip.h:68-73`
///
/// Parses the inner IPv4 header in an IP-in-IP tunnel. This is
/// functionally identical to standard IPv4 parsing — variable length
/// via IHL field, dispatches on protocol field.
pub struct IpInIpOps;

impl ProtocolOps for IpInIpOps {
    const MIN_LEN: usize = 20; // sizeof(struct iphdr)
    const NAME: &'static str = "IP-in-IP";

    /// Return inner IPv4 header length: IHL * 4.
    ///
    /// Reimplements: `ip_in_ip_length()` in `proto_ip_in_ip.h:52-55`
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        if hdr.is_empty() {
            return Err(ParseError::Length);
        }
        let ihl = (hdr[0] & 0x0F) as usize;
        Ok(ihl * 4)
    }

    /// Return inner IPv4 protocol field.
    ///
    /// Reimplements: `ip_in_ip_proto()` in `proto_ip_in_ip.h:47-50`
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        if hdr.len() < 10 {
            return Err(ParseError::Length);
        }
        Ok(hdr[9] as i32) // protocol field at offset 9 in IPv4 header
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv4_header(ihl: u8, protocol: u8) -> [u8; 20] {
        let mut hdr = [0u8; 20];
        hdr[0] = (4 << 4) | ihl;
        hdr[9] = protocol;
        hdr
    }

    #[test]
    fn ip_in_ip_standard_length() {
        let hdr = make_ipv4_header(5, 6); // IHL=5 → 20 bytes
        let ops = IpInIpOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 20);
    }

    #[test]
    fn ip_in_ip_with_options() {
        let hdr = make_ipv4_header(8, 6); // IHL=8 → 32 bytes
        let ops = IpInIpOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 32);
    }

    #[test]
    fn ip_in_ip_next_proto_tcp() {
        let hdr = make_ipv4_header(5, 6);
        let ops = IpInIpOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 6);
    }

    #[test]
    fn ip_in_ip_next_proto_udp() {
        let hdr = make_ipv4_header(5, 17);
        let ops = IpInIpOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 17);
    }
}
