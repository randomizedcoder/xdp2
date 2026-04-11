//! IP version overlay — dispatches to IPv4 or IPv6 based on version nibble.
//!
//! This is an overlay node (doesn't consume bytes) that reads the IP version
//! field (first 4 bits) to determine whether the packet is IPv4 or IPv6.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `IpOverlayOps` | `proto_defs/ip/proto_ip.h:59-64` | `xdp2_parse_ip` |
//! | `IpOverlayOps::next_proto` | `proto_ip.h:40-43` | `ip_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};

/// IP version overlay operations.
///
/// Reimplements: `xdp2_parse_ip` in `proto_ip.h:59-64`
///
/// Reads the IP version nibble (4 bits) from the first byte and returns
/// it as the next protocol number. IPv4 returns 4, IPv6 returns 6.
/// The protocol table maps these to the appropriate IPv4/IPv6 parse nodes.
pub struct IpOverlayOps;

impl ProtocolOps for IpOverlayOps {
    const MIN_LEN: usize = 1; // sizeof(struct ip_hdr_byte)
    const NAME: &'static str = "IP overlay";
    const OVERLAY: bool = true;

    /// Return IP version number (4 or 6).
    ///
    /// Reimplements: `ip_proto()` in `proto_ip.h:40-43`
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        Ok((hdr[0] >> 4) as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_overlay_ipv4() {
        let hdr = [(4 << 4) | 5]; // version=4, IHL=5
        let ops = IpOverlayOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 4);
    }

    #[test]
    fn ip_overlay_ipv6() {
        let hdr = [6 << 4]; // version=6
        let ops = IpOverlayOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 6);
    }

    #[test]
    fn ip_overlay_is_overlay() {
        assert!(IpOverlayOps::OVERLAY);
        assert_eq!(IpOverlayOps::MIN_LEN, 1);
    }
}
