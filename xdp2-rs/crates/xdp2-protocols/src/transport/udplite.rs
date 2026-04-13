//! UDP-Lite (Lightweight User Datagram Protocol, RFC 3828) definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `UdpLiteHeader` | `proto_defs/transport/proto_udplite.h:37-42` | `struct udplitehdr` |
//! | `UdpLiteOps` | `proto_udplite.h:52-55` | `xdp2_parse_udplite` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// UDP-Lite header (8 bytes).
///
/// Reimplements: `struct udplitehdr` in `proto_udplite.h:37-42`
///
/// Same layout as UDP but the length field is checksum coverage instead.
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct UdpLiteHeader {
    /// Source port
    pub source: [u8; 2],
    /// Destination port
    pub dest: [u8; 2],
    /// Checksum coverage (unlike UDP length)
    pub coverage: [u8; 2],
    /// Checksum
    pub checksum: [u8; 2],
}

impl UdpLiteHeader {
    /// Source port.
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.source)
    }

    /// Destination port.
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.dest)
    }

    /// Checksum coverage.
    pub fn coverage(&self) -> u16 {
        u16::from_be_bytes(self.coverage)
    }
}

/// UDP-Lite protocol operations (leaf node).
///
/// Reimplements: `xdp2_parse_udplite` in `proto_udplite.h:52-55`
pub struct UdpLiteOps;

impl ProtocolOps for UdpLiteOps {
    const MIN_LEN: usize = 8; // sizeof(struct udplitehdr)
    const NAME: &'static str = "UDP-Lite";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udplite_is_leaf() {
        let ops = UdpLiteOps;
        assert!(ops.next_proto(&[0u8; 8]).is_err());
    }

    #[test]
    fn udplite_fixed_length() {
        let ops = UdpLiteOps;
        assert_eq!(ops.header_len(&[0u8; 8], 100).unwrap(), 8);
    }

    #[test]
    fn udplite_ports() {
        let mut hdr = [0u8; 8];
        hdr[0..2].copy_from_slice(&8080u16.to_be_bytes());
        hdr[2..4].copy_from_slice(&443u16.to_be_bytes());
        let ul = UdpLiteHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(ul.src_port(), 8080);
        assert_eq!(ul.dst_port(), 443);
    }
}
