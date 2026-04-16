//! TLS (Transport Layer Security) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `TlsHeader` | `proto_tls.h:38-43` | `struct tls_hdr` |
//! | `TlsOps` | `proto_tls.h:50-55` | `xdp2_parse_tls` |
//!
//! ## Behavioral Differences
//! - None. Leaf node — byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// TLS record header (5 bytes).
///
/// Reimplements: `struct tls_hdr` in `proto_tls.h:38-43`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct TlsHeader {
    pub content_type: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub length: [u8; 2],
}

impl TlsHeader {
    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }
}

/// TLS protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_tls` in `proto_tls.h:50-55`
pub struct TlsOps;

impl ProtocolOps for TlsOps {
    const MIN_LEN: usize = 5;
    const NAME: &'static str = "TLS";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_is_leaf() {
        let ops = TlsOps;
        assert!(matches!(ops.next_proto(&[0u8; 5]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn tls_header_fields() {
        let mut hdr = [0u8; 5];
        hdr[0] = 23; // application data
        hdr[1] = 3;  // TLS 1.2
        hdr[2] = 3;
        hdr[3..5].copy_from_slice(&1024u16.to_be_bytes());
        let tls = TlsHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(tls.content_type, 23);
        assert_eq!(tls.version_major, 3);
        assert_eq!(tls.version_minor, 3);
        assert_eq!(tls.length(), 1024);
    }
}
