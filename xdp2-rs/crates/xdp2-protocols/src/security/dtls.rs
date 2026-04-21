//! DTLS (Datagram Transport Layer Security) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `DtlsHeader` | `proto_dtls.h:38-46` | `struct dtls_hdr` |
//! | `DtlsOps` | `proto_dtls.h:53-58` | `xdp2_parse_dtls` |
//!
//! ## Behavioral Differences
//! - None. Leaf node — byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// DTLS record header (13 bytes).
///
/// Reimplements: `struct dtls_hdr` in `proto_dtls.h:38-46`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct DtlsHeader {
    pub content_type: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub epoch: [u8; 2],
    pub sequence: [u8; 6],
    pub length: [u8; 2],
}

impl DtlsHeader {
    pub fn epoch(&self) -> u16 {
        u16::from_be_bytes(self.epoch)
    }
    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }
}

/// DTLS protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_dtls` in `proto_dtls.h:53-58`
pub struct DtlsOps;

impl ProtocolOps for DtlsOps {
    const MIN_LEN: usize = 13;
    const NAME: &'static str = "DTLS";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dtls_is_leaf() {
        let ops = DtlsOps;
        assert!(matches!(
            ops.next_proto(&[0u8; 13]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn dtls_header_fields() {
        let mut hdr = [0u8; 13];
        hdr[0] = 22; // handshake
        hdr[3..5].copy_from_slice(&1u16.to_be_bytes()); // epoch
        hdr[11..13].copy_from_slice(&512u16.to_be_bytes()); // length
        let dtls = DtlsHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(dtls.content_type, 22);
        assert_eq!(dtls.epoch(), 1);
        assert_eq!(dtls.length(), 512);
    }
}
