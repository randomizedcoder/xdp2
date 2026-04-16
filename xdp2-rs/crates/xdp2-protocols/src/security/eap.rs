//! EAP (Extensible Authentication Protocol) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `EapHeader` | `proto_eap.h:38-42` | `struct eap_hdr` |
//! | `EapOps` | `proto_eap.h:49-54` | `xdp2_parse_eap` |
//!
//! ## Behavioral Differences
//! - None. Leaf node — byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// EAP header (4 bytes).
///
/// Reimplements: `struct eap_hdr` in `proto_eap.h:38-42`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct EapHeader {
    pub code: u8,
    pub id: u8,
    pub length: [u8; 2],
}

impl EapHeader {
    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }
}

/// EAP protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_eap` in `proto_eap.h:49-54`
pub struct EapOps;

impl ProtocolOps for EapOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "EAP";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eap_is_leaf() {
        let ops = EapOps;
        assert!(matches!(ops.next_proto(&[0u8; 4]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn eap_header_fields() {
        let mut hdr = [0u8; 4];
        hdr[0] = 1; // request
        hdr[1] = 42; // id
        hdr[2..4].copy_from_slice(&256u16.to_be_bytes());
        let eap = EapHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(eap.code, 1);
        assert_eq!(eap.id, 42);
        assert_eq!(eap.length(), 256);
    }
}
