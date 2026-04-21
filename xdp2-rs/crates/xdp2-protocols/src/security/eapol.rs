//! EAPOL (IEEE 802.1X) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `EapolHeader` | `proto_eapol.h:38-41` | `struct eapol_hdr` |
//! | `EapolOps` | `proto_eapol.h:48-53` | `xdp2_parse_eapol` |
//!
//! ## Behavioral Differences
//! - None. Leaf node — byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// EAPOL header (4 bytes).
///
/// Reimplements: `struct eapol_hdr` in `proto_eapol.h:38-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct EapolHeader {
    pub version: u8,
    pub pkt_type: u8,
    pub body_len: [u8; 2],
}

impl EapolHeader {
    pub fn body_len(&self) -> u16 {
        u16::from_be_bytes(self.body_len)
    }
}

/// EAPOL protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_eapol` in `proto_eapol.h:48-53`
pub struct EapolOps;

impl ProtocolOps for EapolOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "EAPOL";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eapol_is_leaf() {
        let ops = EapolOps;
        assert!(matches!(
            ops.next_proto(&[0u8; 4]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn eapol_header_fields() {
        let mut hdr = [0u8; 4];
        hdr[0] = 2; // version
        hdr[1] = 0; // EAP-Packet
        hdr[2..4].copy_from_slice(&128u16.to_be_bytes());
        let eapol = EapolHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(eapol.version, 2);
        assert_eq!(eapol.pkt_type, 0);
        assert_eq!(eapol.body_len(), 128);
    }
}
