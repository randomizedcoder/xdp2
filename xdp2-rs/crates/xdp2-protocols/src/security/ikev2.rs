//! IKEv2 (Internet Key Exchange v2) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `Ikev2Header` | `proto_ikev2.h:38-47` | `struct ikev2hdr` |
//! | `Ikev2Ops` | `proto_ikev2.h:54-59` | `xdp2_parse_ikev2` |
//!
//! ## Behavioral Differences
//! - None. Leaf node — byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// IKEv2 header (28 bytes).
///
/// Reimplements: `struct ikev2hdr` in `proto_ikev2.h:38-47`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Ikev2Header {
    pub initiator_spi: [u8; 8],
    pub responder_spi: [u8; 8],
    pub next_payload: u8,
    pub version: u8,
    pub exchange_type: u8,
    pub flags: u8,
    pub message_id: [u8; 4],
    pub length: [u8; 4],
}

impl Ikev2Header {
    pub fn initiator_spi(&self) -> u64 {
        u64::from_be_bytes(self.initiator_spi)
    }
    pub fn responder_spi(&self) -> u64 {
        u64::from_be_bytes(self.responder_spi)
    }
    pub fn message_id(&self) -> u32 {
        u32::from_be_bytes(self.message_id)
    }
    pub fn length(&self) -> u32 {
        u32::from_be_bytes(self.length)
    }
}

/// IKEv2 protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_ikev2` in `proto_ikev2.h:54-59`
pub struct Ikev2Ops;

impl ProtocolOps for Ikev2Ops {
    const MIN_LEN: usize = 28;
    const NAME: &'static str = "IKEv2";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ikev2_is_leaf() {
        let ops = Ikev2Ops;
        assert!(matches!(ops.next_proto(&[0u8; 28]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn ikev2_header_fields() {
        let mut hdr = [0u8; 28];
        hdr[0..8].copy_from_slice(&0x1122334455667788u64.to_be_bytes());
        hdr[20..24].copy_from_slice(&1u32.to_be_bytes());
        hdr[24..28].copy_from_slice(&28u32.to_be_bytes());
        let ike = Ikev2Header::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(ike.initiator_spi(), 0x1122334455667788);
        assert_eq!(ike.message_id(), 1);
        assert_eq!(ike.length(), 28);
    }
}
