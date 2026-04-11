//! QUIC (RFC 9000) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `QuicHeader` | `proto_defs/transport/proto_quic.h:37-39` | `struct quic_hdr` |
//! | `QuicOps` | `proto_quic.h:49-52` | `xdp2_parse_quic` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// QUIC header (1 byte minimum — first byte determines form).
///
/// Reimplements: `struct quic_hdr` in `proto_quic.h:37-39`
///
/// QUIC has complex variable-length headers. This just captures the
/// first byte for form detection. Full QUIC parsing would require
/// connection state.
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct QuicHeader {
    /// Header form (1 bit) + fixed (1 bit) + type/spin bits
    pub header_form: u8,
}

impl QuicHeader {
    /// Whether this is a long header (bit 7 set).
    pub fn is_long_header(&self) -> bool {
        (self.header_form & 0x80) != 0
    }
}

/// QUIC protocol operations (leaf node).
///
/// Reimplements: `xdp2_parse_quic` in `proto_quic.h:49-52`
///
/// Leaf protocol — QUIC has complex variable-length encrypted headers
/// that require connection state to fully parse.
pub struct QuicOps;

impl ProtocolOps for QuicOps {
    const MIN_LEN: usize = 1; // sizeof(struct quic_hdr)
    const NAME: &'static str = "QUIC";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_is_leaf() {
        let ops = QuicOps;
        assert!(ops.next_proto(&[0u8; 1]).is_err());
    }

    #[test]
    fn quic_fixed_length() {
        let ops = QuicOps;
        assert_eq!(ops.header_len(&[0u8; 1], 100).unwrap(), 1);
    }

    #[test]
    fn quic_long_header() {
        let hdr = [0xC0u8]; // bit 7 set = long header
        let q = QuicHeader::ref_from_prefix(&hdr).unwrap().0;
        assert!(q.is_long_header());
    }

    #[test]
    fn quic_short_header() {
        let hdr = [0x40u8]; // bit 7 clear = short header
        let q = QuicHeader::ref_from_prefix(&hdr).unwrap().0;
        assert!(!q.is_long_header());
    }
}
