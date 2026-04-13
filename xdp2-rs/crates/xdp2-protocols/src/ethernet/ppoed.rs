//! PPPoE Discovery (RFC 2516) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `PpoedHeader` | `proto_defs/ethernet/proto_ppoed.h:37-42` | `struct ppoed_hdr` |
//! | `PpoedOps` | `proto_ppoed.h:52-55` | `xdp2_parse_ppoed` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// PPPoE Discovery codes.
pub const PPOED_CODE_PADI: u8 = 0x09;
pub const PPOED_CODE_PADO: u8 = 0x07;
pub const PPOED_CODE_PADR: u8 = 0x19;
pub const PPOED_CODE_PADS: u8 = 0x65;
pub const PPOED_CODE_PADT: u8 = 0xA7;

/// PPPoE Discovery header (6 bytes).
///
/// Reimplements: `struct ppoed_hdr` in `proto_ppoed.h:37-42`
///
/// Discovery stage of PPPoE (PADI, PADO, PADR, PADS, PADT).
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct PpoedHeader {
    /// Version (4 bits) + Type (4 bits) — both should be 1
    pub vertype: u8,
    /// Discovery code (PADI=0x09, PADO=0x07, PADR=0x19, PADS=0x65, PADT=0xA7)
    pub code: u8,
    /// Session ID
    pub session_id: [u8; 2],
    /// Payload length
    pub length: [u8; 2],
}

impl PpoedHeader {
    /// Version field (upper 4 bits).
    pub fn version(&self) -> u8 {
        self.vertype >> 4
    }

    /// Type field (lower 4 bits).
    pub fn ptype(&self) -> u8 {
        self.vertype & 0x0F
    }

    /// Session ID.
    pub fn session_id(&self) -> u16 {
        u16::from_be_bytes(self.session_id)
    }

    /// Payload length.
    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }
}

/// PPPoE Discovery protocol operations (leaf node).
///
/// Reimplements: `xdp2_parse_ppoed` in `proto_ppoed.h:52-55`
///
/// Fixed 6-byte header. Leaf protocol — discovery phase has no PPP payload.
pub struct PpoedOps;

impl ProtocolOps for PpoedOps {
    const MIN_LEN: usize = 6; // sizeof(struct ppoed_hdr)
    const NAME: &'static str = "PPPoE Discovery";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ppoed_header(code: u8) -> [u8; 6] {
        let mut hdr = [0u8; 6];
        hdr[0] = 0x11; // version=1, type=1
        hdr[1] = code;
        hdr
    }

    #[test]
    fn ppoed_fixed_length() {
        let hdr = make_ppoed_header(PPOED_CODE_PADI);
        let ops = PpoedOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 6);
    }

    #[test]
    fn ppoed_is_leaf() {
        let ops = PpoedOps;
        assert!(ops.next_proto(&[0u8; 6]).is_err());
    }

    #[test]
    fn ppoed_version_type() {
        let hdr = make_ppoed_header(PPOED_CODE_PADI);
        let ppoed = PpoedHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(ppoed.version(), 1);
        assert_eq!(ppoed.ptype(), 1);
        assert_eq!(ppoed.code, PPOED_CODE_PADI);
    }
}
