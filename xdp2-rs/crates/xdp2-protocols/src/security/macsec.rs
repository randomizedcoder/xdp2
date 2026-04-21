//! MACsec (IEEE 802.1AE) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `MacsecHeader` | `proto_macsec.h:39-43` | `struct macsec_sectag` |
//! | `MacsecOps` | `proto_macsec.h:50-55` | `xdp2_parse_macsec` |
//!
//! ## Behavioral Differences
//! - None. Leaf node — byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// MACsec SecTAG header (6 bytes).
///
/// Reimplements: `struct macsec_sectag` in `proto_macsec.h:39-43`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct MacsecHeader {
    pub tci_an: u8,
    pub sl: u8,
    pub pn: [u8; 4],
}

impl MacsecHeader {
    /// TCI field (upper 6 bits).
    pub fn tci(&self) -> u8 {
        self.tci_an >> 2
    }
    /// Association Number (lower 2 bits).
    pub fn an(&self) -> u8 {
        self.tci_an & 0x03
    }
    /// Packet Number.
    pub fn pn(&self) -> u32 {
        u32::from_be_bytes(self.pn)
    }
}

/// MACsec protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_macsec` in `proto_macsec.h:50-55`
pub struct MacsecOps;

impl ProtocolOps for MacsecOps {
    const MIN_LEN: usize = 6;
    const NAME: &'static str = "MACsec";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macsec_is_leaf() {
        let ops = MacsecOps;
        assert!(matches!(
            ops.next_proto(&[0u8; 6]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn macsec_header_fields() {
        let mut hdr = [0u8; 6];
        hdr[0] = 0b10110001; // TCI=0b101100=44, AN=0b01=1
        hdr[1] = 0x20; // SL
        hdr[2..6].copy_from_slice(&100u32.to_be_bytes());
        let m = MacsecHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(m.tci(), 44);
        assert_eq!(m.an(), 1);
        assert_eq!(m.pn(), 100);
    }
}
