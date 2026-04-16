//! HSR (High-availability Seamless Redundancy) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `HsrHeader` | `proto_hsr.h:37-41` | `struct hsr_tag` |
//! | `HsrOps` | `proto_hsr.h:58-62` | `xdp2_parse_hsr` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// HSR tag header (6 bytes).
///
/// Reimplements: `struct hsr_tag` in `proto_hsr.h:37-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct HsrHeader {
    pub path_and_lsdu_size: [u8; 2],
    pub sequence_nr: [u8; 2],
    pub encap_proto: [u8; 2],
}

impl HsrHeader {
    pub fn encap_proto(&self) -> u16 {
        u16::from_be_bytes(self.encap_proto)
    }
}

/// HSR protocol operations.
///
/// Reimplements: `xdp2_parse_hsr` in `proto_hsr.h:58-62`
pub struct HsrOps;

impl ProtocolOps for HsrOps {
    const MIN_LEN: usize = 6;
    const NAME: &'static str = "HSR";

    /// Return encapsulated EtherType.
    ///
    /// Reimplements: `hsr_proto()` in `proto_hsr.h:44-47`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let h = HsrHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(h.encap_proto() as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hsr_next_proto() {
        let mut hdr = [0u8; 6];
        hdr[4..6].copy_from_slice(&0x0800u16.to_be_bytes());
        assert_eq!(HsrOps.next_proto(&hdr).unwrap(), 0x0800);
    }
}
