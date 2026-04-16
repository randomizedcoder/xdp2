//! GUE (Generic UDP Encapsulation) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `GueHeader` | `proto_gue.h:50-54` | `struct guehdr` |
//! | `GueOps` | `proto_gue.h:70-75` | `xdp2_parse_gue` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// GUE header (4 bytes).
///
/// Reimplements: `struct guehdr` in `proto_gue.h:50-54`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct GueHeader {
    /// Version(2) + Hdr len(5) + C(1)
    pub hdrlen_version: u8,
    /// IP protocol (C=0) or control type (C=1)
    pub proto_ctype: u8,
    /// Flags
    pub flags: [u8; 2],
}

/// GUE protocol operations (encap).
///
/// Reimplements: `xdp2_parse_gue` in `proto_gue.h:70-75`
pub struct GueOps;

impl ProtocolOps for GueOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "GUE";
    const ENCAP: bool = true;

    /// Return proto_ctype field (IP protocol number).
    ///
    /// Reimplements: `gue_proto()` in `proto_gue.h:56-59`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let gue = GueHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(gue.proto_ctype as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gue_next_proto() {
        let mut hdr = [0u8; 4];
        hdr[1] = 4; // IPPROTO_IPIP
        assert_eq!(GueOps.next_proto(&hdr).unwrap(), 4);
    }

    #[test]
    fn gue_is_encap() {
        assert!(GueOps::ENCAP);
    }
}
