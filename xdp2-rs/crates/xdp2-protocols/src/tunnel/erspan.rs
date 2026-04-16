//! ERSPAN protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `ErspanHeader` | `proto_defs/tunnel/proto_erspan.h:38-41` | `struct erspan_base_hdr` |
//! | `ErspanOps` | `proto_erspan.h:51-54` | `xdp2_parse_erspan` |
//!
//! ## Behavioral Differences
//! - None. Leaf node — byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// ERSPAN base header (4 bytes).
///
/// Reimplements: `struct erspan_base_hdr` in `proto_erspan.h:38-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ErspanHeader {
    pub ver_vlan: [u8; 2],
    pub cos_en_t_session: [u8; 2],
}

/// ERSPAN protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_erspan` in `proto_erspan.h:51-54`
pub struct ErspanOps;

impl ProtocolOps for ErspanOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "ERSPAN";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erspan_is_leaf() {
        assert!(ErspanOps.next_proto(&[0u8; 4]).is_err());
    }
}
