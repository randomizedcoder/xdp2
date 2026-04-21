//! OCSP (Online Certificate Status Protocol) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `OcspHeader` | `proto_ocsp.h:38-39` | `struct ocsp_hdr` |
//! | `OcspOps` | `proto_ocsp.h:46-51` | `xdp2_parse_ocsp` |
//!
//! ## Behavioral Differences
//! - None. Leaf node — byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// OCSP header (1 byte marker).
///
/// Reimplements: `struct ocsp_hdr` in `proto_ocsp.h:38-39`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct OcspHeader {
    pub marker: u8,
}

/// OCSP protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_ocsp` in `proto_ocsp.h:46-51`
pub struct OcspOps;

impl ProtocolOps for OcspOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "OCSP";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ocsp_is_leaf() {
        let ops = OcspOps;
        assert!(matches!(
            ops.next_proto(&[0u8; 1]),
            Err(ParseError::UnknownProto)
        ));
    }
}
