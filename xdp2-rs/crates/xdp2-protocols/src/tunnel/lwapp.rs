//! LWAPP (Lightweight Access Point Protocol) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `LwappHeader` | `proto_lwapp.h:37-42` | `struct lwapp_hdr` |
//! | `LwappOps` | `proto_lwapp.h:52-56` | `xdp2_parse_lwapp` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// LWAPP header (6 bytes).
///
/// Reimplements: `struct lwapp_hdr` in `proto_lwapp.h:37-42`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct LwappHeader {
    pub version_flags: u8,
    pub fragment_id: u8,
    pub length: [u8; 2],
    pub status: [u8; 2],
}

/// LWAPP protocol operations (encap leaf — no next protocol dispatch).
///
/// Reimplements: `xdp2_parse_lwapp` in `proto_lwapp.h:52-56`
pub struct LwappOps;

impl ProtocolOps for LwappOps {
    const MIN_LEN: usize = 6;
    const NAME: &'static str = "LWAPP";
    const ENCAP: bool = true;

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lwapp_is_encap_leaf() {
        assert!(LwappOps::ENCAP);
        assert!(LwappOps.next_proto(&[0u8; 6]).is_err());
    }
}
