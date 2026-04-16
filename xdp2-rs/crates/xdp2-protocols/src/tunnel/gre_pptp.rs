//! GRE-PPTP protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `GrePptpHeader` | `proto_gre_pptp.h:37-42` | `struct gre_pptp_hdr` |
//! | `GrePptpOps` | `proto_gre_pptp.h:52-55` | `xdp2_parse_gre_pptp` |
//!
//! ## Behavioral Differences
//! - None. Leaf node — byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// GRE-PPTP header (8 bytes).
///
/// Reimplements: `struct gre_pptp_hdr` in `proto_gre_pptp.h:37-42`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct GrePptpHeader {
    pub flags_version: [u8; 2],
    pub protocol: [u8; 2],
    pub payload_len: [u8; 2],
    pub call_id: [u8; 2],
}

/// GRE-PPTP protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_gre_pptp` in `proto_gre_pptp.h:52-55`
pub struct GrePptpOps;

impl ProtocolOps for GrePptpOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "GRE-PPTP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gre_pptp_is_leaf() {
        assert!(GrePptpOps.next_proto(&[0u8; 8]).is_err());
    }
}
