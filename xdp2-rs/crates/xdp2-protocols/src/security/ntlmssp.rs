//! NTLMSSP (NT LAN Manager Security Support Provider) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `NtlmsspHeader` | `proto_ntlmssp.h:38-42` | `struct ntlmssp_hdr` |
//! | `NtlmsspOps` | `proto_ntlmssp.h:49-54` | `xdp2_parse_ntlmssp` |
//!
//! ## Behavioral Differences
//! - None. Leaf node — byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// NTLMSSP header (12 bytes).
///
/// Reimplements: `struct ntlmssp_hdr` in `proto_ntlmssp.h:38-42`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NtlmsspHeader {
    pub signature: [u8; 8],
    pub message_type: [u8; 4],
}

impl NtlmsspHeader {
    /// Message type (little-endian u32).
    pub fn message_type(&self) -> u32 {
        u32::from_le_bytes(self.message_type)
    }
}

/// NTLMSSP protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_ntlmssp` in `proto_ntlmssp.h:49-54`
pub struct NtlmsspOps;

impl ProtocolOps for NtlmsspOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "NTLMSSP";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntlmssp_is_leaf() {
        let ops = NtlmsspOps;
        assert!(matches!(ops.next_proto(&[0u8; 12]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn ntlmssp_header_fields() {
        let mut hdr = [0u8; 12];
        hdr[0..8].copy_from_slice(b"NTLMSSP\0");
        hdr[8..12].copy_from_slice(&1u32.to_le_bytes()); // negotiate
        let n = NtlmsspHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(&n.signature, b"NTLMSSP\0");
        assert_eq!(n.message_type(), 1);
    }
}
