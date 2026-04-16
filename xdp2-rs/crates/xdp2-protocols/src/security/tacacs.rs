//! TACACS+ (Terminal Access Controller Access-Control System Plus) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `TacacsHeader` | `proto_tacacs.h:38-45` | `struct tacacs_hdr` |
//! | `TacacsOps` | `proto_tacacs.h:52-57` | `xdp2_parse_tacacs` |
//!
//! ## Behavioral Differences
//! - None. Leaf node — byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// TACACS+ header (12 bytes).
///
/// Reimplements: `struct tacacs_hdr` in `proto_tacacs.h:38-45`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct TacacsHeader {
    pub major_minor: u8,
    pub pkt_type: u8,
    pub seq_no: u8,
    pub flags: u8,
    pub session_id: [u8; 4],
    pub length: [u8; 4],
}

impl TacacsHeader {
    /// Major version (upper 4 bits).
    pub fn major_version(&self) -> u8 {
        self.major_minor >> 4
    }
    /// Minor version (lower 4 bits).
    pub fn minor_version(&self) -> u8 {
        self.major_minor & 0x0F
    }
    pub fn session_id(&self) -> u32 {
        u32::from_be_bytes(self.session_id)
    }
    pub fn length(&self) -> u32 {
        u32::from_be_bytes(self.length)
    }
}

/// TACACS+ protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_tacacs` in `proto_tacacs.h:52-57`
pub struct TacacsOps;

impl ProtocolOps for TacacsOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "TACACS+";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tacacs_is_leaf() {
        let ops = TacacsOps;
        assert!(matches!(ops.next_proto(&[0u8; 12]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn tacacs_header_fields() {
        let mut hdr = [0u8; 12];
        hdr[0] = 0xC1; // major=12, minor=1
        hdr[1] = 1; // authentication
        hdr[4..8].copy_from_slice(&0xAABBCCDDu32.to_be_bytes());
        hdr[8..12].copy_from_slice(&64u32.to_be_bytes());
        let t = TacacsHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(t.major_version(), 12);
        assert_eq!(t.minor_version(), 1);
        assert_eq!(t.session_id(), 0xAABBCCDD);
        assert_eq!(t.length(), 64);
    }
}
