//! PIM (Protocol Independent Multicast) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `PimHeader` | `proto_defs/ip/proto_pim.h:36-40` | `struct pimhdr` |
//! | `PimOps` | `proto_pim.h:50-53` | `xdp2_parse_pim` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// PIM header (4 bytes).
///
/// Reimplements: `struct pimhdr` in `proto_pim.h:36-40`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct PimHeader {
    /// PIM version (4 bits) + type (4 bits)
    pub type_ver: u8,
    /// Reserved
    pub reserved: u8,
    /// Checksum
    pub checksum: [u8; 2],
}

impl PimHeader {
    /// PIM version (upper 4 bits).
    pub fn version(&self) -> u8 {
        self.type_ver >> 4
    }

    /// PIM message type (lower 4 bits).
    pub fn msg_type(&self) -> u8 {
        self.type_ver & 0x0F
    }
}

/// PIM protocol operations (leaf node).
///
/// Reimplements: `xdp2_parse_pim` in `proto_pim.h:50-53`
pub struct PimOps;

impl ProtocolOps for PimOps {
    const MIN_LEN: usize = 4; // sizeof(struct pimhdr)
    const NAME: &'static str = "PIM";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pim_is_leaf() {
        let ops = PimOps;
        assert!(ops.next_proto(&[0u8; 4]).is_err());
    }

    #[test]
    fn pim_fixed_length() {
        let ops = PimOps;
        assert_eq!(ops.header_len(&[0u8; 4], 100).unwrap(), 4);
    }

    #[test]
    fn pim_version_and_type() {
        let mut hdr = [0u8; 4];
        hdr[0] = (2 << 4) | 1; // version=2, type=Hello
        let pim = PimHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(pim.version(), 2);
        assert_eq!(pim.msg_type(), 1);
    }
}
