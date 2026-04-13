//! MPLS (Multi-Protocol Label Switching) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `MplsLabel` | `<linux/mpls.h>` | `struct mpls_label` |
//! | `MplsOps` | `proto_defs/tunnel/proto_mpls.h:20-23` | `xdp2_parse_mpls` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// MPLS label entry (4 bytes).
///
/// Reimplements: `struct mpls_label` from `<linux/mpls.h>`
///
/// Format: 20-bit label | 3-bit TC | 1-bit S (bottom-of-stack) | 8-bit TTL
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct MplsLabel {
    pub entry: [u8; 4],
}

impl MplsLabel {
    /// Raw 32-bit label entry (big-endian).
    pub fn raw(&self) -> u32 {
        u32::from_be_bytes(self.entry)
    }

    /// 20-bit label value.
    pub fn label(&self) -> u32 {
        self.raw() >> 12
    }

    /// Traffic Class (3 bits).
    pub fn tc(&self) -> u8 {
        ((self.raw() >> 9) & 0x07) as u8
    }

    /// Bottom-of-stack flag (1 = last label in stack).
    pub fn bos(&self) -> bool {
        (self.raw() >> 8) & 1 == 1
    }

    /// TTL (8 bits).
    pub fn ttl(&self) -> u8 {
        (self.raw() & 0xFF) as u8
    }
}

/// MPLS protocol operations (leaf node).
///
/// Reimplements: `xdp2_parse_mpls` in `proto_mpls.h:20-23`
///
/// The C definition uses `min_len = 2 * sizeof(struct mpls_label)` = 8 bytes
/// (expects at least 2 MPLS labels in the stack).
pub struct MplsOps;

impl ProtocolOps for MplsOps {
    const MIN_LEN: usize = 8; // 2 * sizeof(struct mpls_label)
    const NAME: &'static str = "MPLS";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mpls_fixed_length() {
        let ops = MplsOps;
        assert_eq!(ops.header_len(&[0; 8], 100).unwrap(), 8);
    }

    #[test]
    fn mpls_label_fields() {
        // Label=100, TC=5, S=1 (BOS), TTL=64
        // Binary: 00000000000001100100 101 1 01000000
        // = 0x00064B40
        let entry = 0x00064B40u32.to_be_bytes();
        let label = MplsLabel::ref_from_prefix(&entry).unwrap().0;
        assert_eq!(label.label(), 100);
        assert_eq!(label.tc(), 5);
        assert!(label.bos());
        assert_eq!(label.ttl(), 64);
    }

    #[test]
    fn mpls_label_no_bos() {
        // Label=200, TC=0, S=0, TTL=255
        // = (200 << 12) | (0 << 9) | (0 << 8) | 255
        let val = (200u32 << 12) | 255;
        let entry = val.to_be_bytes();
        let label = MplsLabel::ref_from_prefix(&entry).unwrap().0;
        assert_eq!(label.label(), 200);
        assert!(!label.bos());
        assert_eq!(label.ttl(), 255);
    }

    #[test]
    fn mpls_is_leaf() {
        let ops = MplsOps;
        assert!(ops.next_proto(&[0; 8]).is_err());
    }
}
