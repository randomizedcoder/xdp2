//! Netlink sub-protocol definitions (leaf nodes).
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `GenlmsghdrHeader` | `proto_defs/netlink/proto_genetlink.h` | `struct genlmsghdr` |
//! | `GenlmsghdrOps` | `proto_genetlink.h` | `xdp2_parse_genetlink` |
//! | `NlattrHeader` | `proto_defs/netlink/proto_nlattr.h` | `struct nlattr` |
//! | `NlattrOps` | `proto_nlattr.h` | `xdp2_parse_nlattr` |
//!
//! ## Behavioral Differences
//! - None. All are leaf nodes.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

// ---------------------------------------------------------------------------
// Generic Netlink
// ---------------------------------------------------------------------------

/// Generic Netlink header (4 bytes).
///
/// Reimplements: `struct genlmsghdr` in `proto_genetlink.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct GenlmsghdrHeader {
    pub cmd: u8,
    pub version: u8,
    pub reserved: [u8; 2],
}

/// Generic Netlink protocol operations (leaf).
pub struct GenlmsghdrOps;

impl ProtocolOps for GenlmsghdrOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "Generic Netlink";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ---------------------------------------------------------------------------
// Netlink Attribute
// ---------------------------------------------------------------------------

/// Netlink attribute header (4 bytes).
///
/// Reimplements: `struct nlattr` in `proto_nlattr.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NlattrHeader {
    pub nla_len: [u8; 2],
    pub nla_type: [u8; 2],
}

impl NlattrHeader {
    pub fn nla_len(&self) -> u16 {
        u16::from_le_bytes(self.nla_len)
    }
    pub fn nla_type(&self) -> u16 {
        u16::from_le_bytes(self.nla_type)
    }
}

/// Netlink attribute protocol operations (leaf).
pub struct NlattrOps;

impl ProtocolOps for NlattrOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "Netlink Attr";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genetlink_is_leaf() {
        assert!(matches!(GenlmsghdrOps.next_proto(&[0u8; 4]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn nlattr_is_leaf() {
        assert!(matches!(NlattrOps.next_proto(&[0u8; 4]), Err(ParseError::UnknownProto)));
    }
}
