//! RSVP (Resource Reservation Protocol) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `RsvpHeader` | `proto_defs/ip/proto_rsvp.h:36-42` | `struct rsvphdr` |
//! | `RsvpOps` | `proto_rsvp.h:52-55` | `xdp2_parse_rsvp` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// RSVP header (8 bytes).
///
/// Reimplements: `struct rsvphdr` in `proto_rsvp.h:36-42`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct RsvpHeader {
    /// Version (4 bits) + Flags (4 bits)
    pub version_flags: u8,
    /// Message type
    pub msg_type: u8,
    /// Checksum
    pub checksum: [u8; 2],
    /// Send TTL
    pub send_ttl: u8,
    /// Reserved
    pub reserved: u8,
    /// Message length
    pub length: [u8; 2],
}

impl RsvpHeader {
    /// RSVP version (upper 4 bits).
    pub fn version(&self) -> u8 {
        self.version_flags >> 4
    }

    /// Message length in bytes.
    pub fn msg_length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }
}

/// RSVP protocol operations (leaf node).
///
/// Reimplements: `xdp2_parse_rsvp` in `proto_rsvp.h:52-55`
pub struct RsvpOps;

impl ProtocolOps for RsvpOps {
    const MIN_LEN: usize = 8; // sizeof(struct rsvphdr)
    const NAME: &'static str = "RSVP";

    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsvp_is_leaf() {
        let ops = RsvpOps;
        assert!(ops.next_proto(&[0u8; 8]).is_err());
    }

    #[test]
    fn rsvp_fixed_length() {
        let ops = RsvpOps;
        assert_eq!(ops.header_len(&[0u8; 8], 100).unwrap(), 8);
    }

    #[test]
    fn rsvp_version() {
        let mut hdr = [0u8; 8];
        hdr[0] = 1 << 4; // version=1
        let rsvp = RsvpHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(rsvp.version(), 1);
    }

    #[test]
    fn rsvp_msg_length() {
        let mut hdr = [0u8; 8];
        hdr[6..8].copy_from_slice(&256u16.to_be_bytes());
        let rsvp = RsvpHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(rsvp.msg_length(), 256);
    }
}
