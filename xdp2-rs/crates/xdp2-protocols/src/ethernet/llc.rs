//! LLC/SNAP (IEEE 802.2) protocol definitions.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `LlcHeader` | `proto_defs/ethernet/proto_llc.h:35-39` | `struct llc_hdr` |
//! | `LlcSnapHeader` | `proto_llc.h:42-48` | `struct llc_snap_hdr` |
//! | `LlcOps` | `proto_llc.h:68-71` | `xdp2_parse_llc` |
//! | `LlcSnapOps` | `proto_llc.h:78-83` | `xdp2_parse_llc_snap` |
//! | `LlcSnapOps::next_proto` | `proto_llc.h:55-58` | `llc_snap_next_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// LLC SAP values.
pub const LLC_SAP_SNAP: u8 = 0xAA;
pub const LLC_SAP_IP: u8 = 0x06;
pub const LLC_SAP_STP: u8 = 0x42;
pub const LLC_SAP_IPX: u8 = 0xE0;

/// LLC header (3 bytes).
///
/// Reimplements: `struct llc_hdr` in `proto_llc.h:35-39`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct LlcHeader {
    /// Destination Service Access Point
    pub dsap: u8,
    /// Source Service Access Point
    pub ssap: u8,
    /// Control field
    pub ctrl: u8,
}

/// LLC/SNAP header (8 bytes).
///
/// Reimplements: `struct llc_snap_hdr` in `proto_llc.h:42-48`
///
/// LLC with DSAP/SSAP = 0xAA (SNAP), ctrl = 0x03 (UI frame),
/// followed by 3-byte OUI and 2-byte EtherType.
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct LlcSnapHeader {
    /// DSAP (0xAA for SNAP)
    pub dsap: u8,
    /// SSAP (0xAA for SNAP)
    pub ssap: u8,
    /// Control (0x03 for UI frame)
    pub ctrl: u8,
    /// Organizationally Unique Identifier
    pub oui: [u8; 3],
    /// EtherType of encapsulated payload
    pub ethertype: [u8; 2],
}

impl LlcSnapHeader {
    /// Encapsulated EtherType.
    pub fn ethertype(&self) -> u16 {
        u16::from_be_bytes(self.ethertype)
    }
}

/// LLC protocol operations (leaf node).
///
/// Reimplements: `xdp2_parse_llc` in `proto_llc.h:68-71`
///
/// Basic 3-byte LLC header. Leaf node — no next protocol dispatch.
pub struct LlcOps;

impl ProtocolOps for LlcOps {
    const MIN_LEN: usize = 3; // sizeof(struct llc_hdr)
    const NAME: &'static str = "LLC";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

/// LLC/SNAP protocol operations (encapsulation node).
///
/// Reimplements: `xdp2_parse_llc_snap` in `proto_llc.h:78-83`
///
/// 8-byte LLC/SNAP header. Returns the encapsulated EtherType for dispatch.
/// Marks an encapsulation boundary.
pub struct LlcSnapOps;

impl ProtocolOps for LlcSnapOps {
    const MIN_LEN: usize = 8; // sizeof(struct llc_snap_hdr)
    const NAME: &'static str = "LLC/SNAP";
    const ENCAP: bool = true;

    /// Return encapsulated EtherType.
    ///
    /// Reimplements: `llc_snap_next_proto()` in `proto_llc.h:55-58`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let snap = LlcSnapHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(snap.ethertype() as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn llc_fixed_length() {
        let hdr = [0u8; 3];
        let ops = LlcOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 3);
    }

    #[test]
    fn llc_is_leaf() {
        let ops = LlcOps;
        assert!(ops.next_proto(&[0u8; 3]).is_err());
    }

    #[test]
    fn llc_snap_fixed_length() {
        let hdr = [0u8; 8];
        let ops = LlcSnapOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 8);
    }

    #[test]
    fn llc_snap_next_proto_ipv4() {
        let mut hdr = [0u8; 8];
        hdr[0] = LLC_SAP_SNAP; // dsap
        hdr[1] = LLC_SAP_SNAP; // ssap
        hdr[2] = 0x03; // ctrl (UI)
                       // OUI = 0x000000
        hdr[6] = 0x08; // ethertype = 0x0800
        hdr[7] = 0x00;
        let ops = LlcSnapOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x0800);
    }

    #[test]
    fn llc_snap_is_encap() {
        assert!(LlcSnapOps::ENCAP);
    }

    #[test]
    fn llc_snap_too_short() {
        let ops = LlcSnapOps;
        assert!(ops.next_proto(&[0u8; 5]).is_err());
    }

    #[test]
    fn llc_snap_ethertype_extraction() {
        let mut hdr = [0u8; 8];
        hdr[6] = 0x86;
        hdr[7] = 0xDD;
        let snap = LlcSnapHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(snap.ethertype(), 0x86DD);
    }
}
