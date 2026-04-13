//! IEEE 802.1Q VLAN tag protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `VlanHeader` | `<linux/if_vlan.h>` | `struct vlan_hdr` |
//! | `VlanOps` | `proto_defs/ethernet/proto_vlan.h:25-29` | `xdp2_parse_vlan` |
//! | `VlanOps::next_proto` | `proto_vlan.h:20-23` | `vlan_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// VLAN priority mask (bits 15-13 of TCI).
pub const VLAN_PRIO_MASK: u16 = 0xE000;
/// VLAN priority bit shift.
pub const VLAN_PRIO_SHIFT: u32 = 13;
/// VLAN identifier mask (bits 11-0 of TCI).
pub const VLAN_VID_MASK: u16 = 0x0FFF;

/// IEEE 802.1Q VLAN tag header (4 bytes).
///
/// Reimplements: `struct vlan_hdr` from `<linux/if_vlan.h>`
///
/// Note: The outer EtherType (0x8100) that indicates a VLAN tag is part of
/// the Ethernet header, not this header. This struct starts after that.
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct VlanHeader {
    /// Tag Control Information (priority + CFI + VID)
    pub h_vlan_tci: [u8; 2],
    /// Encapsulated protocol (EtherType of inner frame)
    pub h_vlan_encapsulated_proto: [u8; 2],
}

impl VlanHeader {
    /// Raw TCI value (big-endian).
    pub fn tci(&self) -> u16 {
        u16::from_be_bytes(self.h_vlan_tci)
    }

    /// VLAN priority (PCP, 3 bits).
    pub fn priority(&self) -> u8 {
        ((self.tci() & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT) as u8
    }

    /// VLAN identifier (VID, 12 bits).
    pub fn vid(&self) -> u16 {
        self.tci() & VLAN_VID_MASK
    }

    /// Encapsulated EtherType.
    pub fn encapsulated_proto(&self) -> u16 {
        u16::from_be_bytes(self.h_vlan_encapsulated_proto)
    }
}

/// VLAN protocol operations.
///
/// Reimplements: `xdp2_parse_vlan` in `proto_defs/ethernet/proto_vlan.h:25-29`
///
/// Fixed 4-byte header. Returns the encapsulated EtherType for protocol
/// table lookup (supporting stacked VLANs — ETH_P_8021Q can chain).
pub struct VlanOps;

impl ProtocolOps for VlanOps {
    const MIN_LEN: usize = 4; // sizeof(struct vlan_hdr)
    const NAME: &'static str = "VLAN";

    /// Return encapsulated EtherType.
    ///
    /// Reimplements: `vlan_proto()` in `proto_vlan.h:20-23`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let vh = VlanHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(vh.encapsulated_proto() as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vlan_header(vid: u16, priority: u8, proto: u16) -> [u8; 4] {
        let tci = ((priority as u16) << VLAN_PRIO_SHIFT) | (vid & VLAN_VID_MASK);
        let tci_bytes = tci.to_be_bytes();
        let proto_bytes = proto.to_be_bytes();
        [tci_bytes[0], tci_bytes[1], proto_bytes[0], proto_bytes[1]]
    }

    #[test]
    fn vlan_fixed_length() {
        let hdr = make_vlan_header(100, 3, 0x0800);
        let ops = VlanOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 4);
    }

    #[test]
    fn vlan_next_proto_ipv4() {
        let hdr = make_vlan_header(100, 3, 0x0800);
        let ops = VlanOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x0800);
    }

    #[test]
    fn vlan_next_proto_ipv6() {
        let hdr = make_vlan_header(200, 5, 0x86DD);
        let ops = VlanOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x86DD_u16 as i32);
    }

    #[test]
    fn vlan_stacked() {
        // VLAN encapsulating another VLAN (QinQ)
        let hdr = make_vlan_header(100, 0, 0x8100);
        let ops = VlanOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x8100);
    }

    #[test]
    fn vlan_vid_and_priority() {
        let hdr = make_vlan_header(42, 7, 0x0800);
        let vh = VlanHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(vh.vid(), 42);
        assert_eq!(vh.priority(), 7);
    }

    #[test]
    fn vlan_too_short() {
        let ops = VlanOps;
        assert!(ops.next_proto(&[0x08]).is_err());
    }
}
