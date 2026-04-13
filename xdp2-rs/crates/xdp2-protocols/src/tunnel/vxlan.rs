//! VXLAN (Virtual Extensible LAN) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `VxlanHeader` | `proto_defs/tunnel/proto_vxlan.h:20-23` | `struct vxlanhdr` |
//! | `VxlanOps` | `proto_vxlan.h:29-34` | `xdp2_parse_vxlan` |
//! | `VxlanOps::next_proto` | `proto_vxlan.h:25-28` | `vxlan_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// Ethernet Transparent Bridging (inner frame after VXLAN decap).
const ETH_P_TEB: i32 = 0x6558;

/// VXLAN header (8 bytes).
///
/// Reimplements: `struct vxlanhdr` from `proto_vxlan.h:20-23`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct VxlanHeader {
    /// VXLAN flags
    pub vx_flags: [u8; 4],
    /// VXLAN Network Identifier (VNI) + reserved
    pub vx_vni: [u8; 4],
}

impl VxlanHeader {
    /// VXLAN Network Identifier (24-bit VNI in upper 3 bytes).
    pub fn vni(&self) -> u32 {
        ((self.vx_vni[0] as u32) << 16)
            | ((self.vx_vni[1] as u32) << 8)
            | (self.vx_vni[2] as u32)
    }
}

/// VXLAN protocol operations (encapsulation node).
///
/// Reimplements: `xdp2_parse_vxlan` in `proto_vxlan.h:29-34`
///
/// Fixed 8-byte header. Always returns ETH_P_TEB (Transparent Ethernet
/// Bridging) because VXLAN encapsulates a full Ethernet frame.
pub struct VxlanOps;

impl ProtocolOps for VxlanOps {
    const MIN_LEN: usize = 8; // sizeof(struct vxlanhdr)
    const NAME: &'static str = "VXLAN";
    const ENCAP: bool = true;

    /// Always returns ETH_P_TEB — VXLAN encapsulates Ethernet.
    ///
    /// Reimplements: `vxlan_proto()` in `proto_vxlan.h:25-28`
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(ETH_P_TEB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vxlan_fixed_length() {
        let ops = VxlanOps;
        assert_eq!(ops.header_len(&[0; 8], 100).unwrap(), 8);
    }

    #[test]
    fn vxlan_always_teb() {
        let ops = VxlanOps;
        assert_eq!(ops.next_proto(&[0; 8]).unwrap(), ETH_P_TEB);
    }

    #[test]
    fn vxlan_is_encap() {
        assert!(VxlanOps::ENCAP);
    }

    #[test]
    fn vxlan_vni_extraction() {
        // VNI = 0x123456 stored in upper 3 bytes of vx_vni
        let hdr = [
            0x08, 0x00, 0x00, 0x00, // flags (I flag set)
            0x12, 0x34, 0x56, 0x00, // VNI + reserved
        ];
        let vh = VxlanHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(vh.vni(), 0x123456);
    }
}
