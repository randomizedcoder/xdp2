//! VXLAN-GPE (Generic Protocol Extension, RFC 8926) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `VxlanGpeHeader` | `proto_defs/tunnel/proto_vxlan_gpe.h:45-50` | `struct vxlan_gpe_hdr` |
//! | `VxlanGpeOps` | `proto_vxlan_gpe.h:77-82` | `xdp2_parse_vxlan_gpe` |
//! | `VxlanGpeOps::next_proto` | `proto_vxlan_gpe.h:52-66` | `vxlan_gpe_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// VXLAN-GPE Next Protocol values.
pub const VXLAN_GPE_NP_IPV4: u8 = 1;
pub const VXLAN_GPE_NP_IPV6: u8 = 2;
pub const VXLAN_GPE_NP_ETH: u8 = 3;
pub const VXLAN_GPE_NP_NSH: u8 = 4;

const ETH_P_IP: i32 = 0x0800;
const ETH_P_IPV6: i32 = 0x86DD;
const ETH_P_TEB: i32 = 0x6558;

/// VXLAN-GPE header (8 bytes).
///
/// Reimplements: `struct vxlan_gpe_hdr` in `proto_vxlan_gpe.h:45-50`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct VxlanGpeHeader {
    pub flags: u8,
    pub reserved1: [u8; 2],
    pub next_protocol: u8,
    pub vni_reserved: [u8; 4],
}

impl VxlanGpeHeader {
    /// VNI (24-bit Virtual Network Identifier).
    pub fn vni(&self) -> u32 {
        ((self.vni_reserved[0] as u32) << 16)
            | ((self.vni_reserved[1] as u32) << 8)
            | (self.vni_reserved[2] as u32)
    }
}

/// VXLAN-GPE protocol operations (encap).
///
/// Reimplements: `xdp2_parse_vxlan_gpe` in `proto_vxlan_gpe.h:77-82`
pub struct VxlanGpeOps;

impl ProtocolOps for VxlanGpeOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "VXLAN-GPE";
    const ENCAP: bool = true;

    /// Map next_protocol to EtherType for dispatch.
    ///
    /// Reimplements: `vxlan_gpe_proto()` in `proto_vxlan_gpe.h:52-66`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let vgpe = VxlanGpeHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(match vgpe.next_protocol {
            VXLAN_GPE_NP_IPV4 => ETH_P_IP,
            VXLAN_GPE_NP_IPV6 => ETH_P_IPV6,
            VXLAN_GPE_NP_ETH => ETH_P_TEB,
            _ => 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vxlan_gpe(np: u8) -> [u8; 8] {
        let mut hdr = [0u8; 8];
        hdr[3] = np;
        hdr
    }

    #[test]
    fn vxlan_gpe_ipv4() {
        let ops = VxlanGpeOps;
        assert_eq!(
            ops.next_proto(&make_vxlan_gpe(VXLAN_GPE_NP_IPV4)).unwrap(),
            ETH_P_IP
        );
    }

    #[test]
    fn vxlan_gpe_ipv6() {
        let ops = VxlanGpeOps;
        assert_eq!(
            ops.next_proto(&make_vxlan_gpe(VXLAN_GPE_NP_IPV6)).unwrap(),
            ETH_P_IPV6
        );
    }

    #[test]
    fn vxlan_gpe_eth() {
        let ops = VxlanGpeOps;
        assert_eq!(
            ops.next_proto(&make_vxlan_gpe(VXLAN_GPE_NP_ETH)).unwrap(),
            ETH_P_TEB
        );
    }

    #[test]
    fn vxlan_gpe_is_encap() {
        assert!(VxlanGpeOps::ENCAP);
    }
}
