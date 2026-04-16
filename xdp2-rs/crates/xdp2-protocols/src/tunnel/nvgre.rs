//! NVGRE (Network Virtualization using GRE) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `NvgreHeader` | `proto_nvgre.h:37-41` | `struct nvgrehdr` |
//! | `NvgreOps` | `proto_nvgre.h:57-62` | `xdp2_parse_nvgre` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

const ETH_P_TEB: i32 = 0x6558;

/// NVGRE header (8 bytes).
///
/// Reimplements: `struct nvgrehdr` in `proto_nvgre.h:37-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NvgreHeader {
    pub flags_version: [u8; 2],
    pub protocol_type: [u8; 2],
    pub vsid_flowid: [u8; 4],
}

impl NvgreHeader {
    /// VSID (24-bit Virtual Subnet ID).
    pub fn vsid(&self) -> u32 {
        ((self.vsid_flowid[0] as u32) << 16)
            | ((self.vsid_flowid[1] as u32) << 8)
            | (self.vsid_flowid[2] as u32)
    }
}

/// NVGRE protocol operations (encap — always Ethernet).
///
/// Reimplements: `xdp2_parse_nvgre` in `proto_nvgre.h:57-62`
pub struct NvgreOps;

impl ProtocolOps for NvgreOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "NVGRE";
    const ENCAP: bool = true;

    /// Always returns ETH_P_TEB (inner is Ethernet).
    ///
    /// Reimplements: `nvgre_proto()` in `proto_nvgre.h:43-46`
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(ETH_P_TEB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nvgre_always_teb() {
        assert_eq!(NvgreOps.next_proto(&[0u8; 8]).unwrap(), ETH_P_TEB);
    }

    #[test]
    fn nvgre_is_encap() {
        assert!(NvgreOps::ENCAP);
    }

    #[test]
    fn nvgre_vsid() {
        let mut hdr = [0u8; 8];
        hdr[4] = 0x12;
        hdr[5] = 0x34;
        hdr[6] = 0x56;
        let n = NvgreHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(n.vsid(), 0x123456);
    }
}
