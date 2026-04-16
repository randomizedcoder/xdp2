//! CAPWAP (Control And Provisioning of Wireless Access Points) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `CapwapHeader` | `proto_capwap.h:38-43` | `struct capwap_hdr` |
//! | `CapwapOps` | `proto_capwap.h:60-65` | `xdp2_parse_capwap` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

const ETH_P_TEB: i32 = 0x6558;

/// CAPWAP header (4 bytes minimum).
///
/// Reimplements: `struct capwap_hdr` in `proto_capwap.h:38-43`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct CapwapHeader {
    pub preamble: u8,
    pub hlen_rid: u8,
    pub wbid_flags: u8,
    pub frag_id: u8,
}

/// CAPWAP protocol operations (encap — always Ethernet).
///
/// Reimplements: `xdp2_parse_capwap` in `proto_capwap.h:60-65`
pub struct CapwapOps;

impl ProtocolOps for CapwapOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "CAPWAP";
    const ENCAP: bool = true;

    /// Always returns ETH_P_TEB.
    ///
    /// Reimplements: `capwap_proto()` in `proto_capwap.h:46-49`
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(ETH_P_TEB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capwap_always_teb() {
        assert_eq!(CapwapOps.next_proto(&[0u8; 4]).unwrap(), ETH_P_TEB);
    }

    #[test]
    fn capwap_is_encap() {
        assert!(CapwapOps::ENCAP);
    }
}
