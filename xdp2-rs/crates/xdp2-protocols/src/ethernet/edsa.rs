//! Extended DSA (EDSA) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `EdsaHeader` | `proto_defs/ethernet/proto_edsa.h:37-40` | `struct edsa_hdr` |
//! | `EdsaOps` | `proto_edsa.h:57-61` | `xdp2_parse_edsa` |
//! | `EdsaOps::next_proto` | `proto_edsa.h:43-46` | `edsa_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// ETH_P_EDSA EtherType.
pub const ETH_P_EDSA: u16 = 0xDADA;

/// Extended DSA header (10 bytes).
///
/// Reimplements: `struct edsa_hdr` in `proto_edsa.h:37-40`
///
/// 8-byte extended DSA tag followed by 2-byte inner EtherType.
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct EdsaHeader {
    /// 8-byte extended DSA tag
    pub tag: [u8; 8],
    /// Inner EtherType
    pub etype: [u8; 2],
}

impl EdsaHeader {
    /// Inner EtherType.
    pub fn ethertype(&self) -> u16 {
        u16::from_be_bytes(self.etype)
    }
}

/// EDSA protocol operations.
///
/// Reimplements: `xdp2_parse_edsa` in `proto_edsa.h:57-61`
///
/// Fixed 10-byte header. Returns the inner EtherType for dispatch.
pub struct EdsaOps;

impl ProtocolOps for EdsaOps {
    const MIN_LEN: usize = 10; // sizeof(struct edsa_hdr)
    const NAME: &'static str = "EDSA";

    /// Return inner EtherType.
    ///
    /// Reimplements: `edsa_proto()` in `proto_edsa.h:43-46`
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let edsa = EdsaHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(edsa.ethertype() as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_edsa_header(inner_proto: u16) -> [u8; 10] {
        let mut hdr = [0u8; 10];
        let proto_bytes = inner_proto.to_be_bytes();
        hdr[8] = proto_bytes[0];
        hdr[9] = proto_bytes[1];
        hdr
    }

    #[test]
    fn edsa_fixed_length() {
        let hdr = make_edsa_header(0x0800);
        let ops = EdsaOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 10);
    }

    #[test]
    fn edsa_next_proto_ipv4() {
        let hdr = make_edsa_header(0x0800);
        let ops = EdsaOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x0800);
    }

    #[test]
    fn edsa_next_proto_ipv6() {
        let hdr = make_edsa_header(0x86DD);
        let ops = EdsaOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x86DD_u16 as i32);
    }

    #[test]
    fn edsa_too_short() {
        let ops = EdsaOps;
        assert!(ops.next_proto(&[0u8; 5]).is_err());
    }
}
