//! WireGuard protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `WireguardHeader` | `proto_wireguard.h:38-41` | `struct wireguard_hdr` |
//! | `WireguardOps` | `proto_wireguard.h:48-53` | `xdp2_parse_wireguard` |
//!
//! ## Behavioral Differences
//! - None. Leaf node — byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// WireGuard header (4 bytes).
///
/// Reimplements: `struct wireguard_hdr` in `proto_wireguard.h:38-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct WireguardHeader {
    pub msg_type: u8,
    pub reserved: [u8; 3],
}

/// WireGuard protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_wireguard` in `proto_wireguard.h:48-53`
pub struct WireguardOps;

impl ProtocolOps for WireguardOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "WireGuard";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wireguard_is_leaf() {
        let ops = WireguardOps;
        assert!(matches!(ops.next_proto(&[0u8; 4]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn wireguard_msg_type() {
        let mut hdr = [0u8; 4];
        hdr[0] = 4; // cookie reply
        let wg = WireguardHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(wg.msg_type, 4);
    }
}
