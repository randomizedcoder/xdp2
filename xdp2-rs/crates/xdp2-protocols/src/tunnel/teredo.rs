//! Teredo tunneling protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `TeredoHeader` | `proto_teredo.h:39-41` | `struct teredo_hdr` |
//! | `TeredoOps` | `proto_teredo.h:58-63` | `xdp2_parse_teredo` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

const ETH_P_IPV6: i32 = 0x86DD;

/// Teredo header (2 bytes).
///
/// Reimplements: `struct teredo_hdr` in `proto_teredo.h:39-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct TeredoHeader {
    pub indicator: [u8; 2],
}

/// Teredo protocol operations (encap — always IPv6).
///
/// Reimplements: `xdp2_parse_teredo` in `proto_teredo.h:58-63`
pub struct TeredoOps;

impl ProtocolOps for TeredoOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "Teredo";
    const ENCAP: bool = true;

    /// Always returns ETH_P_IPV6 (inner is IPv6).
    ///
    /// Reimplements: `teredo_proto()` in `proto_teredo.h:44-47`
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(ETH_P_IPV6)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn teredo_always_ipv6() {
        assert_eq!(TeredoOps.next_proto(&[0u8; 2]).unwrap(), ETH_P_IPV6);
    }

    #[test]
    fn teredo_is_encap() {
        assert!(TeredoOps::ENCAP);
    }
}
