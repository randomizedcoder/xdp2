//! TZSP (TaZmen Sniffer Protocol) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `TzspHeader` | `proto_tzsp.h:37-41` | `struct tzsp_hdr` |
//! | `TzspOps` | `proto_tzsp.h:57-62` | `xdp2_parse_tzsp` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// TZSP header (4 bytes).
///
/// Reimplements: `struct tzsp_hdr` in `proto_tzsp.h:37-41`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct TzspHeader {
    pub version: u8,
    pub tzsp_type: u8,
    pub encap_proto: [u8; 2],
}

impl TzspHeader {
    pub fn encap_proto(&self) -> u16 {
        u16::from_be_bytes(self.encap_proto)
    }
}

/// TZSP protocol operations (encap).
///
/// Reimplements: `xdp2_parse_tzsp` in `proto_tzsp.h:57-62`
pub struct TzspOps;

impl ProtocolOps for TzspOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "TZSP";
    const ENCAP: bool = true;

    /// Return encapsulated protocol.
    ///
    /// Reimplements: `tzsp_proto()` in `proto_tzsp.h:43-46`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let tzsp = TzspHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(tzsp.encap_proto() as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tzsp_next_proto() {
        let mut hdr = [0u8; 4];
        hdr[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        assert_eq!(TzspOps.next_proto(&hdr).unwrap(), 0x0800);
    }

    #[test]
    fn tzsp_is_encap() {
        assert!(TzspOps::ENCAP);
    }
}
