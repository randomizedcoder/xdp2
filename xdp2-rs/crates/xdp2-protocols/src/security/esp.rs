//! ESP (Encapsulating Security Payload) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `EspHeader` | `proto_defs/security/proto_esp.h` | `struct ip_esp_hdr` (linux/ip.h) |
//! | `EspOps` | `proto_esp.h:36-41` | `xdp2_parse_esp` |
//!
//! ## Behavioral Differences
//! - None. Leaf node — byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// ESP header (8 bytes).
///
/// Reimplements: `struct ip_esp_hdr` (linux/ip.h) referenced in `proto_esp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct EspHeader {
    pub spi: [u8; 4],
    pub seq_no: [u8; 4],
}

impl EspHeader {
    pub fn spi(&self) -> u32 {
        u32::from_be_bytes(self.spi)
    }
    pub fn seq_no(&self) -> u32 {
        u32::from_be_bytes(self.seq_no)
    }
}

/// ESP protocol operations (leaf).
///
/// Reimplements: `xdp2_parse_esp` in `proto_esp.h:36-41`
pub struct EspOps;

impl ProtocolOps for EspOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "ESP";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esp_is_leaf() {
        let ops = EspOps;
        assert!(matches!(
            ops.next_proto(&[0u8; 8]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn esp_spi_seq() {
        let mut hdr = [0u8; 8];
        hdr[0..4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        hdr[4..8].copy_from_slice(&42u32.to_be_bytes());
        let esp = EspHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(esp.spi(), 0xDEADBEEF);
        assert_eq!(esp.seq_no(), 42);
    }
}
