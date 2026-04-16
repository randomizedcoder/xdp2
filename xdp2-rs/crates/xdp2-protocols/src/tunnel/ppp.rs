//! PPP (Point-to-Point Protocol) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `PppHeader` | `proto_ppp.h:36-40` | `struct ppp_hdr` |
//! | `PppOps` | `proto_ppp.h:57-61` | `xdp2_parse_ppp` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// PPP header (4 bytes).
///
/// Reimplements: `struct ppp_hdr` in `proto_ppp.h:36-40`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct PppHeader {
    pub address: u8,
    pub control: u8,
    pub protocol: [u8; 2],
}

impl PppHeader {
    pub fn protocol(&self) -> u16 {
        u16::from_be_bytes(self.protocol)
    }
}

/// PPP protocol operations.
///
/// Reimplements: `xdp2_parse_ppp` in `proto_ppp.h:57-61`
pub struct PppOps;

impl ProtocolOps for PppOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "PPP";

    /// Return PPP protocol field.
    ///
    /// Reimplements: `ppp_proto()` in `proto_ppp.h:42-45`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let ppp = PppHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(ppp.protocol() as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ppp_next_proto() {
        let mut hdr = [0u8; 4];
        hdr[2..4].copy_from_slice(&0x0021u16.to_be_bytes()); // PPP IPv4
        assert_eq!(PppOps.next_proto(&hdr).unwrap(), 0x0021);
    }
}
