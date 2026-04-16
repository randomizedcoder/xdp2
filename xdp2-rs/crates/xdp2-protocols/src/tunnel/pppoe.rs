//! PPPoE (Point-to-Point Protocol over Ethernet) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `PppoeHeader` | `proto_pppoe.h:32-46` | `struct pppoe_hdr` |
//! | `PppoeOps` | `proto_pppoe.h:66-70` | `xdp2_parse_pppoe` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// PPPoE header (8 bytes).
///
/// Reimplements: `struct pppoe_hdr` in `proto_pppoe.h:32-46`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct PppoeHeader {
    /// Version (4 bits) + Type (4 bits)
    pub vertype: u8,
    /// Code
    pub code: u8,
    /// Session ID
    pub sid: [u8; 2],
    /// Length
    pub length: [u8; 2],
    /// PPP protocol
    pub protocol: [u8; 2],
}

impl PppoeHeader {
    pub fn protocol(&self) -> u16 {
        u16::from_be_bytes(self.protocol)
    }

    pub fn session_id(&self) -> u16 {
        u16::from_be_bytes(self.sid)
    }
}

/// PPPoE protocol operations.
///
/// Reimplements: `xdp2_parse_pppoe` in `proto_pppoe.h:66-70`
pub struct PppoeOps;

impl ProtocolOps for PppoeOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "PPPoE";

    /// Return PPP protocol field.
    ///
    /// Reimplements: `pppoe_proto()` in `proto_pppoe.h:51-54`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let pppoe = PppoeHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(pppoe.protocol() as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pppoe_next_proto() {
        let mut hdr = [0u8; 8];
        hdr[6..8].copy_from_slice(&0x0021u16.to_be_bytes());
        assert_eq!(PppoeOps.next_proto(&hdr).unwrap(), 0x0021);
    }
}
