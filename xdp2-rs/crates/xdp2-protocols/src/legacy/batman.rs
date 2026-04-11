//! BATMAN-adv (B.A.T.M.A.N. Advanced) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `BatmanHeader` | `proto_defs/legacy/proto_batman.h` | `struct batadv_eth` |
//! | `BatmanOps` | `proto_batman.h:98-104` | `xdp2_parse_batman` |
//! | `BatmanOps::header_len` | `proto_batman.h:72-81` | `batman_len_check()` |
//! | `BatmanOps::next_proto` | `proto_batman.h:83-86` | `batman_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// BATMAN-adv constants.
const BATADV_COMPAT_VERSION: u8 = 15;
const BATADV_UNICAST: u8 = 0x01;

/// BATMAN-adv encapsulated Ethernet frame (24 bytes).
///
/// Reimplements: `struct batadv_eth` in `proto_batman.h`
///
/// Layout: batadv_unicast_packet (10B) + inner ethhdr (14B)
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct BatmanHeader {
    // batadv_unicast_packet fields
    pub packet_type: u8,
    pub version: u8,
    pub ttl: u8,
    pub ttvn: u8,
    pub dest: [u8; 6],
    // inner ethhdr fields
    pub h_dest: [u8; 6],
    pub h_source: [u8; 6],
    pub h_proto: [u8; 2],
}

impl BatmanHeader {
    /// Inner EtherType.
    pub fn h_proto(&self) -> u16 {
        u16::from_be_bytes(self.h_proto)
    }
}

/// BATMAN-adv protocol operations (encap).
///
/// Reimplements: `xdp2_parse_batman` in `proto_batman.h:98-104`
///
/// Validates BATMAN version and packet type, then dispatches
/// on the inner Ethernet EtherType.
pub struct BatmanOps;

impl ProtocolOps for BatmanOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "BATMAN";
    const ENCAP: bool = true;

    /// Validate BATMAN header and return fixed length.
    ///
    /// Reimplements: `batman_len_check()` in `proto_batman.h:72-81`
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        let bat = BatmanHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        if bat.version != BATADV_COMPAT_VERSION || bat.packet_type != BATADV_UNICAST {
            return Err(ParseError::Fail);
        }
        Ok(24)
    }

    /// Return inner EtherType for dispatch.
    ///
    /// Reimplements: `batman_proto()` in `proto_batman.h:83-86`
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let bat = BatmanHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(bat.h_proto() as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_batman(version: u8, pkt_type: u8, ethertype: u16) -> [u8; 24] {
        let mut hdr = [0u8; 24];
        hdr[0] = pkt_type;
        hdr[1] = version;
        hdr[22..24].copy_from_slice(&ethertype.to_be_bytes());
        hdr
    }

    #[test]
    fn batman_dispatch_ipv4() {
        let ops = BatmanOps;
        let hdr = make_batman(BATADV_COMPAT_VERSION, BATADV_UNICAST, 0x0800);
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x0800);
    }

    #[test]
    fn batman_valid_len() {
        let ops = BatmanOps;
        let hdr = make_batman(BATADV_COMPAT_VERSION, BATADV_UNICAST, 0x0800);
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 24);
    }

    #[test]
    fn batman_invalid_version() {
        let ops = BatmanOps;
        let hdr = make_batman(0, BATADV_UNICAST, 0x0800);
        assert!(ops.header_len(&hdr, 100).is_err());
    }

    #[test]
    fn batman_invalid_type() {
        let ops = BatmanOps;
        let hdr = make_batman(BATADV_COMPAT_VERSION, 0xFF, 0x0800);
        assert!(ops.header_len(&hdr, 100).is_err());
    }

    #[test]
    fn batman_is_encap() {
        assert!(BatmanOps::ENCAP);
    }
}
