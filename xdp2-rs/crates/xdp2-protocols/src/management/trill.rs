//! TRILL (Transparent Interconnection of Lots of Links) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `TrillHeader` | `proto_defs/management/proto_trill.h` | `struct trill_full_hdr` |
//! | `TrillOps` | `proto_trill.h:73-79` | `xdp2_parse_trill` |
//! | `TrillOps::header_len` | `proto_trill.h:59-62` | `trill_len()` |
//! | `TrillOps::next_proto` | `proto_trill.h:53-56` | `trill_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// TRILL full header (20 bytes): 6B TRILL + 14B inner Ethernet.
///
/// Reimplements: `struct trill_full_hdr` in `proto_trill.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct TrillHeader {
    // TRILL header (6 bytes)
    pub flags_hopcount: [u8; 2],
    pub egress_nick: [u8; 2],
    pub ingress_nick: [u8; 2],
    // Inner Ethernet header (14 bytes)
    pub h_dest: [u8; 6],
    pub h_source: [u8; 6],
    pub h_proto: [u8; 2],
}

impl TrillHeader {
    pub fn egress_nick(&self) -> u16 {
        u16::from_be_bytes(self.egress_nick)
    }
    pub fn ingress_nick(&self) -> u16 {
        u16::from_be_bytes(self.ingress_nick)
    }
    /// Inner EtherType.
    pub fn h_proto(&self) -> u16 {
        u16::from_be_bytes(self.h_proto)
    }
}

/// TRILL protocol operations (encap).
///
/// Reimplements: `xdp2_parse_trill` in `proto_trill.h:73-79`
///
/// Dispatches on the inner Ethernet EtherType.
pub struct TrillOps;

impl ProtocolOps for TrillOps {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "TRILL";
    const ENCAP: bool = true;

    /// Return fixed header length (20 bytes).
    ///
    /// Reimplements: `trill_len()` in `proto_trill.h:59-62`
    #[inline]
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        if hdr.len() < 20 {
            return Err(ParseError::Length);
        }
        Ok(20)
    }

    /// Return inner EtherType for dispatch.
    ///
    /// Reimplements: `trill_proto()` in `proto_trill.h:53-56`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let trill = TrillHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(trill.h_proto() as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trill(ethertype: u16) -> [u8; 20] {
        let mut hdr = [0u8; 20];
        hdr[18..20].copy_from_slice(&ethertype.to_be_bytes());
        hdr
    }

    #[test]
    fn trill_dispatch_ipv4() {
        assert_eq!(TrillOps.next_proto(&make_trill(0x0800)).unwrap(), 0x0800);
    }

    #[test]
    fn trill_dispatch_ipv6() {
        assert_eq!(TrillOps.next_proto(&make_trill(0x86DD)).unwrap(), 0x86DD);
    }

    #[test]
    fn trill_fixed_len() {
        assert_eq!(TrillOps.header_len(&[0u8; 20], 100).unwrap(), 20);
    }

    #[test]
    fn trill_is_encap() {
        assert!(TrillOps::ENCAP);
    }
}
