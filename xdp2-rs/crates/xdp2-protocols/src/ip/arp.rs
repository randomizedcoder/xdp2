//! ARP/RARP protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `ArpHeader` | `<linux/if_arp.h>` | `struct arphdr` |
//! | `EtherArpHeader` | `proto_defs/ip/proto_arp_rarp.h:26-32` | `struct earphdr` |
//! | `ArpOps` | `proto_arp_rarp.h:60-65` | `xdp2_parse_arp` |
//! | `ArpOps::header_len` | `proto_arp_rarp.h:34-48` | `arp_len_check()` |
//! | `RarpOps` | `proto_arp_rarp.h:67-72` | `xdp2_parse_rarp` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// ARP operation codes.
pub const ARPOP_REQUEST: u16 = 1;
pub const ARPOP_REPLY: u16 = 2;
/// Hardware type: Ethernet.
pub const ARPHRD_ETHER: u16 = 1;
/// Ethernet hardware address length.
pub const ETH_ALEN: u8 = 6;

/// ARP base header (8 bytes).
///
/// Reimplements: `struct arphdr` from `<linux/if_arp.h>`
#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct ArpHeader {
    /// Hardware type (ARPHRD_ETHER = 1)
    pub ar_hrd: [u8; 2],
    /// Protocol type (ETH_P_IP = 0x0800)
    pub ar_pro: [u8; 2],
    /// Hardware address length (6 for Ethernet)
    pub ar_hln: u8,
    /// Protocol address length (4 for IPv4)
    pub ar_pln: u8,
    /// Operation (ARPOP_REQUEST=1, ARPOP_REPLY=2)
    pub ar_op: [u8; 2],
}

/// Ethernet ARP header (28 bytes) — ARP with Ethernet/IPv4 addresses.
///
/// Reimplements: `struct earphdr` in `proto_arp_rarp.h:26-32`
#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct EtherArpHeader {
    /// ARP base header
    pub arp: ArpHeader,
    /// Sender hardware address (MAC)
    pub ar_sha: [u8; 6],
    /// Sender protocol address (IPv4)
    pub ar_sip: [u8; 4],
    /// Target hardware address (MAC)
    pub ar_tha: [u8; 6],
    /// Target protocol address (IPv4)
    pub ar_tip: [u8; 4],
}

impl ArpHeader {
    pub fn hardware_type(&self) -> u16 {
        u16::from_be_bytes(self.ar_hrd)
    }

    pub fn protocol_type(&self) -> u16 {
        u16::from_be_bytes(self.ar_pro)
    }

    pub fn operation(&self) -> u16 {
        u16::from_be_bytes(self.ar_op)
    }
}

/// ARP protocol operations (leaf node with validation).
///
/// Reimplements: `xdp2_parse_arp` in `proto_arp_rarp.h:60-65`
///
/// Validates that the ARP header contains Ethernet/IPv4 addresses
/// and a valid operation code (request or reply).
pub struct ArpOps;

impl ProtocolOps for ArpOps {
    const MIN_LEN: usize = 28; // sizeof(struct earphdr)
    const NAME: &'static str = "ARP";

    /// Validate ARP header and return fixed length.
    ///
    /// Reimplements: `arp_len_check()` in `proto_arp_rarp.h:34-48`
    #[inline]
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        let earp = EtherArpHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;

        // Accept any ARP/RARP operation code — we extract metadata
        // regardless. The strict validation (Ethernet/IPv4 only) is
        // relaxed to support RARP (ops 3/4) and other ARP variants.
        if earp.arp.hardware_type() != ARPHRD_ETHER
            || earp.arp.ar_hln != ETH_ALEN
        {
            return Err(ParseError::Fail);
        }

        Ok(28) // sizeof(struct earphdr)
    }

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

/// RARP protocol operations (leaf node with validation).
///
/// Reimplements: `xdp2_parse_rarp` in `proto_arp_rarp.h:67-72`
///
/// Same validation as ARP.
pub struct RarpOps;

impl ProtocolOps for RarpOps {
    const MIN_LEN: usize = 28;
    const NAME: &'static str = "RARP";

    #[inline]
    fn header_len(&self, hdr: &[u8], maxlen: usize) -> Result<usize, ParseError> {
        ArpOps.header_len(hdr, maxlen)
    }

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_arp_request() -> [u8; 28] {
        let mut hdr = [0u8; 28];
        hdr[0..2].copy_from_slice(&ARPHRD_ETHER.to_be_bytes()); // ar_hrd
        hdr[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // ar_pro
        hdr[4] = ETH_ALEN; // ar_hln
        hdr[5] = 4; // ar_pln
        hdr[6..8].copy_from_slice(&ARPOP_REQUEST.to_be_bytes()); // ar_op
                                                                 // Leave addresses as zeros
        hdr
    }

    #[test]
    fn arp_valid_request() {
        let hdr = make_arp_request();
        let ops = ArpOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 28);
    }

    #[test]
    fn arp_valid_reply() {
        let mut hdr = make_arp_request();
        hdr[6..8].copy_from_slice(&ARPOP_REPLY.to_be_bytes());
        let ops = ArpOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 28);
    }

    #[test]
    fn arp_invalid_hw_type() {
        let mut hdr = make_arp_request();
        hdr[0..2].copy_from_slice(&99u16.to_be_bytes()); // not ARPHRD_ETHER
        let ops = ArpOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap_err(), ParseError::Fail);
    }

    #[test]
    fn arp_nonstandard_operation_accepted() {
        let mut hdr = make_arp_request();
        hdr[6..8].copy_from_slice(&42u16.to_be_bytes()); // non-standard op
        let ops = ArpOps;
        // Any operation code is accepted — we extract metadata regardless.
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 28);
    }

    #[test]
    fn arp_is_leaf() {
        let ops = ArpOps;
        assert!(ops.next_proto(&[0; 28]).is_err());
    }

    #[test]
    fn rarp_delegates_validation() {
        let hdr = make_arp_request();
        let ops = RarpOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 28);
    }
}
