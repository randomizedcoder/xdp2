//! Ethernet protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `EthernetHeader` | `<linux/if_ether.h>` | `struct ethhdr` |
//! | `EthernetOps` | `proto_defs/ethernet/proto_ether.h:52-56` | `xdp2_parse_ether` |
//! | `EthernetOps::next_proto` | `proto_ether.h:36-39` | `ether_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout, NetworkEndian, U16};

/// Ethernet header (14 bytes).
///
/// Reimplements: `struct ethhdr` from `<linux/if_ether.h>`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct EthernetHeader {
    /// Destination MAC address
    pub h_dest: [u8; 6],
    /// Source MAC address
    pub h_source: [u8; 6],
    /// EtherType / length
    pub h_proto: U16<NetworkEndian>,
}

/// Ethernet protocol operations.
///
/// Reimplements: `xdp2_parse_ether` in `proto_defs/ethernet/proto_ether.h:52-56`
///
/// Fixed 14-byte header. Next protocol is the EtherType field (e.g., 0x0800
/// for IPv4, 0x86DD for IPv6).
pub struct EthernetOps;

impl ProtocolOps for EthernetOps {
    const MIN_LEN: usize = 14; // sizeof(struct ethhdr)
    const NAME: &'static str = "Ethernet";

    /// Return the EtherType as the next protocol number.
    ///
    /// Reimplements: `ether_proto()` in `proto_ether.h:36-39`
    ///
    /// Returns the raw big-endian EtherType value (matching C behavior where
    /// protocol table entries are also stored in network byte order).
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let eth = EthernetHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(eth.h_proto.get() as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_min_len() {
        assert_eq!(EthernetOps::MIN_LEN, 14);
    }

    #[test]
    fn ethernet_next_proto_ipv4() {
        // Ethernet frame with EtherType 0x0800 (IPv4)
        let mut frame = [0u8; 14];
        frame[12] = 0x08;
        frame[13] = 0x00;

        let ops = EthernetOps;
        assert_eq!(ops.next_proto(&frame).unwrap(), 0x0800);
    }

    #[test]
    fn ethernet_next_proto_ipv6() {
        let mut frame = [0u8; 14];
        frame[12] = 0x86;
        frame[13] = 0xDD;

        let ops = EthernetOps;
        assert_eq!(ops.next_proto(&frame).unwrap(), 0x86DD);
    }

    #[test]
    fn ethernet_too_short() {
        let ops = EthernetOps;
        assert!(ops.next_proto(&[0u8; 13]).is_err());
    }
}
