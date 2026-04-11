//! Linux SLL (cooked capture) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `SllHeader` | `proto_defs/ethernet/proto_sll.h:37-43` | `struct sll_hdr` |
//! | `SllOps` | `proto_sll.h:59-63` | `xdp2_parse_sll` |
//! | `SllOps::next_proto` | `proto_sll.h:45-48` | `sll_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// Linux SLL (cooked capture v1) header (16 bytes).
///
/// Reimplements: `struct sll_hdr` in `proto_sll.h:37-43`
///
/// Used by libpcap for cooked captures (DLT_LINUX_SLL).
#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct SllHeader {
    /// Packet type (incoming, broadcast, etc.)
    pub pkttype: [u8; 2],
    /// ARPHRD_ link-layer address type
    pub arphrd: [u8; 2],
    /// Link-layer address length
    pub ll_addr_len: [u8; 2],
    /// Link-layer address (8 bytes, zero-padded)
    pub ll_addr: [u8; 8],
    /// Protocol (EtherType)
    pub protocol: [u8; 2],
}

impl SllHeader {
    /// EtherType / protocol number.
    pub fn protocol(&self) -> u16 {
        u16::from_be_bytes(self.protocol)
    }

    /// Packet type.
    pub fn pkttype(&self) -> u16 {
        u16::from_be_bytes(self.pkttype)
    }
}

/// SLL protocol operations.
///
/// Reimplements: `xdp2_parse_sll` in `proto_sll.h:59-63`
///
/// Fixed 16-byte header. Returns the protocol field (EtherType) for dispatch.
pub struct SllOps;

impl ProtocolOps for SllOps {
    const MIN_LEN: usize = 16; // sizeof(struct sll_hdr)
    const NAME: &'static str = "SLL";

    /// Return the protocol field (EtherType).
    ///
    /// Reimplements: `sll_proto()` in `proto_sll.h:45-48`
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let sll = SllHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(sll.protocol() as i32)
    }
}

/// SLL2 (cooked capture v2) header (20 bytes).
///
/// Reimplements: `struct sll2_hdr` in `proto_sll2.h:37-45`
///
/// Used by libpcap for cooked captures (DLT_LINUX_SLL2).
/// Protocol field is at offset 0 (unlike SLL where it's at the end).
#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct Sll2Header {
    /// Protocol (EtherType) — at offset 0
    pub protocol: [u8; 2],
    /// Reserved
    pub reserved: [u8; 2],
    /// Interface index
    pub interface_index: [u8; 4],
    /// ARPHRD_ link-layer address type
    pub arphrd: [u8; 2],
    /// Packet type
    pub pkttype: u8,
    /// Link-layer address length
    pub ll_addr_len: u8,
    /// Link-layer address (8 bytes, zero-padded)
    pub ll_addr: [u8; 8],
}

impl Sll2Header {
    /// EtherType / protocol number.
    pub fn protocol(&self) -> u16 {
        u16::from_be_bytes(self.protocol)
    }

    /// Interface index.
    pub fn interface_index(&self) -> u32 {
        u32::from_be_bytes(self.interface_index)
    }
}

/// SLL2 protocol operations.
///
/// Reimplements: `xdp2_parse_sll2` in `proto_sll2.h:61-65`
///
/// Fixed 20-byte header. Returns the protocol field (EtherType) for dispatch.
pub struct Sll2Ops;

impl ProtocolOps for Sll2Ops {
    const MIN_LEN: usize = 20; // sizeof(struct sll2_hdr)
    const NAME: &'static str = "SLL2";

    /// Return the protocol field (EtherType).
    ///
    /// Reimplements: `sll2_proto()` in `proto_sll2.h:47-50`
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let sll2 = Sll2Header::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(sll2.protocol() as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sll_header(proto: u16) -> [u8; 16] {
        let mut hdr = [0u8; 16];
        let proto_bytes = proto.to_be_bytes();
        hdr[14] = proto_bytes[0]; // protocol at offset 14
        hdr[15] = proto_bytes[1];
        hdr
    }

    fn make_sll2_header(proto: u16) -> [u8; 20] {
        let mut hdr = [0u8; 20];
        let proto_bytes = proto.to_be_bytes();
        hdr[0] = proto_bytes[0]; // protocol at offset 0
        hdr[1] = proto_bytes[1];
        hdr
    }

    #[test]
    fn sll_fixed_length() {
        let hdr = make_sll_header(0x0800);
        let ops = SllOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 16);
    }

    #[test]
    fn sll_next_proto_ipv4() {
        let hdr = make_sll_header(0x0800);
        let ops = SllOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x0800);
    }

    #[test]
    fn sll_next_proto_ipv6() {
        let hdr = make_sll_header(0x86DD);
        let ops = SllOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x86DD_u16 as i32);
    }

    #[test]
    fn sll_too_short() {
        let ops = SllOps;
        assert!(ops.next_proto(&[0u8; 10]).is_err());
    }

    #[test]
    fn sll2_fixed_length() {
        let hdr = make_sll2_header(0x0800);
        let ops = Sll2Ops;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 20);
    }

    #[test]
    fn sll2_next_proto_ipv4() {
        let hdr = make_sll2_header(0x0800);
        let ops = Sll2Ops;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x0800);
    }

    #[test]
    fn sll2_next_proto_ipv6() {
        let hdr = make_sll2_header(0x86DD);
        let ops = Sll2Ops;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x86DD_u16 as i32);
    }

    #[test]
    fn sll2_too_short() {
        let ops = Sll2Ops;
        assert!(ops.next_proto(&[0u8; 10]).is_err());
    }

    #[test]
    fn sll2_interface_index() {
        let mut hdr = make_sll2_header(0x0800);
        // interface_index at offset 4..8
        hdr[4..8].copy_from_slice(&42u32.to_be_bytes());
        let sll2 = Sll2Header::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(sll2.interface_index(), 42);
    }
}
