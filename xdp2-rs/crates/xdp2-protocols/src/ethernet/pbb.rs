//! PBB / MAC-in-MAC (IEEE 802.1ah) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `PbbItagHeader` | `proto_defs/ethernet/proto_pbb.h:38-40` | `struct pbb_itag` |
//! | `PbbHeader` | `proto_pbb.h:45-48` | `struct pbb_hdr` |
//! | `PbbOps` | `proto_pbb.h:71-77` | `xdp2_parse_pbb` |
//! | `PbbOps::header_len` | `proto_pbb.h:57-60` | `pbb_len()` |
//! | `PbbOps::next_proto` | `proto_pbb.h:51-54` | `pbb_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// PBB I-TAG header (4 bytes).
///
/// Reimplements: `struct pbb_itag` in `proto_pbb.h:38-40`
///
/// Layout: I-PCP (3 bits) + I-DEI (1) + UCA (1) + Res (3) + I-SID (24 bits)
#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct PbbItagHeader {
    /// I-SID and flags (big-endian)
    pub isid_flags: [u8; 4],
}

impl PbbItagHeader {
    /// Service Instance Identifier (24 bits).
    pub fn isid(&self) -> u32 {
        u32::from_be_bytes(self.isid_flags) & 0x00FF_FFFF
    }
}

/// PBB header (18 bytes) — I-TAG + inner Ethernet header.
///
/// Reimplements: `struct pbb_hdr` in `proto_pbb.h:45-48`
#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct PbbHeader {
    /// I-TAG (4 bytes)
    pub itag: PbbItagHeader,
    /// Inner destination MAC
    pub inner_h_dest: [u8; 6],
    /// Inner source MAC
    pub inner_h_source: [u8; 6],
    /// Inner EtherType
    pub inner_h_proto: [u8; 2],
}

impl PbbHeader {
    /// Inner frame's EtherType.
    pub fn inner_ethertype(&self) -> u16 {
        u16::from_be_bytes(self.inner_h_proto)
    }
}

/// PBB protocol operations (encapsulation node).
///
/// Reimplements: `xdp2_parse_pbb` in `proto_pbb.h:71-77`
///
/// Parses the 4-byte I-TAG + 14-byte inner Ethernet header (18 bytes total).
/// Returns the inner Ethernet EtherType for dispatch. Marks an encapsulation
/// boundary (MAC-in-MAC).
pub struct PbbOps;

impl ProtocolOps for PbbOps {
    const MIN_LEN: usize = 18; // sizeof(struct pbb_hdr) = 4 + 14
    const NAME: &'static str = "PBB";
    const ENCAP: bool = true;

    /// Return fixed length: I-TAG + inner Ethernet header.
    ///
    /// Reimplements: `pbb_len()` in `proto_pbb.h:57-60`
    #[inline]
    fn header_len(&self, _hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        Ok(18)
    }

    /// Return inner Ethernet EtherType.
    ///
    /// Reimplements: `pbb_proto()` in `proto_pbb.h:51-54`
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let pbb = PbbHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(pbb.inner_ethertype() as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pbb_header(isid: u32, inner_proto: u16) -> [u8; 18] {
        let mut hdr = [0u8; 18];
        // I-TAG: isid in lower 24 bits
        let isid_bytes = isid.to_be_bytes();
        hdr[0] = isid_bytes[0]; // flags + upper I-SID bits
        hdr[1] = isid_bytes[1];
        hdr[2] = isid_bytes[2];
        hdr[3] = isid_bytes[3];
        // Inner Ethernet: dest MAC [4..10], src MAC [10..16], EtherType [16..18]
        let proto_bytes = inner_proto.to_be_bytes();
        hdr[16] = proto_bytes[0];
        hdr[17] = proto_bytes[1];
        hdr
    }

    #[test]
    fn pbb_fixed_length() {
        let hdr = make_pbb_header(0x123456, 0x0800);
        let ops = PbbOps;
        assert_eq!(ops.header_len(&hdr, 100).unwrap(), 18);
    }

    #[test]
    fn pbb_next_proto_ipv4() {
        let hdr = make_pbb_header(0x123456, 0x0800);
        let ops = PbbOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x0800);
    }

    #[test]
    fn pbb_next_proto_ipv6() {
        let hdr = make_pbb_header(0xABCDEF, 0x86DD);
        let ops = PbbOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0x86DD_u16 as i32);
    }

    #[test]
    fn pbb_is_encap() {
        assert!(PbbOps::ENCAP);
    }

    #[test]
    fn pbb_isid_extraction() {
        let hdr = make_pbb_header(0x123456, 0x0800);
        let pbb = PbbHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(pbb.itag.isid(), 0x123456);
    }

    #[test]
    fn pbb_too_short() {
        let ops = PbbOps;
        assert!(ops.next_proto(&[0u8; 10]).is_err());
    }
}
