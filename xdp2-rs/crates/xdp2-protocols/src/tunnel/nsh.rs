//! NSH (Network Service Header, RFC 8300) protocol definition.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `NshHeader` | `proto_defs/tunnel/proto_nsh.h:47-52` | `struct nsh_base_hdr` |
//! | `NshOps` | `proto_nsh.h:84-89` | `xdp2_parse_nsh` |
//! | `NshOps::next_proto` | `proto_nsh.h:57-73` | `nsh_proto()` |
//!
//! ## Behavioral Differences
//! - None. Byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// NSH Next Protocol values.
pub const NSH_NEXT_PROTO_IPV4: u8 = 1;
pub const NSH_NEXT_PROTO_IPV6: u8 = 2;
pub const NSH_NEXT_PROTO_ETH: u8 = 3;
pub const NSH_NEXT_PROTO_NSH: u8 = 4;
pub const NSH_NEXT_PROTO_MPLS: u8 = 5;

/// EtherType constants for dispatch.
const ETH_P_IP: i32 = 0x0800;
const ETH_P_IPV6: i32 = 0x86DD;
const ETH_P_TEB: i32 = 0x6558;
const ETH_P_MPLS_UC: i32 = 0x8847;

/// NSH base header (8 bytes).
///
/// Reimplements: `struct nsh_base_hdr` in `proto_nsh.h:47-52`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NshHeader {
    /// Ver(2) + OAM(1) + UN(1) + TTL(6) + Len(6)
    pub ver_flags_ttl_len: [u8; 2],
    /// MD-Type
    pub md_type: u8,
    /// Next Protocol
    pub next_proto: u8,
    /// Service Path Identifier (24 bits) + Service Index (8 bits)
    pub spi_si: [u8; 4],
}

impl NshHeader {
    /// Service Path Identifier (24 bits).
    pub fn spi(&self) -> u32 {
        ((self.spi_si[0] as u32) << 16)
            | ((self.spi_si[1] as u32) << 8)
            | (self.spi_si[2] as u32)
    }

    /// Service Index.
    pub fn si(&self) -> u8 {
        self.spi_si[3]
    }
}

/// NSH protocol operations (encap).
///
/// Reimplements: `xdp2_parse_nsh` in `proto_nsh.h:84-89`
///
/// Maps NSH next_protocol values to EtherType dispatch values.
pub struct NshOps;

impl ProtocolOps for NshOps {
    const MIN_LEN: usize = 8; // sizeof(struct nsh_base_hdr)
    const NAME: &'static str = "NSH";
    const ENCAP: bool = true;

    /// Map NSH next_proto to EtherType for dispatch.
    ///
    /// Reimplements: `nsh_proto()` in `proto_nsh.h:57-73`
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        let nsh = NshHeader::ref_from_prefix(hdr)
            .map_err(|_| ParseError::Length)?
            .0;
        Ok(match nsh.next_proto {
            NSH_NEXT_PROTO_IPV4 => ETH_P_IP,
            NSH_NEXT_PROTO_IPV6 => ETH_P_IPV6,
            NSH_NEXT_PROTO_ETH => ETH_P_TEB,
            NSH_NEXT_PROTO_MPLS => ETH_P_MPLS_UC,
            _ => 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_nsh_header(next_proto: u8) -> [u8; 8] {
        let mut hdr = [0u8; 8];
        hdr[3] = next_proto;
        hdr
    }

    #[test]
    fn nsh_next_proto_ipv4() {
        let hdr = make_nsh_header(NSH_NEXT_PROTO_IPV4);
        let ops = NshOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), ETH_P_IP);
    }

    #[test]
    fn nsh_next_proto_ipv6() {
        let hdr = make_nsh_header(NSH_NEXT_PROTO_IPV6);
        let ops = NshOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), ETH_P_IPV6);
    }

    #[test]
    fn nsh_next_proto_eth() {
        let hdr = make_nsh_header(NSH_NEXT_PROTO_ETH);
        let ops = NshOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), ETH_P_TEB);
    }

    #[test]
    fn nsh_next_proto_mpls() {
        let hdr = make_nsh_header(NSH_NEXT_PROTO_MPLS);
        let ops = NshOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), ETH_P_MPLS_UC);
    }

    #[test]
    fn nsh_next_proto_unknown() {
        let hdr = make_nsh_header(99);
        let ops = NshOps;
        assert_eq!(ops.next_proto(&hdr).unwrap(), 0);
    }

    #[test]
    fn nsh_is_encap() {
        assert!(NshOps::ENCAP);
    }

    #[test]
    fn nsh_spi_si() {
        let mut hdr = [0u8; 8];
        hdr[4] = 0x12;
        hdr[5] = 0x34;
        hdr[6] = 0x56;
        hdr[7] = 0x78;
        let n = NshHeader::ref_from_prefix(&hdr).unwrap().0;
        assert_eq!(n.spi(), 0x123456);
        assert_eq!(n.si(), 0x78);
    }
}
