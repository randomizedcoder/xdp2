//! DNS / Name Resolution protocol definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// DNS header (12 bytes). Reimplements: `struct dnshdr` in `proto_dns.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct DnsHeader {
    pub id: [u8; 2],
    pub flags: [u8; 2],
    pub qdcount: [u8; 2],
    pub ancount: [u8; 2],
    pub nscount: [u8; 2],
    pub arcount: [u8; 2],
}
pub struct DnsOps;
impl ProtocolOps for DnsOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "DNS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// mDNS header. Reimplements: `struct mdns_hdr` in `proto_mdns.h`
pub type MdnsHeader = DnsHeader;
pub struct MdnsOps;
impl ProtocolOps for MdnsOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "mDNS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// NBNS header. Reimplements: `struct nbns_hdr` in `proto_nbns.h`
pub type NbnsHeader = DnsHeader;
pub struct NbnsOps;
impl ProtocolOps for NbnsOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "NBNS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// LLMNR header. Reimplements: `struct llmnr_hdr` in `proto_llmnr.h`
pub type LlmnrHeader = DnsHeader;
pub struct LlmnrOps;
impl ProtocolOps for LlmnrOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "LLMNR";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_is_leaf() {
        assert!(matches!(
            DnsOps.next_proto(&[0u8; 12]),
            Err(ParseError::UnknownProto)
        ));
    }
}
