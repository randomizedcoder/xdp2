//! Routing protocol definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// BGP header (19 bytes). Reimplements: `struct bgphdr` in `proto_bgp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct BgpHeader {
    pub marker: [u8; 16],
    pub length: [u8; 2],
    pub msg_type: u8,
}
pub struct BgpOps;
impl ProtocolOps for BgpOps {
    const MIN_LEN: usize = 19;
    const NAME: &'static str = "BGP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// OSPF header (16 bytes). Reimplements: `struct ospfhdr` in `proto_ospf.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct OspfHeader {
    pub version: u8,
    pub msg_type: u8,
    pub pkt_len: [u8; 2],
    pub router_id: [u8; 4],
    pub area_id: [u8; 4],
    pub checksum: [u8; 2],
    pub au_type: [u8; 2],
}
pub struct OspfOps;
impl ProtocolOps for OspfOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "OSPF";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// IS-IS header (8 bytes). Reimplements: `struct isis_hdr` in `proto_isis.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IsisHeader {
    pub nlpid: u8,
    pub hdr_len: u8,
    pub version: u8,
    pub id_len: u8,
    pub pdu_type: u8,
    pub version2: u8,
    pub reserved: u8,
    pub max_area_addr: u8,
}
pub struct IsisOps;
impl ProtocolOps for IsisOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "IS-IS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// EIGRP header (4 bytes). Reimplements: `struct eigrp_hdr` in `proto_eigrp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct EigrpHeader {
    pub version: u8,
    pub opcode: u8,
    pub checksum: [u8; 2],
}
pub struct EigrpOps;
impl ProtocolOps for EigrpOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "EIGRP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// RIP header (4 bytes). Reimplements: `struct rip_hdr` in `proto_rip.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct RipHeader {
    pub command: u8,
    pub version: u8,
    pub reserved: [u8; 2],
}
pub struct RipOps;
impl ProtocolOps for RipOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "RIP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bgp_is_leaf() {
        assert!(matches!(BgpOps.next_proto(&[0u8; 19]), Err(ParseError::UnknownProto)));
    }
}
