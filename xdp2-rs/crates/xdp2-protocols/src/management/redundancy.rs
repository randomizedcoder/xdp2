//! Redundancy protocol definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// VRRP header (8 bytes). Reimplements: `struct vrrphdr` in `proto_vrrp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct VrrpHeader {
    pub ver_type: u8,
    pub vrid: u8,
    pub priority: u8,
    pub count_ip: u8,
    pub auth_type: u8,
    pub adver_int: u8,
    pub checksum: [u8; 2],
}
pub struct VrrpOps;
impl ProtocolOps for VrrpOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "VRRP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// HSRP header (20 bytes). Reimplements: `struct hsrphdr` in `proto_hsrp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct HsrpHeader {
    pub version: u8,
    pub opcode: u8,
    pub state: u8,
    pub hellotime: u8,
    pub holdtime: u8,
    pub priority: u8,
    pub group: u8,
    pub reserved: u8,
    pub auth: [u8; 8],
    pub vip: [u8; 4],
}
pub struct HsrpOps;
impl ProtocolOps for HsrpOps {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "HSRP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// GLBP header (4 bytes). Reimplements: `struct glbp_hdr` in `proto_glbp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct GlbpHeader {
    pub version: u8,
    pub reserved: u8,
    pub group: [u8; 2],
}
pub struct GlbpOps;
impl ProtocolOps for GlbpOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "GLBP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// CARP header (4 bytes). Reimplements: `struct carp_hdr` in `proto_carp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct CarpHeader {
    pub ver_type: u8,
    pub vhid: u8,
    pub advskew: u8,
    pub authlen: u8,
}
pub struct CarpOps;
impl ProtocolOps for CarpOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "CARP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vrrp_is_leaf() {
        assert!(matches!(VrrpOps.next_proto(&[0u8; 8]), Err(ParseError::UnknownProto)));
    }
}
