//! SNMP / Authentication protocol definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// SNMP header (2 bytes). Reimplements: `struct snmphdr` in `proto_snmp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SnmpHeader {
    pub asn1_type: u8,
    pub length: u8,
}
pub struct SnmpOps;
impl ProtocolOps for SnmpOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "SNMP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// RADIUS header (20 bytes). Reimplements: `struct radiushdr` in `proto_radius.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct RadiusHeader {
    pub code: u8,
    pub id: u8,
    pub length: [u8; 2],
    pub authenticator: [u8; 16],
}
pub struct RadiusOps;
impl ProtocolOps for RadiusOps {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "RADIUS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// Diameter header (20 bytes). Reimplements: `struct diameter_hdr` in `proto_diameter.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct DiameterHeader {
    pub version: u8,
    pub length: [u8; 3],
    pub flags: u8,
    pub command_code: [u8; 3],
    pub app_id: [u8; 4],
    pub hop_by_hop: [u8; 4],
    pub end_to_end: [u8; 4],
}
pub struct DiameterOps;
impl ProtocolOps for DiameterOps {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "Diameter";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snmp_is_leaf() {
        assert!(matches!(SnmpOps.next_proto(&[0u8; 2]), Err(ParseError::UnknownProto)));
    }
}
