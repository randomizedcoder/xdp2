//! Link / Switch Management protocol definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// LLDP header (2 bytes TLV). Reimplements: `struct lldp_hdr` in `proto_lldp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct LldpHeader {
    pub type_len: [u8; 2],
}
pub struct LldpOps;
impl ProtocolOps for LldpOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "LLDP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// STP BPDU header (35 bytes). Reimplements: `struct stp_bpdu` in `proto_stp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct StpHeader {
    pub proto_id: [u8; 2],
    pub version: u8,
    pub bpdu_type: u8,
    pub flags: u8,
    pub root_id: [u8; 8],
    pub root_path_cost: [u8; 4],
    pub bridge_id: [u8; 8],
    pub port_id: [u8; 2],
    pub msg_age: [u8; 2],
    pub max_age: [u8; 2],
    pub hello_time: [u8; 2],
    pub fwd_delay: [u8; 2],
}
pub struct StpOps;
impl ProtocolOps for StpOps {
    const MIN_LEN: usize = 35;
    const NAME: &'static str = "STP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// MAC Control header (2 bytes). Reimplements: `struct mac_control_hdr` in `proto_mac_control.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct MacControlHeader {
    pub opcode: [u8; 2],
}
pub struct MacControlOps;
impl ProtocolOps for MacControlOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "MAC Control";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// LACP header (1 byte). Reimplements: `struct lacpdu_hdr` in `proto_lacp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct LacpHeader {
    pub subtype: u8,
}
pub struct LacpOps;
impl ProtocolOps for LacpOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "LACP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// Slow Protocol header (1 byte). Reimplements: `struct slow_proto_hdr` in `proto_slow.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SlowHeader {
    pub subtype: u8,
}
pub struct SlowOps;
impl ProtocolOps for SlowOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "Slow Protocols";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// MRP/MVRP header (1 byte). Reimplements: `struct mrp_hdr` in `proto_mvrp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct MvrpHeader {
    pub proto_version: u8,
}
pub struct MvrpOps;
impl ProtocolOps for MvrpOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "MVRP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lldp_is_leaf() {
        assert!(matches!(
            LldpOps.next_proto(&[0u8; 2]),
            Err(ParseError::UnknownProto)
        ));
    }

    #[test]
    fn stp_is_leaf() {
        assert!(matches!(
            StpOps.next_proto(&[0u8; 35]),
            Err(ParseError::UnknownProto)
        ));
    }
}
