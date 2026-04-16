//! DHCP / Network Configuration protocol definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// DHCP header (236 bytes fixed). Reimplements: `struct dhcphdr` in `proto_dhcp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct DhcpHeader {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: [u8; 4],
    pub secs: [u8; 2],
    pub flags: [u8; 2],
    pub ciaddr: [u8; 4],
    pub yiaddr: [u8; 4],
    pub siaddr: [u8; 4],
    pub giaddr: [u8; 4],
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
}
pub struct DhcpOps;
impl ProtocolOps for DhcpOps {
    const MIN_LEN: usize = 236;
    const NAME: &'static str = "DHCP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// DHCPv6 header (4 bytes). Reimplements: `struct dhcpv6_hdr` in `proto_dhcpv6.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Dhcpv6Header {
    pub msg_type: u8,
    pub transaction_id: [u8; 3],
}
pub struct Dhcpv6Ops;
impl ProtocolOps for Dhcpv6Ops {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "DHCPv6";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// NTP header (48 bytes). Reimplements: `struct ntphdr` in `proto_ntp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NtpHeader {
    pub li_vn_mode: u8,
    pub stratum: u8,
    pub poll: u8,
    pub precision: u8,
    pub root_delay: [u8; 4],
    pub root_dispersion: [u8; 4],
    pub ref_id: [u8; 4],
    pub ref_ts: [u8; 8],
    pub orig_ts: [u8; 8],
    pub recv_ts: [u8; 8],
    pub xmit_ts: [u8; 8],
}
pub struct NtpOps;
impl ProtocolOps for NtpOps {
    const MIN_LEN: usize = 48;
    const NAME: &'static str = "NTP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dhcp_is_leaf() {
        assert!(matches!(DhcpOps.next_proto(&[0u8; 236]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn ntp_is_leaf() {
        assert!(matches!(NtpOps.next_proto(&[0u8; 48]), Err(ParseError::UnknownProto)));
    }
}
