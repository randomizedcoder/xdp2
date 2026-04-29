//! Media / Monitoring protocol definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// PTP header (34 bytes). Reimplements: `struct ptp_common_hdr` in `proto_ptp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct PtpHeader {
    pub transport_msg_type: u8,
    pub version: u8,
    pub msg_length: [u8; 2],
    pub domain_number: u8,
    pub reserved1: u8,
    pub flags: [u8; 2],
    pub correction: [u8; 8],
    pub reserved2: [u8; 4],
    pub source_port_id: [u8; 10],
    pub sequence_id: [u8; 2],
    pub control: u8,
    pub log_msg_interval: u8,
}
pub struct PtpOps;
impl ProtocolOps for PtpOps {
    const MIN_LEN: usize = 34;
    const NAME: &'static str = "PTP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// Netflow v5 header (24 bytes). Reimplements: `struct netflow_v5_hdr` in `proto_netflow_v5.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NetflowV5Header {
    pub version: [u8; 2],
    pub count: [u8; 2],
    pub sys_uptime: [u8; 4],
    pub unix_secs: [u8; 4],
    pub unix_nsecs: [u8; 4],
    pub flow_sequence: [u8; 4],
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling_interval: [u8; 2],
}
pub struct NetflowV5Ops;
impl ProtocolOps for NetflowV5Ops {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "NetFlow v5";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// Netflow v9 header (20 bytes). Reimplements: `struct netflow_v9_hdr` in `proto_netflow_v9.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NetflowV9Header {
    pub version: [u8; 2],
    pub count: [u8; 2],
    pub sys_uptime: [u8; 4],
    pub unix_secs: [u8; 4],
    pub sequence: [u8; 4],
    pub source_id: [u8; 4],
}
pub struct NetflowV9Ops;
impl ProtocolOps for NetflowV9Ops {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "NetFlow v9";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// IPFIX header (16 bytes). Reimplements: `struct ipfix_hdr` in `proto_ipfix.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IpfixHeader {
    pub version: [u8; 2],
    pub length: [u8; 2],
    pub export_time: [u8; 4],
    pub sequence: [u8; 4],
    pub observation_domain: [u8; 4],
}
pub struct IpfixOps;
impl ProtocolOps for IpfixOps {
    const MIN_LEN: usize = 16;
    const NAME: &'static str = "IPFIX";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// CFLOW/NetFlow header (4 bytes). Reimplements: `struct cflow_hdr` in `proto_cflow.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct CflowHeader {
    pub version: [u8; 2],
    pub count: [u8; 2],
}
pub struct CflowOps;
impl ProtocolOps for CflowOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "CFLOW";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptp_is_leaf() {
        assert!(matches!(
            PtpOps.next_proto(&[0u8; 34]),
            Err(ParseError::UnknownProto)
        ));
    }
}
