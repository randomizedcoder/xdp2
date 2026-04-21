//! Miscellaneous Management leaf protocol definitions.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// CDP header (4 bytes). Reimplements: `struct cdp_hdr` in `proto_cdp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct CdpHeader {
    pub version: u8,
    pub ttl: u8,
    pub checksum: [u8; 2],
}
pub struct CdpOps;
impl ProtocolOps for CdpOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "CDP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// LLTD header (8 bytes). Reimplements: `struct lltd_hdr` in `proto_lltd.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct LltdHeader {
    pub version: u8,
    pub type_of_service: u8,
    pub reserved: u8,
    pub function: u8,
    pub real_dest: [u8; 6],
}
pub struct LltdOps;
impl ProtocolOps for LltdOps {
    const MIN_LEN: usize = 10;
    const NAME: &'static str = "LLTD";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// WoL header (6 bytes sync). Reimplements: `struct wol_hdr` in `proto_wol.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct WolHeader {
    pub sync: [u8; 6],
}
pub struct WolOps;
impl ProtocolOps for WolOps {
    const MIN_LEN: usize = 6;
    const NAME: &'static str = "WoL";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// Syslog header (1 byte marker). Reimplements: `struct syslog_hdr` in `proto_syslog.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SyslogHeader {
    pub marker: u8,
}
pub struct SyslogOps;
impl ProtocolOps for SyslogOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "Syslog";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// NC-SI header (4 bytes). Reimplements: `struct ncsi_hdr` in `proto_ncsi.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NcsiHeader {
    pub mc_id: u8,
    pub hdr_revision: u8,
    pub reserved: u8,
    pub iid: u8,
}
pub struct NcsiOps;
impl ProtocolOps for NcsiOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "NC-SI";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// BFD header (24 bytes). Reimplements: `struct bfdhdr` in `proto_bfd.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct BfdHeader {
    pub ver_diag: u8,
    pub sta_flags: u8,
    pub detect_mult: u8,
    pub length: u8,
    pub my_discriminator: [u8; 4],
    pub your_discriminator: [u8; 4],
    pub min_tx_interval: [u8; 4],
    pub min_rx_interval: [u8; 4],
    pub min_echo_rx_interval: [u8; 4],
}
pub struct BfdOps;
impl ProtocolOps for BfdOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "BFD";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// STUN header (20 bytes). Reimplements: `struct stunhdr` in `proto_stun.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct StunHeader {
    pub msg_type: [u8; 2],
    pub msg_length: [u8; 2],
    pub magic_cookie: [u8; 4],
    pub transaction_id: [u8; 12],
}
pub struct StunOps;
impl ProtocolOps for StunOps {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "STUN";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// MGCP header (1 byte marker). Reimplements: `struct mgcp_hdr` in `proto_mgcp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct MgcpHeader {
    pub marker: u8,
}
pub struct MgcpOps;
impl ProtocolOps for MgcpOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "MGCP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// Skinny/SCCP header (12 bytes). Reimplements: `struct skinny_hdr` in `proto_skinny.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SkinnyHeader {
    pub length: [u8; 4],
    pub reserved: [u8; 4],
    pub msg_id: [u8; 4],
}
pub struct SkinnyOps;
impl ProtocolOps for SkinnyOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "Skinny";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// OPC UA header (8 bytes). Reimplements: `struct opc_ua_hdr` in `proto_opc_ua.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct OpcUaHeader {
    pub msg_type: [u8; 3],
    pub chunk_type: u8,
    pub msg_size: [u8; 4],
}
pub struct OpcUaOps;
impl ProtocolOps for OpcUaOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "OPC UA";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// Zigbee NWK header (8 bytes). Reimplements: `struct zigbee_nwk_hdr` in `proto_zigbee_nwk.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ZigbeeNwkHeader {
    pub frame_control: [u8; 2],
    pub dst_addr: [u8; 2],
    pub src_addr: [u8; 2],
    pub radius: u8,
    pub seq_num: u8,
}
pub struct ZigbeeNwkOps;
impl ProtocolOps for ZigbeeNwkOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "Zigbee NWK";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// Zigbee APS header (8 bytes). Reimplements: `struct zigbee_aps_hdr` in `proto_zigbee_aps.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ZigbeeApsHeader {
    pub frame_control: u8,
    pub dst_endpoint: u8,
    pub cluster_id: [u8; 2],
    pub profile_id: [u8; 2],
    pub src_endpoint: u8,
    pub counter: u8,
}
pub struct ZigbeeApsOps;
impl ProtocolOps for ZigbeeApsOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "Zigbee APS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// FIP header (8 bytes). Reimplements: `struct fip_hdr` in `proto_fip.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FipHeader {
    pub ver: u8,
    pub reserved: u8,
    pub opcode: [u8; 2],
    pub sub_opcode: u8,
    pub desc_list_len: u8,
    pub flags: [u8; 2],
}
pub struct FipOps;
impl ProtocolOps for FipOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "FIP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bfd_is_leaf() {
        assert!(matches!(
            BfdOps.next_proto(&[0u8; 24]),
            Err(ParseError::UnknownProto)
        ));
    }
}
