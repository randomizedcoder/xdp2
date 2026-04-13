//! Management protocol definitions (all leaf nodes).
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/management/`
//!
//! All protocols in this file are leaf nodes — they do not dispatch
//! to further protocol layers.
//!
//! ## Behavioral Differences
//! - None. All are leaf nodes — byte-for-byte compatible with C implementation.

use xdp2_core::{ParseError, ProtocolOps};
use zerocopy::{FromBytes, Immutable, KnownLayout};

// =========================================================================
// DNS / Name Resolution
// =========================================================================

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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// mDNS header. Reimplements: `struct mdns_hdr` in `proto_mdns.h`
pub type MdnsHeader = DnsHeader;
pub struct MdnsOps;
impl ProtocolOps for MdnsOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "mDNS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// NBNS header. Reimplements: `struct nbns_hdr` in `proto_nbns.h`
pub type NbnsHeader = DnsHeader;
pub struct NbnsOps;
impl ProtocolOps for NbnsOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "NBNS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// LLMNR header. Reimplements: `struct llmnr_hdr` in `proto_llmnr.h`
pub type LlmnrHeader = DnsHeader;
pub struct LlmnrOps;
impl ProtocolOps for LlmnrOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "LLMNR";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

// =========================================================================
// DHCP / Network Configuration
// =========================================================================

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

// =========================================================================
// Routing Protocols
// =========================================================================

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

// =========================================================================
// Link/Switch Management
// =========================================================================

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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    const NAME: &'static str = "Slow";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

// =========================================================================
// Redundancy Protocols
// =========================================================================

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

// =========================================================================
// Connectivity / Fault Management
// =========================================================================

/// CFM header (4 bytes). Reimplements: `struct cfm_hdr` in `proto_cfm.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct CfmHeader {
    pub md_level_version: u8,
    pub opcode: u8,
    pub flags: u8,
    pub first_tlv_offset: u8,
}
pub struct CfmOps;
impl ProtocolOps for CfmOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "CFM";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

// =========================================================================
// SNMP / Authentication
// =========================================================================

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

// =========================================================================
// HTTP / Text-based Application Protocols
// =========================================================================

/// HTTP header (1 byte marker). Reimplements: `struct http_hdr` in `proto_http.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct HttpHeader { pub marker: u8 }
pub struct HttpOps;
impl ProtocolOps for HttpOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "HTTP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// HTTP/2 header (9 bytes). Reimplements: `struct http2_hdr` in `proto_http2.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Http2Header {
    pub length: [u8; 3],
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: [u8; 4],
}
pub struct Http2Ops;
impl ProtocolOps for Http2Ops {
    const MIN_LEN: usize = 9;
    const NAME: &'static str = "HTTP/2";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// RTSP header (1 byte marker). Reimplements: `struct rtsp_hdr` in `proto_rtsp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct RtspHeader { pub marker: u8 }
pub struct RtspOps;
impl ProtocolOps for RtspOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "RTSP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// FTP header (1 byte marker). Reimplements: `struct ftp_hdr` in `proto_ftp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct FtpHeader { pub marker: u8 }
pub struct FtpOps;
impl ProtocolOps for FtpOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "FTP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

// =========================================================================
// Application Layer Protocols
// =========================================================================

/// SIP header (1 byte marker). Reimplements: `struct sip_hdr` in `proto_sip.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SipHeader { pub marker: u8 }
pub struct SipOps;
impl ProtocolOps for SipOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "SIP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// SMTP header (1 byte marker). Reimplements: `struct smtp_hdr` in `proto_smtp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SmtpHeader { pub marker: u8 }
pub struct SmtpOps;
impl ProtocolOps for SmtpOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "SMTP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// IMAP header (1 byte marker). Reimplements: `struct imap_hdr` in `proto_imap.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ImapHeader { pub marker: u8 }
pub struct ImapOps;
impl ProtocolOps for ImapOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "IMAP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// Telnet header (1 byte marker). Reimplements: `struct telnet_hdr` in `proto_telnet.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct TelnetHeader { pub marker: u8 }
pub struct TelnetOps;
impl ProtocolOps for TelnetOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "Telnet";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// TFTP header (4 bytes). Reimplements: `struct tftp_hdr` in `proto_tftp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct TftpHeader {
    pub opcode: [u8; 2],
    pub block_or_error: [u8; 2],
}
pub struct TftpOps;
impl ProtocolOps for TftpOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "TFTP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// MQTT header (2 bytes). Reimplements: `struct mqtt_hdr` in `proto_mqtt.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct MqttHeader {
    pub type_flags: u8,
    pub remaining_len: u8,
}
pub struct MqttOps;
impl ProtocolOps for MqttOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "MQTT";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// AMQP header (8 bytes). Reimplements: `struct amqp_hdr` in `proto_amqp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct AmqpHeader {
    pub literal: [u8; 4],
    pub proto_id: u8,
    pub major: u8,
    pub minor: u8,
    pub revision: u8,
}
pub struct AmqpOps;
impl ProtocolOps for AmqpOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "AMQP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// Kafka header (12 bytes). Reimplements: `struct kafka_hdr` in `proto_kafka.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct KafkaHeader {
    pub length: [u8; 4],
    pub api_key: [u8; 2],
    pub api_version: [u8; 2],
    pub correlation_id: [u8; 4],
}
pub struct KafkaOps;
impl ProtocolOps for KafkaOps {
    const MIN_LEN: usize = 12;
    const NAME: &'static str = "Kafka";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// Redis header (1 byte marker). Reimplements: `struct redis_hdr` in `proto_redis.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct RedisHeader { pub marker: u8 }
pub struct RedisOps;
impl ProtocolOps for RedisOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "Redis";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// Memcache header (24 bytes). Reimplements: `struct memcache_hdr` in `proto_memcache.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct MemcacheHeader {
    pub magic: u8,
    pub opcode: u8,
    pub key_len: [u8; 2],
    pub extras_len: u8,
    pub data_type: u8,
    pub status: [u8; 2],
    pub total_body_len: [u8; 4],
    pub opaque: [u8; 4],
    pub cas: [u8; 8],
}
pub struct MemcacheOps;
impl ProtocolOps for MemcacheOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "Memcache";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// ZeroMQ header (1 byte marker). Reimplements: `struct zeromq_hdr` in `proto_zeromq.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ZeromqHeader { pub marker: u8 }
pub struct ZeromqOps;
impl ProtocolOps for ZeromqOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "ZeroMQ";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

// =========================================================================
// RPC / File Services
// =========================================================================

/// ONC RPC header (24 bytes). Reimplements: `struct onc_rpc_hdr` in `proto_onc_rpc.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct OncRpcHeader {
    pub xid: [u8; 4],
    pub msg_type: [u8; 4],
    pub rpc_version: [u8; 4],
    pub program: [u8; 4],
    pub prog_version: [u8; 4],
    pub procedure: [u8; 4],
}
pub struct OncRpcOps;
impl ProtocolOps for OncRpcOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "ONC RPC";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// NFS header (4 bytes). Reimplements: `struct nfs_hdr` in `proto_nfs.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct NfsHeader {
    pub fragment: [u8; 4],
}
pub struct NfsOps;
impl ProtocolOps for NfsOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "NFS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// LDAP header (2 bytes). Reimplements: `struct ldap_hdr` in `proto_ldap.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct LdapHeader {
    pub tag: u8,
    pub length: u8,
}
pub struct LdapOps;
impl ProtocolOps for LdapOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "LDAP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// SMB header (4 bytes). Reimplements: `struct smb_hdr` in `proto_smb.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SmbHeader {
    pub protocol: [u8; 4],
}
pub struct SmbOps;
impl ProtocolOps for SmbOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "SMB";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// SMB2 header (4 bytes). Reimplements: `struct smb2_hdr` in `proto_smb2.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Smb2Header {
    pub protocol: [u8; 4],
}
pub struct Smb2Ops;
impl ProtocolOps for Smb2Ops {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "SMB2";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

// =========================================================================
// Industrial / Control Protocols
// =========================================================================

/// Modbus TCP header (7 bytes). Reimplements: `struct modbus_tcp_hdr` in `proto_modbus.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ModbusHeader {
    pub transaction_id: [u8; 2],
    pub protocol_id: [u8; 2],
    pub length: [u8; 2],
    pub unit_id: u8,
}
pub struct ModbusOps;
impl ProtocolOps for ModbusOps {
    const MIN_LEN: usize = 7;
    const NAME: &'static str = "Modbus";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// Profinet header (2 bytes). Reimplements: `struct profinet_hdr` in `proto_profinet.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct ProfinetHeader {
    pub frame_id: [u8; 2],
}
pub struct ProfinetOps;
impl ProtocolOps for ProfinetOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "Profinet";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// CoAP header (4 bytes). Reimplements: `struct coap_hdr` in `proto_coap.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct CoapHeader {
    pub ver_type_tkl: u8,
    pub code: u8,
    pub message_id: [u8; 2],
}
pub struct CoapOps;
impl ProtocolOps for CoapOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "CoAP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// DNP3 header (10 bytes). Reimplements: `struct dnp3_hdr` in `proto_dnp3.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct Dnp3Header {
    pub start: [u8; 2],
    pub length: u8,
    pub control: u8,
    pub dest: [u8; 2],
    pub src: [u8; 2],
    pub crc: [u8; 2],
}
pub struct Dnp3Ops;
impl ProtocolOps for Dnp3Ops {
    const MIN_LEN: usize = 10;
    const NAME: &'static str = "DNP3";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// BACnet header (4 bytes). Reimplements: `struct bacnet_hdr` in `proto_bacnet.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct BacnetHeader {
    pub type_flags: u8,
    pub reserved: u8,
    pub length: [u8; 2],
}
pub struct BacnetOps;
impl ProtocolOps for BacnetOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "BACnet";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// CIP header (2 bytes). Reimplements: `struct cip_hdr` in `proto_cip.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct CipHeader {
    pub service: u8,
    pub path_size: u8,
}
pub struct CipOps;
impl ProtocolOps for CipOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "CIP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// IEC GOOSE header (8 bytes). Reimplements: `struct iec_goose_hdr` in `proto_iec_goose.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IecGooseHeader {
    pub appid: [u8; 2],
    pub length: [u8; 2],
    pub reserved1: [u8; 2],
    pub reserved2: [u8; 2],
}
pub struct IecGooseOps;
impl ProtocolOps for IecGooseOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "IEC GOOSE";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// IEC SV header (8 bytes). Reimplements: `struct iec_sv_hdr` in `proto_iec_sv.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IecSvHeader {
    pub appid: [u8; 2],
    pub length: [u8; 2],
    pub reserved1: [u8; 2],
    pub reserved2: [u8; 2],
}
pub struct IecSvOps;
impl ProtocolOps for IecSvOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "IEC SV";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// IEC MMS header (2 bytes). Reimplements: `struct iec_mms_hdr` in `proto_iec_mms.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct IecMmsHeader {
    pub tag: u8,
    pub length: u8,
}
pub struct IecMmsOps;
impl ProtocolOps for IecMmsOps {
    const MIN_LEN: usize = 2;
    const NAME: &'static str = "IEC MMS";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// EtherNet/IP header (24 bytes). Reimplements: `struct enip_hdr` in `proto_enip.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct EnipHeader {
    pub command: [u8; 2],
    pub length: [u8; 2],
    pub session_handle: [u8; 4],
    pub status: [u8; 4],
    pub sender_context: [u8; 8],
    pub options: [u8; 4],
}
pub struct EnipOps;
impl ProtocolOps for EnipOps {
    const MIN_LEN: usize = 24;
    const NAME: &'static str = "EtherNet/IP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

// =========================================================================
// MPLS Management
// =========================================================================

/// LDP header (10 bytes). Reimplements: `struct ldp_hdr` in `proto_ldp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct LdpHeader {
    pub version: [u8; 2],
    pub pdu_len: [u8; 2],
    pub lsr_id: [u8; 4],
    pub label_space: [u8; 2],
}
pub struct LdpOps;
impl ProtocolOps for LdpOps {
    const MIN_LEN: usize = 10;
    const NAME: &'static str = "LDP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// MPLS OAM header (4 bytes). Reimplements: `struct mpls_oam_hdr` in `proto_mpls_oam.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct MplsOamHeader {
    pub ver_flags: u8,
    pub msg_type: u8,
    pub reply_mode: u8,
    pub return_code: u8,
}
pub struct MplsOamOps;
impl ProtocolOps for MplsOamOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "MPLS OAM";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

// =========================================================================
// SDN / OpenFlow
// =========================================================================

/// OpenFlow header (8 bytes). Reimplements: `struct openflow_hdr` in `proto_openflow.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct OpenflowHeader {
    pub version: u8,
    pub msg_type: u8,
    pub length: [u8; 2],
    pub xid: [u8; 4],
}
pub struct OpenflowOps;
impl ProtocolOps for OpenflowOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "OpenFlow";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// HomePlug AV header (1 byte). Reimplements: `struct homeplug_av_hdr` in `proto_homeplug_av.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct HomePlugAvHeader { pub version: u8 }
pub struct HomePlugAvOps;
impl ProtocolOps for HomePlugAvOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "HomePlug AV";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

// =========================================================================
// Media / Monitoring
// =========================================================================

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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    const NAME: &'static str = "Netflow v5";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    const NAME: &'static str = "Netflow v9";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

// =========================================================================
// Misc Management Protocols
// =========================================================================

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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// Syslog header (1 byte marker). Reimplements: `struct syslog_hdr` in `proto_syslog.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct SyslogHeader { pub marker: u8 }
pub struct SyslogOps;
impl ProtocolOps for SyslogOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "Syslog";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

/// MGCP header (1 byte marker). Reimplements: `struct mgcp_hdr` in `proto_mgcp.h`
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
#[repr(C, packed)]
pub struct MgcpHeader { pub marker: u8 }
pub struct MgcpOps;
impl ProtocolOps for MgcpOps {
    const MIN_LEN: usize = 1;
    const NAME: &'static str = "MGCP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
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
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> { Err(ParseError::UnknownProto) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Representative sample of tests — one per subcategory
    #[test]
    fn dns_is_leaf() {
        assert!(matches!(DnsOps.next_proto(&[0u8; 12]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn dhcp_is_leaf() {
        assert!(matches!(DhcpOps.next_proto(&[0u8; 236]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn bgp_is_leaf() {
        assert!(matches!(BgpOps.next_proto(&[0u8; 19]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn lldp_is_leaf() {
        assert!(matches!(LldpOps.next_proto(&[0u8; 2]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn vrrp_is_leaf() {
        assert!(matches!(VrrpOps.next_proto(&[0u8; 8]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn snmp_is_leaf() {
        assert!(matches!(SnmpOps.next_proto(&[0u8; 2]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn http_is_leaf() {
        assert!(matches!(HttpOps.next_proto(&[0u8; 1]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn mqtt_is_leaf() {
        assert!(matches!(MqttOps.next_proto(&[0u8; 2]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn modbus_is_leaf() {
        assert!(matches!(ModbusOps.next_proto(&[0u8; 7]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn openflow_is_leaf() {
        assert!(matches!(OpenflowOps.next_proto(&[0u8; 8]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn ptp_is_leaf() {
        assert!(matches!(PtpOps.next_proto(&[0u8; 34]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn bfd_is_leaf() {
        assert!(matches!(BfdOps.next_proto(&[0u8; 24]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn kafka_is_leaf() {
        assert!(matches!(KafkaOps.next_proto(&[0u8; 12]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn ntp_is_leaf() {
        assert!(matches!(NtpOps.next_proto(&[0u8; 48]), Err(ParseError::UnknownProto)));
    }

    #[test]
    fn stp_is_leaf() {
        assert!(matches!(StpOps.next_proto(&[0u8; 35]), Err(ParseError::UnknownProto)));
    }
}
