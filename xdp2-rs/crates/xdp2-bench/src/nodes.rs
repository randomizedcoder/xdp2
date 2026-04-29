// ── Static parse-node declarations ──────────────────────────────
//
// All static ParseNode, ProtoTable, ParseFlagFieldNode, and
// ParseFlagFieldsNode declarations for the benchmark parse graph.

use xdp2_core::flag_fields::{
    FlagFieldsTable, FlagFieldsTableEntry, ParseFlagFieldNode, ParseFlagFieldNodeOps,
    ParseFlagFieldsNode,
};
use xdp2_core::{proto_table, ParseError, ParseNode, ParseNodeOps, ProtoTable, ProtocolOps};
use xdp2_protocols::ethernet::llc::{LlcOps, LlcSnapOps};

use xdp2_protocols::ip::arp::ArpOps;
use xdp2_protocols::ip::icmp::{IcmpV4Ops, IcmpV6Ops};
use xdp2_protocols::ip::ipv4::Ipv4Ops;
use xdp2_protocols::ip::ipv6::Ipv6Ops;
use xdp2_protocols::ip::ipv6_eh::{Ipv6EhOps, Ipv6FragOps};
use xdp2_protocols::transport::dccp::DccpOps;
use xdp2_protocols::transport::sctp::SctpOps;
use xdp2_protocols::transport::udplite::UdpLiteOps;
// IpInIpOps removed — IP-in-IP tunnels dispatch through IP_CHECK_NODE directly.
use xdp2_protocols::ethernet::pbb::PbbOps;
use xdp2_protocols::ip::arp::RarpOps;
use xdp2_protocols::ip::igmp::IgmpOps;
use xdp2_protocols::ip::ip_overlay::IpOverlayOps;
use xdp2_protocols::legacy::BatmanOps;
use xdp2_protocols::management::trill::TrillOps;
use xdp2_protocols::management::{
    CfmOps, FipOps, LldpOps, MacControlOps, MvrpOps, PtpOps, SlowOps,
};
use xdp2_protocols::security::ah::AhOps;
use xdp2_protocols::security::{EapolOps, EspOps, MacsecOps};
use xdp2_protocols::storage::fc::{FcOps, FcoeOps, FC_TYPE_CT, FC_TYPE_ELS, FC_TYPE_FCP};
use xdp2_protocols::storage::fc_els::FcElsLsAccOps;
use xdp2_protocols::storage::fc_gs::FcCtOps;
use xdp2_protocols::storage::fcp::FcpCmndOps;
use xdp2_protocols::storage::iscsi_pdus::IscsiScsiReqOps;
use xdp2_protocols::storage::misc::EthercatOps;
use xdp2_protocols::storage::nvme_tcp::NvmeTcpOps;
use xdp2_protocols::transport::tipc::TipcOps;
use xdp2_protocols::tunnel::geneve::GeneveV0Ops;
use xdp2_protocols::tunnel::gre::{GreBaseOps, GreV0Ops, GRE_FF_OPS, GRE_V0_FLAG_FIELDS};
use xdp2_protocols::tunnel::mpls::MplsOps;
use xdp2_protocols::tunnel::nsh::NshOps;
use xdp2_protocols::tunnel::vxlan::VxlanOps;
use xdp2_protocols::tunnel::{HsrOps, PppoeOps};

// IP protocol family
use xdp2_protocols::ip::pim::PimOps;
use xdp2_protocols::ip::rsvp::RsvpOps;
use xdp2_protocols::ip::ipcomp::IpCompOps;
use xdp2_protocols::ip::pgm::PgmOps;

// Tunnel protocols (with inner dispatch)
use xdp2_protocols::tunnel::gtp::{GtpuOps, Gtpv2cOps};
use xdp2_protocols::tunnel::vxlan_gpe::VxlanGpeOps;
use xdp2_protocols::tunnel::teredo::TeredoOps;
use xdp2_protocols::tunnel::lisp::LispOps;
use xdp2_protocols::tunnel::capwap::CapwapOps;
use xdp2_protocols::tunnel::gue::GueOps;
use xdp2_protocols::tunnel::stt::SttOps;
use xdp2_protocols::tunnel::tzsp::TzspOps;
use xdp2_protocols::tunnel::etherip::EtherIpOps;

// Management / application
use xdp2_protocols::management::{
    DnsOps, NbnsOps, MdnsOps, LlmnrOps, DhcpOps, Dhcpv6Ops, NtpOps, SnmpOps,
    TftpOps, SyslogOps, RipOps, RipngOps, HsrpOps, GlbpOps, SipOps, MgcpOps,
    BfdOps, StunOps, TwampOps, PfcpOps, SflowOps, CflowOps, IpfixOps, WolOps,
    BacnetOps, OspfOps, Ospfv3Ops, EigrpOps, VrrpOps, Vrrpv3Ops, CarpOps,
    BgpOps, LdpOps, MsdpOps, LdapOps, SmtpOps, FtpOps, TelnetOps, ImapOps,
    HttpOps, Http2Ops, RtspOps, DiameterOps, SkinnyOps, PptpOps, OpcUaOps,
    Dnp3Ops, EnipOps, ModbusOps, OpenflowOps, RedisOps, KafkaOps, MqttOps,
    AmqpOps, MemcacheOps, ZeromqOps, NfsOps, OncRpcOps, SmbOps,
    NetflowV5Ops, NetflowV9Ops, CoapOps, RadiusOps,
};
use xdp2_protocols::ip::rtp::{RtpOps, RtcpOps};

// Security
use xdp2_protocols::security::{
    TlsOps, SshOps, Ikev2Ops, KerberosOps, TacacsOps, WireguardOps, DtlsOps,
};

// Transport
use xdp2_protocols::transport::quic::QuicOps;

// Other
use xdp2_protocols::other::{SrtOps, MpegTsOps};

use crate::extractors::*;
use crate::flow_meta::FlowMeta;

// ── Local Ops types (bench-specific behavior) ────────────────────

/// UDP with destination-port dispatch for tunnel detection.
///
/// Unlike the leaf `UdpOps` from xdp2-protocols, this returns the
/// destination port so the engine can dispatch to tunnel nodes
/// (VXLAN 4789, Geneve 6081, etc.) via a proto table.
///
/// Matches C's `xdp2_parse_udp` which returns dport for the
/// `udp_tunnel_table` in flow_dissector_tables.h.
pub struct UdpDportOps;

impl ProtocolOps for UdpDportOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "UDP-dport";

    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        // Return destination port (host-order) for tunnel table lookup.
        Ok(u16::from_be_bytes([hdr[2], hdr[3]]) as i32)
    }
}

// ── LLC-aware Ethernet/VLAN/QinQ Ops ────────────────────────────
//
// When the ethertype field is ≤ 1500, the frame is LLC-encapsulated
// (IEEE 802.3 length field, not Ethernet II ethertype). We map these
// to the sentinel value ETH_P_802_2 (0x0004) so the ETHER_TABLE can
// dispatch to LLC handling.

/// Sentinel ethertype for LLC frames in the ether dispatch table.
const ETH_P_802_2: i32 = 0x0004;

/// Convert raw ethertype to LLC-aware value: ≤ 1500 becomes ETH_P_802_2.
#[inline]
fn etype_or_llc(raw: u16) -> i32 {
    if raw <= 1500 {
        ETH_P_802_2
    } else {
        raw as i32
    }
}

/// Ethernet with LLC detection (14 bytes).
/// Returns ETH_P_802_2 for LLC frames, real ethertype otherwise.
pub(crate) struct EtherLlcOps;

impl ProtocolOps for EtherLlcOps {
    const MIN_LEN: usize = 14;
    const NAME: &'static str = "Ethernet-LLC";

    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(etype_or_llc(u16::from_be_bytes([hdr[12], hdr[13]])))
    }
}

/// VLAN with LLC detection (4 bytes).
/// Returns ETH_P_802_2 for LLC frames, real ethertype otherwise.
struct VlanLlcOps;

impl ProtocolOps for VlanLlcOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "VLAN-LLC";

    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(etype_or_llc(u16::from_be_bytes([hdr[2], hdr[3]])))
    }
}

/// QinQ with LLC detection (4 bytes).
/// Returns ETH_P_802_2 for LLC frames, real ethertype otherwise.
struct QinQLlcOps;

impl ProtocolOps for QinQLlcOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "QinQ-LLC";

    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(etype_or_llc(u16::from_be_bytes([hdr[2], hdr[3]])))
    }
}

/// LLC dispatch: reads DSAP byte, routes to SNAP (0xAA) or STP (0x42).
struct LlcDispatchOps;

impl ProtocolOps for LlcDispatchOps {
    const MIN_LEN: usize = 3; // LLC header is 3 bytes minimum
    const NAME: &'static str = "LLC-dispatch";

    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(hdr[0] as i32) // DSAP byte for table dispatch
    }
}

// ── TCP with destination-port dispatch for application protocols ──

/// TCP with destination-port dispatch for application protocol detection.
///
/// Similar to UdpDportOps, this returns the destination port for table
/// lookup. Known application ports (iSCSI 3260, NVMe/TCP 4420) dispatch
/// to their handler; all other ports fall back to the TCP_LEAF wildcard.
pub struct TcpDportOps;

impl ProtocolOps for TcpDportOps {
    const MIN_LEN: usize = 20;
    const NAME: &'static str = "TCP-dport";

    #[inline]
    fn header_len(&self, hdr: &[u8], _maxlen: usize) -> Result<usize, ParseError> {
        if hdr.len() < 20 {
            return Err(ParseError::Length);
        }
        Ok(((hdr[12] >> 4) as usize) * 4)
    }

    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        if hdr.len() < 20 {
            return Err(ParseError::Length);
        }
        // Return destination port (host-order) for app protocol table lookup.
        Ok(u16::from_be_bytes([hdr[2], hdr[3]]) as i32)
    }
}

// ── iSCSI and NVMe/TCP leaf nodes ──

static ISCSI_NODE: ParseNode<FlowMeta, IscsiScsiReqOps> = ParseNode {
    proto: IscsiScsiReqOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "iscsi",
};

static NVME_TCP_NODE: ParseNode<FlowMeta, NvmeTcpOps> = ParseNode {
    proto: NvmeTcpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "nvme_tcp",
};

// ── New IP protocol leaf nodes ───────────────────────────────────

static OSPF_NODE: ParseNode<FlowMeta, OspfOps> = ParseNode {
    proto: OspfOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ospf",
};

static OSPFV3_NODE: ParseNode<FlowMeta, Ospfv3Ops> = ParseNode {
    proto: Ospfv3Ops,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ospfv3",
};

static EIGRP_NODE: ParseNode<FlowMeta, EigrpOps> = ParseNode {
    proto: EigrpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "eigrp",
};

static VRRP_NODE: ParseNode<FlowMeta, VrrpOps> = ParseNode {
    proto: VrrpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "vrrp",
};

static VRRP3_NODE: ParseNode<FlowMeta, Vrrpv3Ops> = ParseNode {
    proto: Vrrpv3Ops,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "vrrpv3",
};

static PIM_NODE: ParseNode<FlowMeta, PimOps> = ParseNode {
    proto: PimOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "pim",
};

static RSVP_NODE: ParseNode<FlowMeta, RsvpOps> = ParseNode {
    proto: RsvpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "rsvp",
};

static IPCOMP_NODE: ParseNode<FlowMeta, IpCompOps> = ParseNode {
    proto: IpCompOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipcomp",
};

static PGM_NODE: ParseNode<FlowMeta, PgmOps> = ParseNode {
    proto: PgmOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "pgm",
};

#[allow(dead_code)] // Shares IPPROTO 112 with VRRP — defined but not in tables
static CARP_NODE: ParseNode<FlowMeta, CarpOps> = ParseNode {
    proto: CarpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "carp",
};

static ETHERIP_NODE: ParseNode<FlowMeta, EtherIpOps> = ParseNode {
    proto: EtherIpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "etherip",
};

// ── TCP application leaf nodes ──────────────────────────────────

static DNS_TCP_NODE: ParseNode<FlowMeta, DnsOps> = ParseNode {
    proto: DnsOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "dns-tcp",
};

static HTTP_NODE: ParseNode<FlowMeta, HttpOps> = ParseNode {
    proto: HttpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "http",
};

static HTTP2_NODE: ParseNode<FlowMeta, Http2Ops> = ParseNode {
    proto: Http2Ops,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "http2",
};

static TLS_NODE: ParseNode<FlowMeta, TlsOps> = ParseNode {
    proto: TlsOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "tls",
};

static SSH_NODE: ParseNode<FlowMeta, SshOps> = ParseNode {
    proto: SshOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ssh",
};

static BGP_NODE: ParseNode<FlowMeta, BgpOps> = ParseNode {
    proto: BgpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "bgp",
};

static SMTP_NODE: ParseNode<FlowMeta, SmtpOps> = ParseNode {
    proto: SmtpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "smtp",
};

static FTP_NODE: ParseNode<FlowMeta, FtpOps> = ParseNode {
    proto: FtpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ftp",
};

static TELNET_NODE: ParseNode<FlowMeta, TelnetOps> = ParseNode {
    proto: TelnetOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "telnet",
};

static IMAP_NODE: ParseNode<FlowMeta, ImapOps> = ParseNode {
    proto: ImapOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "imap",
};

static LDAP_NODE: ParseNode<FlowMeta, LdapOps> = ParseNode {
    proto: LdapOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ldap",
};

static LDP_NODE: ParseNode<FlowMeta, LdpOps> = ParseNode {
    proto: LdpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ldp",
};

static REDIS_NODE: ParseNode<FlowMeta, RedisOps> = ParseNode {
    proto: RedisOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "redis",
};

static KAFKA_NODE: ParseNode<FlowMeta, KafkaOps> = ParseNode {
    proto: KafkaOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "kafka",
};

static MQTT_NODE: ParseNode<FlowMeta, MqttOps> = ParseNode {
    proto: MqttOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "mqtt",
};

static AMQP_NODE: ParseNode<FlowMeta, AmqpOps> = ParseNode {
    proto: AmqpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "amqp",
};

static MODBUS_NODE: ParseNode<FlowMeta, ModbusOps> = ParseNode {
    proto: ModbusOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "modbus",
};

static SMB_NODE: ParseNode<FlowMeta, SmbOps> = ParseNode {
    proto: SmbOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "smb",
};

static NFS_NODE: ParseNode<FlowMeta, NfsOps> = ParseNode {
    proto: NfsOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "nfs",
};

static ONC_RPC_NODE: ParseNode<FlowMeta, OncRpcOps> = ParseNode {
    proto: OncRpcOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "onc-rpc",
};

static MEMCACHE_NODE: ParseNode<FlowMeta, MemcacheOps> = ParseNode {
    proto: MemcacheOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "memcache",
};

static OPENFLOW_NODE: ParseNode<FlowMeta, OpenflowOps> = ParseNode {
    proto: OpenflowOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "openflow",
};

static DIAMETER_NODE: ParseNode<FlowMeta, DiameterOps> = ParseNode {
    proto: DiameterOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "diameter",
};

static RTSP_NODE: ParseNode<FlowMeta, RtspOps> = ParseNode {
    proto: RtspOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "rtsp",
};

static SKINNY_NODE: ParseNode<FlowMeta, SkinnyOps> = ParseNode {
    proto: SkinnyOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "skinny",
};

static PPTP_NODE: ParseNode<FlowMeta, PptpOps> = ParseNode {
    proto: PptpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "pptp",
};

static OPC_UA_NODE: ParseNode<FlowMeta, OpcUaOps> = ParseNode {
    proto: OpcUaOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "opc-ua",
};

static DNP3_NODE: ParseNode<FlowMeta, Dnp3Ops> = ParseNode {
    proto: Dnp3Ops,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "dnp3",
};

static ENIP_NODE: ParseNode<FlowMeta, EnipOps> = ParseNode {
    proto: EnipOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "enip",
};

static KERBEROS_NODE: ParseNode<FlowMeta, KerberosOps> = ParseNode {
    proto: KerberosOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "kerberos",
};

static TACACS_NODE: ParseNode<FlowMeta, TacacsOps> = ParseNode {
    proto: TacacsOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "tacacs",
};

static ZEROMQ_NODE: ParseNode<FlowMeta, ZeromqOps> = ParseNode {
    proto: ZeromqOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "zeromq",
};

static IKEV2_TCP_NODE: ParseNode<FlowMeta, Ikev2Ops> = ParseNode {
    proto: Ikev2Ops,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ikev2-tcp",
};

static MSDP_NODE: ParseNode<FlowMeta, MsdpOps> = ParseNode {
    proto: MsdpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "msdp",
};

// ── UDP leaf nodes ──────────────────────────────────────────────

static DNS_UDP_NODE: ParseNode<FlowMeta, DnsOps> = ParseNode {
    proto: DnsOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "dns-udp",
};

static DHCP_NODE: ParseNode<FlowMeta, DhcpOps> = ParseNode {
    proto: DhcpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "dhcp",
};

static DHCPV6_NODE: ParseNode<FlowMeta, Dhcpv6Ops> = ParseNode {
    proto: Dhcpv6Ops,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "dhcpv6",
};

static NTP_NODE: ParseNode<FlowMeta, NtpOps> = ParseNode {
    proto: NtpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ntp",
};

static SNMP_NODE: ParseNode<FlowMeta, SnmpOps> = ParseNode {
    proto: SnmpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "snmp",
};

static TFTP_NODE: ParseNode<FlowMeta, TftpOps> = ParseNode {
    proto: TftpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "tftp",
};

static SYSLOG_NODE: ParseNode<FlowMeta, SyslogOps> = ParseNode {
    proto: SyslogOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "syslog",
};

static RIP_NODE: ParseNode<FlowMeta, RipOps> = ParseNode {
    proto: RipOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "rip",
};

static RIPNG_NODE: ParseNode<FlowMeta, RipngOps> = ParseNode {
    proto: RipngOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ripng",
};

static RADIUS_NODE: ParseNode<FlowMeta, RadiusOps> = ParseNode {
    proto: RadiusOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "radius",
};

static BFD_NODE: ParseNode<FlowMeta, BfdOps> = ParseNode {
    proto: BfdOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "bfd",
};

static STUN_NODE: ParseNode<FlowMeta, StunOps> = ParseNode {
    proto: StunOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "stun",
};

static SIP_NODE: ParseNode<FlowMeta, SipOps> = ParseNode {
    proto: SipOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "sip",
};

static RTP_NODE: ParseNode<FlowMeta, RtpOps> = ParseNode {
    proto: RtpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "rtp",
};

static RTCP_NODE: ParseNode<FlowMeta, RtcpOps> = ParseNode {
    proto: RtcpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "rtcp",
};

static COAP_NODE: ParseNode<FlowMeta, CoapOps> = ParseNode {
    proto: CoapOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "coap",
};

static SFLOW_NODE: ParseNode<FlowMeta, SflowOps> = ParseNode {
    proto: SflowOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "sflow",
};

static CFLOW_NODE: ParseNode<FlowMeta, CflowOps> = ParseNode {
    proto: CflowOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "cflow",
};

#[allow(dead_code)] // Available for per-version NetFlow dispatch
static NETFLOW_V5_NODE: ParseNode<FlowMeta, NetflowV5Ops> = ParseNode {
    proto: NetflowV5Ops,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "netflow-v5",
};

#[allow(dead_code)] // Available for per-version NetFlow dispatch
static NETFLOW_V9_NODE: ParseNode<FlowMeta, NetflowV9Ops> = ParseNode {
    proto: NetflowV9Ops,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "netflow-v9",
};

static IPFIX_NODE: ParseNode<FlowMeta, IpfixOps> = ParseNode {
    proto: IpfixOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipfix",
};

static HSRP_NODE: ParseNode<FlowMeta, HsrpOps> = ParseNode {
    proto: HsrpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "hsrp",
};

static GLBP_NODE: ParseNode<FlowMeta, GlbpOps> = ParseNode {
    proto: GlbpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "glbp",
};

static NBNS_NODE: ParseNode<FlowMeta, NbnsOps> = ParseNode {
    proto: NbnsOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "nbns",
};

static MDNS_NODE: ParseNode<FlowMeta, MdnsOps> = ParseNode {
    proto: MdnsOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "mdns",
};

static LLMNR_NODE: ParseNode<FlowMeta, LlmnrOps> = ParseNode {
    proto: LlmnrOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "llmnr",
};

static MGCP_NODE: ParseNode<FlowMeta, MgcpOps> = ParseNode {
    proto: MgcpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "mgcp",
};

static TWAMP_NODE: ParseNode<FlowMeta, TwampOps> = ParseNode {
    proto: TwampOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "twamp",
};

static PFCP_NODE: ParseNode<FlowMeta, PfcpOps> = ParseNode {
    proto: PfcpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "pfcp",
};

static WIREGUARD_NODE: ParseNode<FlowMeta, WireguardOps> = ParseNode {
    proto: WireguardOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "wireguard",
};

static DTLS_NODE: ParseNode<FlowMeta, DtlsOps> = ParseNode {
    proto: DtlsOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "dtls",
};

static IKEV2_NODE: ParseNode<FlowMeta, Ikev2Ops> = ParseNode {
    proto: Ikev2Ops,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ikev2",
};

static QUIC_NODE: ParseNode<FlowMeta, QuicOps> = ParseNode {
    proto: QuicOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "quic",
};

static WOL_UDP_NODE: ParseNode<FlowMeta, WolOps> = ParseNode {
    proto: WolOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "wol-udp",
};

static BACNET_NODE: ParseNode<FlowMeta, BacnetOps> = ParseNode {
    proto: BacnetOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "bacnet",
};

static SRT_NODE: ParseNode<FlowMeta, SrtOps> = ParseNode {
    proto: SrtOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "srt",
};

static MPEG_TS_NODE: ParseNode<FlowMeta, MpegTsOps> = ParseNode {
    proto: MpegTsOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "mpeg-ts",
};

// ── Tunnel nodes (with inner dispatch tables) ───────────────────

static GTPU_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0800, &IP_CHECK_NODE),  // ETH_P_IP
    (0x86DD, &IP_CHECK_NODE),  // ETH_P_IPV6
];

static GTPU_NODE: ParseNode<FlowMeta, GtpuOps> = ParseNode {
    proto: GtpuOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&GTPU_INNER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "gtpu",
};

static GTPV2C_NODE: ParseNode<FlowMeta, Gtpv2cOps> = ParseNode {
    proto: Gtpv2cOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "gtpv2c",
};

static VXLAN_GPE_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0800, &IP_CHECK_NODE),    // ETH_P_IP
    (0x86DD, &IP_CHECK_NODE),    // ETH_P_IPV6
    (0x6558, &ETHER_INNER_NODE), // ETH_P_TEB
    (0x894F, &NSH_NODE),         // ETH_P_NSH
];

static VXLAN_GPE_NODE: ParseNode<FlowMeta, VxlanGpeOps> = ParseNode {
    proto: VxlanGpeOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&VXLAN_GPE_INNER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "vxlan-gpe",
};

static TEREDO_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x86DD, &IPV6_NODE), // ETH_P_IPV6 (always IPv6)
];

static TEREDO_NODE: ParseNode<FlowMeta, TeredoOps> = ParseNode {
    proto: TeredoOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&TEREDO_INNER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "teredo",
};

static LISP_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0800, &IP_CHECK_NODE),  // ETH_P_IP
    (0x86DD, &IP_CHECK_NODE),  // ETH_P_IPV6
];

static LISP_NODE: ParseNode<FlowMeta, LispOps> = ParseNode {
    proto: LispOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&LISP_INNER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "lisp",
};

static CAPWAP_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x6558, &ETHER_INNER_NODE), // ETH_P_TEB (always Ethernet)
];

static CAPWAP_NODE: ParseNode<FlowMeta, CapwapOps> = ParseNode {
    proto: CapwapOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&CAPWAP_INNER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "capwap",
};

// GUE uses IP protocol numbers (not ethertypes)
static GUE_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (4, &IP_CHECK_NODE),  // IPPROTO_IPIP
    (41, &IP_CHECK_NODE), // IPPROTO_IPV6
];

static GUE_NODE: ParseNode<FlowMeta, GueOps> = ParseNode {
    proto: GueOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&GUE_INNER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "gue",
};

static STT_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x6558, &ETHER_INNER_NODE), // ETH_P_TEB (always Ethernet)
];

static STT_NODE: ParseNode<FlowMeta, SttOps> = ParseNode {
    proto: SttOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&STT_INNER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "stt",
};

static TZSP_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0800, &IP_CHECK_NODE),    // ETH_P_IP
    (0x86DD, &IP_CHECK_NODE),    // ETH_P_IPV6
    (0x6558, &ETHER_INNER_NODE), // ETH_P_TEB
];

static TZSP_NODE: ParseNode<FlowMeta, TzspOps> = ParseNode {
    proto: TzspOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&TZSP_INNER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "tzsp",
};

/// TCP application protocol dispatch table — known service ports.
static TCP_APP_TABLE: ProtoTable<FlowMeta> = proto_table![
    (3260, &ISCSI_NODE),      // iSCSI
    (4420, &NVME_TCP_NODE),   // NVMe/TCP
    (7471, &STT_NODE),        // STT tunnel
    (53, &DNS_TCP_NODE),      // DNS/TCP
    (80, &HTTP_NODE),         // HTTP
    (443, &TLS_NODE),         // TLS/HTTPS
    (8080, &HTTP2_NODE),      // HTTP/2
    (22, &SSH_NODE),          // SSH
    (23, &TELNET_NODE),       // Telnet
    (21, &FTP_NODE),          // FTP
    (25, &SMTP_NODE),         // SMTP
    (143, &IMAP_NODE),        // IMAP
    (179, &BGP_NODE),         // BGP
    (646, &LDP_NODE),         // LDP
    (639, &MSDP_NODE),        // MSDP
    (389, &LDAP_NODE),        // LDAP
    (88, &KERBEROS_NODE),     // Kerberos
    (49, &TACACS_NODE),       // TACACS+
    (111, &ONC_RPC_NODE),     // ONC-RPC
    (2049, &NFS_NODE),        // NFS
    (445, &SMB_NODE),         // SMB
    (6379, &REDIS_NODE),      // Redis
    (9092, &KAFKA_NODE),      // Kafka
    (1883, &MQTT_NODE),       // MQTT
    (5672, &AMQP_NODE),       // AMQP
    (11211, &MEMCACHE_NODE),  // Memcached
    (5555, &ZEROMQ_NODE),     // ZeroMQ
    (502, &MODBUS_NODE),      // Modbus/TCP
    (20000, &DNP3_NODE),      // DNP3
    (44818, &ENIP_NODE),      // EtherNet/IP
    (4840, &OPC_UA_NODE),     // OPC-UA
    (3868, &DIAMETER_NODE),   // Diameter
    (554, &RTSP_NODE),        // RTSP
    (2000, &SKINNY_NODE),     // Skinny/SCCP
    (1723, &PPTP_NODE),       // PPTP
    (6653, &OPENFLOW_NODE),   // OpenFlow
    (4500, &IKEV2_TCP_NODE),  // IKEv2/TCP
];

// ── Leaf nodes (no proto_table, parsing stops here) ───────────────

static TCP_NODE: ParseNode<FlowMeta, TcpDportOps> = ParseNode {
    proto: TcpDportOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_tcp_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&TCP_APP_TABLE),
    wildcard_node: Some(&STOP_LEAF_NODE),
    unknown_ret: ParseError::UnknownProto,
    name: "tcp",
};

/// Zero-byte leaf node for wildcard fallback.
///
/// When an intermediate node's table lookup misses (e.g., UDP dport is not
/// a known tunnel port), this wildcard node allows the parse to succeed
/// without reading any additional bytes — the preceding node already
/// consumed its header. MIN_LEN = 0 means the engine immediately reaches
/// the leaf and stops with `ParseResult::Okay`.
///
/// This mirrors C's `XDP2_STOP_OKAY` unknown_proto_ret behavior.
struct StopLeafOps;

impl ProtocolOps for StopLeafOps {
    const MIN_LEN: usize = 0;
    const NAME: &'static str = "stop-leaf";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// Stop-leaf node instance for wildcard fallback.
static STOP_LEAF_NODE: ParseNode<FlowMeta, StopLeafOps> = ParseNode {
    proto: StopLeafOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "stop-leaf",
};

/// UDP tunnel and application dispatch table — known destination ports.
/// Matches C's `udp_tunnel_table` in flow_dissector_tables.h.
static UDP_TUNNEL_TABLE: ProtoTable<FlowMeta> = proto_table![
    // Tunnels
    (4789, &VXLAN_NODE),      // VXLAN
    (6081, &GENEVE_NODE),     // Geneve
    (2152, &GTPU_NODE),       // GTP-U
    (2123, &GTPV2C_NODE),     // GTPv2-C
    (4790, &VXLAN_GPE_NODE),  // VXLAN-GPE
    (3544, &TEREDO_NODE),     // Teredo
    (4341, &LISP_NODE),       // LISP
    (5247, &CAPWAP_NODE),     // CAPWAP data
    (6080, &GUE_NODE),        // GUE
    (37008, &TZSP_NODE),      // TZSP
    // DNS / naming
    (53, &DNS_UDP_NODE),      // DNS
    (137, &NBNS_NODE),        // NBNS
    (5353, &MDNS_NODE),       // mDNS
    (5355, &LLMNR_NODE),      // LLMNR
    // DHCP
    (67, &DHCP_NODE),         // DHCP server
    (68, &DHCP_NODE),         // DHCP client
    (546, &DHCPV6_NODE),      // DHCPv6 client
    (547, &DHCPV6_NODE),      // DHCPv6 server
    // Network management
    (123, &NTP_NODE),         // NTP
    (161, &SNMP_NODE),        // SNMP
    (162, &SNMP_NODE),        // SNMP trap
    (69, &TFTP_NODE),         // TFTP
    (514, &SYSLOG_NODE),      // Syslog
    // Routing
    (520, &RIP_NODE),         // RIP
    (521, &RIPNG_NODE),       // RIPng
    // Security
    (500, &IKEV2_NODE),       // IKEv2
    (4500, &IKEV2_NODE),      // IKEv2 NAT-T
    (51820, &WIREGUARD_NODE), // WireGuard
    (4433, &DTLS_NODE),       // DTLS
    // AAA
    (1812, &RADIUS_NODE),     // RADIUS auth
    (1813, &RADIUS_NODE),     // RADIUS acct
    // Redundancy
    (1985, &HSRP_NODE),       // HSRP
    (3222, &GLBP_NODE),       // GLBP
    // VoIP / media
    (5060, &SIP_NODE),        // SIP
    (5004, &RTP_NODE),        // RTP
    (5005, &RTCP_NODE),       // RTCP
    (2427, &MGCP_NODE),       // MGCP
    // IoT
    (5683, &COAP_NODE),       // CoAP
    // Testing
    (3784, &BFD_NODE),        // BFD
    (3478, &STUN_NODE),       // STUN
    (862, &TWAMP_NODE),       // TWAMP
    // Telco
    (8805, &PFCP_NODE),       // PFCP
    // Flow telemetry
    (6343, &SFLOW_NODE),      // sFlow
    (2055, &CFLOW_NODE),      // CFLOW/NetFlow
    (4739, &IPFIX_NODE),      // IPFIX
    // Transport
    (443, &QUIC_NODE),        // QUIC
    // Misc
    (9, &WOL_UDP_NODE),       // WOL
    (47808, &BACNET_NODE),    // BACnet
    (1935, &SRT_NODE),        // SRT
    (1234, &MPEG_TS_NODE),    // MPEG-TS
];

/// UDP node with dport-based tunnel dispatch.
///
/// Returns the destination port for table lookup. Known tunnel ports
/// dispatch to their encapsulation handler; all other ports fall back
/// to the UDP_LEAF_NODE wildcard (parse succeeds at UDP layer).
///
/// Matches C's `udp_node` in flow_dissector_nodes.h.
static UDP_NODE: ParseNode<FlowMeta, UdpDportOps> = ParseNode {
    proto: UdpDportOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_ports_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&UDP_TUNNEL_TABLE),
    wildcard_node: Some(&STOP_LEAF_NODE),
    unknown_ret: ParseError::UnknownProto,
    name: "udp",
};

static ICMPV4_NODE: ParseNode<FlowMeta, IcmpV4Ops> = ParseNode {
    proto: IcmpV4Ops,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_icmp_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "icmpv4",
};

static ICMPV6_NODE: ParseNode<FlowMeta, IcmpV6Ops> = ParseNode {
    proto: IcmpV6Ops,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_icmp_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "icmpv6",
};

static SCTP_NODE: ParseNode<FlowMeta, SctpOps> = ParseNode {
    proto: SctpOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_ports_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "sctp",
};

static ARP_NODE: ParseNode<FlowMeta, ArpOps> = ParseNode {
    proto: ArpOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_arp_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "arp",
};

// ── New leaf nodes for expanded IP tables ────────────────────────

static IGMP_NODE: ParseNode<FlowMeta, IgmpOps> = ParseNode {
    proto: IgmpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "igmp",
};

static ESP_NODE: ParseNode<FlowMeta, EspOps> = ParseNode {
    proto: EspOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_esp_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "esp",
};

static DCCP_NODE: ParseNode<FlowMeta, DccpOps> = ParseNode {
    proto: DccpOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_ports_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "dccp",
};

static UDPLITE_NODE: ParseNode<FlowMeta, UdpLiteOps> = ParseNode {
    proto: UdpLiteOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_ports_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "udplite",
};

static MPLS_NODE: ParseNode<FlowMeta, MplsOps> = ParseNode {
    proto: MplsOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_mpls_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "mpls",
};

/// L2TPv3 session header (4-byte session ID, leaf node).
///
/// When L2TP runs directly over IP (proto 115), the first 4 bytes
/// are the session ID. This matches C's `l2tp_v3_session_def`.
struct L2tpV3Ops;

impl ProtocolOps for L2tpV3Ops {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "L2TPv3";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

static L2TP_NODE: ParseNode<FlowMeta, L2tpV3Ops> = ParseNode {
    proto: L2tpV3Ops,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_l2tp_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "l2tp",
};

// ── L2 leaf nodes (simple protocols that terminate the parse) ────

static RARP_NODE: ParseNode<FlowMeta, RarpOps> = ParseNode {
    proto: RarpOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_arp_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "rarp",
};

static TIPC_NODE: ParseNode<FlowMeta, TipcOps> = ParseNode {
    proto: TipcOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_tipc_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "tipc",
};

static LLDP_NODE: ParseNode<FlowMeta, LldpOps> = ParseNode {
    proto: LldpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "lldp",
};

static SLOW_NODE: ParseNode<FlowMeta, SlowOps> = ParseNode {
    proto: SlowOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "slow",
};

static MAC_CONTROL_NODE: ParseNode<FlowMeta, MacControlOps> = ParseNode {
    proto: MacControlOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "mac-control",
};

static EAPOL_NODE: ParseNode<FlowMeta, EapolOps> = ParseNode {
    proto: EapolOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "eapol",
};

static PTP_NODE: ParseNode<FlowMeta, PtpOps> = ParseNode {
    proto: PtpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ptp",
};

static MVRP_NODE: ParseNode<FlowMeta, MvrpOps> = ParseNode {
    proto: MvrpOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "mvrp",
};

static CFM_NODE: ParseNode<FlowMeta, CfmOps> = ParseNode {
    proto: CfmOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "cfm",
};

static FIP_NODE: ParseNode<FlowMeta, FipOps> = ParseNode {
    proto: FipOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "fip",
};

static MACSEC_NODE: ParseNode<FlowMeta, MacsecOps> = ParseNode {
    proto: MacsecOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "macsec",
};

static ETHERCAT_NODE: ParseNode<FlowMeta, EthercatOps> = ParseNode {
    proto: EthercatOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ethercat",
};

// ── FC sub-type dispatch (ELS, FCP, CT) ──

static FC_ELS_NODE: ParseNode<FlowMeta, FcElsLsAccOps> = ParseNode {
    proto: FcElsLsAccOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "fc_els",
};

static FC_FCP_NODE: ParseNode<FlowMeta, FcpCmndOps> = ParseNode {
    proto: FcpCmndOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "fcp",
};

static FC_CT_NODE: ParseNode<FlowMeta, FcCtOps> = ParseNode {
    proto: FcCtOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "fc_ct",
};

static FC_TYPE_TABLE: ProtoTable<FlowMeta> = proto_table![
    (FC_TYPE_ELS, &FC_ELS_NODE), // FC Extended Link Services
    (FC_TYPE_FCP, &FC_FCP_NODE), // FC Protocol for SCSI
    (FC_TYPE_CT, &FC_CT_NODE),   // FC Common Transport (Name Server)
];

#[allow(dead_code)] // Available for raw FC traffic (non-FCoE paths)
static FC_NODE: ParseNode<FlowMeta, FcOps> = ParseNode {
    proto: FcOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&FC_TYPE_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "fc",
};

static FCOE_NODE: ParseNode<FlowMeta, FcoeOps> = ParseNode {
    proto: FcoeOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&FC_TYPE_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "fcoe",
};

// ── PPPoE → PPP dispatch ─────────────────────────────────────────

/// PPP protocol dispatch table.
/// PppoeOps returns the PPP protocol number.
static PPP_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0021, &IP_CHECK_NODE), // PPP_IP → IPv4
    (0x0057, &IP_CHECK_NODE), // PPP_IPV6 → IPv6
];

static PPPOE_NODE: ParseNode<FlowMeta, PppoeOps> = ParseNode {
    proto: PppoeOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&PPP_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "pppoe",
};

// ── HSR/PRP → Ether dispatch ────────────────────────────────────

static HSR_NODE: ParseNode<FlowMeta, HsrOps> = ParseNode {
    proto: HsrOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "hsr",
};

// ── BATMAN → Ether dispatch ──────────────────────────────────────

static BATMAN_NODE: ParseNode<FlowMeta, BatmanOps> = ParseNode {
    proto: BatmanOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "batman",
};

// ── PBB (802.1ah) → Ether dispatch ──────────────────────────────

static PBB_NODE: ParseNode<FlowMeta, PbbOps> = ParseNode {
    proto: PbbOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "pbb",
};

// ── TRILL → Ether dispatch ───────────────────────────────────────

static TRILL_NODE: ParseNode<FlowMeta, TrillOps> = ParseNode {
    proto: TrillOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "trill",
};

// ── NSH → inner protocol dispatch ────────────────────────────────

/// NSH inner protocol table — NshOps returns mapped EtherType values.
static NSH_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0800, &IP_CHECK_NODE),    // ETH_P_IP
    (0x86DD, &IP_CHECK_NODE),    // ETH_P_IPV6
    (0x6558, &ETHER_INNER_NODE), // ETH_P_TEB
    (0x8847, &MPLS_NODE),        // ETH_P_MPLS_UC
];

static NSH_NODE: ParseNode<FlowMeta, NshOps> = ParseNode {
    proto: NshOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&NSH_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "nsh",
};

// ── IPv4 dispatch ─────────────────────────────────────────────────

static IPV4_TABLE: ProtoTable<FlowMeta> = proto_table![
    (6, &TCP_NODE),       // IPPROTO_TCP
    (17, &UDP_NODE),      // IPPROTO_UDP
    (1, &ICMPV4_NODE),    // IPPROTO_ICMP
    (2, &IGMP_NODE),      // IPPROTO_IGMP
    (4, &IP_CHECK_NODE),  // IPPROTO_IPIP (IPv4-in-IPv4)
    (33, &DCCP_NODE),     // IPPROTO_DCCP
    (41, &IP_CHECK_NODE), // IPPROTO_IPV6 (IPv6-in-IPv4)
    (47, &GRE_BASE_NODE), // IPPROTO_GRE
    (50, &ESP_NODE),      // IPPROTO_ESP
    (51, &AH_V4_NODE),    // IPPROTO_AH
    (132, &SCTP_NODE),    // IPPROTO_SCTP
    (115, &L2TP_NODE),    // IPPROTO_L2TP
    (136, &UDPLITE_NODE), // IPPROTO_UDPLITE
    (137, &MPLS_NODE),    // IPPROTO_MPLS
    (89, &OSPF_NODE),    // IPPROTO_OSPF
    (88, &EIGRP_NODE),   // IPPROTO_EIGRP
    (112, &VRRP_NODE),   // IPPROTO_VRRP
    (103, &PIM_NODE),    // IPPROTO_PIM
    (46, &RSVP_NODE),    // IPPROTO_RSVP
    (108, &IPCOMP_NODE), // IPPROTO_COMP
    (113, &PGM_NODE),    // IPPROTO_PGM
    (97, &ETHERIP_NODE), // IPPROTO_ETHERIP
];

static IPV4_NODE: ParseNode<FlowMeta, Ipv4Ops> = ParseNode {
    proto: Ipv4Ops,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_ipv4_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&IPV4_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv4",
};

// ── IP-in-IP (protocols 4 and 41) ────────────────────────────────
//
// Routes directly to IP_CHECK_NODE which reads the version nibble
// and dispatches to IPv4 or IPv6. No separate IpInIpOps node needed.

// ── AH (Authentication Header) — chains to next protocol ──────────

static AH_V4_NODE: ParseNode<FlowMeta, AhOps> = ParseNode {
    proto: AhOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_ah_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&IPV4_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ah-v4",
};

static AH_V6_NODE: ParseNode<FlowMeta, AhOps> = ParseNode {
    proto: AhOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_ah_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&IPV6_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ah-v6",
};

// ── GRE with flag-field sub-parsing ──────────────────────────────
//
// GRE v0 uses the flag-fields engine for optional checksum, key,
// and sequence fields. This is the first real integration of the
// flag-fields machinery in the benchmark graph.
//
// Graph structure:
//   gre_base_node (overlay, version dispatch)
//     → 0: gre_v0_node (ParseFlagFieldsNode wrapping GreV0Ops)
//            ├── extract_metadata: gre flags
//            ├── flag-fields: csum, key, seq
//            └── proto_table: IPv4, IPv6, TEB
//     → 1: stop-leaf (GRE v1/PPTP not common — parse succeeds at GRE)

// ── GRE flag-field parse nodes ──

static GRE_FLAG_CSUM_NODE: ParseFlagFieldNode<FlowMeta> = ParseFlagFieldNode {
    ops: ParseFlagFieldNodeOps {
        extract_metadata: Some(extract_gre_checksum),
        handler: None,
    },
    name: "gre-csum",
};

static GRE_FLAG_KEY_NODE: ParseFlagFieldNode<FlowMeta> = ParseFlagFieldNode {
    ops: ParseFlagFieldNodeOps {
        extract_metadata: Some(extract_gre_keyid),
        handler: None,
    },
    name: "gre-key",
};

static GRE_FLAG_SEQ_NODE: ParseFlagFieldNode<FlowMeta> = ParseFlagFieldNode {
    ops: ParseFlagFieldNodeOps {
        extract_metadata: Some(extract_gre_seq),
        handler: None,
    },
    name: "gre-seq",
};

// ── GRE v0 flag-fields table (maps field index → parse node) ──

static GRE_V0_FF_TABLE: FlagFieldsTable<FlowMeta> = FlagFieldsTable {
    entries: &[
        FlagFieldsTableEntry {
            index: 0,
            node: &GRE_FLAG_CSUM_NODE,
        }, // checksum
        FlagFieldsTableEntry {
            index: 1,
            node: &GRE_FLAG_KEY_NODE,
        }, // key
        FlagFieldsTableEntry {
            index: 2,
            node: &GRE_FLAG_SEQ_NODE,
        }, // sequence
    ],
};

// ── GRE v0 inner protocol dispatch ──

/// GRE v0 inner protocol table — dispatches on encapsulated EtherType.
/// Matches C's `gre_v0_table` in flow_dissector_tables.h.
static GRE_V0_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0800, &IP_CHECK_NODE),    // ETH_P_IP
    (0x86DD, &IP_CHECK_NODE),    // ETH_P_IPV6
    (0x6558, &ETHER_INNER_NODE), // ETH_P_TEB (Ethernet bridging)
];

/// GRE v0 inner parse node — provides header_len, next_proto, extract_metadata.
/// This is wrapped by GRE_V0_NODE (ParseFlagFieldsNode) which adds flag-field
/// sub-parsing via sub_parse().
static GRE_V0_INNER_NODE: ParseNode<FlowMeta, GreV0Ops> = ParseNode {
    proto: GreV0Ops,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_gre_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&GRE_V0_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "gre-v0",
};

/// GRE v0 parse node with flag-fields — wraps GRE_V0_INNER_NODE.
///
/// The engine processes this node as:
/// 1. header_len (from GreV0Ops — validates flags, computes variable length)
/// 2. extract_metadata (extract_gre_metadata — stores GRE flags)
/// 3. sub_parse → parse_flag_fields (iterates csum/key/seq, calls extractors)
/// 4. next_proto → proto_table lookup (dispatch to inner protocol)
///
/// Matches C's `gre_v0_node` (XDP2_MAKE_FLAG_FIELDS_PARSE_NODE) in
/// flow_dissector_nodes.h.
static GRE_V0_NODE: ParseFlagFieldsNode<FlowMeta> = ParseFlagFieldsNode {
    inner: &GRE_V0_INNER_NODE,
    ff_proto_table: &GRE_V0_FF_TABLE,
    flag_fields: &GRE_V0_FLAG_FIELDS,
    ff_ops: &GRE_FF_OPS,
};

// ── GRE base (version overlay dispatch) ──

/// GRE base version dispatch table.
/// Matches C's `gre_base_table` in flow_dissector_tables.h.
static GRE_BASE_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0, &GRE_V0_NODE),    // GRE v0
    (1, &STOP_LEAF_NODE), // GRE v1/PPTP — simplified (rare in practice)
];

/// GRE base overlay node — reads version nibble and dispatches.
///
/// OVERLAY=true so no bytes are consumed; the version is read from
/// the same position that GreV0Ops/v1 will read the full header.
///
/// Matches C's `gre_base_node` in flow_dissector_nodes.h.
static GRE_BASE_NODE: ParseNode<FlowMeta, GreBaseOps> = ParseNode {
    proto: GreBaseOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&GRE_BASE_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "gre-base",
};

// ── IPv6 dispatch ─────────────────────────────────────────────────

static IPV6_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0, &IPV6_HBH_NODE),      // IPPROTO_HOPOPTS
    (4, &IP_CHECK_NODE),      // IPPROTO_IPIP (IPv4-in-IPv6)
    (6, &TCP_NODE),           // IPPROTO_TCP
    (17, &UDP_NODE),          // IPPROTO_UDP
    (33, &DCCP_NODE),         // IPPROTO_DCCP
    (41, &IP_CHECK_NODE),     // IPPROTO_IPV6 (IPv6-in-IPv6)
    (43, &IPV6_ROUTING_NODE), // IPPROTO_ROUTING
    (44, &IPV6_FRAG_NODE),    // IPPROTO_FRAGMENT
    (47, &GRE_BASE_NODE),     // IPPROTO_GRE
    (50, &ESP_NODE),          // IPPROTO_ESP
    (51, &AH_V6_NODE),        // IPPROTO_AH
    (58, &ICMPV6_NODE),       // IPPROTO_ICMPV6
    (60, &IPV6_DST_NODE),     // IPPROTO_DSTOPTS
    (115, &L2TP_NODE),        // IPPROTO_L2TP
    (132, &SCTP_NODE),        // IPPROTO_SCTP
    (136, &UDPLITE_NODE),     // IPPROTO_UDPLITE
    (137, &MPLS_NODE),        // IPPROTO_MPLS
    (89, &OSPFV3_NODE),  // IPPROTO_OSPF (OSPFv3 for IPv6)
    (88, &EIGRP_NODE),   // IPPROTO_EIGRP
    (112, &VRRP3_NODE),  // IPPROTO_VRRP (VRRPv3 for IPv6)
    (103, &PIM_NODE),    // IPPROTO_PIM
    (46, &RSVP_NODE),    // IPPROTO_RSVP
    (108, &IPCOMP_NODE), // IPPROTO_COMP
    (113, &PGM_NODE),    // IPPROTO_PGM
];

static IPV6_NODE: ParseNode<FlowMeta, Ipv6Ops> = ParseNode {
    proto: Ipv6Ops,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_ipv6_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&IPV6_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv6",
};

// ── IPv6 extension headers ────────────────────────────────────────

static IPV6_HBH_NODE: ParseNode<FlowMeta, Ipv6EhOps> = ParseNode {
    proto: Ipv6EhOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_ipv6_eh_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&IPV6_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv6-hbh",
};

static IPV6_DST_NODE: ParseNode<FlowMeta, Ipv6EhOps> = ParseNode {
    proto: Ipv6EhOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_ipv6_eh_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&IPV6_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv6-dst",
};

static IPV6_ROUTING_NODE: ParseNode<FlowMeta, Ipv6EhOps> = ParseNode {
    proto: Ipv6EhOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_ipv6_eh_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&IPV6_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv6-routing",
};

static IPV6_FRAG_NODE: ParseNode<FlowMeta, Ipv6FragOps> = ParseNode {
    proto: Ipv6FragOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_ipv6_frag_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&IPV6_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv6-frag",
};

// ── IP version overlay (matches C's ip_check_node) ───────────────

/// IP version dispatch table: version nibble → IPv4 or IPv6.
static IP_CHECK_TABLE: ProtoTable<FlowMeta> = proto_table![
    (4, &IPV4_NODE), // IP version 4
    (6, &IPV6_NODE), // IP version 6
];

/// IP version check overlay node.
///
/// Reads the IP version nibble (first 4 bits of byte 0) and dispatches
/// to IPv4 or IPv6. Does not consume any bytes (OVERLAY=true).
///
/// Matches C's `ip_check_node` in flow_dissector_nodes.h.
static IP_CHECK_NODE: ParseNode<FlowMeta, IpOverlayOps> = ParseNode {
    proto: IpOverlayOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&IP_CHECK_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ip-check",
};

// ── Tunnel nodes (VXLAN, Geneve) ─────────────────────────────────

/// VXLAN inner dispatch — always ETH_P_TEB → inner Ethernet.
static VXLAN_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x6558, &ETHER_INNER_NODE), // ETH_P_TEB
];

/// VXLAN encapsulation node (8 bytes, always wraps Ethernet).
///
/// Matches C's `vxlan_node` in flow_dissector_nodes.h.
static VXLAN_NODE: ParseNode<FlowMeta, VxlanOps> = ParseNode {
    proto: VxlanOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_vxlan_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&VXLAN_INNER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "vxlan",
};

/// Geneve inner dispatch — ETH_P_TEB, IPv4, or IPv6.
///
/// Matches C's `geneve_inner_table` in flow_dissector_tables.h.
static GENEVE_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x6558, &ETHER_INNER_NODE), // ETH_P_TEB (Ethernet inside)
    (0x0800, &IP_CHECK_NODE),    // ETH_P_IP (raw IPv4 inside)
    (0x86DD, &IP_CHECK_NODE),    // ETH_P_IPV6 (raw IPv6 inside)
];

/// Geneve encapsulation node (variable-length, dispatches on protocol field).
///
/// Uses GeneveV0Ops (simple, no TLV option parsing) matching C's
/// `geneve_simple_def` in flow_dissector_proto_defs.h.
static GENEVE_NODE: ParseNode<FlowMeta, GeneveV0Ops> = ParseNode {
    proto: GeneveV0Ops,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_geneve_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&GENEVE_INNER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "geneve",
};

/// Inner Ethernet node — re-dispatches through ETHER_TABLE after tunnel decap.
///
/// Matches C's `ether_inner_node` in flow_dissector_nodes.h.
static ETHER_INNER_NODE: ParseNode<FlowMeta, EtherLlcOps> = ParseNode {
    proto: EtherLlcOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_ether_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ethernet-inner",
};

// ── LLC/SNAP dispatch ────────────────────────────────────────────
//
// When Ethernet/VLAN returns ETH_P_802_2 (ethertype ≤ 1500), we dispatch
// through the LLC layer. DSAP=0xAA routes to SNAP (which re-dispatches
// through ETHER_TABLE), DSAP=0x42 routes to STP (leaf).

static STP_NODE: ParseNode<FlowMeta, LlcOps> = ParseNode {
    proto: LlcOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "stp",
};

static SNAP_NODE: ParseNode<FlowMeta, LlcSnapOps> = ParseNode {
    proto: LlcSnapOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&ETHER_TABLE), // re-dispatch encapsulated ethertype
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "llc-snap",
};

/// LLC dispatch table — routes DSAP to SNAP or STP.
static LLC_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0xAA, &SNAP_NODE), // LLC_SAP_SNAP → LLC/SNAP encapsulation
    (0x42, &STP_NODE),  // LLC_SAP_STP → STP BPDU (leaf)
];

static LLC_NODE: ParseNode<FlowMeta, LlcDispatchOps> = ParseNode {
    proto: LlcDispatchOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&LLC_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "llc",
};

// ── Ethernet + VLAN dispatch ──────────────────────────────────────

static ETHER_TABLE: ProtoTable<FlowMeta> = proto_table![
    // Core L3
    (0x0800, &IP_CHECK_NODE), // ETH_P_IP → ip version check → IPv4/IPv6
    (0x86DD, &IP_CHECK_NODE), // ETH_P_IPV6 → ip version check
    (0x0806, &ARP_NODE),      // ETH_P_ARP
    (0x8035, &RARP_NODE),     // ETH_P_RARP
    // VLAN
    (0x8100, &VLAN_NODE), // ETH_P_8021Q
    (0x88A8, &QINQ_NODE), // ETH_P_8021AD
    // MPLS
    (0x8847, &MPLS_NODE), // ETH_P_MPLS_UC
    (0x8848, &MPLS_NODE), // ETH_P_MPLS_MC
    // Tunnels / encapsulation
    (0x8864, &PPPOE_NODE),  // ETH_P_PPP_SES
    (0x4305, &BATMAN_NODE), // ETH_P_BATMAN
    (0x88E7, &PBB_NODE),    // ETH_P_8021AH (PBB)
    (0x22F3, &TRILL_NODE),  // ETH_P_TRILL
    (0x892F, &HSR_NODE),    // ETH_P_HSR
    (0x88FB, &HSR_NODE),    // ETH_P_PRP (same handler as HSR)
    (0x894F, &NSH_NODE),    // ETH_P_NSH
    // Management / L2 leaves
    (0x88CC, &LLDP_NODE),        // ETH_P_LLDP
    (0x8809, &SLOW_NODE),        // ETH_P_SLOW (LACP/STP)
    (0x8808, &MAC_CONTROL_NODE), // ETH_P_PAUSE (MAC control)
    (0x888E, &EAPOL_NODE),       // ETH_P_PAE (802.1X)
    (0x88F7, &PTP_NODE),         // ETH_P_1588 (PTP)
    (0x88F5, &MVRP_NODE),        // ETH_P_MVRP
    (0x8902, &CFM_NODE),         // ETH_P_CFM
    (0x8914, &FIP_NODE),         // ETH_P_FIP
    (0x88E5, &MACSEC_NODE),      // ETH_P_MACSEC
    (0x88A4, &ETHERCAT_NODE),    // ETH_P_ETHERCAT
    (0x88CA, &TIPC_NODE),        // ETH_P_TIPC
    // Storage
    (0x8906, &FCOE_NODE), // ETH_P_FCOE
    // LLC
    (ETH_P_802_2, &LLC_NODE), // IEEE 802.2 LLC (ethertype ≤ 1500)
];

pub(crate) static ETHER_NODE: ParseNode<FlowMeta, EtherLlcOps> = ParseNode {
    proto: EtherLlcOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_ether_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ethernet",
};

static VLAN_NODE: ParseNode<FlowMeta, VlanLlcOps> = ParseNode {
    proto: VlanLlcOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_vlan_8021q_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "vlan",
};

static QINQ_NODE: ParseNode<FlowMeta, QinQLlcOps> = ParseNode {
    proto: QinQLlcOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_vlan_8021ad_metadata),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "qinq",
};
