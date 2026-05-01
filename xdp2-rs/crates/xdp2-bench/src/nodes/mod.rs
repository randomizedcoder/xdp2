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
pub(crate) struct VlanLlcOps;

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
pub(crate) struct QinQLlcOps;

impl ProtocolOps for QinQLlcOps {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "QinQ-LLC";

    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(etype_or_llc(u16::from_be_bytes([hdr[2], hdr[3]])))
    }
}

/// LLC dispatch: reads DSAP byte, routes to SNAP (0xAA) or STP (0x42).
pub(crate) struct LlcDispatchOps;

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

mod tcp_app;
pub(crate) use tcp_app::*;
mod udp_app;
pub(crate) use udp_app::*;
mod leaves;
pub(crate) use leaves::*;
mod tunnels;
pub(crate) use tunnels::*;
mod ip;
pub(crate) use ip::*;
mod encap;
pub(crate) use encap::*;

