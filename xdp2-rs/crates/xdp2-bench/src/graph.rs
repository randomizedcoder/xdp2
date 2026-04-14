// FlowMeta fields and UdpDportOps are used in later phases (metadata extraction, tunnel dispatch).
#![allow(dead_code)]

//! Static parse graph for benchmarking.
//!
//! Builds an Ethernet → IP → Transport parse graph matching the protocol
//! coverage of the C flow_dissector benchmark. Uses protocol Ops from
//! xdp2-protocols with FlowMeta metadata extraction to match C's
//! `xdp2_metadata_all` for apples-to-apples benchmarking.
//!
//! ## Protocol Coverage
//!
//! **Ether table (26 entries):**
//! - Core L3: IPv4, IPv6 (via IP check overlay), ARP, RARP
//! - VLAN: 802.1Q, 802.1AD (QinQ)
//! - MPLS: unicast (0x8847), multicast (0x8848)
//! - Tunnels: PPPoE→PPP→IP, BATMAN, PBB, TRILL, HSR/PRP, NSH
//! - Management leaves: LLDP, SLOW, MAC_CONTROL, EAPOL, PTP, MVRP, CFM, FIP
//! - Security/storage leaves: MACsec, EtherCAT, TIPC
//!
//! **IPv4/IPv6 tables (13/16 entries):**
//! TCP, UDP (tunnel dispatch), ICMP, IGMP, SCTP, DCCP, UDPLite,
//! GRE (flag-fields), ESP, AH, MPLS, IP-in-IP
//!
//! **Tunnel dispatch:** UDP dport → VXLAN (4789), Geneve (6081)
//! **GRE v0:** flag-field sub-parsing (csum/key/seq) → IPv4/IPv6/TEB

use xdp2_core::{
    parse, CtrlData, ParseError, ParseNode, ParseNodeOps, ParseOutput,
    Parser, ParserConfig, ParserType, ProtocolOps, ProtoTable,
    proto_table,
};
use xdp2_core::flag_fields::{
    FlagFieldsTable, FlagFieldsTableEntry,
    ParseFlagFieldNode, ParseFlagFieldNodeOps, ParseFlagFieldsNode,
};
use xdp2_protocols::ethernet::ether::EthernetOps;
use xdp2_protocols::ethernet::vlan::VlanOps;
use xdp2_protocols::ethernet::qinq::QinQOps;
use xdp2_protocols::ip::arp::ArpOps;
use xdp2_protocols::ip::ipv4::Ipv4Ops;
use xdp2_protocols::ip::ipv6::Ipv6Ops;
use xdp2_protocols::ip::ipv6_eh::{Ipv6EhOps, Ipv6FragOps};
use xdp2_protocols::ip::icmp::{IcmpV4Ops, IcmpV6Ops};
use xdp2_protocols::transport::tcp::TcpOps;
use xdp2_protocols::transport::sctp::SctpOps;
use xdp2_protocols::transport::dccp::DccpOps;
use xdp2_protocols::transport::udplite::UdpLiteOps;
// IpInIpOps removed — IP-in-IP tunnels dispatch through IP_CHECK_NODE directly.
use xdp2_protocols::tunnel::mpls::MplsOps;
use xdp2_protocols::ip::igmp::IgmpOps;
use xdp2_protocols::security::misc::{EspOps, EapolOps, MacsecOps};
use xdp2_protocols::tunnel::vxlan::VxlanOps;
use xdp2_protocols::tunnel::geneve::GeneveV0Ops;
use xdp2_protocols::tunnel::gre::{GreBaseOps, GreV0Ops, GRE_V0_FLAG_FIELDS, GRE_FF_OPS};
use xdp2_protocols::ip::ip_overlay::IpOverlayOps;
use xdp2_protocols::security::ah::AhOps;
use xdp2_protocols::ip::arp::RarpOps;
use xdp2_protocols::transport::tipc::TipcOps;
use xdp2_protocols::management::misc::{LldpOps, SlowOps, MacControlOps, PtpOps, MvrpOps, CfmOps, FipOps};
use xdp2_protocols::management::trill::TrillOps;
use xdp2_protocols::storage::misc::EthercatOps;
use xdp2_protocols::legacy::BatmanOps;
use xdp2_protocols::ethernet::pbb::PbbOps;
use xdp2_protocols::tunnel::misc::{PppoeOps, HsrOps};
use xdp2_protocols::tunnel::nsh::NshOps;

// ── Flow metadata ────────────────────────────────────────────────
//
// Matches C's `struct xdp2_metadata_all` from parser_metadata.h.
// Each field group corresponds to a C metadata macro (XDP2_METADATA_*).

/// Address type — matches `enum xdp2_addr_types` in parser_metadata.h.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum AddrType {
    #[default]
    Invalid = 0,
    Ipv4 = 1,
    Ipv6 = 2,
    Tipc = 3,
    Sunh = 4,
}

/// IPv4 or IPv6 addresses — matches `XDP2_METADATA_addrs` union.
#[derive(Clone, Copy, Debug, Default)]
pub struct AddrsMeta {
    pub v4_src: u32,
    pub v4_dst: u32,
    pub v6_src: [u8; 16],
    pub v6_dst: [u8; 16],
    pub tipc_key: u32,
}

/// Transport ports — matches `XDP2_METADATA_ports` union.
#[derive(Clone, Copy, Debug, Default)]
pub struct PortsMeta {
    pub src_port: u16,
    pub dst_port: u16,
}

/// ICMP metadata — matches `XDP2_METADATA_icmp`.
#[derive(Clone, Copy, Debug, Default)]
pub struct IcmpMeta {
    pub icmp_type: u8,
    pub code: u8,
    pub id: u16,
}

/// VLAN tag metadata — matches `XDP2_METADATA_vlan` array element.
#[derive(Clone, Copy, Debug, Default)]
pub struct VlanMeta {
    pub tci: u16,
    pub tpid: u16,
}

/// MPLS label metadata — matches `XDP2_METADATA_mpls`.
#[derive(Clone, Copy, Debug, Default)]
pub struct MplsMeta {
    pub label: u32,
    pub tc: u8,
    pub bos: bool,
    pub ttl: u8,
}

/// ARP metadata — matches `XDP2_METADATA_arp`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArpMeta {
    pub op: u8,
    pub sha: [u8; 6],
    pub spa: u32,
    pub tha: [u8; 6],
    pub tpa: u32,
}

/// GRE v0 metadata — matches `XDP2_METADATA_gre`.
#[derive(Clone, Copy, Debug, Default)]
pub struct GreMeta {
    pub flags: u32,
    pub csum: u16,
    pub keyid: u32,
    pub seq: u32,
    pub routing: u32,
}

/// GRE v1/PPTP metadata — matches `XDP2_METADATA_gre_pptp`.
#[derive(Clone, Copy, Debug, Default)]
pub struct GrePptpMeta {
    pub flags: u32,
    pub length: u16,
    pub callid: u16,
    pub seq: u32,
    pub ack: u32,
}

/// Flow metadata — Rust equivalent of C's `struct xdp2_metadata_all`.
///
/// Populated by `extract_metadata` callbacks at each protocol layer.
/// Fields ordered to match the C struct for easy cross-reference.
#[derive(Clone, Debug, Default)]
pub struct FlowMeta {
    pub addr_type: AddrType,
    pub is_fragment: bool,
    pub first_frag: bool,
    pub vlan_count: u8,
    pub eth_addrs: [u8; 12],       // dst[6] + src[6] MACs
    pub mpls: MplsMeta,
    pub arp: ArpMeta,
    pub gre: GreMeta,
    pub gre_pptp: GrePptpMeta,
    pub l2_off: u16,
    pub l3_off: u16,
    pub l4_off: u16,
    pub eth_proto: u16,
    pub ip_proto: u8,
    pub flow_label: u32,
    pub vlan: [VlanMeta; 2],
    pub keyid: u32,
    pub esp_spi: u32,
    pub ah_spi: u32,
    pub ports: PortsMeta,
    pub icmp: IcmpMeta,
    pub addrs: AddrsMeta,
}

// ── Metadata extractors ─────────────────────────────────────────
//
// Each function matches a C `XDP2_METADATA_TEMP_*` macro from
// parser_metadata.h. The engine calls these with `hdr` pointing
// to the current protocol header (not the full packet).

/// Ethernet: extract MACs and ethertype.
/// Matches C's `XDP2_METADATA_TEMP_ether`.
fn extract_ether_metadata(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    meta.eth_addrs[..12].copy_from_slice(&hdr[0..12]);
    meta.eth_proto = u16::from_be_bytes([hdr[12], hdr[13]]);
}

/// IPv4: fragment info, addresses, protocol.
/// Matches C's `XDP2_METADATA_TEMP_ipv4`.
fn extract_ipv4_metadata(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    let frag_off = u16::from_be_bytes([hdr[6], hdr[7]]);
    const IP_MF: u16 = 0x2000;
    const IP_OFFSET: u16 = 0x1FFF;
    if (frag_off & (IP_MF | IP_OFFSET)) != 0 {
        meta.is_fragment = true;
        meta.first_frag = (frag_off & IP_OFFSET) == 0;
    }
    meta.addr_type = AddrType::Ipv4;
    meta.ip_proto = hdr[9];
    meta.addrs.v4_src = u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]);
    meta.addrs.v4_dst = u32::from_be_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]);
}

/// IPv6: addresses, next header, flow label.
/// Matches C's `XDP2_METADATA_TEMP_ipv6`.
fn extract_ipv6_metadata(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    meta.addr_type = AddrType::Ipv6;
    meta.ip_proto = hdr[6]; // next header
    meta.flow_label = ((hdr[1] as u32 & 0x0F) << 16) | ((hdr[2] as u32) << 8) | (hdr[3] as u32);
    meta.addrs.v6_src.copy_from_slice(&hdr[8..24]);
    meta.addrs.v6_dst.copy_from_slice(&hdr[24..40]);
}

/// IPv6 extension header: update ip_proto with next header.
/// Matches C's `XDP2_METADATA_TEMP_ipv6_eh`.
fn extract_ipv6_eh_metadata(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    meta.ip_proto = hdr[0];
}

/// IPv6 fragment header: fragment info + next header.
/// Matches C's `XDP2_METADATA_TEMP_ipv6_frag`.
fn extract_ipv6_frag_metadata(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    meta.ip_proto = hdr[0];
    let frag_off = u16::from_be_bytes([hdr[2], hdr[3]]);
    const IP6_OFFSET: u16 = 0xFFF8;
    meta.is_fragment = true;
    meta.first_frag = (frag_off & IP6_OFFSET) == 0;
}

/// Transport ports (TCP, UDP, SCTP, DCCP, UDPLite).
/// Matches C's `XDP2_METADATA_TEMP_ports`.
fn extract_ports_metadata(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    meta.ports.src_port = u16::from_be_bytes([hdr[0], hdr[1]]);
    meta.ports.dst_port = u16::from_be_bytes([hdr[2], hdr[3]]);
}

/// ICMP (v4 and v6): type, code, echo ID.
/// Matches C's `XDP2_METADATA_TEMP_icmp`.
fn extract_icmp_metadata(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    meta.icmp.icmp_type = hdr[0];
    meta.icmp.code = hdr[1];
    // Echo request/reply: v4 type 0/8, v6 type 128/129
    let t = hdr[0];
    if t == 0 || t == 8 || t == 128 || t == 129 {
        meta.icmp.id = u16::from_be_bytes([hdr[4], hdr[5]]);
    }
}

/// VLAN 802.1Q tag.
/// Matches C's `XDP2_METADATA_TEMP_vlan_8021Q`.
fn extract_vlan_8021q_metadata(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    let idx = if meta.vlan_count < 2 { meta.vlan_count as usize } else { 1 };
    if meta.vlan_count < 2 { meta.vlan_count += 1; }
    meta.vlan[idx].tci = u16::from_be_bytes([hdr[0], hdr[1]]);
    meta.vlan[idx].tpid = 0x8100;
}

/// VLAN 802.1AD (QinQ) tag.
/// Matches C's `XDP2_METADATA_TEMP_vlan_8021AD`.
fn extract_vlan_8021ad_metadata(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    let idx = if meta.vlan_count < 2 { meta.vlan_count as usize } else { 1 };
    if meta.vlan_count < 2 { meta.vlan_count += 1; }
    meta.vlan[idx].tci = u16::from_be_bytes([hdr[0], hdr[1]]);
    meta.vlan[idx].tpid = 0x88A8;
}

/// ARP/RARP: opcode, sender/target HW+IP addresses.
/// Matches C's `XDP2_METADATA_TEMP_arp_rarp`.
fn extract_arp_metadata(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    meta.arp.op = (u16::from_be_bytes([hdr[6], hdr[7]]) & 0xFF) as u8;
    meta.arp.sha.copy_from_slice(&hdr[8..14]);
    meta.arp.spa = u32::from_be_bytes([hdr[14], hdr[15], hdr[16], hdr[17]]);
    meta.arp.tha.copy_from_slice(&hdr[18..24]);
    meta.arp.tpa = u32::from_be_bytes([hdr[24], hdr[25], hdr[26], hdr[27]]);
}

/// MPLS label: label, TC, BoS, TTL from first 4-byte label entry.
/// Matches C's `XDP2_METADATA_TEMP_mpls`.
fn extract_mpls_metadata(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    let w = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    meta.mpls.label = w >> 12;
    meta.mpls.tc = ((w >> 9) & 0x7) as u8;
    meta.mpls.bos = ((w >> 8) & 0x1) != 0;
    meta.mpls.ttl = (w & 0xFF) as u8;
}

/// ESP: extract SPI.
/// Matches C's `XDP2_METADATA_TEMP_esp`.
fn extract_esp_metadata(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    meta.esp_spi = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
}

/// AH: extract SPI (Security Parameters Index).
/// Matches C's `XDP2_METADATA_TEMP_ah`.
fn extract_ah_metadata(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    meta.ah_spi = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
}

/// TIPC: extract addr_type and originating node.
/// Matches C's `XDP2_METADATA_TEMP_tipc`.
fn extract_tipc_metadata(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    meta.addr_type = AddrType::Tipc;
    meta.addrs.tipc_key = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
}

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

// ── Leaf nodes (no proto_table, parsing stops here) ───────────────

static TCP_NODE: ParseNode<FlowMeta, TcpOps> = ParseNode {
    proto: TcpOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_ports_metadata), handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
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
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "stop-leaf",
};

/// UDP tunnel dispatch table — known tunnel destination ports.
/// Matches C's `udp_tunnel_table` in flow_dissector_tables.h.
static UDP_TUNNEL_TABLE: ProtoTable<FlowMeta> = proto_table![
    (4789, &VXLAN_NODE),   // VXLAN
    (6081, &GENEVE_NODE),  // Geneve
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
    ops: ParseNodeOps { extract_metadata: Some(extract_ports_metadata), handler: None, post_handler: None },
    proto_table: Some(&UDP_TUNNEL_TABLE),
    wildcard_node: Some(&STOP_LEAF_NODE),
    unknown_ret: ParseError::UnknownProto,
    name: "udp",
};

static ICMPV4_NODE: ParseNode<FlowMeta, IcmpV4Ops> = ParseNode {
    proto: IcmpV4Ops,
    ops: ParseNodeOps { extract_metadata: Some(extract_icmp_metadata), handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "icmpv4",
};

static ICMPV6_NODE: ParseNode<FlowMeta, IcmpV6Ops> = ParseNode {
    proto: IcmpV6Ops,
    ops: ParseNodeOps { extract_metadata: Some(extract_icmp_metadata), handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "icmpv6",
};

static SCTP_NODE: ParseNode<FlowMeta, SctpOps> = ParseNode {
    proto: SctpOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_ports_metadata), handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "sctp",
};

static ARP_NODE: ParseNode<FlowMeta, ArpOps> = ParseNode {
    proto: ArpOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_arp_metadata), handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "arp",
};

// ── New leaf nodes for expanded IP tables ────────────────────────

static IGMP_NODE: ParseNode<FlowMeta, IgmpOps> = ParseNode {
    proto: IgmpOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "igmp",
};

static ESP_NODE: ParseNode<FlowMeta, EspOps> = ParseNode {
    proto: EspOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_esp_metadata), handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "esp",
};

static DCCP_NODE: ParseNode<FlowMeta, DccpOps> = ParseNode {
    proto: DccpOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_ports_metadata), handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "dccp",
};

static UDPLITE_NODE: ParseNode<FlowMeta, UdpLiteOps> = ParseNode {
    proto: UdpLiteOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_ports_metadata), handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "udplite",
};

static MPLS_NODE: ParseNode<FlowMeta, MplsOps> = ParseNode {
    proto: MplsOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_mpls_metadata), handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "mpls",
};

// ── L2 leaf nodes (simple protocols that terminate the parse) ────

static RARP_NODE: ParseNode<FlowMeta, RarpOps> = ParseNode {
    proto: RarpOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_arp_metadata), handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "rarp",
};

static TIPC_NODE: ParseNode<FlowMeta, TipcOps> = ParseNode {
    proto: TipcOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_tipc_metadata), handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "tipc",
};

static LLDP_NODE: ParseNode<FlowMeta, LldpOps> = ParseNode {
    proto: LldpOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "lldp",
};

static SLOW_NODE: ParseNode<FlowMeta, SlowOps> = ParseNode {
    proto: SlowOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "slow",
};

static MAC_CONTROL_NODE: ParseNode<FlowMeta, MacControlOps> = ParseNode {
    proto: MacControlOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "mac-control",
};

static EAPOL_NODE: ParseNode<FlowMeta, EapolOps> = ParseNode {
    proto: EapolOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "eapol",
};

static PTP_NODE: ParseNode<FlowMeta, PtpOps> = ParseNode {
    proto: PtpOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ptp",
};

static MVRP_NODE: ParseNode<FlowMeta, MvrpOps> = ParseNode {
    proto: MvrpOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "mvrp",
};

static CFM_NODE: ParseNode<FlowMeta, CfmOps> = ParseNode {
    proto: CfmOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "cfm",
};

static FIP_NODE: ParseNode<FlowMeta, FipOps> = ParseNode {
    proto: FipOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "fip",
};

static MACSEC_NODE: ParseNode<FlowMeta, MacsecOps> = ParseNode {
    proto: MacsecOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "macsec",
};

static ETHERCAT_NODE: ParseNode<FlowMeta, EthercatOps> = ParseNode {
    proto: EthercatOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ethercat",
};

// ── PPPoE → PPP dispatch ─────────────────────────────────────────

/// PPP protocol dispatch table.
/// PppoeOps returns the PPP protocol number.
static PPP_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0021, &IP_CHECK_NODE),  // PPP_IP → IPv4
    (0x0057, &IP_CHECK_NODE),  // PPP_IPV6 → IPv6
];

static PPPOE_NODE: ParseNode<FlowMeta, PppoeOps> = ParseNode {
    proto: PppoeOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&PPP_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "pppoe",
};

// ── HSR/PRP → Ether dispatch ────────────────────────────────────

static HSR_NODE: ParseNode<FlowMeta, HsrOps> = ParseNode {
    proto: HsrOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "hsr",
};

// ── BATMAN → Ether dispatch ──────────────────────────────────────

static BATMAN_NODE: ParseNode<FlowMeta, BatmanOps> = ParseNode {
    proto: BatmanOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "batman",
};

// ── PBB (802.1ah) → Ether dispatch ──────────────────────────────

static PBB_NODE: ParseNode<FlowMeta, PbbOps> = ParseNode {
    proto: PbbOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "pbb",
};

// ── TRILL → Ether dispatch ───────────────────────────────────────

static TRILL_NODE: ParseNode<FlowMeta, TrillOps> = ParseNode {
    proto: TrillOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "trill",
};

// ── NSH → inner protocol dispatch ────────────────────────────────

/// NSH inner protocol table — NshOps returns mapped EtherType values.
static NSH_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0800, &IP_CHECK_NODE),      // ETH_P_IP
    (0x86DD, &IP_CHECK_NODE),      // ETH_P_IPV6
    (0x6558, &ETHER_INNER_NODE),   // ETH_P_TEB
    (0x8847, &MPLS_NODE),          // ETH_P_MPLS_UC
];

static NSH_NODE: ParseNode<FlowMeta, NshOps> = ParseNode {
    proto: NshOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&NSH_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "nsh",
};

// ── IPv4 dispatch ─────────────────────────────────────────────────

static IPV4_TABLE: ProtoTable<FlowMeta> = proto_table![
    (6, &TCP_NODE),           // IPPROTO_TCP
    (17, &UDP_NODE),          // IPPROTO_UDP
    (1, &ICMPV4_NODE),        // IPPROTO_ICMP
    (2, &IGMP_NODE),          // IPPROTO_IGMP
    (4, &IP_CHECK_NODE),      // IPPROTO_IPIP (IPv4-in-IPv4)
    (33, &DCCP_NODE),         // IPPROTO_DCCP
    (41, &IP_CHECK_NODE),     // IPPROTO_IPV6 (IPv6-in-IPv4)
    (47, &GRE_BASE_NODE),     // IPPROTO_GRE
    (50, &ESP_NODE),          // IPPROTO_ESP
    (51, &AH_V4_NODE),        // IPPROTO_AH
    (132, &SCTP_NODE),        // IPPROTO_SCTP
    (136, &UDPLITE_NODE),     // IPPROTO_UDPLITE
    (137, &MPLS_NODE),        // IPPROTO_MPLS
];

static IPV4_NODE: ParseNode<FlowMeta, Ipv4Ops> = ParseNode {
    proto: Ipv4Ops,
    ops: ParseNodeOps { extract_metadata: Some(extract_ipv4_metadata), handler: None, post_handler: None },
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
    ops: ParseNodeOps { extract_metadata: Some(extract_ah_metadata), handler: None, post_handler: None },
    proto_table: Some(&IPV4_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ah-v4",
};

static AH_V6_NODE: ParseNode<FlowMeta, AhOps> = ParseNode {
    proto: AhOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_ah_metadata), handler: None, post_handler: None },
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

// ── GRE metadata extractors ──

/// Extract GRE base flags into FlowMeta.gre.flags.
/// Matches C's `XDP2_METADATA_TEMP_gre` in parser_metadata.h.
fn extract_gre_metadata(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    meta.gre.flags = u16::from_be_bytes([hdr[0], hdr[1]]) as u32;
}

/// Extract GRE checksum field (4-byte flag-field: checksum + reserved).
/// Matches C's `XDP2_METADATA_TEMP_gre_checksum` in parser_metadata.h.
fn extract_gre_checksum(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    meta.gre.csum = u16::from_ne_bytes([hdr[0], hdr[1]]);
}

/// Extract GRE key/ID field (4-byte flag-field).
/// Matches C's `XDP2_METADATA_TEMP_gre_keyid` — stores in both gre.keyid and keyid.
fn extract_gre_keyid(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    let v = u32::from_ne_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    meta.gre.keyid = v;
    meta.keyid = v;
}

/// Extract GRE sequence number field (4-byte flag-field).
/// Matches C's `XDP2_METADATA_TEMP_gre_seq` in parser_metadata.h.
fn extract_gre_seq(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    meta.gre.seq = u32::from_ne_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
}

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
        FlagFieldsTableEntry { index: 0, node: &GRE_FLAG_CSUM_NODE },  // checksum
        FlagFieldsTableEntry { index: 1, node: &GRE_FLAG_KEY_NODE },   // key
        FlagFieldsTableEntry { index: 2, node: &GRE_FLAG_SEQ_NODE },   // sequence
    ],
};

// ── GRE v0 inner protocol dispatch ──

/// GRE v0 inner protocol table — dispatches on encapsulated EtherType.
/// Matches C's `gre_v0_table` in flow_dissector_tables.h.
static GRE_V0_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0800, &IP_CHECK_NODE),      // ETH_P_IP
    (0x86DD, &IP_CHECK_NODE),      // ETH_P_IPV6
    (0x6558, &ETHER_INNER_NODE),   // ETH_P_TEB (Ethernet bridging)
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
    (0, &GRE_V0_NODE),       // GRE v0
    (1, &STOP_LEAF_NODE),    // GRE v1/PPTP — simplified (rare in practice)
];

/// GRE base overlay node — reads version nibble and dispatches.
///
/// OVERLAY=true so no bytes are consumed; the version is read from
/// the same position that GreV0Ops/v1 will read the full header.
///
/// Matches C's `gre_base_node` in flow_dissector_nodes.h.
static GRE_BASE_NODE: ParseNode<FlowMeta, GreBaseOps> = ParseNode {
    proto: GreBaseOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&GRE_BASE_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "gre-base",
};

// ── IPv6 dispatch ─────────────────────────────────────────────────

static IPV6_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0, &IPV6_HBH_NODE),      // IPPROTO_HOPOPTS
    (4, &IP_CHECK_NODE),       // IPPROTO_IPIP (IPv4-in-IPv6)
    (6, &TCP_NODE),            // IPPROTO_TCP
    (17, &UDP_NODE),           // IPPROTO_UDP
    (33, &DCCP_NODE),          // IPPROTO_DCCP
    (41, &IP_CHECK_NODE),      // IPPROTO_IPV6 (IPv6-in-IPv6)
    (43, &IPV6_ROUTING_NODE),  // IPPROTO_ROUTING
    (44, &IPV6_FRAG_NODE),     // IPPROTO_FRAGMENT
    (47, &GRE_BASE_NODE),      // IPPROTO_GRE
    (50, &ESP_NODE),           // IPPROTO_ESP
    (51, &AH_V6_NODE),         // IPPROTO_AH
    (58, &ICMPV6_NODE),        // IPPROTO_ICMPV6
    (60, &IPV6_DST_NODE),      // IPPROTO_DSTOPTS
    (132, &SCTP_NODE),         // IPPROTO_SCTP
    (136, &UDPLITE_NODE),      // IPPROTO_UDPLITE
    (137, &MPLS_NODE),         // IPPROTO_MPLS
];

static IPV6_NODE: ParseNode<FlowMeta, Ipv6Ops> = ParseNode {
    proto: Ipv6Ops,
    ops: ParseNodeOps { extract_metadata: Some(extract_ipv6_metadata), handler: None, post_handler: None },
    proto_table: Some(&IPV6_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv6",
};

// ── IPv6 extension headers ────────────────────────────────────────

static IPV6_HBH_NODE: ParseNode<FlowMeta, Ipv6EhOps> = ParseNode {
    proto: Ipv6EhOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_ipv6_eh_metadata), handler: None, post_handler: None },
    proto_table: Some(&IPV6_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv6-hbh",
};

static IPV6_DST_NODE: ParseNode<FlowMeta, Ipv6EhOps> = ParseNode {
    proto: Ipv6EhOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_ipv6_eh_metadata), handler: None, post_handler: None },
    proto_table: Some(&IPV6_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv6-dst",
};

static IPV6_ROUTING_NODE: ParseNode<FlowMeta, Ipv6EhOps> = ParseNode {
    proto: Ipv6EhOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_ipv6_eh_metadata), handler: None, post_handler: None },
    proto_table: Some(&IPV6_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv6-routing",
};

static IPV6_FRAG_NODE: ParseNode<FlowMeta, Ipv6FragOps> = ParseNode {
    proto: Ipv6FragOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_ipv6_frag_metadata), handler: None, post_handler: None },
    proto_table: Some(&IPV6_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv6-frag",
};

// ── IP version overlay (matches C's ip_check_node) ───────────────

/// IP version dispatch table: version nibble → IPv4 or IPv6.
static IP_CHECK_TABLE: ProtoTable<FlowMeta> = proto_table![
    (4, &IPV4_NODE),   // IP version 4
    (6, &IPV6_NODE),   // IP version 6
];

/// IP version check overlay node.
///
/// Reads the IP version nibble (first 4 bits of byte 0) and dispatches
/// to IPv4 or IPv6. Does not consume any bytes (OVERLAY=true).
///
/// Matches C's `ip_check_node` in flow_dissector_nodes.h.
static IP_CHECK_NODE: ParseNode<FlowMeta, IpOverlayOps> = ParseNode {
    proto: IpOverlayOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&IP_CHECK_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ip-check",
};

// ── Tunnel nodes (VXLAN, Geneve) ─────────────────────────────────

/// VXLAN inner dispatch — always ETH_P_TEB → inner Ethernet.
static VXLAN_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x6558, &ETHER_INNER_NODE),  // ETH_P_TEB
];

/// VXLAN encapsulation node (8 bytes, always wraps Ethernet).
///
/// Matches C's `vxlan_node` in flow_dissector_nodes.h.
/// VXLAN: extract VNI into keyid.
fn extract_vxlan_metadata(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    // VNI is in bytes 4-6 (24-bit), byte 7 is reserved.
    meta.keyid = ((hdr[4] as u32) << 16) | ((hdr[5] as u32) << 8) | (hdr[6] as u32);
}

static VXLAN_NODE: ParseNode<FlowMeta, VxlanOps> = ParseNode {
    proto: VxlanOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_vxlan_metadata), handler: None, post_handler: None },
    proto_table: Some(&VXLAN_INNER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "vxlan",
};

/// Geneve inner dispatch — ETH_P_TEB, IPv4, or IPv6.
///
/// Matches C's `geneve_inner_table` in flow_dissector_tables.h.
static GENEVE_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x6558, &ETHER_INNER_NODE),  // ETH_P_TEB (Ethernet inside)
    (0x0800, &IP_CHECK_NODE),     // ETH_P_IP (raw IPv4 inside)
    (0x86DD, &IP_CHECK_NODE),     // ETH_P_IPV6 (raw IPv6 inside)
];

/// Geneve encapsulation node (variable-length, dispatches on protocol field).
///
/// Uses GeneveV0Ops (simple, no TLV option parsing) matching C's
/// `geneve_simple_def` in flow_dissector_proto_defs.h.
/// Geneve: extract VNI into keyid.
fn extract_geneve_metadata(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    // VNI is in bytes 4-6 (24-bit), byte 7 is reserved.
    meta.keyid = ((hdr[4] as u32) << 16) | ((hdr[5] as u32) << 8) | (hdr[6] as u32);
}

static GENEVE_NODE: ParseNode<FlowMeta, GeneveV0Ops> = ParseNode {
    proto: GeneveV0Ops,
    ops: ParseNodeOps { extract_metadata: Some(extract_geneve_metadata), handler: None, post_handler: None },
    proto_table: Some(&GENEVE_INNER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "geneve",
};

/// Inner Ethernet node — re-dispatches through ETHER_TABLE after tunnel decap.
///
/// Matches C's `ether_inner_node` in flow_dissector_nodes.h.
static ETHER_INNER_NODE: ParseNode<FlowMeta, EthernetOps> = ParseNode {
    proto: EthernetOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_ether_metadata), handler: None, post_handler: None },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ethernet-inner",
};

// ── Ethernet + VLAN dispatch ──────────────────────────────────────

static ETHER_TABLE: ProtoTable<FlowMeta> = proto_table![
    // Core L3
    (0x0800, &IP_CHECK_NODE),      // ETH_P_IP → ip version check → IPv4/IPv6
    (0x86DD, &IP_CHECK_NODE),      // ETH_P_IPV6 → ip version check
    (0x0806, &ARP_NODE),           // ETH_P_ARP
    (0x8035, &RARP_NODE),          // ETH_P_RARP
    // VLAN
    (0x8100, &VLAN_NODE),          // ETH_P_8021Q
    (0x88A8, &QINQ_NODE),         // ETH_P_8021AD
    // MPLS
    (0x8847, &MPLS_NODE),          // ETH_P_MPLS_UC
    (0x8848, &MPLS_NODE),          // ETH_P_MPLS_MC
    // Tunnels / encapsulation
    (0x8864, &PPPOE_NODE),         // ETH_P_PPP_SES
    (0x4305, &BATMAN_NODE),        // ETH_P_BATMAN
    (0x88E7, &PBB_NODE),           // ETH_P_8021AH (PBB)
    (0x22F3, &TRILL_NODE),         // ETH_P_TRILL
    (0x892F, &HSR_NODE),           // ETH_P_HSR
    (0x88FB, &HSR_NODE),           // ETH_P_PRP (same handler as HSR)
    (0x894F, &NSH_NODE),           // ETH_P_NSH
    // Management / L2 leaves
    (0x88CC, &LLDP_NODE),          // ETH_P_LLDP
    (0x8809, &SLOW_NODE),          // ETH_P_SLOW (LACP/STP)
    (0x8808, &MAC_CONTROL_NODE),   // ETH_P_PAUSE (MAC control)
    (0x888E, &EAPOL_NODE),         // ETH_P_PAE (802.1X)
    (0x88F7, &PTP_NODE),           // ETH_P_1588 (PTP)
    (0x88F5, &MVRP_NODE),          // ETH_P_MVRP
    (0x8902, &CFM_NODE),           // ETH_P_CFM
    (0x8914, &FIP_NODE),           // ETH_P_FIP
    (0x88E5, &MACSEC_NODE),        // ETH_P_MACSEC
    (0x88A4, &ETHERCAT_NODE),      // ETH_P_ETHERCAT
    (0x88CA, &TIPC_NODE),          // ETH_P_TIPC
];

static ETHER_NODE: ParseNode<FlowMeta, EthernetOps> = ParseNode {
    proto: EthernetOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_ether_metadata), handler: None, post_handler: None },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ethernet",
};

static VLAN_NODE: ParseNode<FlowMeta, VlanOps> = ParseNode {
    proto: VlanOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_vlan_8021q_metadata), handler: None, post_handler: None },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "vlan",
};

static QINQ_NODE: ParseNode<FlowMeta, QinQOps> = ParseNode {
    proto: QinQOps,
    ops: ParseNodeOps { extract_metadata: Some(extract_vlan_8021ad_metadata), handler: None, post_handler: None },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "qinq",
};

// ── Parser entry point ────────────────────────────────────────────

/// Build the benchmark parser.
pub fn make_parser() -> Parser<FlowMeta> {
    Parser {
        name: "bench-flow-dissector",
        config: ParserConfig::default(),
        root_node: &ETHER_NODE,
        parser_type: ParserType::Generic,
    }
}

/// Parse a single packet, returning Ok or Err.
#[inline]
pub fn parse_packet(parser: &Parser<FlowMeta>, pkt: &[u8]) -> Result<ParseOutput<FlowMeta>, ParseError> {
    parse(parser, pkt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xdp2_core::ParseResult;

    /// Ethernet + IPv4 + TCP (54 bytes minimum).
    fn make_eth_ipv4_tcp() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]);            // MACs
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType: IPv4
        pkt.push((4 << 4) | 5);                       // IPv4 ver=4, IHL=5
        pkt.push(0);                                   // TOS
        pkt.extend_from_slice(&40u16.to_be_bytes());   // total length
        pkt.extend_from_slice(&[0; 4]);                // ID + frag
        pkt.push(64);                                  // TTL
        pkt.push(6);                                   // protocol = TCP
        pkt.extend_from_slice(&[0; 2]);                // checksum
        pkt.extend_from_slice(&[10, 0, 0, 1]);        // src IP
        pkt.extend_from_slice(&[10, 0, 0, 2]);        // dst IP
        // TCP header (20 bytes)
        pkt.extend_from_slice(&80u16.to_be_bytes());   // src port
        pkt.extend_from_slice(&443u16.to_be_bytes());  // dst port
        pkt.extend_from_slice(&[0; 8]);                // seq + ack
        pkt.push(5 << 4);                              // data offset=5
        pkt.push(0x02);                                // SYN
        pkt.extend_from_slice(&[0; 6]);                // window + cksum + urg
        pkt
    }

    #[test]
    fn parse_eth_ipv4_tcp() {
        let parser = make_parser();
        let pkt = make_eth_ipv4_tcp();
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_eth_ipv4_udp_non_tunnel() {
        // Regular UDP (non-tunnel port) should still parse via wildcard.
        let parser = make_parser();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]);              // MACs
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        pkt.push((4 << 4) | 5);                         // ver=4, IHL=5
        pkt.push(0);
        pkt.extend_from_slice(&28u16.to_be_bytes());    // total length
        pkt.extend_from_slice(&[0; 4]);                  // ID + frag
        pkt.push(64);                                    // TTL
        pkt.push(17);                                    // protocol = UDP
        pkt.extend_from_slice(&[0; 2]);                  // checksum
        pkt.extend_from_slice(&[10, 0, 0, 1]);          // src IP
        pkt.extend_from_slice(&[10, 0, 0, 2]);          // dst IP
        // UDP header (8 bytes) — non-tunnel dport
        pkt.extend_from_slice(&1234u16.to_be_bytes());   // src port
        pkt.extend_from_slice(&5678u16.to_be_bytes());   // dst port (not a tunnel)
        pkt.extend_from_slice(&8u16.to_be_bytes());      // length
        pkt.extend_from_slice(&[0; 2]);                  // checksum
        let result = parse_packet(&parser, &pkt).unwrap();
        // Wildcard UDP_LEAF_NODE is hit, parse succeeds.
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_vxlan_inner_tcp() {
        // Eth → IPv4 → UDP(4789) → VXLAN → inner Eth → IPv4 → TCP
        let parser = make_parser();
        let mut pkt = Vec::new();
        // Outer Ethernet
        pkt.extend_from_slice(&[0u8; 12]);              // MACs
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        // Outer IPv4
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&100u16.to_be_bytes());   // total length (unused by parser)
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(17);                                    // UDP
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        // Outer UDP → VXLAN port
        pkt.extend_from_slice(&12345u16.to_be_bytes()); // src port
        pkt.extend_from_slice(&4789u16.to_be_bytes());  // dst port = VXLAN
        pkt.extend_from_slice(&80u16.to_be_bytes());    // length
        pkt.extend_from_slice(&[0; 2]);                  // checksum
        // VXLAN header (8 bytes)
        pkt.extend_from_slice(&[0x08, 0, 0, 0]);       // flags (I bit set)
        pkt.extend_from_slice(&[0x12, 0x34, 0x56, 0]); // VNI
        // Inner Ethernet
        pkt.extend_from_slice(&[0u8; 12]);              // MACs
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        // Inner IPv4
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(6);                                     // TCP
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[192, 168, 1, 1]);
        pkt.extend_from_slice(&[192, 168, 1, 2]);
        // Inner TCP (20 bytes)
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 8]);
        pkt.push(5 << 4);
        pkt.push(0x02);
        pkt.extend_from_slice(&[0; 6]);

        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_geneve_inner_tcp() {
        // Eth → IPv4 → UDP(6081) → Geneve → inner Eth → IPv4 → TCP
        let parser = make_parser();
        let mut pkt = Vec::new();
        // Outer Ethernet
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        // Outer IPv4
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&100u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(17);                                    // UDP
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        // Outer UDP → Geneve port
        pkt.extend_from_slice(&12345u16.to_be_bytes());
        pkt.extend_from_slice(&6081u16.to_be_bytes());  // dst port = Geneve
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 2]);
        // Geneve header (8 bytes, no options)
        pkt.push(0x00);                                  // ver=0, optlen=0
        pkt.push(0x00);                                  // flags
        pkt.extend_from_slice(&0x6558u16.to_be_bytes()); // protocol = ETH_P_TEB
        pkt.extend_from_slice(&[0x12, 0x34, 0x56, 0]);  // VNI
        // Inner Ethernet
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        // Inner IPv4
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(6);                                     // TCP
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[192, 168, 1, 1]);
        pkt.extend_from_slice(&[192, 168, 1, 2]);
        // Inner TCP
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 8]);
        pkt.push(5 << 4);
        pkt.push(0x02);
        pkt.extend_from_slice(&[0; 6]);

        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    /// Ethernet + IPv4 + GRE v0 (no flags) + IPv4 + TCP.
    fn make_gre_v0_ipv4_tcp(gre_flags: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Outer Ethernet
        pkt.extend_from_slice(&[0u8; 12]);              // MACs
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        // Outer IPv4 (protocol=47 GRE)
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&100u16.to_be_bytes());   // total length
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(47);                                    // IPPROTO_GRE
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        // GRE header: flags + protocol
        pkt.extend_from_slice(&gre_flags.to_be_bytes());
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // inner IPv4
        // Optional flag fields
        if gre_flags & 0x8000 != 0 { pkt.extend_from_slice(&[0xAA, 0xBB, 0, 0]); } // csum+reserved
        if gre_flags & 0x2000 != 0 { pkt.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); } // key
        if gre_flags & 0x1000 != 0 { pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x42]); } // seq
        // Inner IPv4 + TCP
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(6);                                     // TCP
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[192, 168, 1, 1]);
        pkt.extend_from_slice(&[192, 168, 1, 2]);
        // Inner TCP
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 8]);
        pkt.push(5 << 4);
        pkt.push(0x02);
        pkt.extend_from_slice(&[0; 6]);
        pkt
    }

    #[test]
    fn parse_gre_v0_no_flags() {
        let parser = make_parser();
        let pkt = make_gre_v0_ipv4_tcp(0x0000);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_gre_v0_with_key() {
        let parser = make_parser();
        let pkt = make_gre_v0_ipv4_tcp(0x2000); // key flag
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
        // Verify key was extracted via flag-field callback.
        let key_bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        let expected_key = u32::from_ne_bytes(key_bytes);
        assert_eq!(result.metadata.gre.keyid, expected_key);
        assert_eq!(result.metadata.keyid, expected_key);
    }

    #[test]
    fn parse_gre_v0_all_flags() {
        let parser = make_parser();
        let pkt = make_gre_v0_ipv4_tcp(0x8000 | 0x2000 | 0x1000); // csum+key+seq
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
        // Verify GRE flags were extracted.
        assert_eq!(result.metadata.gre.flags, 0x8000 | 0x2000 | 0x1000);
        // Verify checksum extracted.
        let expected_csum = u16::from_ne_bytes([0xAA, 0xBB]);
        assert_eq!(result.metadata.gre.csum, expected_csum);
        // Verify key extracted.
        let expected_key = u32::from_ne_bytes([0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(result.metadata.gre.keyid, expected_key);
        // Verify sequence extracted.
        let expected_seq = u32::from_ne_bytes([0x00, 0x00, 0x00, 0x42]);
        assert_eq!(result.metadata.gre.seq, expected_seq);
    }

    #[test]
    fn parse_gre_v0_inner_ethernet() {
        // GRE v0 carrying Ethernet (TEB) — used for NVGRE-like encapsulation.
        let parser = make_parser();
        let mut pkt = Vec::new();
        // Outer Ethernet + IPv4 (proto=47)
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&100u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(47);
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        // GRE: flags=key(0x2000), protocol=ETH_P_TEB(0x6558)
        pkt.extend_from_slice(&0x2000u16.to_be_bytes());
        pkt.extend_from_slice(&0x6558u16.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // key
        // Inner Ethernet + IPv4 + TCP
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(6);
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[192, 168, 1, 1]);
        pkt.extend_from_slice(&[192, 168, 1, 2]);
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 8]);
        pkt.push(5 << 4);
        pkt.push(0x02);
        pkt.extend_from_slice(&[0; 6]);

        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn metadata_ipv4_tcp() {
        // Verify that metadata extractors populate FlowMeta correctly.
        let parser = make_parser();
        let pkt = make_eth_ipv4_tcp();
        let result = parse_packet(&parser, &pkt).unwrap();
        let m = &result.metadata;
        // Ethernet extractor: MACs + ethertype
        assert_eq!(m.eth_proto, 0x0800);
        // IPv4 extractor: addresses, protocol
        assert_eq!(m.addr_type, AddrType::Ipv4);
        assert_eq!(m.ip_proto, 6); // TCP
        assert_eq!(m.addrs.v4_src, u32::from_be_bytes([10, 0, 0, 1]));
        assert_eq!(m.addrs.v4_dst, u32::from_be_bytes([10, 0, 0, 2]));
        assert!(!m.is_fragment);
        // Port extractor: TCP ports
        assert_eq!(m.ports.src_port, 80);
        assert_eq!(m.ports.dst_port, 443);
    }

    #[test]
    fn metadata_vlan() {
        // Verify VLAN TCI extraction.
        let parser = make_parser();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xAA; 6]); // dst MAC
        pkt.extend_from_slice(&[0xBB; 6]); // src MAC
        pkt.extend_from_slice(&0x8100u16.to_be_bytes()); // VLAN
        pkt.extend_from_slice(&100u16.to_be_bytes());    // TCI = 100
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // inner: IPv4
        // IPv4 + TCP (just enough)
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(6);
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 8]);
        pkt.push(5 << 4);
        pkt.push(0x02);
        pkt.extend_from_slice(&[0; 6]);

        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.metadata.vlan_count, 1);
        assert_eq!(result.metadata.vlan[0].tci, 100);
        assert_eq!(result.metadata.vlan[0].tpid, 0x8100);
    }

    #[test]
    fn metadata_icmpv4_echo() {
        // ICMPv4 echo request → type, code, id extracted.
        let parser = make_parser();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]);              // MACs
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&28u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(1);                                    // ICMP
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        // ICMP echo request
        pkt.push(8);                                    // type = echo request
        pkt.push(0);                                    // code
        pkt.extend_from_slice(&[0; 2]);                  // checksum
        pkt.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        pkt.extend_from_slice(&[0; 2]);                  // sequence

        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.metadata.icmp.icmp_type, 8);
        assert_eq!(result.metadata.icmp.code, 0);
        assert_eq!(result.metadata.icmp.id, 0x1234);
    }

    #[test]
    fn parse_vlan_ipv4_tcp() {
        let parser = make_parser();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x8100u16.to_be_bytes()); // VLAN
        pkt.extend_from_slice(&100u16.to_be_bytes());    // TCI
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // inner: IPv4
        // IPv4 + TCP
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(6);
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 8]);
        pkt.push(5 << 4);
        pkt.push(0x02);
        pkt.extend_from_slice(&[0; 6]);

        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    // ── Phase 4: L2 leaf protocol tests ──

    /// Helper: build Eth frame with given ethertype + payload bytes.
    fn make_eth_l2(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]);                  // MACs
        pkt.extend_from_slice(&ethertype.to_be_bytes());
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn parse_lldp() {
        let parser = make_parser();
        // LLDP: MIN_LEN=2
        let pkt = make_eth_l2(0x88CC, &[0x02, 0x00, 0x07, 0x04, 0x00, 0x00]);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_slow() {
        let parser = make_parser();
        // SLOW (LACP/STP): MIN_LEN=1
        let pkt = make_eth_l2(0x8809, &[0x01, 0x01, 0x00, 0x00]);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_ptp() {
        let parser = make_parser();
        // PTP: MIN_LEN=34
        let pkt = make_eth_l2(0x88F7, &[0; 34]);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_eapol() {
        let parser = make_parser();
        // EAPOL (802.1X): MIN_LEN varies
        let pkt = make_eth_l2(0x888E, &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_mpls_in_ether() {
        let parser = make_parser();
        // MPLS unicast in Ethernet: ethertype 0x8847, MIN_LEN=8 (2 label entries)
        let mut payload = [0u8; 8];
        // Set BoS=1 on first label entry (byte 2, bit 0)
        payload[2] |= 0x01;
        let pkt = make_eth_l2(0x8847, &payload);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
        assert_eq!(result.metadata.mpls.bos, true);
    }

    #[test]
    fn parse_rarp() {
        let parser = make_parser();
        // RARP: MIN_LEN=28, validated via ArpOps::header_len().
        // Note: ArpOps only accepts op=1/2; RarpOps delegates to it.
        // Use op=1 to pass validation (xdp2-protocols bug: RARP ops 3/4 rejected).
        let mut payload = [0u8; 28];
        payload[0..2].copy_from_slice(&1u16.to_be_bytes());      // ar_hrd = ARPHRD_ETHER
        payload[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // ar_pro = IPv4
        payload[4] = 6;                                            // ar_hln = ETH_ALEN
        payload[5] = 4;                                            // ar_pln = 4
        payload[6..8].copy_from_slice(&1u16.to_be_bytes());      // ar_op = REQUEST (workaround)
        let pkt = make_eth_l2(0x8035, &payload);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_tipc() {
        let parser = make_parser();
        // TIPC: MIN_LEN=16, originating node at bytes 8-11
        let mut payload = [0u8; 16];
        payload[8..12].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        let pkt = make_eth_l2(0x88CA, &payload);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
        assert_eq!(result.metadata.addr_type, AddrType::Tipc);
        assert_eq!(result.metadata.addrs.tipc_key, 0xDEADBEEF);
    }

    #[test]
    fn parse_pppoe_ipv4_tcp() {
        // PPPoE → IPv4 → TCP
        let parser = make_parser();
        let mut pkt = Vec::new();
        // Ethernet
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x8864u16.to_be_bytes()); // ETH_P_PPP_SES
        // PPPoE header (8 bytes): ver=1, type=1, code=0, session_id, length, ppp_proto
        pkt.push(0x11);              // ver=1, type=1
        pkt.push(0x00);              // code=0 (session data)
        pkt.extend_from_slice(&[0x00, 0x01]); // session ID
        pkt.extend_from_slice(&44u16.to_be_bytes()); // length
        pkt.extend_from_slice(&0x0021u16.to_be_bytes()); // PPP protocol = IPv4
        // IPv4 + TCP
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(6); // TCP
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        // TCP header
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 8]);
        pkt.push(5 << 4);
        pkt.push(0x02);
        pkt.extend_from_slice(&[0; 6]);

        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
        assert_eq!(result.metadata.addr_type, AddrType::Ipv4);
        assert_eq!(result.metadata.ports.src_port, 80);
    }

    #[test]
    fn parse_macsec() {
        let parser = make_parser();
        let pkt = make_eth_l2(0x88E5, &[0; 16]);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_ethercat() {
        let parser = make_parser();
        let pkt = make_eth_l2(0x88A4, &[0; 8]);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }
}
