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
use xdp2_protocols::transport::tcp::TcpOps;
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
use xdp2_protocols::storage::fc::FcoeOps;
use xdp2_protocols::storage::misc::EthercatOps;
use xdp2_protocols::transport::tipc::TipcOps;
use xdp2_protocols::tunnel::geneve::GeneveV0Ops;
use xdp2_protocols::tunnel::gre::{GreBaseOps, GreV0Ops, GRE_FF_OPS, GRE_V0_FLAG_FIELDS};
use xdp2_protocols::tunnel::mpls::MplsOps;
use xdp2_protocols::tunnel::nsh::NshOps;
use xdp2_protocols::tunnel::vxlan::VxlanOps;
use xdp2_protocols::tunnel::{HsrOps, PppoeOps};

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

// ── Leaf nodes (no proto_table, parsing stops here) ───────────────

static TCP_NODE: ParseNode<FlowMeta, TcpOps> = ParseNode {
    proto: TcpOps,
    ops: ParseNodeOps {
        extract_metadata: Some(extract_ports_metadata),
        handler: None,
        post_handler: None,
    },
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

/// UDP tunnel dispatch table — known tunnel destination ports.
/// Matches C's `udp_tunnel_table` in flow_dissector_tables.h.
static UDP_TUNNEL_TABLE: ProtoTable<FlowMeta> = proto_table![
    (4789, &VXLAN_NODE),  // VXLAN
    (6081, &GENEVE_NODE), // Geneve
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

static FCOE_NODE: ParseNode<FlowMeta, FcoeOps> = ParseNode {
    proto: FcoeOps,
    ops: ParseNodeOps {
        extract_metadata: None,
        handler: None,
        post_handler: None,
    },
    proto_table: None,
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
