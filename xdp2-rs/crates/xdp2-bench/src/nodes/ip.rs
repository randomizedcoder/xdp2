// ── IP protocol dispatch ────────────────────────────────────────
//
// IPv4/IPv6 dispatch tables, extension headers, IP version overlay
// (IP_CHECK_NODE), AH (Authentication Header), GRE with flag-fields.

use super::*;

// ── IPv4 dispatch ─────────────────────────────────────────────────

pub(crate) static IPV4_TABLE: ProtoTable<FlowMeta> = proto_table![
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

pub(crate) static IPV4_NODE: ParseNode<FlowMeta, Ipv4Ops> = ParseNode {
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

pub(crate) static AH_V4_NODE: ParseNode<FlowMeta, AhOps> = ParseNode {
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

pub(crate) static AH_V6_NODE: ParseNode<FlowMeta, AhOps> = ParseNode {
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

pub(crate) static GRE_FLAG_CSUM_NODE: ParseFlagFieldNode<FlowMeta> = ParseFlagFieldNode {
    ops: ParseFlagFieldNodeOps {
        extract_metadata: Some(extract_gre_checksum),
        handler: None,
    },
    name: "gre-csum",
};

pub(crate) static GRE_FLAG_KEY_NODE: ParseFlagFieldNode<FlowMeta> = ParseFlagFieldNode {
    ops: ParseFlagFieldNodeOps {
        extract_metadata: Some(extract_gre_keyid),
        handler: None,
    },
    name: "gre-key",
};

pub(crate) static GRE_FLAG_SEQ_NODE: ParseFlagFieldNode<FlowMeta> = ParseFlagFieldNode {
    ops: ParseFlagFieldNodeOps {
        extract_metadata: Some(extract_gre_seq),
        handler: None,
    },
    name: "gre-seq",
};

// ── GRE v0 flag-fields table (maps field index → parse node) ──

pub(crate) static GRE_V0_FF_TABLE: FlagFieldsTable<FlowMeta> = FlagFieldsTable {
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
pub(crate) static GRE_V0_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0800, &IP_CHECK_NODE),    // ETH_P_IP
    (0x86DD, &IP_CHECK_NODE),    // ETH_P_IPV6
    (0x6558, &ETHER_INNER_NODE), // ETH_P_TEB (Ethernet bridging)
];

/// GRE v0 inner parse node — provides header_len, next_proto, extract_metadata.
/// This is wrapped by GRE_V0_NODE (ParseFlagFieldsNode) which adds flag-field
/// sub-parsing via sub_parse().
pub(crate) static GRE_V0_INNER_NODE: ParseNode<FlowMeta, GreV0Ops> = ParseNode {
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
pub(crate) static GRE_V0_NODE: ParseFlagFieldsNode<FlowMeta> = ParseFlagFieldsNode {
    inner: &GRE_V0_INNER_NODE,
    ff_proto_table: &GRE_V0_FF_TABLE,
    flag_fields: &GRE_V0_FLAG_FIELDS,
    ff_ops: &GRE_FF_OPS,
};

// ── GRE base (version overlay dispatch) ──

/// GRE base version dispatch table.
/// Matches C's `gre_base_table` in flow_dissector_tables.h.
pub(crate) static GRE_BASE_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0, &GRE_V0_NODE),    // GRE v0
    (1, &STOP_LEAF_NODE), // GRE v1/PPTP — simplified (rare in practice)
];

/// GRE base overlay node — reads version nibble and dispatches.
///
/// OVERLAY=true so no bytes are consumed; the version is read from
/// the same position that GreV0Ops/v1 will read the full header.
///
/// Matches C's `gre_base_node` in flow_dissector_nodes.h.
pub(crate) static GRE_BASE_NODE: ParseNode<FlowMeta, GreBaseOps> = ParseNode {
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

pub(crate) static IPV6_TABLE: ProtoTable<FlowMeta> = proto_table![
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

pub(crate) static IPV6_NODE: ParseNode<FlowMeta, Ipv6Ops> = ParseNode {
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

pub(crate) static IPV6_HBH_NODE: ParseNode<FlowMeta, Ipv6EhOps> = ParseNode {
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

pub(crate) static IPV6_DST_NODE: ParseNode<FlowMeta, Ipv6EhOps> = ParseNode {
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

pub(crate) static IPV6_ROUTING_NODE: ParseNode<FlowMeta, Ipv6EhOps> = ParseNode {
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

pub(crate) static IPV6_FRAG_NODE: ParseNode<FlowMeta, Ipv6FragOps> = ParseNode {
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
pub(crate) static IP_CHECK_TABLE: ProtoTable<FlowMeta> = proto_table![
    (4, &IPV4_NODE), // IP version 4
    (6, &IPV6_NODE), // IP version 6
];

/// IP version check overlay node.
///
/// Reads the IP version nibble (first 4 bits of byte 0) and dispatches
/// to IPv4 or IPv6. Does not consume any bytes (OVERLAY=true).
///
/// Matches C's `ip_check_node` in flow_dissector_nodes.h.
pub(crate) static IP_CHECK_NODE: ParseNode<FlowMeta, IpOverlayOps> = ParseNode {
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
