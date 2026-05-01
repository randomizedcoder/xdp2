// ── Tunnel nodes ────────────────────────────────────────────────
//
// VXLAN, Geneve, GTP, VXLAN-GPE, Teredo, LISP, CAPWAP, GUE, STT,
// TZSP tunnel encapsulation nodes, inner dispatch tables, and the
// inner Ethernet node for tunnel decapsulation.

use super::*;

// ── Tunnel nodes (with inner dispatch tables) ───────────────────

pub(crate) static GTPU_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0800, &IP_CHECK_NODE),  // ETH_P_IP
    (0x86DD, &IP_CHECK_NODE),  // ETH_P_IPV6
];

pub(crate) static GTPU_NODE: ParseNode<FlowMeta, GtpuOps> = ParseNode {
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

pub(crate) static GTPV2C_NODE: ParseNode<FlowMeta, Gtpv2cOps> = ParseNode {
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

pub(crate) static VXLAN_GPE_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0800, &IP_CHECK_NODE),    // ETH_P_IP
    (0x86DD, &IP_CHECK_NODE),    // ETH_P_IPV6
    (0x6558, &ETHER_INNER_NODE), // ETH_P_TEB
    (0x894F, &NSH_NODE),         // ETH_P_NSH
];

pub(crate) static VXLAN_GPE_NODE: ParseNode<FlowMeta, VxlanGpeOps> = ParseNode {
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

pub(crate) static TEREDO_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x86DD, &IPV6_NODE), // ETH_P_IPV6 (always IPv6)
];

pub(crate) static TEREDO_NODE: ParseNode<FlowMeta, TeredoOps> = ParseNode {
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

pub(crate) static LISP_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0800, &IP_CHECK_NODE),  // ETH_P_IP
    (0x86DD, &IP_CHECK_NODE),  // ETH_P_IPV6
];

pub(crate) static LISP_NODE: ParseNode<FlowMeta, LispOps> = ParseNode {
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

pub(crate) static CAPWAP_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x6558, &ETHER_INNER_NODE), // ETH_P_TEB (always Ethernet)
];

pub(crate) static CAPWAP_NODE: ParseNode<FlowMeta, CapwapOps> = ParseNode {
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
pub(crate) static GUE_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (4, &IP_CHECK_NODE),  // IPPROTO_IPIP
    (41, &IP_CHECK_NODE), // IPPROTO_IPV6
];

pub(crate) static GUE_NODE: ParseNode<FlowMeta, GueOps> = ParseNode {
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

pub(crate) static STT_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x6558, &ETHER_INNER_NODE), // ETH_P_TEB (always Ethernet)
];

pub(crate) static STT_NODE: ParseNode<FlowMeta, SttOps> = ParseNode {
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

pub(crate) static TZSP_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0800, &IP_CHECK_NODE),    // ETH_P_IP
    (0x86DD, &IP_CHECK_NODE),    // ETH_P_IPV6
    (0x6558, &ETHER_INNER_NODE), // ETH_P_TEB
];

pub(crate) static TZSP_NODE: ParseNode<FlowMeta, TzspOps> = ParseNode {
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



// ── Tunnel nodes (VXLAN, Geneve) ─────────────────────────────────

/// VXLAN inner dispatch — always ETH_P_TEB → inner Ethernet.
pub(crate) static VXLAN_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x6558, &ETHER_INNER_NODE), // ETH_P_TEB
];

/// VXLAN encapsulation node (8 bytes, always wraps Ethernet).
///
/// Matches C's `vxlan_node` in flow_dissector_nodes.h.
pub(crate) static VXLAN_NODE: ParseNode<FlowMeta, VxlanOps> = ParseNode {
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
pub(crate) static GENEVE_INNER_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x6558, &ETHER_INNER_NODE), // ETH_P_TEB (Ethernet inside)
    (0x0800, &IP_CHECK_NODE),    // ETH_P_IP (raw IPv4 inside)
    (0x86DD, &IP_CHECK_NODE),    // ETH_P_IPV6 (raw IPv6 inside)
];

/// Geneve encapsulation node (variable-length, dispatches on protocol field).
///
/// Uses GeneveV0Ops (simple, no TLV option parsing) matching C's
/// `geneve_simple_def` in flow_dissector_proto_defs.h.
pub(crate) static GENEVE_NODE: ParseNode<FlowMeta, GeneveV0Ops> = ParseNode {
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
pub(crate) static ETHER_INNER_NODE: ParseNode<FlowMeta, EtherLlcOps> = ParseNode {
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
