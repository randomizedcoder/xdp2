// ── Encapsulation dispatch ──────────────────────────────────────
//
// Ethernet/VLAN tables (ETHER_TABLE, VLAN_TABLE, QINQ_TABLE),
// LLC/SNAP dispatch, PPPoE, HSR, BATMAN, PBB, TRILL, NSH,
// and ETHER_NODE (the root entry point for the parse graph).

use super::*;

// ── PPPoE → PPP dispatch ─────────────────────────────────────────

/// PPP protocol dispatch table.
/// PppoeOps returns the PPP protocol number.
pub(crate) static PPP_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0021, &IP_CHECK_NODE), // PPP_IP → IPv4
    (0x0057, &IP_CHECK_NODE), // PPP_IPV6 → IPv6
];

pub(crate) static PPPOE_NODE: ParseNode<FlowMeta, PppoeOps> = ParseNode {
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

pub(crate) static HSR_NODE: ParseNode<FlowMeta, HsrOps> = ParseNode {
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

pub(crate) static BATMAN_NODE: ParseNode<FlowMeta, BatmanOps> = ParseNode {
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

pub(crate) static PBB_NODE: ParseNode<FlowMeta, PbbOps> = ParseNode {
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

pub(crate) static TRILL_NODE: ParseNode<FlowMeta, TrillOps> = ParseNode {
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
pub(crate) static NSH_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0x0800, &IP_CHECK_NODE),    // ETH_P_IP
    (0x86DD, &IP_CHECK_NODE),    // ETH_P_IPV6
    (0x6558, &ETHER_INNER_NODE), // ETH_P_TEB
    (0x8847, &MPLS_NODE),        // ETH_P_MPLS_UC
];

pub(crate) static NSH_NODE: ParseNode<FlowMeta, NshOps> = ParseNode {
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


// ── LLC/SNAP dispatch ────────────────────────────────────────────
//
// When Ethernet/VLAN returns ETH_P_802_2 (ethertype ≤ 1500), we dispatch
// through the LLC layer. DSAP=0xAA routes to SNAP (which re-dispatches
// through ETHER_TABLE), DSAP=0x42 routes to STP (leaf).

pub(crate) static STP_NODE: ParseNode<FlowMeta, LlcOps> = ParseNode {
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

pub(crate) static SNAP_NODE: ParseNode<FlowMeta, LlcSnapOps> = ParseNode {
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
pub(crate) static LLC_TABLE: ProtoTable<FlowMeta> = proto_table![
    (0xAA, &SNAP_NODE), // LLC_SAP_SNAP → LLC/SNAP encapsulation
    (0x42, &STP_NODE),  // LLC_SAP_STP → STP BPDU (leaf)
];

pub(crate) static LLC_NODE: ParseNode<FlowMeta, LlcDispatchOps> = ParseNode {
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

pub(crate) static ETHER_TABLE: ProtoTable<FlowMeta> = proto_table![
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

pub(crate) static VLAN_NODE: ParseNode<FlowMeta, VlanLlcOps> = ParseNode {
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

pub(crate) static QINQ_NODE: ParseNode<FlowMeta, QinQLlcOps> = ParseNode {
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
