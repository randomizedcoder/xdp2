// ── Leaf nodes ──────────────────────────────────────────────────
//
// Transport leaves (TCP wildcard, UDP wildcard, SCTP, DCCP),
// IP protocol leaves (OSPF, EIGRP, etc.), L2 management/security
// leaves (LLDP, LACP, etc.), FC sub-type dispatch, and the
// stop-leaf wildcard handler (StopLeafOps).

use super::*;

// ── New IP protocol leaf nodes ───────────────────────────────────

pub(crate) static OSPF_NODE: ParseNode<FlowMeta, OspfOps> = ParseNode {
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

pub(crate) static OSPFV3_NODE: ParseNode<FlowMeta, Ospfv3Ops> = ParseNode {
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

pub(crate) static EIGRP_NODE: ParseNode<FlowMeta, EigrpOps> = ParseNode {
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

pub(crate) static VRRP_NODE: ParseNode<FlowMeta, VrrpOps> = ParseNode {
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

pub(crate) static VRRP3_NODE: ParseNode<FlowMeta, Vrrpv3Ops> = ParseNode {
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

pub(crate) static PIM_NODE: ParseNode<FlowMeta, PimOps> = ParseNode {
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

pub(crate) static RSVP_NODE: ParseNode<FlowMeta, RsvpOps> = ParseNode {
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

pub(crate) static IPCOMP_NODE: ParseNode<FlowMeta, IpCompOps> = ParseNode {
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

pub(crate) static PGM_NODE: ParseNode<FlowMeta, PgmOps> = ParseNode {
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
pub(crate) static CARP_NODE: ParseNode<FlowMeta, CarpOps> = ParseNode {
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

pub(crate) static ETHERIP_NODE: ParseNode<FlowMeta, EtherIpOps> = ParseNode {
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
/// Zero-byte leaf node for wildcard fallback.
///
/// When an intermediate node's table lookup misses (e.g., UDP dport is not
/// a known tunnel port), this wildcard node allows the parse to succeed
/// without reading any additional bytes — the preceding node already
/// consumed its header. MIN_LEN = 0 means the engine immediately reaches
/// the leaf and stops with `ParseResult::Okay`.
///
/// This mirrors C's `XDP2_STOP_OKAY` unknown_proto_ret behavior.
pub(crate) struct StopLeafOps;

impl ProtocolOps for StopLeafOps {
    const MIN_LEN: usize = 0;
    const NAME: &'static str = "stop-leaf";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

/// Stop-leaf node instance for wildcard fallback.
pub(crate) static STOP_LEAF_NODE: ParseNode<FlowMeta, StopLeafOps> = ParseNode {
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
pub(crate) static ICMPV4_NODE: ParseNode<FlowMeta, IcmpV4Ops> = ParseNode {
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

pub(crate) static ICMPV6_NODE: ParseNode<FlowMeta, IcmpV6Ops> = ParseNode {
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

pub(crate) static SCTP_NODE: ParseNode<FlowMeta, SctpOps> = ParseNode {
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

pub(crate) static ARP_NODE: ParseNode<FlowMeta, ArpOps> = ParseNode {
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

pub(crate) static IGMP_NODE: ParseNode<FlowMeta, IgmpOps> = ParseNode {
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

pub(crate) static ESP_NODE: ParseNode<FlowMeta, EspOps> = ParseNode {
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

pub(crate) static DCCP_NODE: ParseNode<FlowMeta, DccpOps> = ParseNode {
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

pub(crate) static UDPLITE_NODE: ParseNode<FlowMeta, UdpLiteOps> = ParseNode {
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

pub(crate) static MPLS_NODE: ParseNode<FlowMeta, MplsOps> = ParseNode {
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
pub(crate) struct L2tpV3Ops;

impl ProtocolOps for L2tpV3Ops {
    const MIN_LEN: usize = 4;
    const NAME: &'static str = "L2TPv3";

    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto) // Leaf node
    }
}

pub(crate) static L2TP_NODE: ParseNode<FlowMeta, L2tpV3Ops> = ParseNode {
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

pub(crate) static RARP_NODE: ParseNode<FlowMeta, RarpOps> = ParseNode {
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

pub(crate) static TIPC_NODE: ParseNode<FlowMeta, TipcOps> = ParseNode {
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

pub(crate) static LLDP_NODE: ParseNode<FlowMeta, LldpOps> = ParseNode {
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

pub(crate) static SLOW_NODE: ParseNode<FlowMeta, SlowOps> = ParseNode {
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

pub(crate) static MAC_CONTROL_NODE: ParseNode<FlowMeta, MacControlOps> = ParseNode {
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

pub(crate) static EAPOL_NODE: ParseNode<FlowMeta, EapolOps> = ParseNode {
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

pub(crate) static PTP_NODE: ParseNode<FlowMeta, PtpOps> = ParseNode {
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

pub(crate) static MVRP_NODE: ParseNode<FlowMeta, MvrpOps> = ParseNode {
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

pub(crate) static CFM_NODE: ParseNode<FlowMeta, CfmOps> = ParseNode {
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

pub(crate) static FIP_NODE: ParseNode<FlowMeta, FipOps> = ParseNode {
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

pub(crate) static MACSEC_NODE: ParseNode<FlowMeta, MacsecOps> = ParseNode {
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

pub(crate) static ETHERCAT_NODE: ParseNode<FlowMeta, EthercatOps> = ParseNode {
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

pub(crate) static FC_ELS_NODE: ParseNode<FlowMeta, FcElsLsAccOps> = ParseNode {
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

pub(crate) static FC_FCP_NODE: ParseNode<FlowMeta, FcpCmndOps> = ParseNode {
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

pub(crate) static FC_CT_NODE: ParseNode<FlowMeta, FcCtOps> = ParseNode {
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

pub(crate) static FC_TYPE_TABLE: ProtoTable<FlowMeta> = proto_table![
    (FC_TYPE_ELS, &FC_ELS_NODE), // FC Extended Link Services
    (FC_TYPE_FCP, &FC_FCP_NODE), // FC Protocol for SCSI
    (FC_TYPE_CT, &FC_CT_NODE),   // FC Common Transport (Name Server)
];

#[allow(dead_code)] // Available for raw FC traffic (non-FCoE paths)
pub(crate) static FC_NODE: ParseNode<FlowMeta, FcOps> = ParseNode {
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

pub(crate) static FCOE_NODE: ParseNode<FlowMeta, FcoeOps> = ParseNode {
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
