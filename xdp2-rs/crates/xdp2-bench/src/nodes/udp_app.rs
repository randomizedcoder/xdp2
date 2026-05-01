// ── UDP leaf nodes + UDP port dispatch ──────────────────────────
//
// UDP application/tunnel leaf nodes and the UDP_TUNNEL_TABLE dispatch
// table that routes destination ports to specific protocol handlers.

use super::*;

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
/// UDP tunnel and application dispatch table — known destination ports.
/// Matches C's `udp_tunnel_table` in flow_dissector_tables.h.
pub(crate) static UDP_TUNNEL_TABLE: ProtoTable<FlowMeta> = proto_table![
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
pub(crate) static UDP_NODE: ParseNode<FlowMeta, UdpDportOps> = ParseNode {
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
