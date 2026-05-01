// ── TCP application leaf nodes + TCP port dispatch ──────────────
//
// TCP application protocol leaf nodes and the TCP_APP_TABLE dispatch
// table that routes destination ports to specific protocol handlers.

use super::*;

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

/// TCP application protocol dispatch table — known service ports.
pub(crate) static TCP_APP_TABLE: ProtoTable<FlowMeta> = proto_table![
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

/// TCP node with dport-based application protocol dispatch.
pub(crate) static TCP_NODE: ParseNode<FlowMeta, TcpDportOps> = ParseNode {
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
