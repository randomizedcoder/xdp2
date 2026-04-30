//! PCAP routing: protocol stack construction, constants, and template loading.

use std::collections::BTreeMap;

use crate::ir::ProtocolDef;

use super::embedded::embedded_proto;

/// Link-layer root protocols and their PCAP Data Link Types (DLTs).
pub(super) const LINK_ROOTS: &[(&str, u32)] = &[
    ("Ethernet",       1),    // DLT_EN10MB
    ("Ethernet_802_3", 1),    // DLT_EN10MB (802.3 length framing)
    ("HCI",            187),  // DLT_BLUETOOTH_HCI_H4
    // IB_LRH routed via UpperPDU (tshark doesn't support DLT_INFINIBAND=247)
    ("CAN",            227),  // DLT_CAN_SOCKETCAN
    ("CAN_FD",         227),  // DLT_CAN_SOCKETCAN
    ("CAN_XL",         227),  // DLT_CAN_SOCKETCAN
    ("IEEE802.11",     105),  // DLT_IEEE802_11
    ("IEEE802154",     195),  // DLT_IEEE802_15_4
    ("Netlink",        253),  // DLT_NETLINK
    ("SLL",            113),  // DLT_LINUX_SLL
    ("SLL2",           276),  // DLT_LINUX_SLL2
    ("PPP",            9),    // DLT_PPP
    // ATM routed via UpperPDU (tshark doesn't support DLT_ATM_RFC1483=11 from PCAP)
    ("FC",             224),  // DLT_FC_2
    ("ERF",            197),  // DLT_ERF
    ("MPEG_TS",        243),  // DLT_MPEG_2_TS
    ("UpperPDU",       252),  // DLT_WIRESHARK_UPPER_PDU
];

/// Check if a protocol is a link-layer root (i.e., it can be the first layer in a PCAP).
pub fn is_root(name: &str) -> bool {
    LINK_ROOTS.iter().any(|(root, _)| *root == name)
}

/// Get the PCAP Data Link Type for a root protocol.
fn dlt_for_root(name: &str) -> u32 {
    LINK_ROOTS
        .iter()
        .find(|(r, _)| *r == name)
        .map(|(_, d)| *d)
        .unwrap_or(1)
}

/// Look up a STACK_ROUTES entry for a child protocol.
pub fn stack_route_for(child: &str) -> Option<(&'static str, &'static str, &'static str, u64)> {
    STACK_ROUTES
        .iter()
        .find(|(c, _, _, _)| *c == child)
        .copied()
}

/// Wireshark Upper PDU dissector names for protocols routed via DLT_WIRESHARK_UPPER_PDU.
pub(super) const UPPER_PDU_DISSECTORS: &[(&str, &str)] = &[
    ("BT_RFCOMM", "btrfcomm"),
    ("BT_BNEP", "btbnep"),
    ("BT_SDP", "btsdp"),
    ("BT_AVDTP", "btavdtp"),
    ("SCSI", "scsi"),
    ("iSER", "iser"),
    ("NTLMSSP", "ntlmssp"),
    ("OCSP", "ocsp_req"),
    ("Phonet", "phonet"),
    ("MCTP", "mctp"),
    ("X25", "x.25"),
    // DSA (Marvell DSA tag): no tshark dissector exists
    ("AMQP", "amqp"),
    ("NFS", "rpc"),
    ("STT", "stt"),
    ("CIP", "cip"),
    ("TPLINK_SMARTHOME", "tplink-smarthome"),
    ("WOL", "wol"),
    ("SMTP", "smtp"),
    ("IB_LRH", "infiniband"),
    ("ATM", "atm"),
    ("FDDI", "fddi"),
    // Phase 5b
    ("SCCP", "sccp"),
    ("ISUP", "isup"),
    ("TCAP", "tcap"),
    ("BSSGP", "bssgp"),
    ("NAS_EPS", "nas-eps"),
    ("NAS_5GS", "nas-5gs"),
    ("RANAP", "ranap"),
    ("H225", "h225"),
    ("H245", "h245"),
    ("SDP", "sdp"),
    ("WebSocket", "websocket"),
    ("HTTP3", "http3"),
    ("UDS", "uds"),
    ("XCP", "xcp"),
    ("LoRaWAN", "lorawan"),
    ("Radiotap", "radiotap"),
    ("PPI", "ppi"),
    ("AIS", "ais"),
    ("CAN_TP", "iso15765"),
    ("ACME", "acme"),
    ("EST", "est"),
    ("RMON", "rmon"),
    // Batch 3
    ("DoH", "dns"),
    ("FCP", "fcp"),
    ("RDMA_CM", "iwarp_mpa"),
    ("G8032", "elmi"),
    ("ELMI", "elmi"),
    ("R_GOOSE", "r-goose"),
    ("OPC_DA", "opc-da"),
    ("PWE3", "pw_eth_cw"),
    ("IEEE802_11_Beacon", "wlan_mgt"),
    ("IEEE802_11_Data", "wlan"),
    ("Thread", "thread"),
    ("Matter", "matter"),
    ("BLE_LL", "btle"),
    ("OCSP_Response", "ocsp"),
    // Batch 4
    ("NFSv4", "nfs"),
    ("CAN_J1939", "j1939"),
    ("CAN_OBD2", "obd-ii"),
    // Bucket 5: protocols with tshark dissectors but routing issues
    ("SOCKS", "socks"),
    ("IRC", "irc"),
    ("GVRP", "gvrp"),
    ("MMRP", "mmrp"),
    ("TACACS", "tacacs"),
    ("sFlow", "sflow"),
    ("LMP", "lmp"),
    ("ERSPAN", "erspan"),
    ("PVST", "stp"),
    ("RSTP", "stp"),
    // ML/HPC networking
    ("PFC", "pfc"),
    // SCSI/SAS/FC storage protocols
    ("SRP_Login_Req", "scsi.srp"),
    ("SRP_Login_Rsp", "scsi.srp"),
    ("SRP_Login_Rej", "scsi.srp"),
    ("SRP_Cmd", "scsi.srp"),
    ("SRP_Rsp", "scsi.srp"),
    ("SRP_TSK_Mgmt", "scsi.srp"),
    ("SRP_I_Logout", "scsi.srp"),
    ("SRP_T_Logout", "scsi.srp"),
    ("SRP_Cred_Req", "scsi.srp"),
    ("SRP_Cred_Rsp", "scsi.srp"),
    ("FCP_CMND", "fcp"),
    ("FCP_TXRDY", "fcp"),
    ("FCP_RSP", "fcp"),
    ("FCP_RSP_EXT", "fcp"),
    ("FCP_SRR", "fcp"),
    ("FC_ELS_FLOGI", "fc.els"),
    ("FC_ELS_LOGO", "fc.els"),
    ("FC_ELS_PRLI", "fc.els"),
    ("FC_ELS_ADISC", "fc.els"),
    ("FC_ELS_RSCN", "fc.els"),
    ("FC_ELS_SCR", "fc.els"),
    ("FC_ELS_LS_ACC", "fc.els"),
    ("FC_ELS_LS_RJT", "fc.els"),
    ("FC_CT_HDR", "fc.ct"),
    ("FC_NS_GID_FT", "fc.ct"),
    ("FC_NS_GPN_FT_Rsp", "fc.ct"),
    ("SSP_Frame_Hdr", "sas"),
    ("SSP_Command_IU", "sas"),
    ("SSP_Response_IU", "sas"),
    ("SSP_XFER_RDY", "sas"),
    ("SSP_TMF_IU", "sas"),
    ("ATA_H2D_FIS", "ata"),
    ("ATA_D2H_FIS", "ata"),
    ("SAS_Identify", "sas"),
];

/// One layer in the protocol stack being constructed.
pub(super) struct StackLayer {
    pub(super) proto_name: String,
    pub(super) proto_def: ProtocolDef,
    /// Overrides for specific fields (e.g., ether_type=0x0800)
    pub(super) overrides: BTreeMap<String, u64>,
}

/// Result of building a protocol stack.
pub(super) struct StackResult {
    pub(super) layers: Vec<StackLayer>,
    pub(super) link_type: u32,
}

/// (child, parent, parent_dispatch_field, dispatch_value)
pub(super) const STACK_ROUTES: &[(&str, &str, &str, u64)] = &[
    // ── L2: Ethernet-direct (ether_type dispatch) ──
    ("IPv4", "Ethernet", "ether_type", 0x0800),
    ("IPv6", "Ethernet", "ether_type", 0x86DD),
    ("ARP", "Ethernet", "ether_type", 0x0806),
    ("VLAN", "Ethernet", "ether_type", 0x8100),
    ("RARP", "Ethernet", "ether_type", 0x8035),
    ("MPLS", "Ethernet", "ether_type", 0x8847),
    ("PPPoE", "Ethernet", "ether_type", 0x8864),
    ("PPPoED", "Ethernet", "ether_type", 0x8863),
    ("LLDP", "Ethernet", "ether_type", 0x88CC),
    ("PTP", "Ethernet", "ether_type", 0x88F7),
    ("EAPOL", "Ethernet", "ether_type", 0x888E),
    ("MACsec", "Ethernet", "ether_type", 0x88E5),
    ("QinQ", "Ethernet", "ether_type", 0x88A8),
    ("PBB", "Ethernet", "ether_type", 0x88E7),
    ("TRILL", "Ethernet", "ether_type", 0x22F3),
    ("EtherCAT", "Ethernet", "ether_type", 0x88A4),
    ("PROFINET", "Ethernet", "ether_type", 0x8892),
    ("FCoE", "Ethernet", "ether_type", 0x8906),
    ("FIP", "Ethernet", "ether_type", 0x8914),
    ("Slow_Protocols", "Ethernet", "ether_type", 0x8809),
    ("LACP", "Ethernet", "ether_type", 0x8809),
    ("MAC_Control", "Ethernet", "ether_type", 0x8808),
    ("CFM", "Ethernet", "ether_type", 0x8902),
    ("HSR", "Ethernet", "ether_type", 0x892F),
    ("BATMAN", "Ethernet", "ether_type", 0x4305),
    ("NSH", "Ethernet", "ether_type", 0x894F),
    ("HomePlug_AV", "Ethernet", "ether_type", 0x88E1),
    ("AoE", "Ethernet", "ether_type", 0x88A2),
    ("MVRP", "Ethernet", "ether_type", 0x88F5),
    ("NC_SI", "Ethernet", "ether_type", 0x88F8),
    ("IEC_GOOSE", "Ethernet", "ether_type", 0x88B8),
    ("IEC_SV", "Ethernet", "ether_type", 0x88BA),
    ("IPX", "Ethernet", "ether_type", 0x8137),
    ("AppleTalk", "Ethernet", "ether_type", 0x809B),
    ("TIPC", "Ethernet", "ether_type", 0x88CA),
    // ── L3: IPv4 (protocol dispatch) ──
    ("TCP", "IPv4", "protocol", 6),
    ("UDP", "IPv4", "protocol", 17),
    ("ICMPv4", "IPv4", "protocol", 1),
    ("ICMP", "IPv4", "protocol", 1),
    ("GRE", "IPv4", "protocol", 47),
    ("SCTP", "IPv4", "protocol", 132),
    ("IGMP", "IPv4", "protocol", 2),
    ("OSPF", "IPv4", "protocol", 89),
    ("VRRP", "IPv4", "protocol", 112),
    ("PIM", "IPv4", "protocol", 103),
    ("L2TP", "IPv4", "protocol", 115),
    ("ESP", "IPv4", "protocol", 50),
    ("AH", "IPv4", "protocol", 51),
    ("IP_in_IP", "IPv4", "protocol", 4),
    ("DCCP", "IPv4", "protocol", 33),
    ("UDPLite", "IPv4", "protocol", 136),
    ("EIGRP", "IPv4", "protocol", 88),
    // ── L3: IPv6 (next_header dispatch) ──
    ("ICMPv6", "IPv6", "next_header", 58),
    ("IPv6_EH", "IPv6", "next_header", 0),
    ("IPv6_DestOpts", "IPv6", "next_header", 60),
    ("IPv6_Routing", "IPv6", "next_header", 43),
    ("IPv6_Fragment", "IPv6", "next_header", 44),
    ("SRv6", "IPv6", "next_header", 43),
    // ── L4: UDP port dispatch (stack: Eth → IPv4 → UDP → target) ──
    ("DNS", "UDP", "dst_port", 53),
    ("mDNS", "UDP", "dst_port", 5353),
    ("LLMNR", "UDP", "dst_port", 5355),
    ("NBNS", "UDP", "dst_port", 137),
    ("DHCP", "UDP", "dst_port", 67),
    ("DHCPv6", "UDP", "dst_port", 547),
    ("NTP", "UDP", "dst_port", 123),
    ("SNMP", "UDP", "dst_port", 161),
    ("TFTP", "UDP", "dst_port", 69),
    ("SIP", "UDP", "dst_port", 5060),
    ("RADIUS", "UDP", "dst_port", 1812),
    ("GTP_U", "UDP", "dst_port", 2152),
    ("GTP_C", "UDP", "dst_port", 2123),
    ("VXLAN", "UDP", "dst_port", 4789),
    ("Geneve", "UDP", "dst_port", 6081),
    ("WireGuard", "UDP", "dst_port", 51820),
    ("BFD", "UDP", "dst_port", 3784),
    ("RTP", "UDP", "dst_port", 5004),
    ("RTCP", "UDP", "dst_port", 5005),
    ("STUN", "UDP", "dst_port", 3478),
    ("QUIC", "UDP", "dst_port", 443),
    ("RIP", "UDP", "dst_port", 520),
    ("VXLAN_GPE", "UDP", "dst_port", 4790),
    ("LISP", "UDP", "dst_port", 4341),
    ("CAPWAP", "UDP", "dst_port", 5247),
    ("LWAPP", "UDP", "dst_port", 12222),
    ("Syslog", "UDP", "dst_port", 514),
    ("NetFlow_v5", "UDP", "dst_port", 2055),
    ("IPFIX", "UDP", "dst_port", 4739),
    ("MQTT", "TCP", "dst_port", 1883),
    ("CoAP", "UDP", "dst_port", 5683),
    ("DTLS", "UDP", "dst_port", 4433),
    ("IKEv2", "UDP", "dst_port", 500),
    ("TZSP", "UDP", "dst_port", 37008),
    ("OpenFlow", "TCP", "dst_port", 6653),
    ("SRT", "UDP", "dst_port", 1935),
    // ── L4: TCP port dispatch (stack: Eth → IPv4 → TCP → target) ──
    ("HTTP", "TCP", "dst_port", 80),
    ("TLS", "TCP", "dst_port", 443),
    ("BGP", "TCP", "dst_port", 179),
    ("SSH", "TCP", "dst_port", 22),
    ("Telnet", "TCP", "dst_port", 23),
    ("FTP", "TCP", "dst_port", 21),
    ("SMTP", "UpperPDU", "_always", 0),
    ("IMAP", "TCP", "dst_port", 143),
    ("SMB", "TCP", "dst_port", 445),
    ("LDAP", "TCP", "dst_port", 389),
    ("Diameter", "TCP", "dst_port", 3868),
    ("AMQP", "UpperPDU", "_always", 0),
    ("Kafka", "TCP", "dst_port", 9092),
    ("Redis", "TCP", "dst_port", 6379),
    ("Memcache", "TCP", "dst_port", 11211),
    ("Kerberos", "TCP", "dst_port", 88),
    ("MODBUS_TCP", "TCP", "dst_port", 502),
    ("DNP3", "TCP", "dst_port", 20000),
    ("ENIP", "TCP", "dst_port", 44818),
    ("OPC_UA", "TCP", "dst_port", 4840),
    ("RTSP", "TCP", "dst_port", 554),
    ("Skinny", "TCP", "dst_port", 2000),
    ("TACACS", "TCP", "dst_port", 49),
    // ── Tunnels over GRE (protocol_type dispatch) ──
    ("NVGRE", "GRE", "protocol_type", 0x6558),
    ("ERSPAN", "GRE", "protocol_type", 0x88BE),
    ("GRE_PPTP", "GRE", "protocol_type", 0x880B),
    // ── Additional Ethernet-direct routes ──
    ("WOL", "UpperPDU", "_always", 0),
    ("LLTD", "Ethernet", "ether_type", 0x88D9),
    ("EDSA", "Ethernet", "ether_type", 0xDADA),
    // ── Additional IPv4 routes ──
    ("CARP", "IPv4", "protocol", 112),
    ("RSVP", "IPv4", "protocol", 46),
    // ── Additional UDP routes ──
    ("BACnet", "UDP", "dst_port", 47808),
    ("GLBP", "UDP", "dst_port", 3222),
    ("GUE", "UDP", "dst_port", 6080),
    ("HSRP", "UDP", "dst_port", 1985),
    ("MGCP", "UDP", "dst_port", 2427),
    ("MPLS_OAM", "UDP", "dst_port", 3503),
    ("Teredo", "UDP", "dst_port", 3544),
    ("NetFlow_v9", "UDP", "dst_port", 2055),
    ("TPLINK_SMARTHOME", "UpperPDU", "_always", 0),
    ("ONC_RPC", "UDP", "dst_port", 111),
    // ── Additional TCP routes ──
    ("HTTP2", "TCP", "dst_port", 443),
    ("IEC_MMS", "TCP", "dst_port", 102),
    ("SMB2", "TCP", "dst_port", 445),
    ("STT", "UpperPDU", "_always", 0),
    ("ZeroMQ", "TCP", "dst_port", 5555),
    ("LDP", "TCP", "dst_port", 646),
    ("iSCSI", "TCP", "dst_port", 3260),
    ("NFS", "UpperPDU", "_always", 0),
    ("NVMe", "TCP", "dst_port", 4420),
    // ── Sub-protocol dispatch (IGMP, ICMPv6, etc.) ──
    ("IGMPv3_Query", "IGMP", "type", 0x11),
    ("IGMPv3_Report", "IGMP", "type", 0x22),
    ("IPv6_ND", "ICMPv6", "type", 135),
    ("MLD", "ICMPv6", "type", 130),
    ("MLDv2_Query", "ICMPv6", "type", 130),
    ("MLDv2_Report", "ICMPv6", "type", 143),
    ("SCTP_Chunk", "SCTP", "_always", 0),
    ("EAP", "EAPOL", "_always", 0),
    ("CIP", "UpperPDU", "_always", 0),
    // ── Bluetooth (DLT=187, root=HCI) ──
    ("HCI_CMD", "HCI", "type", 0x01),
    ("HCI_ACL", "HCI", "type", 0x02),
    ("HCI_SCO", "HCI", "type", 0x03),
    ("HCI_Event", "HCI", "type", 0x04),
    ("HCI_ISO", "HCI", "type", 0x05),
    ("L2CAP", "HCI_ACL", "_always", 0),
    ("BT_ATT", "L2CAP", "cid", 0x0004),
    ("BT_SMP", "L2CAP", "cid", 0x0006),
    // ── InfiniBand (via UpperPDU, tshark doesn't support DLT_INFINIBAND) ──
    ("IB_LRH", "UpperPDU", "_always", 0),
    ("IB_GRH", "IB_LRH", "lnh", 0x03),
    ("IB_BTH", "IB_LRH", "lnh", 0x02),
    ("IB_DETH", "IB_BTH", "opcode", 100),
    ("IB_RETH", "IB_BTH", "opcode", 10),
    ("IB_AETH", "IB_BTH", "opcode", 17),
    ("IB_RDETH", "IB_BTH", "opcode", 40),
    ("IB_AtomicETH", "IB_BTH", "opcode", 20),
    ("IB_ImmDt", "IB_BTH", "opcode", 9),
    ("IB_MAD", "IB_BTH", "opcode", 3),
    // ── Standalone root children ──
    ("Zigbee_NWK", "IEEE802154", "_always", 0),
    ("Zigbee_APS", "Zigbee_NWK", "_always", 0),
    ("GenNetlink", "Netlink", "_always", 0),
    ("NLAttr", "GenNetlink", "_always", 0),
    // ── 802.2 LLC/SNAP (root=Ethernet_802_3) ──
    ("LLC", "Ethernet_802_3", "_always", 0),
    ("SNAP", "LLC", "dsap", 0xAA),
    ("STP", "LLC", "dsap", 0x42),
    ("ISIS", "LLC", "dsap", 0xFE),
    ("CDP", "SNAP", "protocol_id", 0x2000),
    // ── UpperPDU fallback (DLT=252) ──
    ("BT_RFCOMM", "UpperPDU", "_always", 0),
    ("BT_BNEP", "UpperPDU", "_always", 0),
    ("BT_SDP", "UpperPDU", "_always", 0),
    ("BT_AVDTP", "UpperPDU", "_always", 0),
    ("SCSI", "UpperPDU", "_always", 0),
    ("iSER", "UpperPDU", "_always", 0),
    ("NTLMSSP", "UpperPDU", "_always", 0),
    ("OCSP", "UpperPDU", "_always", 0),
    ("Phonet", "UpperPDU", "_always", 0),
    ("MCTP", "UpperPDU", "_always", 0),
    ("X25", "UpperPDU", "_always", 0),
    ("DSA", "UpperPDU", "_always", 0),
    ("ATM", "UpperPDU", "_always", 0),
    // ── Phase 5: Additional protocols ──
    ("IPComp", "IPv4", "protocol", 108),
    ("PGM", "IPv4", "protocol", 113),
    ("GRE6", "IPv6", "next_header", 47),
    ("OSPFv3", "IPv6", "next_header", 89),
    ("EtherIP", "IPv4", "protocol", 97),
    ("RIPng", "UDP", "dst_port", 521),
    ("TWAMP", "UDP", "dst_port", 862),
    ("OWAMP", "UDP", "dst_port", 861),
    ("CFLOW", "UDP", "dst_port", 2055),
    ("sFlow", "UDP", "dst_port", 6343),
    ("GTPv2_C", "UDP", "dst_port", 2123),
    ("PFCP", "UDP", "dst_port", 8805),
    ("PPTP", "TCP", "dst_port", 1723),
    ("Diameter_S6a", "TCP", "dst_port", 3868),
    ("L2TPv3", "IPv4", "protocol", 115),
    ("LLDP_MED", "Ethernet", "ether_type", 0x88CC),
    ("VRRP3", "IPv4", "protocol", 112),
    ("MSDP", "TCP", "dst_port", 639),
    ("FDDI", "UpperPDU", "_always", 0),
    // ── Phase 5b: Telecom / Signaling (SS7/SIGTRAN) ──
    ("SCCP", "UpperPDU", "_always", 0),
    ("M3UA", "SCTP", "dst_port", 2905),
    ("M2PA", "SCTP", "dst_port", 3565),
    ("SUA", "SCTP", "dst_port", 14001),
    ("ISUP", "UpperPDU", "_always", 0),
    ("TCAP", "UpperPDU", "_always", 0),
    // ── Phase 5b: Mobile Core ──
    ("GTP_Prime", "UDP", "dst_port", 3386),
    ("BSSGP", "UpperPDU", "_always", 0),
    ("NAS_EPS", "UpperPDU", "_always", 0),
    ("NAS_5GS", "UpperPDU", "_always", 0),
    ("S1AP", "SCTP", "dst_port", 36412),
    ("NGAP", "SCTP", "dst_port", 38412),
    ("RANAP", "UpperPDU", "_always", 0),
    // ── Phase 5b: VoIP / Media ──
    ("MEGACO", "UDP", "dst_port", 2944),
    ("H323", "TCP", "dst_port", 1720),
    ("H225", "UpperPDU", "_always", 0),
    ("H245", "UpperPDU", "_always", 0),
    ("T38", "UDP", "dst_port", 4000),
    ("SDP", "UpperPDU", "_always", 0),
    ("RTMP", "TCP", "dst_port", 1935),
    // ── Phase 5b: Modern Web ──
    ("gRPC", "TCP", "dst_port", 50051),
    ("WebSocket", "UpperPDU", "_always", 0),
    ("HTTP3", "UpperPDU", "_always", 0),
    // ── Phase 5b: Automotive / Industrial ──
    ("SOME_IP", "UDP", "dst_port", 30490),
    ("DoIP", "TCP", "dst_port", 13400),
    ("UDS", "UpperPDU", "_always", 0),
    ("XCP", "UpperPDU", "_always", 0),
    ("S7COMM", "TCP", "dst_port", 102),
    ("IEC_104", "TCP", "dst_port", 2404),
    ("PROFINET_DCP", "Ethernet", "ether_type", 0x8892),
    // ── Phase 5b: Wireless / IoT ──
    ("AVTP", "Ethernet", "ether_type", 0x22F0),
    ("gPTP", "Ethernet", "ether_type", 0x88F7),
    ("LoRaWAN", "UpperPDU", "_always", 0),
    ("SixLoWPAN", "IEEE802154", "_always", 0),
    ("Radiotap", "UpperPDU", "_always", 0),
    ("PPI", "UpperPDU", "_always", 0),
    // ── Phase 5b: Routing extensions ──
    ("Babel", "UDP", "dst_port", 6696),
    ("RPKI_RTR", "TCP", "dst_port", 323),
    ("PCP", "UDP", "dst_port", 5351),
    ("COPS", "TCP", "dst_port", 3288),
    // ── Phase 5b: Database / Application ──
    ("MySQL", "TCP", "dst_port", 3306),
    ("PostgreSQL", "TCP", "dst_port", 5432),
    ("MongoDB", "TCP", "dst_port", 27017),
    ("Cassandra", "TCP", "dst_port", 9042),
    ("Elasticsearch", "TCP", "dst_port", 9200),
    ("NATS", "TCP", "dst_port", 4222),
    // ── Phase 5b: Messaging / Chat ──
    ("IRC", "TCP", "dst_port", 6667),
    ("XMPP", "TCP", "dst_port", 5222),
    ("POP3", "TCP", "dst_port", 110),
    ("NNTP", "TCP", "dst_port", 119),
    // ── Phase 5b: Monitoring / Telemetry ──
    ("Collectd", "UDP", "dst_port", 25826),
    ("RADIUS_ACCT", "UDP", "dst_port", 1813),
    // ── Phase 5b: Maritime / Aviation ──
    ("AIS", "UpperPDU", "_always", 0),
    ("ASTERIX", "UDP", "dst_port", 8600),
    // ── Phase 5b: TSN / Automotive Ethernet ──
    ("MRP", "Ethernet", "ether_type", 0x88E3),
    ("CAN_TP", "UpperPDU", "_always", 0),
    // ── Phase 5b: Security / Auth ──
    ("ACME", "UpperPDU", "_always", 0),
    ("EST", "UpperPDU", "_always", 0),
    ("CMP", "TCP", "dst_port", 829),
    // ── Phase 5b: Management ──
    ("LLDP_802_1AB", "Ethernet", "ether_type", 0x88CC),
    ("RMON", "UpperPDU", "_always", 0),
    // ── Phase 5b: Tunneling ──
    ("AYIYA", "UDP", "dst_port", 5072),
    ("SixToFour", "IPv4", "protocol", 41),
    ("SixInFour", "IPv4", "protocol", 41),
    ("AMT", "UDP", "dst_port", 2268),
    // ── Phase 5c: Batch 3 ──
    ("MPLS_Echo", "UDP", "dst_port", 3503),
    ("LMP", "UDP", "dst_port", 701),
    ("PCEP", "TCP", "dst_port", 4189),
    ("BMP", "TCP", "dst_port", 11019),
    ("VRRP_IPv6", "IPv6", "next_header", 112),
    ("PIMv6", "IPv6", "next_header", 103),
    ("VXLAN_GPB", "UDP", "dst_port", 4789),
    ("DNS_TCP", "TCP", "dst_port", 53),
    ("DoH", "UpperPDU", "_always", 0),
    ("DoT", "TCP", "dst_port", 853),
    ("FCP", "UpperPDU", "_always", 0),
    ("FCOE_FIP", "Ethernet", "ether_type", 0x8914),
    ("RDMA_CM", "UpperPDU", "_always", 0),
    ("Y1731", "Ethernet", "ether_type", 0x8902),
    ("G8032", "UpperPDU", "_always", 0),
    ("ELMI", "UpperPDU", "_always", 0),
    ("MGCP_NCS", "UDP", "dst_port", 2727),
    ("SCTP_Init", "SCTP", "_always", 0),
    ("GOOSE", "Ethernet", "ether_type", 0x88B8),
    ("R_GOOSE", "UpperPDU", "_always", 0),
    ("OPC_DA", "UpperPDU", "_always", 0),
    ("EtherNet_IP", "TCP", "dst_port", 44818),
    ("GTP_V0", "UDP", "dst_port", 3386),
    ("LISP_Control", "UDP", "dst_port", 4342),
    ("MPLS_TP", "Ethernet", "ether_type", 0x8847),
    ("PWE3", "UpperPDU", "_always", 0),
    ("LLDP_EXT_DOT1", "Ethernet", "ether_type", 0x88CC),
    ("LLDP_EXT_DOT3", "Ethernet", "ether_type", 0x88CC),
    ("SFLOW_V5", "UDP", "dst_port", 6343),
    ("IEEE802_11_Beacon", "UpperPDU", "_always", 0),
    ("IEEE802_11_Data", "UpperPDU", "_always", 0),
    ("WPA_EAPOL_Key", "EAPOL", "_always", 0),
    ("Thread", "UpperPDU", "_always", 0),
    ("Matter", "UpperPDU", "_always", 0),
    ("Zigbee_ZCL", "Zigbee_APS", "_always", 0),
    ("Zigbee_ZDP", "Zigbee_APS", "_always", 0),
    ("BLE_LL", "UpperPDU", "_always", 0),
    ("OCSP_Response", "UpperPDU", "_always", 0),
    ("DTLS_13", "UDP", "dst_port", 4433),
    ("EtherType_TSN", "Ethernet", "ether_type", 0xF1C1),
    ("LLDP_CDP", "SNAP", "protocol_id", 0x2000),
    // ── Phase 5d: Batch 4 ──
    ("QUIC_Initial", "UDP", "dst_port", 443),
    ("QUIC_Retry", "UDP", "dst_port", 443),
    ("IPv6_HopByHop", "IPv6", "next_header", 0),
    ("IPv6_MobileIP", "IPv6", "next_header", 135),
    ("MLD_Report_v1", "ICMPv6", "type", 131),
    ("SCTP_Data", "SCTP", "_always", 0),
    ("SCTP_Sack", "SCTP", "_always", 0),
    ("GRE_Cisco", "IPv4", "protocol", 47),
    ("GRE_WCCPv2", "GRE", "protocol_type", 0x883E),
    ("MPLS_PW_ETH", "MPLS", "_always", 0),
    ("GTP_U_V1", "UDP", "dst_port", 2152),
    ("L2TP_AVP", "L2TP", "_always", 0),
    ("GENEVE_OPT", "Geneve", "_always", 0),
    ("PPP_LCP", "PPP", "protocol", 0xC021),
    ("PPP_IPCP", "PPP", "protocol", 0x8021),
    ("PPP_IPv6CP", "PPP", "protocol", 0x8057),
    ("PPP_CCP", "PPP", "protocol", 0x80FD),
    ("PPP_CHAP", "PPP", "protocol", 0xC223),
    ("PPP_PAP", "PPP", "protocol", 0xC023),
    ("PIM_BSR", "IPv4", "protocol", 103),
    ("PIM_Assert", "IPv4", "protocol", 103),
    ("MSDP_SA", "TCP", "dst_port", 639),
    ("RSTP", "LLC", "dsap", 0x42),
    ("MSTP", "LLC", "dsap", 0x42),
    ("PVST", "LLC", "dsap", 0x42),
    ("IKEv1", "UDP", "dst_port", 500),
    ("ESP_NULL", "IPv4", "protocol", 50),
    ("MARKER", "Ethernet", "ether_type", 0x8809),
    ("OAM_LBM", "Ethernet", "ether_type", 0x8902),
    ("OAM_LTM", "Ethernet", "ether_type", 0x8902),
    ("EAP_TLS", "EAPOL", "_always", 0),
    ("EAP_TTLS", "EAPOL", "_always", 0),
    ("EAP_PEAP", "EAPOL", "_always", 0),
    ("EAP_SIM", "EAPOL", "_always", 0),
    ("EAP_AKA", "EAPOL", "_always", 0),
    ("NTS", "UDP", "dst_port", 123),
    ("PTP_V1", "Ethernet", "ether_type", 0x88F7),
    ("DHCP_Option", "UDP", "dst_port", 67),
    ("DHCPv6_Option", "UDP", "dst_port", 547),
    ("SOCKS", "TCP", "dst_port", 1080),
    ("WHOIS", "TCP", "dst_port", 43),
    ("FINGER", "TCP", "dst_port", 79),
    ("DAYTIME", "TCP", "dst_port", 13),
    ("CHARGEN", "TCP", "dst_port", 19),
    ("ECHO", "UDP", "dst_port", 7),
    ("DISCARD", "TCP", "dst_port", 9),
    ("TIME", "UDP", "dst_port", 37),
    ("NETCONF", "TCP", "dst_port", 830),
    ("gNMI", "TCP", "dst_port", 9339),
    ("gNOI", "TCP", "dst_port", 9340),
    ("RTP_MPEG", "UDP", "dst_port", 5004),
    ("RTP_H264", "UDP", "dst_port", 5004),
    ("RTP_H265", "UDP", "dst_port", 5004),
    ("RTP_OPUS", "UDP", "dst_port", 5004),
    ("RTCP_SR", "UDP", "dst_port", 5005),
    ("RTCP_RR", "UDP", "dst_port", 5005),
    ("NFSv4", "UpperPDU", "_always", 0),
    ("CIFS", "TCP", "dst_port", 445),
    ("RADIUS_COA", "UDP", "dst_port", 3799),
    ("SNMPv3", "UDP", "dst_port", 161),
    ("SNMP_Trap", "UDP", "dst_port", 162),
    ("GVRP", "Ethernet", "ether_type", 0x88F5),
    ("MMRP", "Ethernet", "ether_type", 0x88F6),
    ("DCBX", "Ethernet", "ether_type", 0x88CC),
    ("FCoE_Init", "Ethernet", "ether_type", 0x8906),
    ("CAN_J1939", "UpperPDU", "_always", 0),
    ("CAN_OBD2", "UpperPDU", "_always", 0),
    ("TZSP_V2", "UDP", "dst_port", 37008),
    ("ERSPAN_V3", "GRE", "protocol_type", 0x22EB),
    ("VXLAN_GBP", "UDP", "dst_port", 4789),
    // Bucket 5: UpperPDU fallback routes for protocols with tshark dissectors
    ("SOCKS", "UpperPDU", "_always", 0),
    ("IRC", "UpperPDU", "_always", 0),
    ("MMRP", "UpperPDU", "_always", 0),
    ("TACACS", "UpperPDU", "_always", 0),
    ("PVST", "UpperPDU", "_always", 0),
    ("RSTP", "UpperPDU", "_always", 0),
    ("ERSPAN", "UpperPDU", "_always", 0),
    // eCPRI (EtherType 0xAEFE)
    ("eCPRI", "Ethernet", "ether_type", 0xAEFE),
    // ── Falcon Transport Protocol (UDP port 7777) ──
    ("Falcon-Version-OV", "UDP", "dst_port", 7777),
    ("Falcon-Packet-Type-OV", "Falcon-Version-OV", "version", 1),
    ("Falcon-Pull-Request", "Falcon-Packet-Type-OV", "packet_type", 0),
    ("Falcon-Pull-Data", "Falcon-Packet-Type-OV", "packet_type", 3),
    ("Falcon-Push-Data", "Falcon-Packet-Type-OV", "packet_type", 5),
    ("Falcon-Resync", "Falcon-Packet-Type-OV", "packet_type", 6),
    ("Falcon-NACK", "Falcon-Packet-Type-OV", "packet_type", 8),
    ("Falcon-Base-ACK", "Falcon-Packet-Type-OV", "packet_type", 9),
    ("Falcon-Ext-ACK", "Falcon-Packet-Type-OV", "packet_type", 10),
    // ── NVMe/TCP (TCP port 4420, PDU type dispatch) ──
    ("NVMe_TCP", "TCP", "dst_port", 4420),
    ("NVMe_TCP_ICReq", "NVMe_TCP", "type", 0x0),
    ("NVMe_TCP_ICResp", "NVMe_TCP", "type", 0x1),
    ("NVMe_TCP_R2T", "NVMe_TCP", "type", 0x9),
    ("NVMe_TCP_Data", "NVMe_TCP", "type", 0x7),
    ("NVMe_TCP_Rsp", "NVMe_TCP", "type", 0x5),
    // ── NVMe/RDMA CM private data (connection setup for NVMe over RoCEv2) ──
    ("NVMe_RDMA_CM_Req", "RDMA_CM", "_always", 0),
    ("NVMe_RDMA_CM_Rep", "RDMA_CM", "_always", 0),
    ("NVMe_RDMA_CM_Rej", "RDMA_CM", "_always", 0),
    // ── PFC (MAC Control sub-type, via UpperPDU for tshark) ──
    ("PFC", "UpperPDU", "_always", 0),
    // ── RoCEv2 (UDP port 4791 → BTH) ──
    ("RoCEv2", "UDP", "dst_port", 4791),
    ("CNP", "RoCEv2", "opcode", 0x81),
    // ── iSCSI PDU types (TCP port 3260, opcode dispatch) ──
    ("iSCSI_SCSI_Cmd", "iSCSI", "opcode", 0x01),
    ("iSCSI_SCSI_Rsp", "iSCSI", "opcode", 0x21),
    ("iSCSI_TMF", "iSCSI", "opcode", 0x02),
    ("iSCSI_TMF_Rsp", "iSCSI", "opcode", 0x22),
    ("iSCSI_Data_Out", "iSCSI", "opcode", 0x05),
    ("iSCSI_Data_In", "iSCSI", "opcode", 0x25),
    ("iSCSI_R2T", "iSCSI", "opcode", 0x31),
    ("iSCSI_NOP_Out", "iSCSI", "opcode", 0x00),
    ("iSCSI_NOP_In", "iSCSI", "opcode", 0x20),
    ("iSCSI_Login_Req", "iSCSI", "opcode", 0x03),
    ("iSCSI_Login_Rsp", "iSCSI", "opcode", 0x23),
    ("iSCSI_Text", "iSCSI", "opcode", 0x04),
    ("iSCSI_Text_Rsp", "iSCSI", "opcode", 0x24),
    ("iSCSI_Logout", "iSCSI", "opcode", 0x06),
    ("iSCSI_Logout_Rsp", "iSCSI", "opcode", 0x26),
    ("iSCSI_Async", "iSCSI", "opcode", 0x32),
    ("iSCSI_Reject", "iSCSI", "opcode", 0x3f),
    // ── SRP (SCSI RDMA Protocol, via UpperPDU) ──
    ("SRP_Login_Req", "UpperPDU", "_always", 0),
    ("SRP_Login_Rsp", "UpperPDU", "_always", 0),
    ("SRP_Login_Rej", "UpperPDU", "_always", 0),
    ("SRP_Cmd", "UpperPDU", "_always", 0),
    ("SRP_Rsp", "UpperPDU", "_always", 0),
    ("SRP_TSK_Mgmt", "UpperPDU", "_always", 0),
    ("SRP_I_Logout", "UpperPDU", "_always", 0),
    ("SRP_T_Logout", "UpperPDU", "_always", 0),
    ("SRP_Cred_Req", "UpperPDU", "_always", 0),
    ("SRP_Cred_Rsp", "UpperPDU", "_always", 0),
    // ── FC FCP IUs (via UpperPDU / FC type=0x08) ──
    ("FCP_CMND", "UpperPDU", "_always", 0),
    ("FCP_TXRDY", "UpperPDU", "_always", 0),
    ("FCP_RSP", "UpperPDU", "_always", 0),
    ("FCP_RSP_EXT", "UpperPDU", "_always", 0),
    ("FCP_SRR", "UpperPDU", "_always", 0),
    // ── FC ELS (via UpperPDU / FC type=0x01) ──
    ("FC_ELS_FLOGI", "UpperPDU", "_always", 0),
    ("FC_ELS_LOGO", "UpperPDU", "_always", 0),
    ("FC_ELS_PRLI", "UpperPDU", "_always", 0),
    ("FC_ELS_ADISC", "UpperPDU", "_always", 0),
    ("FC_ELS_RSCN", "UpperPDU", "_always", 0),
    ("FC_ELS_SCR", "UpperPDU", "_always", 0),
    ("FC_ELS_LS_ACC", "UpperPDU", "_always", 0),
    ("FC_ELS_LS_RJT", "UpperPDU", "_always", 0),
    // ── FC GS/NS (via UpperPDU / FC type=0x20) ──
    ("FC_CT_HDR", "UpperPDU", "_always", 0),
    ("FC_NS_GID_FT", "UpperPDU", "_always", 0),
    ("FC_NS_GPN_FT_Rsp", "UpperPDU", "_always", 0),
    // ── SAS SSP/SMP (point-to-point, via UpperPDU) ──
    ("SSP_Frame_Hdr", "UpperPDU", "_always", 0),
    ("SSP_Command_IU", "UpperPDU", "_always", 0),
    ("SSP_Response_IU", "UpperPDU", "_always", 0),
    ("SSP_XFER_RDY", "UpperPDU", "_always", 0),
    ("SSP_TMF_IU", "UpperPDU", "_always", 0),
    ("ATA_H2D_FIS", "UpperPDU", "_always", 0),
    ("ATA_D2H_FIS", "UpperPDU", "_always", 0),
    ("SAS_Identify", "UpperPDU", "_always", 0),
];

/// Protocols that cannot round-trip through PCAP validation because they lack
/// a tshark dissector.
#[allow(dead_code)]
const PCAP_UNSUPPORTED: &[&str] = &[];

/// Build the Wireshark Upper PDU TLV preamble for a given dissector name.
pub(super) fn upper_pdu_preamble(dissector: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    // Tag 0x000C = EXP_PDU_TAG_DISSECTOR_NAME (triggers dissection)
    buf.extend_from_slice(&0x000Cu16.to_be_bytes());
    let name_len = dissector.len();
    buf.extend_from_slice(&(name_len as u16).to_be_bytes());
    buf.extend_from_slice(dissector.as_bytes());
    // Wireshark EXP_PDU TLV values must be padded to 4-byte boundary
    let padded_len = (name_len + 3) & !3;
    for _ in name_len..padded_len {
        buf.push(0);
    }
    // End marker
    buf.extend_from_slice(&[0, 0, 0, 0]);
    buf
}

/// Build encapsulation chain from a link-layer root down to the target protocol.
pub(super) fn build_protocol_stack(
    target: &str,
    all_protos: &BTreeMap<String, ProtocolDef>,
    discovery_state: &crate::discovery::DiscoveryState,
    discovered_protos: &BTreeMap<String, crate::discovery::DiscoveredProtocol>,
) -> Result<StackResult, String> {
    // If target is itself a root, return single-layer stack
    if is_root(target) {
        let def = resolve_proto(target, all_protos);
        return Ok(StackResult {
            layers: vec![StackLayer {
                proto_name: target.to_string(),
                proto_def: def,
                overrides: BTreeMap::new(),
            }],
            link_type: dlt_for_root(target),
        });
    }

    // Walk from target back to a root
    // We use owned strings to handle both static routes and discovered routes
    let mut chain: Vec<(String, String, u64)> = Vec::new(); // (proto, parent_dispatch_field, value)
    let mut current = target.to_string();

    for _ in 0..10 {
        // max depth guard
        // Try curated routes first
        if let Some(route) = STACK_ROUTES
            .iter()
            .find(|(child, _, _, _)| *child == current.as_str())
        {
            chain.push((route.0.to_string(), route.2.to_string(), route.3));
            current = route.1.to_string();
        }
        // Fallback: try discovered routes from tshark registry (uses pre-built map)
        else if let Some(disc_route) = try_discovery_route(&current, discovery_state, discovered_protos) {
            chain.push((
                current.clone(),
                disc_route.dispatch_field.clone(),
                disc_route.dispatch_value,
            ));
            current = disc_route.parent.clone();
        }
        // Fallback: check PCAP templates
        else if let Some(template_result) = try_pcap_template(target) {
            return Ok(template_result);
        } else {
            return Err(format!(
                "No route to '{}': protocol not in STACK_ROUTES or discovery",
                target
            ));
        }

        if is_root(&current) {
            break;
        }
    }

    if !is_root(&current) {
        return Err(format!(
            "Could not reach a link-layer root from '{}' within 10 hops",
            target
        ));
    }

    let root_name = current;
    let link_type = dlt_for_root(&root_name);

    // Reverse: root first, target last
    chain.reverse();

    let mut layers = Vec::new();

    // Root layer with dispatch override from first chain entry
    let mut root_overrides = BTreeMap::new();
    root_overrides.insert(chain[0].1.clone(), chain[0].2);
    layers.push(StackLayer {
        proto_name: root_name.to_string(),
        proto_def: resolve_proto(&root_name, all_protos),
        overrides: root_overrides,
    });

    // Intermediate + target layers
    for i in 0..chain.len() {
        let proto_name = &chain[i].0;
        let mut overrides = BTreeMap::new();

        // If not the last layer, set dispatch field for next layer
        if i + 1 < chain.len() {
            overrides.insert(chain[i + 1].1.clone(), chain[i + 1].2);
        }

        layers.push(StackLayer {
            proto_name: proto_name.to_string(),
            proto_def: resolve_proto(proto_name, all_protos),
            overrides,
        });
    }

    Ok(StackResult { layers, link_type })
}

/// Resolve a protocol definition: prefer embedded (PCAP-correct field names),
/// fall back to extracted IR. Embedded protos use dispatch field names that
/// match STACK_ROUTES (e.g., "ether_type", "protocol"), while extracted protos
/// use source-specific names (e.g., kernel's "h_proto", "ip_proto").
fn resolve_proto(name: &str, all_protos: &BTreeMap<String, ProtocolDef>) -> ProtocolDef {
    if let Some(def) = embedded_proto(name) {
        return def;
    }
    if let Some(def) = all_protos.get(name) {
        if !def.fields.is_empty() {
            return def.clone();
        }
    }
    ProtocolDef::new(name, 0)
}

/// Try to find a discovered route via the tshark registry.
/// Uses a pre-built protocol map to avoid rebuilding it on every call.
fn try_discovery_route(
    proto: &str,
    state: &crate::discovery::DiscoveryState,
    discovered_protos: &std::collections::BTreeMap<String, crate::discovery::DiscoveredProtocol>,
) -> Option<crate::discovery::routes::StackRoute> {
    let registry = state.tshark.as_ref()?;
    // The proto might be a canonical name; look up its tshark filter from the pre-built map
    let dp = discovered_protos.get(proto)?;
    let filter = dp.tshark_filter.as_deref()?;
    crate::discovery::routes::discovered_route(filter, registry)
}

/// A PCAP template loaded from disk.
pub struct PcapTemplate {
    pub pcap_bytes: Vec<u8>,
    pub packet_bytes: Vec<u8>,
    pub link_type: u32,
}

/// Try to load a PCAP template for protocols that can't be auto-routed.
fn try_pcap_template(target: &str) -> Option<StackResult> {
    load_pcap_template(target).map(|tmpl| {
        let def = ProtocolDef::new(target, 0);
        StackResult {
            layers: vec![StackLayer {
                proto_name: target.to_string(),
                proto_def: def,
                overrides: BTreeMap::new(),
            }],
            link_type: tmpl.link_type,
        }
    })
}

/// Load a PCAP template file for a given protocol name.
///
/// Looks for `$PROTO_AUDIT_PCAP_TEMPLATES/<proto>.pcap`.
pub fn load_pcap_template(target: &str) -> Option<PcapTemplate> {
    let lower = target.to_lowercase();
    let filenames = [
        format!("{}.pcap", lower),
        format!("{}.pcap", lower.replace('.', "").replace('-', "_")),
        format!("{}.pcap", lower.replace('-', "_")),
    ];

    // Candidate directories in priority order.
    // When PROTO_AUDIT_PCAP_TEMPLATES is set, use ONLY that directory
    // (makes tests deterministic by avoiding CWD-relative discovery).
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(d) = std::env::var("PROTO_AUDIT_PCAP_TEMPLATES") {
        dirs.push(std::path::PathBuf::from(d));
    } else {
        dirs.push(std::path::PathBuf::from("pcap_templates"));
        dirs.push(std::path::PathBuf::from("samples/proto_audit/pcap_templates"));
        if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
            dirs.push(std::path::PathBuf::from(&manifest).join("pcap_templates"));
        }
    }

    let mut template_path: Option<std::path::PathBuf> = None;
    'outer: for dir in &dirs {
        for fname in &filenames {
            let p = dir.join(fname);
            if p.exists() {
                template_path = Some(p);
                break 'outer;
            }
        }
    }
    let template_path = template_path?;

    let data = std::fs::read(&template_path).ok()?;
    if data.len() < 24 + 16 {
        return None; // Too short for global header + record header
    }

    // Parse global header (24 bytes, little-endian)
    let link_type = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

    // Parse first record header (16 bytes at offset 24)
    let incl_len = u32::from_le_bytes([data[32], data[33], data[34], data[35]]) as usize;

    // Extract packet bytes
    let pkt_start = 40; // 24 (global) + 16 (record)
    if pkt_start + incl_len > data.len() {
        return None;
    }
    let packet_bytes = data[pkt_start..pkt_start + incl_len].to_vec();

    Some(PcapTemplate {
        pcap_bytes: data,
        packet_bytes,
        link_type,
    })
}
