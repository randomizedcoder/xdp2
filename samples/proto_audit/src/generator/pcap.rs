//! PCAP generator: IR ProtocolDef → wire bytes in PCAP format.
//!
//! Generates a complete PCAP file containing one minimal packet for a target
//! protocol, building the full encapsulation stack (Ethernet → IPv4 → TCP, etc.).
//! The generated PCAP can be fed back to tshark for round-trip validation.

use std::collections::BTreeMap;

use crate::ir::{Endian, FieldDef, FieldType, ProtocolDef};

/// Link-layer root protocols and their PCAP Data Link Types (DLTs).
const LINK_ROOTS: &[(&str, u32)] = &[
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
const UPPER_PDU_DISSECTORS: &[(&str, &str)] = &[
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
];

/// Output from PCAP generation.
pub struct PcapOutput {
    /// Complete PCAP file bytes (global header + record header + packet)
    pub pcap_bytes: Vec<u8>,
    /// Raw packet bytes (no PCAP framing)
    pub packet_bytes: Vec<u8>,
    /// Protocols in encapsulation order (e.g., ["Ethernet", "IPv4", "TCP"])
    pub stack: Vec<String>,
    /// PCAP Data Link Type used for this packet
    pub link_type: u32,
}

/// One layer in the protocol stack being constructed.
struct StackLayer {
    proto_name: String,
    proto_def: ProtocolDef,
    /// Overrides for specific fields (e.g., ether_type=0x0800)
    overrides: BTreeMap<String, u64>,
}

/// Result of building a protocol stack.
struct StackResult {
    layers: Vec<StackLayer>,
    link_type: u32,
}

/// (child, parent, parent_dispatch_field, dispatch_value)
const STACK_ROUTES: &[(&str, &str, &str, u64)] = &[
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
];

/// Protocols that cannot round-trip through PCAP validation because they lack
/// a tshark dissector.
#[allow(dead_code)]
const PCAP_UNSUPPORTED: &[&str] = &[];

/// Generate a complete PCAP file containing one packet for the target protocol.
pub fn generate_pcap(
    target_proto: &ProtocolDef,
    all_protos: &BTreeMap<String, ProtocolDef>,
) -> Result<PcapOutput, String> {
    let discovery_state = crate::discovery::DiscoveryState::load_from_env();
    generate_pcap_with_discovery(target_proto, all_protos, &discovery_state)
}

/// Generate a PCAP with an externally-provided DiscoveryState (avoids reloading).
pub fn generate_pcap_with_discovery(
    target_proto: &ProtocolDef,
    all_protos: &BTreeMap<String, ProtocolDef>,
    discovery_state: &crate::discovery::DiscoveryState,
) -> Result<PcapOutput, String> {
    // Pre-build the protocol map once for discovery route lookups
    let discovered_protos = crate::discovery::all_protocols(discovery_state);

    // Try PCAP template first — templates contain valid protocol content
    // (e.g., real DHCP Discover, NTP query, BGP OPEN) that tshark can dissect,
    // whereas synthetic generation produces zero-filled payloads that tshark
    // often can't identify as the target protocol.
    // Skip templates for UpperPDU-routed protocols: their templates use TCP/UDP
    // encapsulation which tshark can't dissect without proper TCP state.
    let is_upper_pdu_routed = UPPER_PDU_DISSECTORS
        .iter()
        .any(|(proto, _)| *proto == target_proto.name);
    if !is_upper_pdu_routed {
        if let Some(tmpl) = load_pcap_template(&target_proto.name) {
            return Ok(PcapOutput {
                pcap_bytes: tmpl.pcap_bytes,
                packet_bytes: tmpl.packet_bytes,
                stack: vec![format!("template:{}", target_proto.name)],
                link_type: tmpl.link_type,
            });
        }
    }

    // Fall back to synthetic stack construction
    let result = match build_protocol_stack(&target_proto.name, all_protos, discovery_state, &discovered_protos) {
        Ok(r) => r,
        Err(e) => {
            return Err(e);
        }
    };
    let link_type = result.link_type;

    // Serialize each layer
    let mut packet = Vec::new();
    let stack_names: Vec<String> = result.layers.iter().map(|l| l.proto_name.clone()).collect();

    for (i, layer) in result.layers.iter().enumerate() {
        if i == 0 && layer.proto_name == "UpperPDU" {
            // UpperPDU root: emit TLV preamble instead of serializing a header
            let target_name = stack_names.last().map(|s| s.as_str()).unwrap_or("");
            let dissector = UPPER_PDU_DISSECTORS
                .iter()
                .find(|(proto, _)| *proto == target_name)
                .map(|(_, d)| *d)
                .unwrap_or("data");
            packet.extend_from_slice(&upper_pdu_preamble(dissector));
        } else {
            let header = serialize_header(&layer.proto_def, &layer.overrides);
            packet.extend_from_slice(&header);
        }
    }

    // Fixup: IPv4 total_length and checksum
    fixup_ipv4(&mut packet, &result.layers);
    // Fixup: IPv6 payload_length
    fixup_ipv6(&mut packet, &result.layers);
    // Fixup: UDP length
    fixup_udp_length(&mut packet, &result.layers);
    // Fixup: 802.3 length field
    fixup_802_3_length(&mut packet, &result.layers);

    // Build PCAP file
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&pcap_global_header(link_type));
    pcap.extend_from_slice(&pcap_record_header(packet.len() as u32));
    pcap.extend_from_slice(&packet);

    Ok(PcapOutput {
        pcap_bytes: pcap,
        packet_bytes: packet,
        stack: stack_names,
        link_type,
    })
}

/// Build the Wireshark Upper PDU TLV preamble for a given dissector name.
fn upper_pdu_preamble(dissector: &str) -> Vec<u8> {
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
fn build_protocol_stack(
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

/// Embedded minimal protocol definitions for stack construction.
fn embedded_proto(name: &str) -> Option<ProtocolDef> {
    match name {
        "Ethernet" => Some(
            ProtocolDef::new("Ethernet", 112)
                .with_fields(vec![
                    FieldDef::new("dst_mac", 0, 48, FieldType::MacAddr).with_endian(Endian::Big),
                    FieldDef::new("src_mac", 48, 48, FieldType::MacAddr).with_endian(Endian::Big),
                    FieldDef::new("ether_type", 96, 16, FieldType::Enum).with_endian(Endian::Big),
                ])
                .with_dispatch_field("ether_type"),
        ),
        "IPv4" => Some(
            ProtocolDef::new("IPv4", 160)
                .with_variable_length()
                .with_fields(vec![
                    FieldDef::new("version", 0, 4, FieldType::Uint).with_default_value("4"),
                    FieldDef::new("ihl", 4, 4, FieldType::Uint)
                        .with_length(Some(4))
                        .with_default_value("5"),
                    FieldDef::new("tos", 8, 8, FieldType::Uint),
                    FieldDef::new("total_length", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("identification", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("flags", 48, 3, FieldType::Flags),
                    FieldDef::new("fragment_offset", 51, 13, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("ttl", 64, 8, FieldType::Uint).with_default_value("64"),
                    FieldDef::new("protocol", 72, 8, FieldType::Enum).with_dispatch(),
                    FieldDef::new("checksum", 80, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("src_addr", 96, 32, FieldType::Ipv4Addr)
                        .with_endian(Endian::Big),
                    FieldDef::new("dst_addr", 128, 32, FieldType::Ipv4Addr)
                        .with_endian(Endian::Big),
                ])
                .with_dispatch_field("protocol"),
        ),
        "IPv6" => Some(
            ProtocolDef::new("IPv6", 320)
                .with_fields(vec![
                    FieldDef::new("version", 0, 4, FieldType::Uint).with_default_value("6"),
                    FieldDef::new("traffic_class", 4, 8, FieldType::Uint),
                    FieldDef::new("flow_label", 12, 20, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("payload_length", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("next_header", 48, 8, FieldType::Enum).with_dispatch(),
                    FieldDef::new("hop_limit", 56, 8, FieldType::Uint).with_default_value("64"),
                    FieldDef::new("src_addr", 64, 128, FieldType::Ipv6Addr)
                        .with_endian(Endian::Big),
                    FieldDef::new("dst_addr", 192, 128, FieldType::Ipv6Addr)
                        .with_endian(Endian::Big),
                ])
                .with_dispatch_field("next_header"),
        ),
        "UDP" => Some(
            ProtocolDef::new("UDP", 64)
                .with_fields(vec![
                    FieldDef::new("src_port", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("dst_port", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("length", 32, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("checksum", 48, 16, FieldType::Uint).with_endian(Endian::Big),
                ])
                .with_dispatch_field("dst_port"),
        ),
        "TCP" => Some(
            ProtocolDef::new("TCP", 160)
                .with_variable_length()
                .with_fields(vec![
                    FieldDef::new("src_port", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("dst_port", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("seq", 32, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("ack", 64, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("data_offset", 96, 4, FieldType::Uint).with_default_value("5"),
                    FieldDef::new("reserved", 100, 3, FieldType::Pad),
                    FieldDef::new("flags", 103, 9, FieldType::Flags),
                    FieldDef::new("window", 112, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("checksum", 128, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("urgent_ptr", 144, 16, FieldType::Uint).with_endian(Endian::Big),
                ])
                .with_dispatch_field("dst_port"),
        ),
        "GRE" => Some(
            ProtocolDef::new("GRE", 32)
                .with_variable_length()
                .with_fields(vec![
                    FieldDef::new("flags_version", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("protocol_type", 16, 16, FieldType::Enum)
                        .with_endian(Endian::Big),
                ])
                .with_dispatch_field("protocol_type"),
        ),
        // ── IGMP (dispatch on type for IGMPv3 subtypes) ──
        "IGMP" => Some(
            ProtocolDef::new("IGMP", 64)
                .with_fields(vec![
                    FieldDef::new("type", 0, 8, FieldType::Enum).with_dispatch(),
                    FieldDef::new("max_resp", 8, 8, FieldType::Uint),
                    FieldDef::new("checksum", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("group_addr", 32, 32, FieldType::Ipv4Addr)
                        .with_endian(Endian::Big),
                ])
                .with_dispatch_field("type"),
        ),
        // ── ICMPv6 (dispatch on type for ND, MLD subtypes) ──
        "ICMPv6" => Some(
            ProtocolDef::new("ICMPv6", 32)
                .with_fields(vec![
                    FieldDef::new("type", 0, 8, FieldType::Enum).with_dispatch(),
                    FieldDef::new("code", 8, 8, FieldType::Uint),
                    FieldDef::new("checksum", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                ])
                .with_dispatch_field("type"),
        ),
        // ── SCTP (96 bits, child of IPv4 protocol=132) ──
        "SCTP" => Some(
            ProtocolDef::new("SCTP", 96)
                .with_fields(vec![
                    FieldDef::new("src_port", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("dst_port", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("vtag", 32, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("checksum", 64, 32, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── EAPOL (32 bits, child of Ethernet ether_type=0x888E) ──
        "EAPOL" => Some(
            ProtocolDef::new("EAPOL", 32)
                .with_fields(vec![
                    FieldDef::new("version", 0, 8, FieldType::Uint).with_default_value("2"),
                    FieldDef::new("type", 8, 8, FieldType::Uint),
                    FieldDef::new("length", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── ENIP (192 bits, child of TCP dst_port=44818) ──
        "ENIP" => Some(
            ProtocolDef::new("ENIP", 192)
                .with_fields(vec![
                    FieldDef::new("command", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("length", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("session_handle", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("status", 64, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("sender_context", 96, 64, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("options", 160, 32, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── Bluetooth: HCI H4 (8 bits, root DLT=187) ──
        "HCI" => Some(
            ProtocolDef::new("HCI", 8)
                .with_fields(vec![
                    FieldDef::new("type", 0, 8, FieldType::Enum).with_dispatch(),
                ])
                .with_dispatch_field("type"),
        ),
        // ── HCI ACL (32 bits, child of HCI type=0x02) ──
        "HCI_ACL" => Some(
            ProtocolDef::new("HCI_ACL", 32)
                .with_fields(vec![
                    FieldDef::new("handle_flags", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("dlen", 16, 16, FieldType::Uint).with_endian(Endian::Little),
                ]),
        ),
        // ── L2CAP (32 bits, child of HCI_ACL, dispatch on cid) ──
        "L2CAP" => Some(
            ProtocolDef::new("L2CAP", 32)
                .with_fields(vec![
                    FieldDef::new("len", 0, 16, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("cid", 16, 16, FieldType::Enum).with_endian(Endian::Little)
                        .with_dispatch(),
                ])
                .with_dispatch_field("cid"),
        ),
        // ── InfiniBand: LRH (64 bits, root DLT=247, dispatch on lnh) ──
        "IB_LRH" => Some(
            ProtocolDef::new("IB_LRH", 64)
                .with_fields(vec![
                    FieldDef::new("vl", 0, 4, FieldType::Uint),
                    FieldDef::new("lver", 4, 4, FieldType::Uint),
                    FieldDef::new("sl", 8, 4, FieldType::Uint),
                    FieldDef::new("reserved", 12, 2, FieldType::Pad),
                    FieldDef::new("lnh", 14, 2, FieldType::Enum).with_dispatch(),
                    FieldDef::new("dlid", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("pktlen_raw", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("slid", 48, 16, FieldType::Uint).with_endian(Endian::Big),
                ])
                .with_dispatch_field("lnh"),
        ),
        // ── InfiniBand: GRH (320 bits, similar to IPv6) ──
        "IB_GRH" => Some(
            ProtocolDef::new("IB_GRH", 320)
                .with_fields(vec![
                    FieldDef::new("ip_version", 0, 4, FieldType::Uint).with_default_value("6"),
                    FieldDef::new("traffic_class", 4, 8, FieldType::Uint),
                    FieldDef::new("flow_label", 12, 20, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("payload_length", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("next_header", 48, 8, FieldType::Uint),
                    FieldDef::new("hop_limit", 56, 8, FieldType::Uint).with_default_value("64"),
                    FieldDef::new("sgid", 64, 128, FieldType::Ipv6Addr)
                        .with_endian(Endian::Big),
                    FieldDef::new("dgid", 192, 128, FieldType::Ipv6Addr)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── InfiniBand: BTH (96 bits, dispatch on opcode) ──
        "IB_BTH" => Some(
            ProtocolDef::new("IB_BTH", 96)
                .with_fields(vec![
                    FieldDef::new("opcode", 0, 8, FieldType::Enum).with_dispatch(),
                    FieldDef::new("se_m_flags", 8, 8, FieldType::Uint),
                    FieldDef::new("pkey", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("dest_qp", 32, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("ack_psn", 64, 32, FieldType::Uint).with_endian(Endian::Big),
                ])
                .with_dispatch_field("opcode"),
        ),
        // ── CAN (128 bits, root DLT=227) ──
        "CAN" => Some(
            ProtocolDef::new("CAN", 128)
                .with_fields(vec![
                    FieldDef::new("can_id", 0, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("len", 32, 8, FieldType::Uint),
                    FieldDef::new("pad", 40, 8, FieldType::Pad),
                    FieldDef::new("res", 48, 16, FieldType::Pad),
                    FieldDef::new("data", 64, 64, FieldType::Bytes),
                ]),
        ),
        // ── CAN FD (576 bits, root DLT=227) ──
        "CAN_FD" => Some(
            ProtocolDef::new("CAN_FD", 576)
                .with_fields(vec![
                    FieldDef::new("can_id", 0, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("len", 32, 8, FieldType::Uint),
                    FieldDef::new("flags", 40, 8, FieldType::Uint),
                    FieldDef::new("res", 48, 16, FieldType::Pad),
                    FieldDef::new("data", 64, 512, FieldType::Bytes),
                ]),
        ),
        // ── CAN XL (128 bits min, root DLT=227) ──
        "CAN_XL" => Some(
            ProtocolDef::new("CAN_XL", 128)
                .with_fields(vec![
                    FieldDef::new("priority", 0, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("flags", 32, 8, FieldType::Uint),
                    FieldDef::new("sdu_type", 40, 8, FieldType::Uint),
                    FieldDef::new("len", 48, 16, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("af", 64, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("reserved", 96, 32, FieldType::Pad),
                ]),
        ),
        // ── IEEE 802.11 (192 bits, root DLT=105) ──
        "IEEE802.11" => Some(
            ProtocolDef::new("IEEE802.11", 192)
                .with_fields(vec![
                    FieldDef::new("frame_control", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("duration", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("addr1", 32, 48, FieldType::MacAddr).with_endian(Endian::Big),
                    FieldDef::new("addr2", 80, 48, FieldType::MacAddr).with_endian(Endian::Big),
                    FieldDef::new("addr3", 128, 48, FieldType::MacAddr).with_endian(Endian::Big),
                    FieldDef::new("seq_ctrl", 176, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                ]),
        ),
        // ── IEEE 802.15.4 (24 bits min, root DLT=195) ──
        "IEEE802154" => Some(
            ProtocolDef::new("IEEE802154", 24)
                .with_fields(vec![
                    FieldDef::new("frame_control", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("seq_num", 16, 8, FieldType::Uint),
                ]),
        ),
        // ── Linux SLL (128 bits, root DLT=113) ──
        "SLL" => Some(
            ProtocolDef::new("SLL", 128)
                .with_fields(vec![
                    FieldDef::new("pkttype", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("hatype", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("halen", 32, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("addr", 48, 64, FieldType::Bytes),
                    FieldDef::new("protocol", 112, 16, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── Linux SLL2 (160 bits, root DLT=276) ──
        "SLL2" => Some(
            ProtocolDef::new("SLL2", 160)
                .with_fields(vec![
                    FieldDef::new("protocol", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("reserved", 16, 16, FieldType::Pad),
                    FieldDef::new("ifindex", 32, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("hatype", 64, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("pkttype", 80, 8, FieldType::Uint),
                    FieldDef::new("halen", 88, 8, FieldType::Uint),
                    FieldDef::new("addr", 96, 64, FieldType::Bytes),
                ]),
        ),
        // ── Netlink (160 bits = 20 bytes, root DLT=253) ──
        // DLT_NETLINK requires a 4-byte pseudo-header: family(u16 LE) + pad(u16)
        // followed by the 16-byte nlmsghdr.
        // NOTE: pack_field always uses BE byte order, so LE values must be
        // pre-swapped: nlmsg_len=16 LE → bytes 10 00 00 00 → BE 0x10000000.
        "Netlink" => Some(
            ProtocolDef::new("Netlink", 160)
                .with_fields(vec![
                    // Pseudo-header: Netlink family (0 = NETLINK_ROUTE)
                    FieldDef::new("nl_family", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("nl_pad", 16, 16, FieldType::Pad),
                    // nlmsghdr starts at byte 4
                    // nlmsg_len=16 in LE = 0x10000000 in BE
                    FieldDef::new("nlmsg_len", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Little)
                        .with_default_value("268435456"),
                    // type=3 (NLMSG_DONE) in LE = 0x0300 in BE
                    FieldDef::new("type", 64, 16, FieldType::Uint)
                        .with_endian(Endian::Little)
                        .with_default_value("768"), // 3 LE = 0x0300 BE
                    FieldDef::new("flags", 80, 16, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("seq", 96, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("pid", 128, 32, FieldType::Uint).with_endian(Endian::Little),
                ]),
        ),
        // ── GenNetlink (32 bits, child of Netlink) ──
        "GenNetlink" => Some(
            ProtocolDef::new("GenNetlink", 32)
                .with_fields(vec![
                    FieldDef::new("cmd", 0, 8, FieldType::Uint),
                    FieldDef::new("version", 8, 8, FieldType::Uint).with_default_value("1"),
                    FieldDef::new("reserved", 16, 16, FieldType::Pad),
                ]),
        ),
        // ── PPP (32 bits, root DLT=9) ──
        "PPP" => Some(
            ProtocolDef::new("PPP", 32)
                .with_fields(vec![
                    FieldDef::new("address", 0, 8, FieldType::Uint).with_default_value("255"),
                    FieldDef::new("control", 8, 8, FieldType::Uint).with_default_value("3"),
                    FieldDef::new("protocol", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── ATM AAL5 (64 bits min, root DLT=11) ──
        "ATM" => Some(
            ProtocolDef::new("ATM", 64)
                .with_fields(vec![
                    FieldDef::new("llc_dsap", 0, 8, FieldType::Uint)
                        .with_default_value("170"),
                    FieldDef::new("llc_ssap", 8, 8, FieldType::Uint)
                        .with_default_value("170"),
                    FieldDef::new("llc_control", 16, 8, FieldType::Uint)
                        .with_default_value("3"),
                    FieldDef::new("snap_oui", 24, 24, FieldType::Uint),
                    FieldDef::new("snap_type", 48, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── Fibre Channel (192 bits, root DLT=224) ──
        "FC" => Some(
            ProtocolDef::new("FC", 192)
                .with_fields(vec![
                    FieldDef::new("r_ctl", 0, 8, FieldType::Uint),
                    FieldDef::new("d_id", 8, 24, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("cs_ctl", 32, 8, FieldType::Uint),
                    FieldDef::new("s_id", 40, 24, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("type", 64, 8, FieldType::Uint),
                    FieldDef::new("f_ctl", 72, 24, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("seq_id", 96, 8, FieldType::Uint),
                    FieldDef::new("df_ctl", 104, 8, FieldType::Uint),
                    FieldDef::new("seq_cnt", 112, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("ox_id", 128, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("rx_id", 144, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("parameter", 160, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── ERF (128 bits, root DLT=197) ──
        "ERF" => Some(
            ProtocolDef::new("ERF", 128)
                .with_fields(vec![
                    FieldDef::new("timestamp", 0, 64, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("type", 64, 8, FieldType::Uint),
                    FieldDef::new("flags", 72, 8, FieldType::Uint),
                    FieldDef::new("rlen", 80, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("color", 96, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("wlen", 112, 16, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── MPEG-TS (1504 bits = 188 bytes, root DLT=243) ──
        "MPEG_TS" => Some(
            ProtocolDef::new("MPEG_TS", 1504)
                .with_fields(vec![
                    FieldDef::new("sync", 0, 8, FieldType::Uint).with_default_value("71"), // 0x47
                    FieldDef::new("pid_raw", 8, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("flags_cc", 24, 8, FieldType::Uint)
                        .with_default_value("16"), // no adaptation, payload only (0x10)
                ]),
        ),
        // ── Zigbee NWK (64 bits, child of IEEE802154) ──
        "Zigbee_NWK" => Some(
            ProtocolDef::new("Zigbee_NWK", 64)
                .with_fields(vec![
                    FieldDef::new("frame_control", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("dst_addr", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("src_addr", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("radius", 48, 8, FieldType::Uint).with_default_value("1"),
                    FieldDef::new("seq_num", 56, 8, FieldType::Uint),
                ]),
        ),
        // ── Ethernet 802.3 (112 bits, same as Ethernet but with length field) ──
        "Ethernet_802_3" => Some(
            ProtocolDef::new("Ethernet_802_3", 112)
                .with_fields(vec![
                    FieldDef::new("dst_mac", 0, 48, FieldType::MacAddr).with_endian(Endian::Big),
                    FieldDef::new("src_mac", 48, 48, FieldType::MacAddr).with_endian(Endian::Big),
                    FieldDef::new("length", 96, 16, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── LLC (24 bits, child of Ethernet_802_3, dispatch on dsap) ──
        "LLC" => Some(
            ProtocolDef::new("LLC", 24)
                .with_fields(vec![
                    FieldDef::new("dsap", 0, 8, FieldType::Enum).with_dispatch(),
                    FieldDef::new("ssap", 8, 8, FieldType::Uint),
                    FieldDef::new("control", 16, 8, FieldType::Uint).with_default_value("3"),
                ])
                .with_dispatch_field("dsap"),
        ),
        // ── SNAP (40 bits, child of LLC dsap=0xAA, dispatch on protocol_id) ──
        "SNAP" => Some(
            ProtocolDef::new("SNAP", 40)
                .with_fields(vec![
                    FieldDef::new("oui", 0, 24, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("protocol_id", 24, 16, FieldType::Enum)
                        .with_endian(Endian::Big)
                        .with_dispatch(),
                ])
                .with_dispatch_field("protocol_id"),
        ),
        // ── LLDP (mandatory TLV: chassis ID type=1, length=7, subtype=4, 4-byte value) ──
        "LLDP" => Some(
            ProtocolDef::new("LLDP", 72)
                .with_fields(vec![
                    // TLV type=1 (Chassis ID), length=5
                    FieldDef::new("tlv_type_len", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("514"), // (1 << 9) | 5 = 0x0205
                    FieldDef::new("chassis_subtype", 16, 8, FieldType::Uint)
                        .with_default_value("4"), // MAC address subtype
                    FieldDef::new("chassis_id", 24, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("33554433"), // 02:00:00:01
                    // End of LLDPDU TLV (type=0, length=0)
                    FieldDef::new("end_tlv", 56, 16, FieldType::Uint),
                ]),
        ),
        // ── CFM (Connectivity Fault Management, 802.1ag) ──
        "CFM" => Some(
            ProtocolDef::new("CFM", 32)
                .with_fields(vec![
                    // MD level (3 bits) + version (5 bits)
                    FieldDef::new("md_level_version", 0, 8, FieldType::Uint)
                        .with_default_value("0"), // MD level 0, version 0
                    FieldDef::new("opcode", 8, 8, FieldType::Uint)
                        .with_default_value("1"), // CCM
                    FieldDef::new("flags", 16, 8, FieldType::Uint)
                        .with_default_value("4"), // interval=4 (1s)
                    FieldDef::new("first_tlv_offset", 24, 8, FieldType::Uint)
                        .with_default_value("70"), // standard CCM first TLV offset
                ]),
        ),
        // ── BATMAN (B.A.T.M.A.N. Advanced OGM v2, 192 bits = 24 bytes) ──
        "BATMAN" => Some(
            ProtocolDef::new("BATMAN", 192)
                .with_fields(vec![
                    FieldDef::new("packet_type", 0, 8, FieldType::Uint)
                        .with_default_value("1"), // BATADV_OGM2
                    FieldDef::new("version", 8, 8, FieldType::Uint)
                        .with_default_value("15"),
                    FieldDef::new("ttl", 16, 8, FieldType::Uint)
                        .with_default_value("50"),
                    FieldDef::new("flags", 24, 8, FieldType::Uint),
                    FieldDef::new("seqno", 32, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("orig", 64, 48, FieldType::MacAddr).with_endian(Endian::Big),
                    FieldDef::new("tvlv_len", 112, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("throughput", 128, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("reserved", 160, 32, FieldType::Pad),
                ]),
        ),
        // ── TRILL ──
        "TRILL" => Some(
            ProtocolDef::new("TRILL", 48)
                .with_fields(vec![
                    // V(2)=0, R(2)=0, M(1)=0, Op-Length(5)=0, Hop Count(6)
                    FieldDef::new("flags_hopcount", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("63"), // hop count=63
                    FieldDef::new("egress_nick", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"),
                    FieldDef::new("ingress_nick", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("2"),
                ]),
        ),
        // ── WOL (Wake-on-LAN: 6x FF sync + 16x target MAC = 102 bytes = 816 bits) ──
        // tshark "wol" dissector needs: 6 bytes 0xFF + 16 copies of same MAC.
        // With MAC=00:00:00:00:00:00, the 96 zero bytes satisfy the repeat check.
        "WOL" => Some(
            ProtocolDef::new("WOL", 816)
                .with_fields(vec![
                    FieldDef::new("sync", 0, 48, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("281474976710655"), // 0xFFFFFFFFFFFF
                ]),
        ),
        // ── PBB (Provider Backbone Bridging I-TAG, 32 bits) ──
        "PBB" => Some(
            ProtocolDef::new("PBB", 32)
                .with_fields(vec![
                    FieldDef::new("flags", 0, 8, FieldType::Uint),
                    FieldDef::new("isid", 8, 24, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"),
                ]),
        ),
        // ── MVRP (MRP-based VLAN Registration Protocol) ──
        "MVRP" => Some(
            ProtocolDef::new("MVRP", 16)
                .with_fields(vec![
                    FieldDef::new("protocol_version", 0, 8, FieldType::Uint),
                    FieldDef::new("message_type", 8, 8, FieldType::Uint)
                        .with_default_value("1"),
                ]),
        ),
        // ── NC-SI (Network Controller Sideband Interface) ──
        "NC_SI" => Some(
            ProtocolDef::new("NC_SI", 128)
                .with_fields(vec![
                    FieldDef::new("mc_id", 0, 8, FieldType::Uint),
                    FieldDef::new("header_revision", 8, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("reserved", 16, 8, FieldType::Pad),
                    FieldDef::new("iid", 24, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("command", 32, 8, FieldType::Uint)
                        .with_default_value("1"), // Clear Initial State
                    FieldDef::new("channel_id", 40, 8, FieldType::Uint),
                    FieldDef::new("payload_length", 48, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("reserved2", 64, 32, FieldType::Pad),
                    FieldDef::new("reserved3", 96, 32, FieldType::Pad),
                ]),
        ),
        // ── LLTD (Link Layer Topology Discovery, 14 bytes min) ──
        "LLTD" => Some(
            ProtocolDef::new("LLTD", 112)
                .with_variable_length()
                .with_fields(vec![
                    FieldDef::new("version", 0, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("type_of_service", 8, 8, FieldType::Uint),
                    FieldDef::new("reserved", 16, 8, FieldType::Pad),
                    FieldDef::new("function", 24, 8, FieldType::Uint),
                    FieldDef::new("real_dst_mac", 32, 48, FieldType::MacAddr)
                        .with_endian(Endian::Big),
                    FieldDef::new("real_src_mac", 80, 48, FieldType::MacAddr)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── EDSA (Marvell EtherType DSA tag) ──
        "EDSA" => Some(
            ProtocolDef::new("EDSA", 64)
                .with_fields(vec![
                    FieldDef::new("tag_hi", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("tag_lo", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("ether_type", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("2048"), // 0x0800 = IPv4
                ]),
        ),
        // ── IEC GOOSE (minimal valid BER-encoded GOOSE PDU) ──
        "IEC_GOOSE" => Some(
            ProtocolDef::new("IEC_GOOSE", 48)
                .with_fields(vec![
                    FieldDef::new("appid", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"),
                    FieldDef::new("length", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("8"),
                    FieldDef::new("reserved1", 32, 8, FieldType::Pad),
                    FieldDef::new("reserved2", 40, 8, FieldType::Pad),
                ]),
        ),
        // ── IEC SV (Sampled Values) ──
        "IEC_SV" => Some(
            ProtocolDef::new("IEC_SV", 48)
                .with_fields(vec![
                    FieldDef::new("appid", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("16384"), // 0x4000
                    FieldDef::new("length", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("8"),
                    FieldDef::new("reserved1", 32, 8, FieldType::Pad),
                    FieldDef::new("reserved2", 40, 8, FieldType::Pad),
                ]),
        ),
        // ── CAPWAP (Control And Provisioning of Wireless APs) ──
        "CAPWAP" => Some(
            ProtocolDef::new("CAPWAP", 32)
                .with_fields(vec![
                    // Preamble: version(4)=0, type(4)=0
                    FieldDef::new("preamble", 0, 8, FieldType::Uint),
                    // HLEN(5)=2, RID(5)=0, WBID(5)=1, T(1), F(1), L(1)
                    FieldDef::new("header_flags", 8, 24, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("4194304"), // HLEN=2, WBID=1 -> 0x400000
                ]),
        ),
        // ── TZSP (TaZmen Sniffer Protocol) ──
        "TZSP" => Some(
            ProtocolDef::new("TZSP", 32)
                .with_fields(vec![
                    FieldDef::new("version", 0, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("type", 8, 8, FieldType::Uint),
                    FieldDef::new("encap", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"), // Ethernet
                ]),
        ),
        // ── SRT (Secure Reliable Transport) ──
        "SRT" => Some(
            ProtocolDef::new("SRT", 128)
                .with_fields(vec![
                    // UDT/SRT header: control bit + type + subtype
                    FieldDef::new("header", 0, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("2147483648"), // 0x80000000 = control packet
                    FieldDef::new("additional_info", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("timestamp", 64, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("dst_socket_id", 96, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── GUE (Generic UDP Encapsulation) ──
        "GUE" => Some(
            ProtocolDef::new("GUE", 32)
                .with_fields(vec![
                    // Version(2)=0, C(1)=0, Hlen(5)=0, Proto/CT
                    FieldDef::new("flags_proto", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("4"), // proto=IPv4 (4)
                    FieldDef::new("flags2", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── STT (Stateless Transport Tunneling) ──
        "STT" => Some(
            ProtocolDef::new("STT", 144)
                .with_fields(vec![
                    FieldDef::new("version", 0, 8, FieldType::Uint),
                    FieldDef::new("flags", 8, 8, FieldType::Uint),
                    FieldDef::new("l4_offset", 16, 8, FieldType::Uint)
                        .with_default_value("14"),
                    FieldDef::new("reserved", 24, 8, FieldType::Pad),
                    FieldDef::new("max_seg_size", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("pcp_dei_vid", 48, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("context_id", 64, 64, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("padding", 128, 16, FieldType::Pad),
                ]),
        ),
        // ── BT_RFCOMM (RFCOMM frame: address + control + length + FCS) ──
        "BT_RFCOMM" => Some(
            ProtocolDef::new("BT_RFCOMM", 32)
                .with_fields(vec![
                    FieldDef::new("address", 0, 8, FieldType::Uint)
                        .with_default_value("3"), // DLCI=0, EA=1, CR=1
                    FieldDef::new("control", 8, 8, FieldType::Uint)
                        .with_default_value("63"), // SABM (0x3F)
                    FieldDef::new("length", 16, 8, FieldType::Uint)
                        .with_default_value("1"), // length=0, EA=1
                    FieldDef::new("fcs", 24, 8, FieldType::Uint)
                        .with_default_value("29"), // FCS for DLCI=0 SABM
                ]),
        ),
        // ── BT_BNEP (Bluetooth Network Encapsulation Protocol) ──
        "BT_BNEP" => Some(
            ProtocolDef::new("BT_BNEP", 16)
                .with_fields(vec![
                    // Type(7) + extension(1): type=0 (General Ethernet)
                    FieldDef::new("type_ext", 0, 8, FieldType::Uint),
                    FieldDef::new("reserved", 8, 8, FieldType::Pad),
                ]),
        ),
        // ── BT_SDP (Service Discovery Protocol) ──
        "BT_SDP" => Some(
            ProtocolDef::new("BT_SDP", 40)
                .with_fields(vec![
                    FieldDef::new("pdu_id", 0, 8, FieldType::Uint)
                        .with_default_value("1"), // SDP_ErrorResponse
                    FieldDef::new("transaction_id", 8, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("param_length", 24, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── BT_AVDTP (Audio/Video Distribution Transport Protocol) ──
        "BT_AVDTP" => Some(
            ProtocolDef::new("BT_AVDTP", 16)
                .with_fields(vec![
                    // Transaction label(4) + Packet type(2) + Message type(2)
                    FieldDef::new("header", 0, 8, FieldType::Uint)
                        .with_default_value("48"), // trans=0, single=3, command=0
                    FieldDef::new("signal_id", 8, 8, FieldType::Uint)
                        .with_default_value("1"), // AVDTP_DISCOVER
                ]),
        ),
        // ── NTLMSSP (NT LAN Manager Security Support Provider) ──
        "NTLMSSP" => Some(
            ProtocolDef::new("NTLMSSP", 96)
                .with_fields(vec![
                    // Signature: "NTLMSSP\0" = 4E544C4D53535000
                    FieldDef::new("signature_lo", 0, 32, FieldType::Uint)
                        .with_endian(Endian::Little)
                        .with_default_value("1296847950"), // "NTLM" LE = 0x4D4C544E
                    FieldDef::new("signature_hi", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Little)
                        .with_default_value("5264211"), // "SSP\0" LE = 0x00505353
                    FieldDef::new("message_type", 64, 32, FieldType::Uint)
                        .with_endian(Endian::Little)
                        .with_default_value("1"), // Negotiate
                ]),
        ),
        // ── MCTP (Management Component Transport Protocol) ──
        "MCTP" => Some(
            ProtocolDef::new("MCTP", 32)
                .with_fields(vec![
                    FieldDef::new("version", 0, 4, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("reserved", 4, 4, FieldType::Pad),
                    FieldDef::new("dest_eid", 8, 8, FieldType::Uint),
                    FieldDef::new("src_eid", 16, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("flags_seq_tag", 24, 8, FieldType::Uint)
                        .with_default_value("200"), // SOM=1, EOM=1, seq=0, TO=0, tag=8
                ]),
        ),
        // ── X25 (X.25 Packet Layer Protocol) ──
        "X25" => Some(
            ProtocolDef::new("X25", 24)
                .with_fields(vec![
                    FieldDef::new("gfi_lcg", 0, 8, FieldType::Uint)
                        .with_default_value("16"), // GFI=0001 (modulo 8), LCG=0
                    FieldDef::new("lcn", 8, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("type", 16, 8, FieldType::Uint)
                        .with_default_value("11"), // Call Request (0x0B)
                ]),
        ),
        // ── DSA (Distributed Switch Architecture tag) ──
        "DSA" => Some(
            ProtocolDef::new("DSA", 32)
                .with_fields(vec![
                    FieldDef::new("tag_hi", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("tag_lo", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── Teredo (IPv6 over UDP tunneling, RFC 4380) ──
        // Minimum: an encapsulated IPv6 header (version=6 in first nibble)
        "Teredo" => Some(
            ProtocolDef::new("Teredo", 320) // 40-byte IPv6 header
                .with_fields(vec![
                    FieldDef::new("version", 0, 4, FieldType::Uint)
                        .with_default_value("6"), // IPv6
                    FieldDef::new("traffic_class", 4, 8, FieldType::Uint),
                    FieldDef::new("flow_label", 12, 20, FieldType::Uint),
                    FieldDef::new("payload_length", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("next_header", 48, 8, FieldType::Uint)
                        .with_default_value("59"), // No Next Header
                    FieldDef::new("hop_limit", 56, 8, FieldType::Uint)
                        .with_default_value("64"),
                    // src: 2001:0000:... (Teredo prefix)
                    FieldDef::new("src_addr_hi", 64, 64, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("2306124484190404608"), // 0x20010000_00000000
                    FieldDef::new("src_addr_lo", 128, 64, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("dst_addr_hi", 192, 64, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("2306124484190404608"),
                    FieldDef::new("dst_addr_lo", 256, 64, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"),
                ]),
        ),
        // ── LWAPP (Lightweight Access Point Protocol) ──
        "LWAPP" => Some(
            ProtocolDef::new("LWAPP", 48) // 6-byte LWAPP header
                .with_fields(vec![
                    // Flags: version(2)=0, RID(3)=0, C(1)=1 (control), F(1)=0, L(1)=0
                    FieldDef::new("flags", 0, 8, FieldType::Uint)
                        .with_default_value("4"), // C bit = control message
                    FieldDef::new("fragment_id", 8, 8, FieldType::Uint),
                    FieldDef::new("length", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("status", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── MPLS_OAM (MPLS Echo / LSP Ping, RFC 4379) ──
        "MPLS_OAM" => Some(
            ProtocolDef::new("MPLS_OAM", 256) // 32-byte minimum MPLS echo
                .with_fields(vec![
                    FieldDef::new("version", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"),
                    // msg_type: 1=request, 2=reply
                    FieldDef::new("msg_type", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"), // Echo Request
                    FieldDef::new("reply_mode", 32, 8, FieldType::Uint)
                        .with_default_value("2"), // Reply via IPv4
                    FieldDef::new("return_code", 40, 8, FieldType::Uint),
                    FieldDef::new("return_subcode", 48, 8, FieldType::Uint),
                    FieldDef::new("sender_handle", 56, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("seq_number", 88, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"),
                    // Timestamps: sender (64 bits) + receiver (64 bits)
                    FieldDef::new("ts_sent_sec", 120, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("ts_sent_usec", 152, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("ts_recv_sec", 184, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("ts_recv_usec", 216, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── TPLINK_SMARTHOME (TP-Link Smart Home JSON) ──
        // tshark expects a 4-byte length prefix then XOR-encrypted JSON
        "TPLINK_SMARTHOME" => Some(
            ProtocolDef::new("TPLINK_SMARTHOME", 64) // 4-byte len + 4 bytes data
                .with_fields(vec![
                    FieldDef::new("length", 0, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("4"), // 4 bytes of encrypted data follow
                    // XOR-encrypted JSON payload (first byte XOR'd with 0xAB)
                    FieldDef::new("data", 32, 32, FieldType::Bytes),
                ]),
        ),
        // ── NFS (via ONC-RPC header, RPC program=100003) ──
        "NFS" => Some(
            ProtocolDef::new("NFS", 320) // 40-byte RPC Call header
                .with_fields(vec![
                    FieldDef::new("xid", 0, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"),
                    FieldDef::new("msg_type", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Big), // 0=Call
                    FieldDef::new("rpc_version", 64, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("2"),
                    FieldDef::new("program", 96, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("100003"), // NFS
                    FieldDef::new("program_version", 128, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("3"), // NFSv3
                    FieldDef::new("procedure", 160, 32, FieldType::Uint)
                        .with_endian(Endian::Big), // NULL procedure
                    FieldDef::new("cred_flavor", 192, 32, FieldType::Uint)
                        .with_endian(Endian::Big), // AUTH_NULL
                    FieldDef::new("cred_length", 224, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("verf_flavor", 256, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("verf_length", 288, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── AMQP (Advanced Message Queuing Protocol) ──
        // AMQP 0-9-1 protocol header: "AMQP" + 0x00 + major.minor.revision
        "AMQP" => Some(
            ProtocolDef::new("AMQP", 64)
                .with_fields(vec![
                    FieldDef::new("signature", 0, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1095586645"), // "AMQP" = 0x414D5150
                    FieldDef::new("proto_id", 32, 8, FieldType::Uint), // 0 for AMQP
                    FieldDef::new("major", 40, 8, FieldType::Uint)
                        .with_default_value("0"),
                    FieldDef::new("minor", 48, 8, FieldType::Uint)
                        .with_default_value("9"),
                    FieldDef::new("revision", 56, 8, FieldType::Uint)
                        .with_default_value("1"),
                ]),
        ),
        // ── SMTP: text protocol, needs banner line ──
        // SMTP needs "220 " server greeting to trigger dissector
        "SMTP" => Some(
            ProtocolDef::new("SMTP", 96) // "220 srv\r\n" = 12 bytes (96 bits)
                .with_fields(vec![
                    // "220 " = 0x32323020
                    FieldDef::new("greeting_code", 0, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("842014752"), // "220 "
                    // "srv\r" = 0x7372760D
                    FieldDef::new("greeting_host", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1936941837"), // "srv\r"
                    // "\nOK\n" or just pad
                    FieldDef::new("greeting_end", 64, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("178257930"), // "\nOK\n" = 0x0A4F4B0A
                ]),
        ),
        // ── OCSP (Online Certificate Status Protocol) ──
        // Minimal DER: SEQUENCE { SEQUENCE { SEQUENCE { ... } } }
        // OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest }
        // TBSRequest ::= SEQUENCE { requestList SEQUENCE OF Request }
        "OCSP" => Some(
            ProtocolDef::new("OCSP", 80) // 10 bytes minimal DER
                .with_fields(vec![
                    // SEQUENCE tag + length (outer OCSPRequest)
                    FieldDef::new("seq_tag", 0, 8, FieldType::Uint)
                        .with_default_value("48"), // 0x30 = SEQUENCE
                    FieldDef::new("seq_len", 8, 8, FieldType::Uint)
                        .with_default_value("8"),
                    // Inner SEQUENCE (TBSRequest)
                    FieldDef::new("tbs_tag", 16, 8, FieldType::Uint)
                        .with_default_value("48"), // 0x30
                    FieldDef::new("tbs_len", 24, 8, FieldType::Uint)
                        .with_default_value("6"),
                    // requestList SEQUENCE OF
                    FieldDef::new("reqlist_tag", 32, 8, FieldType::Uint)
                        .with_default_value("48"), // 0x30
                    FieldDef::new("reqlist_len", 40, 8, FieldType::Uint)
                        .with_default_value("4"),
                    // Single Request: SEQUENCE { reqCert CertID }
                    FieldDef::new("req_tag", 48, 8, FieldType::Uint)
                        .with_default_value("48"), // 0x30
                    FieldDef::new("req_len", 56, 8, FieldType::Uint)
                        .with_default_value("2"),
                    // CertID: SEQUENCE {}
                    FieldDef::new("certid_tag", 64, 8, FieldType::Uint)
                        .with_default_value("48"), // 0x30
                    FieldDef::new("certid_len", 72, 8, FieldType::Uint)
                        .with_default_value("0"),
                ]),
        ),
        // ── UpperPDU (virtual, 0 bits, root DLT=252) ──
        "UpperPDU" => Some(ProtocolDef::new("UpperPDU", 0)),
        _ => None,
    }
}

/// Serialize one protocol header to bytes.
pub fn serialize_header(proto: &ProtocolDef, overrides: &BTreeMap<String, u64>) -> Vec<u8> {
    let byte_len = (proto.min_header_bits + 7) / 8;
    let mut buf = vec![0u8; byte_len as usize];

    for field in &proto.fields {
        if field.offset_bits + field.size_bits > proto.min_header_bits {
            continue; // skip fields beyond minimum header
        }
        let value = select_field_value(field, overrides);
        pack_field(&mut buf, field, value);
    }

    buf
}

/// Choose a value for a field: override > default_value > type-based default > 0.
fn select_field_value(field: &FieldDef, overrides: &BTreeMap<String, u64>) -> u64 {
    // Check overrides (match by field name or any source name)
    if let Some(&val) = overrides.get(&field.name) {
        return val;
    }
    for src_name in field.source_names.values() {
        if let Some(&val) = overrides.get(src_name) {
            return val;
        }
    }

    // Check default_value
    if let Some(ref dv) = field.default_value {
        if let Some(val) = parse_int_value(dv) {
            return val;
        }
    }

    // Type-based defaults
    match field.field_type {
        FieldType::Ipv4Addr => {
            let name_lower = field.name.to_lowercase();
            if name_lower.contains("src") || name_lower.contains("source") {
                // 10.0.0.1
                return u64::from(u32::from_be_bytes([10, 0, 0, 1]));
            }
            // 10.0.0.2
            u64::from(u32::from_be_bytes([10, 0, 0, 2]))
        }
        FieldType::Ipv6Addr => {
            // We handle IPv6 specially in pack_field since it's 128 bits
            // Return 0 here; pack_field will use embedded addresses
            0
        }
        FieldType::MacAddr => {
            let name_lower = field.name.to_lowercase();
            if name_lower.contains("src") || name_lower.contains("source") {
                // 02:00:00:00:00:01
                return 0x020000000001;
            }
            // 02:00:00:00:00:02
            0x020000000002
        }
        FieldType::Uint if field.is_length => {
            // Compute from min_header_bits if multiplier is set
            if let Some(mult) = field.length_multiplier {
                if mult > 0 {
                    return (field.offset_bits + field.size_bits) as u64 / 8 / mult as u64;
                }
            }
            0
        }
        FieldType::Flags | FieldType::Pad => 0,
        _ => 0,
    }
}

/// Parse an integer from a string (supports decimal, 0x hex, 0b binary).
fn parse_int_value(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if let Some(bin) = s.strip_prefix("0b") {
        u64::from_str_radix(bin, 2).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// Pack a single field value into a byte buffer at the correct bit offset.
/// Network order: MSB-first within each byte.
pub fn pack_field(buf: &mut [u8], field: &FieldDef, value: u64) {
    let offset = field.offset_bits as usize;
    let size = field.size_bits as usize;

    if size == 0 || offset + size > buf.len() * 8 {
        return;
    }

    // Special handling for IPv6 addresses (128 bits)
    if field.field_type == FieldType::Ipv6Addr && size == 128 {
        pack_ipv6_addr(buf, offset, field);
        return;
    }

    // Special handling for MAC addresses (48 bits)
    if field.field_type == FieldType::MacAddr && size == 48 {
        let bytes = value.to_be_bytes();
        let start_byte = offset / 8;
        // MAC is in the lower 6 bytes of u64
        buf[start_byte..start_byte + 6].copy_from_slice(&bytes[2..8]);
        return;
    }

    // Byte-aligned fast path
    if offset % 8 == 0 && size % 8 == 0 {
        let start_byte = offset / 8;
        let num_bytes = size / 8;
        if num_bytes <= 8 {
            let be_bytes = value.to_be_bytes();
            let src_start = 8 - num_bytes;
            buf[start_byte..start_byte + num_bytes].copy_from_slice(&be_bytes[src_start..]);
        } else {
            // Large field (>64 bits): zero-fill, write low 8 bytes at the end
            let end = start_byte + num_bytes;
            let buf_len = buf.len();
            let clamped_end = end.min(buf_len);
            for i in start_byte..clamped_end {
                buf[i] = 0;
            }
            let be_bytes = value.to_be_bytes();
            let write_start = end.saturating_sub(8);
            if write_start < clamped_end {
                let copy_len = clamped_end - write_start;
                let src_start = 8 - copy_len;
                buf[write_start..clamped_end].copy_from_slice(&be_bytes[src_start..src_start + copy_len]);
            }
        }
        return;
    }

    // Bitfield path: pack MSB-first
    for i in 0..size {
        let bit_val = (value >> (size - 1 - i)) & 1;
        let target_bit = offset + i;
        let byte_idx = target_bit / 8;
        let bit_in_byte = 7 - (target_bit % 8); // MSB-first
        if bit_val == 1 {
            buf[byte_idx] |= 1 << bit_in_byte;
        }
    }
}

/// Pack an IPv6 address into the buffer. Uses fd00::1 for src, fd00::2 for dst.
fn pack_ipv6_addr(buf: &mut [u8], offset: usize, field: &FieldDef) {
    let start_byte = offset / 8;
    let name_lower = field.name.to_lowercase();
    let addr: [u8; 16] = if name_lower.contains("src") || name_lower.contains("source") {
        // fd00::1
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    } else {
        // fd00::2
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
    };
    buf[start_byte..start_byte + 16].copy_from_slice(&addr);
}

/// Fixup IPv4 total_length and header checksum after all layers are serialized.
fn fixup_ipv4(packet: &mut [u8], stack: &[StackLayer]) {
    let mut ipv4_offset: Option<usize> = None;
    let mut byte_offset = 0usize;

    for layer in stack {
        if layer.proto_name == "IPv4" {
            ipv4_offset = Some(byte_offset);
        }
        byte_offset += (layer.proto_def.min_header_bits as usize + 7) / 8;
    }

    if let Some(off) = ipv4_offset {
        let total_len = (packet.len() - off) as u16;
        // total_length is at offset 16 bits (2 bytes) from IPv4 header start
        packet[off + 2] = (total_len >> 8) as u8;
        packet[off + 3] = (total_len & 0xFF) as u8;

        // Zero checksum field first (at offset 80 bits = 10 bytes)
        packet[off + 10] = 0;
        packet[off + 11] = 0;

        // Compute and set checksum over 20-byte IPv4 header
        let cksum = ipv4_checksum(&packet[off..off + 20]);
        packet[off + 10] = (cksum >> 8) as u8;
        packet[off + 11] = (cksum & 0xFF) as u8;
    }
}

/// IPv4 header checksum (RFC 791): ones-complement sum of 16-bit words.
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | (header[i + 1] as u32)
        } else {
            (header[i] as u32) << 8
        };
        sum += word;
    }
    // Fold carry
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Fixup IPv6 payload_length after all layers are serialized.
fn fixup_ipv6(packet: &mut [u8], stack: &[StackLayer]) {
    let mut ipv6_offset: Option<usize> = None;
    let mut byte_offset = 0usize;

    for layer in stack {
        if layer.proto_name == "IPv6" {
            ipv6_offset = Some(byte_offset);
        }
        byte_offset += (layer.proto_def.min_header_bits as usize + 7) / 8;
    }

    if let Some(off) = ipv6_offset {
        // payload_length = packet_len - ipv6_offset - 40 (IPv6 header is 40 bytes)
        let payload_len = (packet.len() - off - 40) as u16;
        // payload_length is at offset 32 bits (4 bytes) from IPv6 header start
        packet[off + 4] = (payload_len >> 8) as u8;
        packet[off + 5] = (payload_len & 0xFF) as u8;
    }
}

/// Fixup UDP length field after all layers are serialized.
fn fixup_udp_length(packet: &mut [u8], stack: &[StackLayer]) {
    let mut udp_offset: Option<usize> = None;
    let mut byte_offset = 0usize;

    for layer in stack {
        if layer.proto_name == "UDP" {
            udp_offset = Some(byte_offset);
        }
        byte_offset += (layer.proto_def.min_header_bits as usize + 7) / 8;
    }

    if let Some(off) = udp_offset {
        // UDP length = packet_len - udp_offset (includes UDP header + payload)
        let udp_len = (packet.len() - off) as u16;
        // length field is at offset 32 bits (4 bytes) from UDP header start
        packet[off + 4] = (udp_len >> 8) as u8;
        packet[off + 5] = (udp_len & 0xFF) as u8;
    }
}

/// Fixup 802.3 Ethernet length field (bytes 12-13 = payload length).
fn fixup_802_3_length(packet: &mut [u8], stack: &[StackLayer]) {
    if stack.is_empty() || stack[0].proto_name != "Ethernet_802_3" {
        return;
    }
    if packet.len() > 14 {
        let payload_len = (packet.len() - 14) as u16;
        packet[12] = (payload_len >> 8) as u8;
        packet[13] = (payload_len & 0xFF) as u8;
    }
}

/// PCAP global header: magic, version 2.4, snaplen 65535, parameterized linktype.
fn pcap_global_header(link_type: u32) -> [u8; 24] {
    let mut hdr = [0u8; 24];
    // Magic number (little-endian PCAP)
    hdr[0..4].copy_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    // Version 2.4
    hdr[4..6].copy_from_slice(&2u16.to_le_bytes());
    hdr[6..8].copy_from_slice(&4u16.to_le_bytes());
    // thiszone, sigfigs = 0
    // snaplen = 65535
    hdr[16..20].copy_from_slice(&65535u32.to_le_bytes());
    // linktype
    hdr[20..24].copy_from_slice(&link_type.to_le_bytes());
    hdr
}

/// PCAP record header: timestamp=0, captured_len=original_len=packet_len.
fn pcap_record_header(packet_len: u32) -> [u8; 16] {
    let mut hdr = [0u8; 16];
    // ts_sec, ts_usec = 0
    // incl_len
    hdr[8..12].copy_from_slice(&packet_len.to_le_bytes());
    // orig_len
    hdr[12..16].copy_from_slice(&packet_len.to_le_bytes());
    hdr
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
    let template_dir = std::env::var("PROTO_AUDIT_PCAP_TEMPLATES").ok()?;
    let template_path = std::path::Path::new(&template_dir)
        .join(format!("{}.pcap", target.to_lowercase()));

    if !template_path.exists() {
        return None;
    }

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

pub fn hex_dump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        out.push_str(&format!("{:04x}  ", i * 16));
        for (j, byte) in chunk.iter().enumerate() {
            out.push_str(&format!("{:02x} ", byte));
            if j == 7 {
                out.push(' ');
            }
        }
        // Pad if short line
        if chunk.len() < 16 {
            let pad = (16 - chunk.len()) * 3 + if chunk.len() <= 8 { 1 } else { 0 };
            for _ in 0..pad {
                out.push(' ');
            }
        }
        out.push(' ');
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                out.push(*byte as char);
            } else {
                out.push('.');
            }
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build_protocol_stack with empty discovery state (for tests that
    /// only exercise curated STACK_ROUTES).
    fn build_stack_no_discovery(
        target: &str,
        all_protos: &BTreeMap<String, ProtocolDef>,
    ) -> Result<StackResult, String> {
        let ds = crate::discovery::DiscoveryState {
            tshark: None,
            scapy: None,
            kernel: None,
        };
        let dp = BTreeMap::new();
        build_protocol_stack(target, all_protos, &ds, &dp)
    }

    #[test]
    fn test_pack_field_byte_aligned_u8() {
        let mut buf = [0u8; 4];
        let field = FieldDef::new("ttl", 8, 8, FieldType::Uint);
        pack_field(&mut buf, &field, 64);
        assert_eq!(buf[1], 64);
    }

    #[test]
    fn test_pack_field_byte_aligned_u16() {
        let mut buf = [0u8; 4];
        let field = FieldDef::new("ether_type", 0, 16, FieldType::Enum).with_endian(Endian::Big);
        pack_field(&mut buf, &field, 0x0800);
        assert_eq!(buf[0], 0x08);
        assert_eq!(buf[1], 0x00);
    }

    #[test]
    fn test_pack_field_bitfield_ipv4_ver_ihl() {
        // IPv4 byte 0: version=4 (4 bits), ihl=5 (4 bits) → 0x45
        let mut buf = [0u8; 1];
        let ver = FieldDef::new("version", 0, 4, FieldType::Uint);
        let ihl = FieldDef::new("ihl", 4, 4, FieldType::Uint);
        pack_field(&mut buf, &ver, 4);
        pack_field(&mut buf, &ihl, 5);
        assert_eq!(buf[0], 0x45);
    }

    #[test]
    fn test_pack_field_3bit_flags() {
        // IP flags at offset 48, 3 bits. Value 2 (DF set) → bits: 010
        let mut buf = [0u8; 8];
        let field = FieldDef::new("flags", 48, 3, FieldType::Flags);
        pack_field(&mut buf, &field, 0b010);
        // Byte 6 (offset 48): bits 7..5 = 010, rest 0 → 0x40
        assert_eq!(buf[6], 0x40);
    }

    #[test]
    fn test_pack_field_13bit_frag_offset() {
        // Fragment offset at bit 51, 13 bits. Value 0.
        let mut buf = [0u8; 8];
        let field = FieldDef::new("fragment_offset", 51, 13, FieldType::Uint);
        pack_field(&mut buf, &field, 0);
        assert_eq!(buf[6], 0x00);
        assert_eq!(buf[7], 0x00);
    }

    #[test]
    fn test_pack_field_mac_address() {
        let mut buf = [0u8; 6];
        let field = FieldDef::new("dst_mac", 0, 48, FieldType::MacAddr).with_endian(Endian::Big);
        pack_field(&mut buf, &field, 0x020000000002);
        assert_eq!(buf, [0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    }

    #[test]
    fn test_ipv4_checksum() {
        // Standard example: IPv4 header with known checksum
        let mut header = [0u8; 20];
        header[0] = 0x45; // ver=4, ihl=5
        header[8] = 64; // ttl
        header[9] = 6; // protocol=TCP
        // src = 10.0.0.1
        header[12..16].copy_from_slice(&[10, 0, 0, 1]);
        // dst = 10.0.0.2
        header[16..20].copy_from_slice(&[10, 0, 0, 2]);
        // total_length = 40 (20 header + 20 TCP)
        header[2] = 0;
        header[3] = 40;

        let cksum = ipv4_checksum(&header);
        // Verify it's valid by checking header sums to 0 with checksum included
        header[10] = (cksum >> 8) as u8;
        header[11] = (cksum & 0xFF) as u8;
        let verify = ipv4_checksum(&header);
        assert_eq!(verify, 0, "checksum verification should be 0");
    }

    #[test]
    fn test_pcap_global_header_magic() {
        let hdr = pcap_global_header(1);
        // Little-endian magic: 0xD4C3B2A1
        assert_eq!(hdr[0], 0xD4);
        assert_eq!(hdr[1], 0xC3);
        assert_eq!(hdr[2], 0xB2);
        assert_eq!(hdr[3], 0xA1);
    }

    #[test]
    fn test_pcap_record_header_length() {
        let hdr = pcap_record_header(54);
        let incl_len = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
        let orig_len = u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]);
        assert_eq!(incl_len, 54);
        assert_eq!(orig_len, 54);
    }

    #[test]
    fn test_select_field_value_override() {
        let field = FieldDef::new("protocol", 72, 8, FieldType::Enum);
        let mut overrides = BTreeMap::new();
        overrides.insert("protocol".to_string(), 6u64);
        assert_eq!(select_field_value(&field, &overrides), 6);
    }

    #[test]
    fn test_select_field_value_default() {
        let field = FieldDef::new("version", 0, 4, FieldType::Uint).with_default_value("4");
        let overrides = BTreeMap::new();
        assert_eq!(select_field_value(&field, &overrides), 4);
    }

    #[test]
    fn test_select_field_value_ipv4_src() {
        let field = FieldDef::new("src_addr", 96, 32, FieldType::Ipv4Addr);
        let overrides = BTreeMap::new();
        let val = select_field_value(&field, &overrides);
        assert_eq!(val, u64::from(u32::from_be_bytes([10, 0, 0, 1])));
    }

    #[test]
    fn test_select_field_value_mac_dst() {
        let field = FieldDef::new("dst_mac", 0, 48, FieldType::MacAddr);
        let overrides = BTreeMap::new();
        assert_eq!(select_field_value(&field, &overrides), 0x020000000002);
    }

    #[test]
    fn test_serialize_ethernet_header() {
        let eth = embedded_proto("Ethernet").unwrap();
        let mut overrides = BTreeMap::new();
        overrides.insert("ether_type".to_string(), 0x0800u64);
        let buf = serialize_header(&eth, &overrides);
        assert_eq!(buf.len(), 14);
        // dst_mac = 02:00:00:00:00:02
        assert_eq!(&buf[0..6], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        // src_mac = 02:00:00:00:00:01
        assert_eq!(&buf[6..12], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        // ether_type = 0x0800
        assert_eq!(&buf[12..14], &[0x08, 0x00]);
    }

    #[test]
    fn test_serialize_ipv4_header() {
        let ipv4 = embedded_proto("IPv4").unwrap();
        let mut overrides = BTreeMap::new();
        overrides.insert("protocol".to_string(), 6u64);
        let buf = serialize_header(&ipv4, &overrides);
        assert_eq!(buf.len(), 20);
        // Byte 0: version=4, ihl=5 → 0x45
        assert_eq!(buf[0], 0x45);
        // Byte 8: ttl=64
        assert_eq!(buf[8], 64);
        // Byte 9: protocol=6 (TCP)
        assert_eq!(buf[9], 6);
        // src = 10.0.0.1
        assert_eq!(&buf[12..16], &[10, 0, 0, 1]);
        // dst = 10.0.0.2
        assert_eq!(&buf[16..20], &[10, 0, 0, 2]);
    }

    #[test]
    fn test_build_stack_ethernet() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("Ethernet", &protos).unwrap();
        assert_eq!(result.layers.len(), 1);
        assert_eq!(result.layers[0].proto_name, "Ethernet");
        assert_eq!(result.link_type, 1);
    }

    #[test]
    fn test_build_stack_ipv4() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("IPv4", &protos).unwrap();
        assert_eq!(result.layers.len(), 2);
        assert_eq!(result.layers[0].proto_name, "Ethernet");
        assert_eq!(result.layers[1].proto_name, "IPv4");
        assert_eq!(result.layers[0].overrides.get("ether_type"), Some(&0x0800u64));
        assert_eq!(result.link_type, 1);
    }

    #[test]
    fn test_build_stack_tcp() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("TCP", &protos).unwrap();
        assert_eq!(result.layers.len(), 3);
        assert_eq!(result.layers[0].proto_name, "Ethernet");
        assert_eq!(result.layers[1].proto_name, "IPv4");
        assert_eq!(result.layers[2].proto_name, "TCP");
        assert_eq!(result.layers[1].overrides.get("protocol"), Some(&6u64));
        assert_eq!(result.link_type, 1);
    }

    #[test]
    fn test_build_stack_unknown_proto() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("UnknownProto", &protos);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_pcap_ipv4() {
        let protos = BTreeMap::new();
        let target = embedded_proto("IPv4").unwrap();
        let output = generate_pcap(&target, &protos).unwrap();

        // PCAP = 24 (global) + 16 (record) + packet
        assert_eq!(output.stack, vec!["Ethernet", "IPv4"]);
        // Packet = 14 (Ethernet) + 20 (IPv4) = 34 bytes
        assert_eq!(output.packet_bytes.len(), 34);
        assert_eq!(output.pcap_bytes.len(), 24 + 16 + 34);

        // Verify PCAP magic
        assert_eq!(&output.pcap_bytes[0..4], &[0xD4, 0xC3, 0xB2, 0xA1]);

        // Verify IPv4 version+IHL
        assert_eq!(output.packet_bytes[14], 0x45);

        // Verify IPv4 checksum is valid
        let ipv4_hdr = &output.packet_bytes[14..34];
        assert_eq!(ipv4_checksum(ipv4_hdr), 0);
    }

    #[test]
    fn test_generate_pcap_tcp() {
        let mut protos = BTreeMap::new();
        // Minimal TCP def
        protos.insert(
            "TCP".to_string(),
            ProtocolDef::new("TCP", 160).with_fields(vec![
                FieldDef::new("src_port", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("dst_port", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("seq", 32, 32, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("ack", 64, 32, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("data_offset", 96, 4, FieldType::Uint).with_default_value("5"),
                FieldDef::new("reserved", 100, 3, FieldType::Pad),
                FieldDef::new("flags", 103, 9, FieldType::Flags),
                FieldDef::new("window", 112, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("checksum", 128, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("urgent_ptr", 144, 16, FieldType::Uint).with_endian(Endian::Big),
            ]),
        );

        let target = protos.get("TCP").unwrap().clone();
        let output = generate_pcap(&target, &protos).unwrap();

        assert_eq!(output.stack, vec!["Ethernet", "IPv4", "TCP"]);
        // 14 (Eth) + 20 (IPv4) + 20 (TCP) = 54
        assert_eq!(output.packet_bytes.len(), 54);

        // IPv4 protocol field should be 6 (TCP)
        assert_eq!(output.packet_bytes[14 + 9], 6);

        // Ethernet ether_type should be 0x0800
        assert_eq!(&output.packet_bytes[12..14], &[0x08, 0x00]);
    }

    #[test]
    fn test_hex_dump_format() {
        let data = vec![0x45, 0x00, 0x00, 0x28];
        let dump = hex_dump(&data);
        assert!(dump.contains("45 00 00 28"));
    }

    #[test]
    fn test_parse_int_value() {
        assert_eq!(parse_int_value("42"), Some(42));
        assert_eq!(parse_int_value("0x0800"), Some(0x0800));
        assert_eq!(parse_int_value("0b1010"), Some(10));
        assert_eq!(parse_int_value("abc"), None);
    }

    // ── Helper: verify a route builds the expected stack ──

    fn assert_stack(
        proto: &str,
        expected_layers: &[&str],
        parent_idx: usize,
        dispatch_field: &str,
        dispatch_value: u64,
    ) {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery(proto, &protos).unwrap();
        assert_eq!(
            result.layers.len(),
            expected_layers.len(),
            "{}: expected {} layers, got {}",
            proto,
            expected_layers.len(),
            result.layers.len()
        );
        for (i, name) in expected_layers.iter().enumerate() {
            assert_eq!(result.layers[i].proto_name, *name, "{}: layer {}", proto, i);
        }
        assert_eq!(
            result.layers[parent_idx].overrides.get(dispatch_field),
            Some(&dispatch_value),
            "{}: {}={:#x} override on layer {}",
            proto,
            dispatch_field,
            dispatch_value,
            expected_layers[parent_idx],
        );
    }

    // ── Phase 1: L2 Ethernet-direct routes ──

    #[test]
    fn test_build_stack_rarp() {
        assert_stack("RARP", &["Ethernet", "RARP"], 0, "ether_type", 0x8035);
    }

    #[test]
    fn test_build_stack_mpls() {
        assert_stack("MPLS", &["Ethernet", "MPLS"], 0, "ether_type", 0x8847);
    }

    #[test]
    fn test_build_stack_pppoe() {
        assert_stack("PPPoE", &["Ethernet", "PPPoE"], 0, "ether_type", 0x8864);
    }

    #[test]
    fn test_build_stack_lldp() {
        assert_stack("LLDP", &["Ethernet", "LLDP"], 0, "ether_type", 0x88CC);
    }

    #[test]
    fn test_build_stack_ptp() {
        assert_stack("PTP", &["Ethernet", "PTP"], 0, "ether_type", 0x88F7);
    }

    #[test]
    fn test_build_stack_eapol() {
        assert_stack("EAPOL", &["Ethernet", "EAPOL"], 0, "ether_type", 0x888E);
    }

    #[test]
    fn test_build_stack_macsec() {
        assert_stack("MACsec", &["Ethernet", "MACsec"], 0, "ether_type", 0x88E5);
    }

    #[test]
    fn test_build_stack_qinq() {
        assert_stack("QinQ", &["Ethernet", "QinQ"], 0, "ether_type", 0x88A8);
    }

    #[test]
    fn test_build_stack_pbb() {
        assert_stack("PBB", &["Ethernet", "PBB"], 0, "ether_type", 0x88E7);
    }

    #[test]
    fn test_build_stack_trill() {
        assert_stack("TRILL", &["Ethernet", "TRILL"], 0, "ether_type", 0x22F3);
    }

    #[test]
    fn test_build_stack_ethercat() {
        assert_stack("EtherCAT", &["Ethernet", "EtherCAT"], 0, "ether_type", 0x88A4);
    }

    #[test]
    fn test_build_stack_profinet() {
        assert_stack("PROFINET", &["Ethernet", "PROFINET"], 0, "ether_type", 0x8892);
    }

    #[test]
    fn test_build_stack_fcoe() {
        assert_stack("FCoE", &["Ethernet", "FCoE"], 0, "ether_type", 0x8906);
    }

    #[test]
    fn test_build_stack_fip() {
        assert_stack("FIP", &["Ethernet", "FIP"], 0, "ether_type", 0x8914);
    }

    #[test]
    fn test_build_stack_slow_protocols() {
        assert_stack("Slow_Protocols", &["Ethernet", "Slow_Protocols"], 0, "ether_type", 0x8809);
    }

    #[test]
    fn test_build_stack_lacp() {
        assert_stack("LACP", &["Ethernet", "LACP"], 0, "ether_type", 0x8809);
    }

    #[test]
    fn test_build_stack_mac_control() {
        assert_stack("MAC_Control", &["Ethernet", "MAC_Control"], 0, "ether_type", 0x8808);
    }

    #[test]
    fn test_build_stack_cfm() {
        assert_stack("CFM", &["Ethernet", "CFM"], 0, "ether_type", 0x8902);
    }

    #[test]
    fn test_build_stack_hsr() {
        assert_stack("HSR", &["Ethernet", "HSR"], 0, "ether_type", 0x892F);
    }

    #[test]
    fn test_build_stack_batman() {
        assert_stack("BATMAN", &["Ethernet", "BATMAN"], 0, "ether_type", 0x4305);
    }

    #[test]
    fn test_build_stack_nsh() {
        assert_stack("NSH", &["Ethernet", "NSH"], 0, "ether_type", 0x894F);
    }

    #[test]
    fn test_build_stack_homeplug_av() {
        assert_stack("HomePlug_AV", &["Ethernet", "HomePlug_AV"], 0, "ether_type", 0x88E1);
    }

    #[test]
    fn test_build_stack_aoe() {
        assert_stack("AoE", &["Ethernet", "AoE"], 0, "ether_type", 0x88A2);
    }

    #[test]
    fn test_build_stack_mvrp() {
        assert_stack("MVRP", &["Ethernet", "MVRP"], 0, "ether_type", 0x88F5);
    }

    #[test]
    fn test_build_stack_nc_si() {
        assert_stack("NC_SI", &["Ethernet", "NC_SI"], 0, "ether_type", 0x88F8);
    }

    #[test]
    fn test_build_stack_iec_goose() {
        assert_stack("IEC_GOOSE", &["Ethernet", "IEC_GOOSE"], 0, "ether_type", 0x88B8);
    }

    #[test]
    fn test_build_stack_iec_sv() {
        assert_stack("IEC_SV", &["Ethernet", "IEC_SV"], 0, "ether_type", 0x88BA);
    }

    #[test]
    fn test_build_stack_ipx() {
        assert_stack("IPX", &["Ethernet", "IPX"], 0, "ether_type", 0x8137);
    }

    #[test]
    fn test_build_stack_appletalk() {
        assert_stack("AppleTalk", &["Ethernet", "AppleTalk"], 0, "ether_type", 0x809B);
    }

    #[test]
    fn test_build_stack_tipc() {
        assert_stack("TIPC", &["Ethernet", "TIPC"], 0, "ether_type", 0x88CA);
    }

    #[test]
    fn test_build_stack_pppoed() {
        assert_stack("PPPoED", &["Ethernet", "PPPoED"], 0, "ether_type", 0x8863);
    }

    // ── Phase 2: L3 IPv4/IPv6 routes ──

    #[test]
    fn test_build_stack_ospf() {
        assert_stack("OSPF", &["Ethernet", "IPv4", "OSPF"], 1, "protocol", 89);
    }

    #[test]
    fn test_build_stack_vrrp() {
        assert_stack("VRRP", &["Ethernet", "IPv4", "VRRP"], 1, "protocol", 112);
    }

    #[test]
    fn test_build_stack_pim() {
        assert_stack("PIM", &["Ethernet", "IPv4", "PIM"], 1, "protocol", 103);
    }

    #[test]
    fn test_build_stack_l2tp() {
        assert_stack("L2TP", &["Ethernet", "IPv4", "L2TP"], 1, "protocol", 115);
    }

    #[test]
    fn test_build_stack_esp() {
        assert_stack("ESP", &["Ethernet", "IPv4", "ESP"], 1, "protocol", 50);
    }

    #[test]
    fn test_build_stack_ah() {
        assert_stack("AH", &["Ethernet", "IPv4", "AH"], 1, "protocol", 51);
    }

    #[test]
    fn test_build_stack_ip_in_ip() {
        assert_stack("IP_in_IP", &["Ethernet", "IPv4", "IP_in_IP"], 1, "protocol", 4);
    }

    #[test]
    fn test_build_stack_dccp() {
        assert_stack("DCCP", &["Ethernet", "IPv4", "DCCP"], 1, "protocol", 33);
    }

    #[test]
    fn test_build_stack_udplite() {
        assert_stack("UDPLite", &["Ethernet", "IPv4", "UDPLite"], 1, "protocol", 136);
    }

    #[test]
    fn test_build_stack_eigrp() {
        assert_stack("EIGRP", &["Ethernet", "IPv4", "EIGRP"], 1, "protocol", 88);
    }

    #[test]
    fn test_build_stack_ipv6_eh() {
        assert_stack("IPv6_EH", &["Ethernet", "IPv6", "IPv6_EH"], 1, "next_header", 0);
    }

    #[test]
    fn test_build_stack_ipv6_destopts() {
        assert_stack("IPv6_DestOpts", &["Ethernet", "IPv6", "IPv6_DestOpts"], 1, "next_header", 60);
    }

    #[test]
    fn test_build_stack_ipv6_routing() {
        assert_stack("IPv6_Routing", &["Ethernet", "IPv6", "IPv6_Routing"], 1, "next_header", 43);
    }

    #[test]
    fn test_build_stack_ipv6_fragment() {
        assert_stack("IPv6_Fragment", &["Ethernet", "IPv6", "IPv6_Fragment"], 1, "next_header", 44);
    }

    #[test]
    fn test_build_stack_srv6() {
        assert_stack("SRv6", &["Ethernet", "IPv6", "SRv6"], 1, "next_header", 43);
    }

    // ── Phase 2: fixup_ipv6 ──

    #[test]
    fn test_fixup_ipv6_payload_length() {
        let protos = BTreeMap::new();
        let target = embedded_proto("IPv6").unwrap();
        let output = generate_pcap(&target, &protos).unwrap();
        // Packet: 14 (Eth) + 40 (IPv6) = 54
        assert_eq!(output.packet_bytes.len(), 54);
        // IPv6 payload_length should be 0 (no payload after IPv6 header itself)
        assert_eq!(output.packet_bytes[14 + 4], 0);
        assert_eq!(output.packet_bytes[14 + 5], 0);
    }

    #[test]
    fn test_fixup_ipv6_with_payload() {
        // ICMPv6 over IPv6: should have payload_length = icmpv6 header size
        let mut protos = BTreeMap::new();
        let icmpv6_def = ProtocolDef::new("ICMPv6", 32).with_fields(vec![
            FieldDef::new("type", 0, 8, FieldType::Uint),
            FieldDef::new("code", 8, 8, FieldType::Uint),
            FieldDef::new("checksum", 16, 16, FieldType::Uint).with_endian(Endian::Big),
        ]);
        protos.insert("ICMPv6".to_string(), icmpv6_def.clone());
        let output = generate_pcap(&icmpv6_def, &protos).unwrap();
        // Packet: 14 (Eth) + 40 (IPv6) + 4 (ICMPv6) = 58
        assert_eq!(output.packet_bytes.len(), 58);
        // IPv6 payload_length = 4 (ICMPv6 header)
        let pl = u16::from_be_bytes([output.packet_bytes[14 + 4], output.packet_bytes[14 + 5]]);
        assert_eq!(pl, 4);
    }

    // ── Phase 3: Embedded protocol serialization ──

    #[test]
    fn test_embedded_udp() {
        let udp = embedded_proto("UDP").unwrap();
        assert_eq!(udp.min_header_bits, 64);
        assert_eq!(udp.fields.len(), 4);
        assert_eq!(udp.dispatch_field, Some("dst_port".to_string()));
        let buf = serialize_header(&udp, &BTreeMap::new());
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn test_embedded_tcp() {
        let tcp = embedded_proto("TCP").unwrap();
        assert_eq!(tcp.min_header_bits, 160);
        assert_eq!(tcp.fields.len(), 10);
        assert!(tcp.is_variable_length);
        assert_eq!(tcp.dispatch_field, Some("dst_port".to_string()));
        let buf = serialize_header(&tcp, &BTreeMap::new());
        assert_eq!(buf.len(), 20);
        // data_offset=5 → byte 12 upper nibble = 0x50
        assert_eq!(buf[12] & 0xF0, 0x50);
    }

    #[test]
    fn test_embedded_gre() {
        let gre = embedded_proto("GRE").unwrap();
        assert_eq!(gre.min_header_bits, 32);
        assert_eq!(gre.fields.len(), 2);
        assert!(gre.is_variable_length);
        assert_eq!(gre.dispatch_field, Some("protocol_type".to_string()));
        let buf = serialize_header(&gre, &BTreeMap::new());
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn test_serialize_udp_with_port_override() {
        let udp = embedded_proto("UDP").unwrap();
        let mut overrides = BTreeMap::new();
        overrides.insert("dst_port".to_string(), 53u64);
        let buf = serialize_header(&udp, &overrides);
        assert_eq!(buf.len(), 8);
        // dst_port at offset 16 bits (bytes 2-3), value 53
        assert_eq!(buf[2], 0);
        assert_eq!(buf[3], 53);
    }

    #[test]
    fn test_serialize_tcp_with_port_override() {
        let tcp = embedded_proto("TCP").unwrap();
        let mut overrides = BTreeMap::new();
        overrides.insert("dst_port".to_string(), 80u64);
        let buf = serialize_header(&tcp, &overrides);
        // dst_port at bytes 2-3, value 80
        assert_eq!(buf[2], 0);
        assert_eq!(buf[3], 80);
    }

    #[test]
    fn test_serialize_gre_with_protocol_override() {
        let gre = embedded_proto("GRE").unwrap();
        let mut overrides = BTreeMap::new();
        overrides.insert("protocol_type".to_string(), 0x6558u64);
        let buf = serialize_header(&gre, &overrides);
        assert_eq!(buf[2], 0x65);
        assert_eq!(buf[3], 0x58);
    }

    // ── Phase 3: fixup_udp_length ──

    #[test]
    fn test_fixup_udp_length() {
        let mut protos = BTreeMap::new();
        // DNS over UDP: Eth → IPv4 → UDP → DNS
        let dns_def = ProtocolDef::new("DNS", 96).with_fields(vec![
            FieldDef::new("id", 0, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("flags", 16, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("qdcount", 32, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("ancount", 48, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("nscount", 64, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("arcount", 80, 16, FieldType::Uint).with_endian(Endian::Big),
        ]);
        protos.insert("DNS".to_string(), dns_def.clone());
        let output = generate_pcap(&dns_def, &protos).unwrap();
        // Stack: Eth(14) + IPv4(20) + UDP(8) + DNS(12) = 54
        assert_eq!(output.stack, vec!["Ethernet", "IPv4", "UDP", "DNS"]);
        assert_eq!(output.packet_bytes.len(), 54);
        // UDP offset = 34, UDP length = 54 - 34 = 20 (8 hdr + 12 DNS)
        let udp_len = u16::from_be_bytes([output.packet_bytes[34 + 4], output.packet_bytes[34 + 5]]);
        assert_eq!(udp_len, 20);
        // UDP dst_port should be 53 (DNS)
        let dst_port = u16::from_be_bytes([output.packet_bytes[34 + 2], output.packet_bytes[34 + 3]]);
        assert_eq!(dst_port, 53);
    }

    // ── Phase 3: UDP-routed protocol stacks ──

    #[test]
    fn test_build_stack_dns() {
        assert_stack("DNS", &["Ethernet", "IPv4", "UDP", "DNS"], 2, "dst_port", 53);
    }

    #[test]
    fn test_build_stack_mdns() {
        assert_stack("mDNS", &["Ethernet", "IPv4", "UDP", "mDNS"], 2, "dst_port", 5353);
    }

    #[test]
    fn test_build_stack_dhcp() {
        assert_stack("DHCP", &["Ethernet", "IPv4", "UDP", "DHCP"], 2, "dst_port", 67);
    }

    #[test]
    fn test_build_stack_ntp() {
        assert_stack("NTP", &["Ethernet", "IPv4", "UDP", "NTP"], 2, "dst_port", 123);
    }

    #[test]
    fn test_build_stack_snmp() {
        assert_stack("SNMP", &["Ethernet", "IPv4", "UDP", "SNMP"], 2, "dst_port", 161);
    }

    #[test]
    fn test_build_stack_vxlan() {
        assert_stack("VXLAN", &["Ethernet", "IPv4", "UDP", "VXLAN"], 2, "dst_port", 4789);
    }

    #[test]
    fn test_build_stack_geneve() {
        assert_stack("Geneve", &["Ethernet", "IPv4", "UDP", "Geneve"], 2, "dst_port", 6081);
    }

    #[test]
    fn test_build_stack_wireguard() {
        assert_stack("WireGuard", &["Ethernet", "IPv4", "UDP", "WireGuard"], 2, "dst_port", 51820);
    }

    #[test]
    fn test_build_stack_quic() {
        assert_stack("QUIC", &["Ethernet", "IPv4", "UDP", "QUIC"], 2, "dst_port", 443);
    }

    #[test]
    fn test_build_stack_gtp_u() {
        assert_stack("GTP_U", &["Ethernet", "IPv4", "UDP", "GTP_U"], 2, "dst_port", 2152);
    }

    #[test]
    fn test_build_stack_gtp_c() {
        assert_stack("GTP_C", &["Ethernet", "IPv4", "UDP", "GTP_C"], 2, "dst_port", 2123);
    }

    #[test]
    fn test_build_stack_radius() {
        assert_stack("RADIUS", &["Ethernet", "IPv4", "UDP", "RADIUS"], 2, "dst_port", 1812);
    }

    #[test]
    fn test_build_stack_sip() {
        assert_stack("SIP", &["Ethernet", "IPv4", "UDP", "SIP"], 2, "dst_port", 5060);
    }

    #[test]
    fn test_build_stack_bfd() {
        assert_stack("BFD", &["Ethernet", "IPv4", "UDP", "BFD"], 2, "dst_port", 3784);
    }

    #[test]
    fn test_build_stack_rtp() {
        assert_stack("RTP", &["Ethernet", "IPv4", "UDP", "RTP"], 2, "dst_port", 5004);
    }

    #[test]
    fn test_build_stack_rtcp() {
        assert_stack("RTCP", &["Ethernet", "IPv4", "UDP", "RTCP"], 2, "dst_port", 5005);
    }

    #[test]
    fn test_build_stack_stun() {
        assert_stack("STUN", &["Ethernet", "IPv4", "UDP", "STUN"], 2, "dst_port", 3478);
    }

    #[test]
    fn test_build_stack_rip() {
        assert_stack("RIP", &["Ethernet", "IPv4", "UDP", "RIP"], 2, "dst_port", 520);
    }

    #[test]
    fn test_build_stack_vxlan_gpe() {
        assert_stack("VXLAN_GPE", &["Ethernet", "IPv4", "UDP", "VXLAN_GPE"], 2, "dst_port", 4790);
    }

    #[test]
    fn test_build_stack_lisp() {
        assert_stack("LISP", &["Ethernet", "IPv4", "UDP", "LISP"], 2, "dst_port", 4341);
    }

    #[test]
    fn test_build_stack_coap() {
        assert_stack("CoAP", &["Ethernet", "IPv4", "UDP", "CoAP"], 2, "dst_port", 5683);
    }

    #[test]
    fn test_build_stack_tftp() {
        assert_stack("TFTP", &["Ethernet", "IPv4", "UDP", "TFTP"], 2, "dst_port", 69);
    }

    #[test]
    fn test_build_stack_dhcpv6() {
        assert_stack("DHCPv6", &["Ethernet", "IPv4", "UDP", "DHCPv6"], 2, "dst_port", 547);
    }

    #[test]
    fn test_build_stack_llmnr() {
        assert_stack("LLMNR", &["Ethernet", "IPv4", "UDP", "LLMNR"], 2, "dst_port", 5355);
    }

    #[test]
    fn test_build_stack_nbns() {
        assert_stack("NBNS", &["Ethernet", "IPv4", "UDP", "NBNS"], 2, "dst_port", 137);
    }

    #[test]
    fn test_build_stack_capwap() {
        assert_stack("CAPWAP", &["Ethernet", "IPv4", "UDP", "CAPWAP"], 2, "dst_port", 5247);
    }

    #[test]
    fn test_build_stack_syslog() {
        assert_stack("Syslog", &["Ethernet", "IPv4", "UDP", "Syslog"], 2, "dst_port", 514);
    }

    #[test]
    fn test_build_stack_netflow_v5() {
        assert_stack("NetFlow_v5", &["Ethernet", "IPv4", "UDP", "NetFlow_v5"], 2, "dst_port", 2055);
    }

    #[test]
    fn test_build_stack_ipfix() {
        assert_stack("IPFIX", &["Ethernet", "IPv4", "UDP", "IPFIX"], 2, "dst_port", 4739);
    }

    #[test]
    fn test_build_stack_ikev2() {
        assert_stack("IKEv2", &["Ethernet", "IPv4", "UDP", "IKEv2"], 2, "dst_port", 500);
    }

    #[test]
    fn test_build_stack_dtls() {
        assert_stack("DTLS", &["Ethernet", "IPv4", "UDP", "DTLS"], 2, "dst_port", 4433);
    }

    #[test]
    fn test_build_stack_mqtt() {
        assert_stack("MQTT", &["Ethernet", "IPv4", "TCP", "MQTT"], 2, "dst_port", 1883);
    }

    #[test]
    fn test_build_stack_openflow() {
        assert_stack("OpenFlow", &["Ethernet", "IPv4", "TCP", "OpenFlow"], 2, "dst_port", 6653);
    }

    #[test]
    fn test_build_stack_srt() {
        assert_stack("SRT", &["Ethernet", "IPv4", "UDP", "SRT"], 2, "dst_port", 1935);
    }

    #[test]
    fn test_build_stack_lwapp() {
        assert_stack("LWAPP", &["Ethernet", "IPv4", "UDP", "LWAPP"], 2, "dst_port", 12222);
    }

    #[test]
    fn test_build_stack_tzsp() {
        assert_stack("TZSP", &["Ethernet", "IPv4", "UDP", "TZSP"], 2, "dst_port", 37008);
    }

    // ── Phase 3: TCP-routed protocol stacks ──

    #[test]
    fn test_build_stack_http() {
        assert_stack("HTTP", &["Ethernet", "IPv4", "TCP", "HTTP"], 2, "dst_port", 80);
    }

    #[test]
    fn test_build_stack_tls() {
        assert_stack("TLS", &["Ethernet", "IPv4", "TCP", "TLS"], 2, "dst_port", 443);
    }

    #[test]
    fn test_build_stack_bgp() {
        assert_stack("BGP", &["Ethernet", "IPv4", "TCP", "BGP"], 2, "dst_port", 179);
    }

    #[test]
    fn test_build_stack_ssh() {
        assert_stack("SSH", &["Ethernet", "IPv4", "TCP", "SSH"], 2, "dst_port", 22);
    }

    #[test]
    fn test_build_stack_telnet() {
        assert_stack("Telnet", &["Ethernet", "IPv4", "TCP", "Telnet"], 2, "dst_port", 23);
    }

    #[test]
    fn test_build_stack_ftp() {
        assert_stack("FTP", &["Ethernet", "IPv4", "TCP", "FTP"], 2, "dst_port", 21);
    }

    #[test]
    fn test_build_stack_smtp() {
        assert_stack("SMTP", &["UpperPDU", "SMTP"], 0, "_always", 0);
    }

    #[test]
    fn test_build_stack_imap() {
        assert_stack("IMAP", &["Ethernet", "IPv4", "TCP", "IMAP"], 2, "dst_port", 143);
    }

    #[test]
    fn test_build_stack_smb() {
        assert_stack("SMB", &["Ethernet", "IPv4", "TCP", "SMB"], 2, "dst_port", 445);
    }

    #[test]
    fn test_build_stack_ldap() {
        assert_stack("LDAP", &["Ethernet", "IPv4", "TCP", "LDAP"], 2, "dst_port", 389);
    }

    #[test]
    fn test_build_stack_diameter() {
        assert_stack("Diameter", &["Ethernet", "IPv4", "TCP", "Diameter"], 2, "dst_port", 3868);
    }

    #[test]
    fn test_build_stack_amqp() {
        assert_stack("AMQP", &["UpperPDU", "AMQP"], 0, "_always", 0);
    }

    #[test]
    fn test_build_stack_kafka() {
        assert_stack("Kafka", &["Ethernet", "IPv4", "TCP", "Kafka"], 2, "dst_port", 9092);
    }

    #[test]
    fn test_build_stack_redis() {
        assert_stack("Redis", &["Ethernet", "IPv4", "TCP", "Redis"], 2, "dst_port", 6379);
    }

    #[test]
    fn test_build_stack_memcache() {
        assert_stack("Memcache", &["Ethernet", "IPv4", "TCP", "Memcache"], 2, "dst_port", 11211);
    }

    #[test]
    fn test_build_stack_kerberos() {
        assert_stack("Kerberos", &["Ethernet", "IPv4", "TCP", "Kerberos"], 2, "dst_port", 88);
    }

    #[test]
    fn test_build_stack_modbus_tcp() {
        assert_stack("MODBUS_TCP", &["Ethernet", "IPv4", "TCP", "MODBUS_TCP"], 2, "dst_port", 502);
    }

    #[test]
    fn test_build_stack_dnp3() {
        assert_stack("DNP3", &["Ethernet", "IPv4", "TCP", "DNP3"], 2, "dst_port", 20000);
    }

    #[test]
    fn test_build_stack_enip() {
        assert_stack("ENIP", &["Ethernet", "IPv4", "TCP", "ENIP"], 2, "dst_port", 44818);
    }

    #[test]
    fn test_build_stack_opc_ua() {
        assert_stack("OPC_UA", &["Ethernet", "IPv4", "TCP", "OPC_UA"], 2, "dst_port", 4840);
    }

    #[test]
    fn test_build_stack_rtsp() {
        assert_stack("RTSP", &["Ethernet", "IPv4", "TCP", "RTSP"], 2, "dst_port", 554);
    }

    #[test]
    fn test_build_stack_skinny() {
        assert_stack("Skinny", &["Ethernet", "IPv4", "TCP", "Skinny"], 2, "dst_port", 2000);
    }

    #[test]
    fn test_build_stack_tacacs() {
        assert_stack("TACACS", &["Ethernet", "IPv4", "TCP", "TACACS"], 2, "dst_port", 49);
    }

    // ── Phase 3: GRE tunnel routes ──

    #[test]
    fn test_build_stack_nvgre() {
        assert_stack("NVGRE", &["Ethernet", "IPv4", "GRE", "NVGRE"], 2, "protocol_type", 0x6558);
    }

    #[test]
    fn test_build_stack_erspan() {
        assert_stack("ERSPAN", &["Ethernet", "IPv4", "GRE", "ERSPAN"], 2, "protocol_type", 0x88BE);
    }

    #[test]
    fn test_build_stack_gre_pptp() {
        assert_stack("GRE_PPTP", &["Ethernet", "IPv4", "GRE", "GRE_PPTP"], 2, "protocol_type", 0x880B);
    }

    // ── Phase 3: full PCAP generation for multi-layer stacks ──

    #[test]
    fn test_generate_pcap_dns_over_udp() {
        let mut protos = BTreeMap::new();
        protos.insert(
            "DNS".to_string(),
            ProtocolDef::new("DNS", 96).with_fields(vec![
                FieldDef::new("id", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("flags", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("qdcount", 32, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("ancount", 48, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("nscount", 64, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("arcount", 80, 16, FieldType::Uint).with_endian(Endian::Big),
            ]),
        );
        let target = protos.get("DNS").unwrap().clone();
        let output = generate_pcap(&target, &protos).unwrap();

        assert_eq!(output.stack, vec!["Ethernet", "IPv4", "UDP", "DNS"]);
        // 14 + 20 + 8 + 12 = 54
        assert_eq!(output.packet_bytes.len(), 54);

        // Ethernet ether_type = 0x0800
        assert_eq!(&output.packet_bytes[12..14], &[0x08, 0x00]);
        // IPv4 protocol = 17 (UDP)
        assert_eq!(output.packet_bytes[14 + 9], 17);
        // IPv4 checksum valid
        assert_eq!(ipv4_checksum(&output.packet_bytes[14..34]), 0);
        // UDP dst_port = 53
        assert_eq!(&output.packet_bytes[36..38], &[0, 53]);
        // UDP length = 20
        let udp_len = u16::from_be_bytes([output.packet_bytes[38], output.packet_bytes[39]]);
        assert_eq!(udp_len, 20);
    }

    #[test]
    fn test_generate_pcap_http_over_tcp() {
        let mut protos = BTreeMap::new();
        protos.insert("HTTP".to_string(), ProtocolDef::new("HTTP", 0));
        let http_def = protos.get("HTTP").unwrap().clone();
        let output = generate_pcap(&http_def, &protos).unwrap();

        assert_eq!(output.stack, vec!["Ethernet", "IPv4", "TCP", "HTTP"]);
        // 14 + 20 + 20 + 0 = 54
        assert_eq!(output.packet_bytes.len(), 54);
        // IPv4 protocol = 6 (TCP)
        assert_eq!(output.packet_bytes[14 + 9], 6);
        // TCP dst_port = 80
        assert_eq!(&output.packet_bytes[36..38], &[0, 80]);
    }

    #[test]
    fn test_generate_pcap_nvgre_over_gre() {
        let mut protos = BTreeMap::new();
        protos.insert(
            "NVGRE".to_string(),
            ProtocolDef::new("NVGRE", 32).with_fields(vec![
                FieldDef::new("vsid", 0, 24, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("flow_id", 24, 8, FieldType::Uint),
            ]),
        );
        let nvgre_def = protos.get("NVGRE").unwrap().clone();
        let output = generate_pcap(&nvgre_def, &protos).unwrap();

        assert_eq!(output.stack, vec!["Ethernet", "IPv4", "GRE", "NVGRE"]);
        // 14 + 20 + 4 + 4 = 42
        assert_eq!(output.packet_bytes.len(), 42);
        // IPv4 protocol = 47 (GRE)
        assert_eq!(output.packet_bytes[14 + 9], 47);
        // GRE protocol_type = 0x6558
        assert_eq!(&output.packet_bytes[36..38], &[0x65, 0x58]);
    }

    // ── Verify all STACK_ROUTES resolve ──

    #[test]
    fn test_all_stack_routes_resolve() {
        let protos = BTreeMap::new();
        for &(child, _, _, _) in STACK_ROUTES {
            let result = build_stack_no_discovery(child, &protos);
            assert!(
                result.is_ok(),
                "STACK_ROUTE for '{}' failed to build: {:?}",
                child,
                result.err()
            );
            let sr = result.unwrap();
            assert!(
                is_root(&sr.layers[0].proto_name),
                "'{}' stack should start with a link-layer root, got '{}'",
                child,
                sr.layers[0].proto_name
            );
            assert_eq!(
                sr.layers.last().unwrap().proto_name, child,
                "'{}' stack should end with the target",
                child
            );
        }
    }

    // ── Phase 1 new routes ──

    #[test]
    fn test_build_stack_wol() {
        assert_stack("WOL", &["UpperPDU", "WOL"], 0, "_always", 0);
    }

    #[test]
    fn test_build_stack_carp() {
        assert_stack("CARP", &["Ethernet", "IPv4", "CARP"], 1, "protocol", 112);
    }

    #[test]
    fn test_build_stack_rsvp() {
        assert_stack("RSVP", &["Ethernet", "IPv4", "RSVP"], 1, "protocol", 46);
    }

    #[test]
    fn test_build_stack_bacnet() {
        assert_stack("BACnet", &["Ethernet", "IPv4", "UDP", "BACnet"], 2, "dst_port", 47808);
    }

    #[test]
    fn test_build_stack_iscsi() {
        assert_stack("iSCSI", &["Ethernet", "IPv4", "TCP", "iSCSI"], 2, "dst_port", 3260);
    }

    #[test]
    fn test_build_stack_nfs() {
        assert_stack("NFS", &["UpperPDU", "NFS"], 0, "_always", 0);
    }

    #[test]
    fn test_build_stack_nvme() {
        assert_stack("NVMe", &["Ethernet", "IPv4", "TCP", "NVMe"], 2, "dst_port", 4420);
    }

    // ── Phase 2 sub-dispatch routes ──

    #[test]
    fn test_build_stack_igmpv3_query() {
        assert_stack(
            "IGMPv3_Query",
            &["Ethernet", "IPv4", "IGMP", "IGMPv3_Query"],
            2,
            "type",
            0x11,
        );
    }

    #[test]
    fn test_build_stack_ipv6_nd() {
        assert_stack(
            "IPv6_ND",
            &["Ethernet", "IPv6", "ICMPv6", "IPv6_ND"],
            2,
            "type",
            135,
        );
    }

    #[test]
    fn test_build_stack_eap() {
        assert_stack("EAP", &["Ethernet", "EAPOL", "EAP"], 1, "_always", 0);
    }

    #[test]
    fn test_build_stack_cip() {
        assert_stack(
            "CIP",
            &["UpperPDU", "CIP"],
            0,
            "_always",
            0,
        );
    }

    // ── Phase 4 Bluetooth routes ──

    #[test]
    fn test_build_stack_hci_cmd() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("HCI_CMD", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "HCI");
        assert_eq!(result.layers[1].proto_name, "HCI_CMD");
        assert_eq!(result.link_type, 187);
    }

    #[test]
    fn test_build_stack_bt_att() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("BT_ATT", &protos).unwrap();
        assert_eq!(result.layers.len(), 4);
        assert_eq!(result.layers[0].proto_name, "HCI");
        assert_eq!(result.layers[1].proto_name, "HCI_ACL");
        assert_eq!(result.layers[2].proto_name, "L2CAP");
        assert_eq!(result.layers[3].proto_name, "BT_ATT");
        assert_eq!(result.link_type, 187);
    }

    #[test]
    fn test_build_stack_bt_rfcomm_upper_pdu() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("BT_RFCOMM", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "UpperPDU");
        assert_eq!(result.layers[1].proto_name, "BT_RFCOMM");
        assert_eq!(result.link_type, 252);
    }

    // ── Phase 5 InfiniBand routes ──

    #[test]
    fn test_build_stack_ib_deth() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("IB_DETH", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "UpperPDU");
        assert_eq!(result.layers[1].proto_name, "IB_LRH");
        assert_eq!(result.layers[2].proto_name, "IB_BTH");
        assert_eq!(result.layers[3].proto_name, "IB_DETH");
        assert_eq!(result.link_type, 252);
    }

    // ── Phase 6 standalone root tests ──

    #[test]
    fn test_build_stack_can_root() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("CAN", &protos).unwrap();
        assert_eq!(result.layers.len(), 1);
        assert_eq!(result.layers[0].proto_name, "CAN");
        assert_eq!(result.link_type, 227);
    }

    #[test]
    fn test_build_stack_zigbee_aps() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("Zigbee_APS", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "IEEE802154");
        assert_eq!(result.layers[1].proto_name, "Zigbee_NWK");
        assert_eq!(result.layers[2].proto_name, "Zigbee_APS");
        assert_eq!(result.link_type, 195);
    }

    #[test]
    fn test_build_stack_nlattr() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("NLAttr", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "Netlink");
        assert_eq!(result.layers[1].proto_name, "GenNetlink");
        assert_eq!(result.layers[2].proto_name, "NLAttr");
        assert_eq!(result.link_type, 253);
    }

    // ── Phase 7 802.2 LLC/SNAP routes ──

    #[test]
    fn test_build_stack_stp() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("STP", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "Ethernet_802_3");
        assert_eq!(result.layers[1].proto_name, "LLC");
        assert_eq!(result.layers[2].proto_name, "STP");
        assert_eq!(result.link_type, 1); // DLT_EN10MB
    }

    #[test]
    fn test_build_stack_cdp() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("CDP", &protos).unwrap();
        assert_eq!(result.layers.len(), 4);
        assert_eq!(result.layers[0].proto_name, "Ethernet_802_3");
        assert_eq!(result.layers[1].proto_name, "LLC");
        assert_eq!(result.layers[2].proto_name, "SNAP");
        assert_eq!(result.layers[3].proto_name, "CDP");
    }

    // ── Phase 8 UpperPDU routes ──

    #[test]
    fn test_build_stack_scsi_upper_pdu() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("SCSI", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "UpperPDU");
        assert_eq!(result.layers[1].proto_name, "SCSI");
        assert_eq!(result.link_type, 252);
    }

    // ── Integration tests: PCAP generation for new DLTs ──

    #[test]
    fn test_generate_pcap_bt_att() {
        let protos = BTreeMap::new();
        let target = ProtocolDef::new("BT_ATT", 8).with_fields(vec![
            FieldDef::new("opcode", 0, 8, FieldType::Uint),
        ]);
        let output = generate_pcap(&target, &protos).unwrap();
        assert_eq!(output.stack, vec!["HCI", "HCI_ACL", "L2CAP", "BT_ATT"]);
        assert_eq!(output.link_type, 187);
        // Verify DLT in PCAP header (bytes 20-23, little-endian)
        let dlt = u32::from_le_bytes([
            output.pcap_bytes[20],
            output.pcap_bytes[21],
            output.pcap_bytes[22],
            output.pcap_bytes[23],
        ]);
        assert_eq!(dlt, 187);
    }

    #[test]
    fn test_generate_pcap_stp() {
        let protos = BTreeMap::new();
        let target = ProtocolDef::new("STP", 0);
        let output = generate_pcap(&target, &protos).unwrap();
        assert_eq!(
            output.stack,
            vec!["Ethernet_802_3", "LLC", "STP"]
        );
        assert_eq!(output.link_type, 1);
        // 802.3 length field (bytes 12-13) should be payload length
        let length = u16::from_be_bytes([
            output.packet_bytes[12],
            output.packet_bytes[13],
        ]);
        let expected_payload = output.packet_bytes.len() as u16 - 14;
        assert_eq!(length, expected_payload);
    }

    #[test]
    fn test_generate_pcap_upper_pdu() {
        let protos = BTreeMap::new();
        let target = ProtocolDef::new("SCSI", 0);
        let output = generate_pcap(&target, &protos).unwrap();
        assert_eq!(output.stack, vec!["UpperPDU", "SCSI"]);
        assert_eq!(output.link_type, 252);
        // Verify TLV preamble: tag=0x000C (EXP_PDU_TAG_DISSECTOR_NAME), len=4 ("scsi"), then 4 zero bytes
        assert_eq!(output.packet_bytes[0], 0x00);
        assert_eq!(output.packet_bytes[1], 0x0C);
        assert_eq!(output.packet_bytes[2], 0x00);
        assert_eq!(output.packet_bytes[3], 0x04); // "scsi" = 4 bytes
        assert_eq!(&output.packet_bytes[4..8], b"scsi");
        assert_eq!(&output.packet_bytes[8..12], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_link_type_for_roots() {
        for &(name, expected_dlt) in LINK_ROOTS {
            let protos = BTreeMap::new();
            let result = build_stack_no_discovery(name, &protos).unwrap();
            assert_eq!(
                result.link_type, expected_dlt,
                "DLT mismatch for root '{}'",
                name
            );
        }
    }

    #[test]
    fn test_upper_pdu_preamble_format() {
        let buf = upper_pdu_preamble("scsi");
        // tag=0x000C (EXP_PDU_TAG_DISSECTOR_NAME), len=4, "scsi", end marker
        assert_eq!(&buf[0..2], &[0x00, 0x0C]);
        assert_eq!(&buf[2..4], &[0x00, 0x04]);
        assert_eq!(&buf[4..8], b"scsi");
        assert_eq!(&buf[8..12], &[0, 0, 0, 0]);
        assert_eq!(buf.len(), 12);

        // Test padding: "stt" (3 bytes) should be padded to 4
        let buf2 = upper_pdu_preamble("stt");
        assert_eq!(&buf2[0..2], &[0x00, 0x0C]);
        assert_eq!(&buf2[2..4], &[0x00, 0x03]); // actual len=3
        assert_eq!(&buf2[4..7], b"stt");
        assert_eq!(buf2[7], 0); // padding byte
        assert_eq!(&buf2[8..12], &[0, 0, 0, 0]); // end marker
        assert_eq!(buf2.len(), 12);

        // Test "btsdp" (5 bytes) → padded to 8
        let buf3 = upper_pdu_preamble("btsdp");
        assert_eq!(&buf3[2..4], &[0x00, 0x05]); // actual len=5
        assert_eq!(&buf3[4..9], b"btsdp");
        assert_eq!(&buf3[9..12], &[0, 0, 0]); // 3 padding bytes
        assert_eq!(&buf3[12..16], &[0, 0, 0, 0]); // end marker
        assert_eq!(buf3.len(), 16);
    }

    #[test]
    fn test_is_root() {
        assert!(is_root("Ethernet"));
        assert!(is_root("HCI"));
        assert!(!is_root("IB_LRH")); // now routed via UpperPDU
        assert!(is_root("UpperPDU"));
        assert!(is_root("CAN"));
        assert!(!is_root("IPv4"));
        assert!(!is_root("TCP"));
        assert!(!is_root("DNS"));
    }

    #[test]
    fn test_all_link_roots_have_embedded_defs() {
        for &(name, _) in LINK_ROOTS {
            assert!(
                embedded_proto(name).is_some(),
                "LINK_ROOT '{}' has no embedded_proto",
                name
            );
        }
    }
}
