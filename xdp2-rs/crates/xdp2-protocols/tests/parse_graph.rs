//! Integration tests: build multi-node parse graphs and parse real packet bytes.
//!
//! These tests verify the end-to-end flow through the parse engine using
//! protocols from xdp2-protocols, matching the behavior of the C parse engine.

use xdp2_core::{
    parse, proto_table, ParseError, ParseNode, ParseNodeOps, ParseResult, Parser, ParserConfig,
    ParserType, ProtoTable,
};
use xdp2_protocols::ethernet::ether::EthernetOps;
use xdp2_protocols::ethernet::vlan::VlanOps;
use xdp2_protocols::ip::ipv4::Ipv4Ops;
use xdp2_protocols::ip::ipv6::Ipv6Ops;
use xdp2_protocols::transport::tcp::TcpOps;
use xdp2_protocols::transport::udp::UdpOps;

// --- Metadata type for integration tests ---

/// Simple metadata that records which protocols were visited.
#[derive(Default, Debug)]
struct TestMeta {
    protocols: Vec<&'static str>,
}

// --- Parse node definitions ---
// These must be `static` because the parse graph uses `&'static` references.

static TCP_NODE: ParseNode<TestMeta, TcpOps> = ParseNode {
    proto: TcpOps,
    ops: ParseNodeOps {
        extract_metadata: Some(|_hdr, _len, meta, _ctrl| {
            meta.protocols.push("TCP");
        }),
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "tcp",
};

static UDP_NODE: ParseNode<TestMeta, UdpOps> = ParseNode {
    proto: UdpOps,
    ops: ParseNodeOps {
        extract_metadata: Some(|_hdr, _len, meta, _ctrl| {
            meta.protocols.push("UDP");
        }),
        handler: None,
        post_handler: None,
    },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "udp",
};

static IPV4_TABLE: ProtoTable<TestMeta> = proto_table![
    (6, &TCP_NODE),  // IPPROTO_TCP
    (17, &UDP_NODE), // IPPROTO_UDP
];

static IPV4_NODE: ParseNode<TestMeta, Ipv4Ops> = ParseNode {
    proto: Ipv4Ops,
    ops: ParseNodeOps {
        extract_metadata: Some(|_hdr, _len, meta, _ctrl| {
            meta.protocols.push("IPv4");
        }),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&IPV4_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv4",
};

static IPV6_TABLE: ProtoTable<TestMeta> = proto_table![
    (6, &TCP_NODE),  // IPPROTO_TCP
    (17, &UDP_NODE), // IPPROTO_UDP
];

static IPV6_NODE: ParseNode<TestMeta, Ipv6Ops> = ParseNode {
    proto: Ipv6Ops,
    ops: ParseNodeOps {
        extract_metadata: Some(|_hdr, _len, meta, _ctrl| {
            meta.protocols.push("IPv6");
        }),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&IPV6_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv6",
};

static ETHER_TABLE: ProtoTable<TestMeta> = proto_table![
    (0x0800, &IPV4_NODE), // ETH_P_IP
    (0x86DD, &IPV6_NODE), // ETH_P_IPV6
];

static ETHER_NODE: ParseNode<TestMeta, EthernetOps> = ParseNode {
    proto: EthernetOps,
    ops: ParseNodeOps {
        extract_metadata: Some(|_hdr, _len, meta, _ctrl| {
            meta.protocols.push("Ethernet");
        }),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ethernet",
};

fn make_parser() -> Parser<TestMeta> {
    Parser {
        name: "test-eth-ip-tcp",
        config: ParserConfig::default(),
        root_node: &ETHER_NODE,
        parser_type: ParserType::Generic,
    }
}

// --- Helper: build raw packet bytes ---

/// Build Ethernet + IPv4 + TCP packet bytes.
fn make_eth_ipv4_tcp_packet() -> Vec<u8> {
    let mut pkt = Vec::new();

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]); // dst MAC
    pkt.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x02]); // src MAC
    pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType: IPv4

    // IPv4 header (20 bytes, IHL=5)
    pkt.push((4 << 4) | 5); // version=4, IHL=5
    pkt.push(0); // TOS
    pkt.extend_from_slice(&60u16.to_be_bytes()); // total length (20 IP + 20 TCP + 20 payload)
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ID
    pkt.extend_from_slice(&0u16.to_be_bytes()); // flags + frag offset
    pkt.push(64); // TTL
    pkt.push(6); // protocol = TCP
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
    pkt.extend_from_slice(&[192, 168, 1, 1]); // src IP
    pkt.extend_from_slice(&[10, 0, 0, 1]); // dst IP

    // TCP header (20 bytes, data offset=5)
    pkt.extend_from_slice(&80u16.to_be_bytes()); // src port
    pkt.extend_from_slice(&443u16.to_be_bytes()); // dst port
    pkt.extend_from_slice(&1u32.to_be_bytes()); // seq
    pkt.extend_from_slice(&0u32.to_be_bytes()); // ack
    pkt.push(5 << 4); // data offset=5 (20 bytes)
    pkt.push(0x02); // flags: SYN
    pkt.extend_from_slice(&65535u16.to_be_bytes()); // window
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
    pkt.extend_from_slice(&0u16.to_be_bytes()); // urgent

    // Payload (20 bytes)
    pkt.extend_from_slice(&[0xAA; 20]);

    pkt
}

/// Build Ethernet + IPv4 + UDP packet bytes.
fn make_eth_ipv4_udp_packet() -> Vec<u8> {
    let mut pkt = Vec::new();

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(&[0xFF; 6]); // dst MAC (broadcast)
    pkt.extend_from_slice(&[0x00; 6]); // src MAC
    pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType: IPv4

    // IPv4 header (20 bytes, IHL=5)
    pkt.push((4 << 4) | 5);
    pkt.push(0); // TOS
    pkt.extend_from_slice(&36u16.to_be_bytes()); // total length (20 IP + 8 UDP + 8 payload)
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ID
    pkt.extend_from_slice(&0u16.to_be_bytes()); // flags + frag
    pkt.push(64); // TTL
    pkt.push(17); // protocol = UDP
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
    pkt.extend_from_slice(&[10, 0, 0, 1]); // src IP
    pkt.extend_from_slice(&[10, 0, 0, 255]); // dst IP

    // UDP header (8 bytes)
    pkt.extend_from_slice(&53u16.to_be_bytes()); // src port
    pkt.extend_from_slice(&12345u16.to_be_bytes()); // dst port
    pkt.extend_from_slice(&16u16.to_be_bytes()); // length
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum

    // Payload (8 bytes)
    pkt.extend_from_slice(&[0xBB; 8]);

    pkt
}

/// Build Ethernet + IPv6 + TCP packet bytes.
fn make_eth_ipv6_tcp_packet() -> Vec<u8> {
    let mut pkt = Vec::new();

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(&[0x01; 6]); // dst MAC
    pkt.extend_from_slice(&[0x02; 6]); // src MAC
    pkt.extend_from_slice(&0x86DDu16.to_be_bytes()); // EtherType: IPv6

    // IPv6 header (40 bytes)
    let ver_tc_fl: u32 = 6 << 28; // version=6, TC=0, FL=0
    pkt.extend_from_slice(&ver_tc_fl.to_be_bytes());
    pkt.extend_from_slice(&20u16.to_be_bytes()); // payload length (TCP header)
    pkt.push(6); // next header = TCP
    pkt.push(64); // hop limit
    pkt.extend_from_slice(&[0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // src
    pkt.extend_from_slice(&[0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]); // dst

    // TCP header (20 bytes, data offset=5)
    pkt.extend_from_slice(&8080u16.to_be_bytes()); // src port
    pkt.extend_from_slice(&80u16.to_be_bytes()); // dst port
    pkt.extend_from_slice(&100u32.to_be_bytes()); // seq
    pkt.extend_from_slice(&0u32.to_be_bytes()); // ack
    pkt.push(5 << 4); // data offset=5
    pkt.push(0x02); // SYN
    pkt.extend_from_slice(&65535u16.to_be_bytes()); // window
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
    pkt.extend_from_slice(&0u16.to_be_bytes()); // urgent

    pkt
}

// --- Integration tests ---

#[test]
fn parse_ethernet_ipv4_tcp() {
    let parser = make_parser();
    let pkt = make_eth_ipv4_tcp_packet();
    let result = parse(&parser, &pkt).unwrap();

    assert_eq!(result.result, ParseResult::Okay);
    assert_eq!(result.metadata.protocols, vec!["Ethernet", "IPv4", "TCP"]);
    assert_eq!(result.ctrl.pkt.pkt_len, pkt.len());
}

#[test]
fn parse_ethernet_ipv4_udp() {
    let parser = make_parser();
    let pkt = make_eth_ipv4_udp_packet();
    let result = parse(&parser, &pkt).unwrap();

    assert_eq!(result.result, ParseResult::Okay);
    assert_eq!(result.metadata.protocols, vec!["Ethernet", "IPv4", "UDP"]);
}

#[test]
fn parse_ethernet_ipv6_tcp() {
    let parser = make_parser();
    let pkt = make_eth_ipv6_tcp_packet();
    let result = parse(&parser, &pkt).unwrap();

    assert_eq!(result.result, ParseResult::Okay);
    assert_eq!(result.metadata.protocols, vec!["Ethernet", "IPv6", "TCP"]);
}

#[test]
fn parse_truncated_packet_fails() {
    let parser = make_parser();
    // Only 10 bytes — shorter than Ethernet's 14-byte minimum
    let result = parse(&parser, &[0u8; 10]);
    assert_eq!(result.unwrap_err(), ParseError::Length);
}

#[test]
fn parse_unknown_ethertype_fails() {
    let parser = make_parser();
    let mut pkt = [0u8; 14];
    // EtherType 0x9999 — not in the table
    pkt[12] = 0x99;
    pkt[13] = 0x99;
    let result = parse(&parser, &pkt);
    assert_eq!(result.unwrap_err(), ParseError::UnknownProto);
}

#[test]
fn parse_truncated_at_ipv4_fails() {
    let parser = make_parser();
    let mut pkt = Vec::new();

    // Ethernet header (14 bytes) with IPv4 EtherType
    pkt.extend_from_slice(&[0u8; 12]);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());

    // Only 10 bytes of IPv4 (needs 20)
    pkt.extend_from_slice(&[0u8; 10]);

    let result = parse(&parser, &pkt);
    assert_eq!(result.unwrap_err(), ParseError::Length);
}

#[test]
fn parse_node_count_tracking() {
    let parser = make_parser();
    let pkt = make_eth_ipv4_tcp_packet();
    let result = parse(&parser, &pkt).unwrap();

    // Ethernet → IPv4 → TCP = 3 nodes, but node_cnt tracks increments (2 transitions)
    // Actually: node_cnt increments happen during transition to next node (not for final node)
    // After Ethernet: node_cnt = 1 (transition to IPv4)
    // After IPv4: node_cnt = 2 (transition to TCP)
    // TCP is leaf, no transition
    assert_eq!(result.ctrl.var.node_cnt, 2);
}

// --- VLAN tests ---

static VLAN_TABLE: ProtoTable<TestMeta> = proto_table![
    (0x0800, &IPV4_NODE), // ETH_P_IP
    (0x86DD, &IPV6_NODE), // ETH_P_IPV6
];

static VLAN_NODE: ParseNode<TestMeta, VlanOps> = ParseNode {
    proto: VlanOps,
    ops: ParseNodeOps {
        extract_metadata: Some(|_hdr, _len, meta, _ctrl| {
            meta.protocols.push("VLAN");
        }),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&VLAN_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "vlan",
};

static ETHER_WITH_VLAN_TABLE: ProtoTable<TestMeta> = proto_table![
    (0x0800, &IPV4_NODE), // ETH_P_IP
    (0x86DD, &IPV6_NODE), // ETH_P_IPV6
    (0x8100, &VLAN_NODE), // ETH_P_8021Q
];

static ETHER_VLAN_NODE: ParseNode<TestMeta, EthernetOps> = ParseNode {
    proto: EthernetOps,
    ops: ParseNodeOps {
        extract_metadata: Some(|_hdr, _len, meta, _ctrl| {
            meta.protocols.push("Ethernet");
        }),
        handler: None,
        post_handler: None,
    },
    proto_table: Some(&ETHER_WITH_VLAN_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ethernet-vlan",
};

#[test]
fn parse_ethernet_vlan_ipv4_tcp() {
    let parser = Parser {
        name: "test-eth-vlan-ip-tcp",
        config: ParserConfig::default(),
        root_node: &ETHER_VLAN_NODE,
        parser_type: ParserType::Generic,
    };

    let mut pkt = Vec::new();

    // Ethernet header (14 bytes) with VLAN EtherType
    pkt.extend_from_slice(&[0u8; 12]); // MACs
    pkt.extend_from_slice(&0x8100u16.to_be_bytes()); // EtherType: 802.1Q

    // VLAN header (4 bytes)
    let tci: u16 = (3 << 13) | 100; // priority=3, VID=100
    pkt.extend_from_slice(&tci.to_be_bytes());
    pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // encapsulated: IPv4

    // IPv4 header (20 bytes, IHL=5)
    pkt.push((4 << 4) | 5);
    pkt.push(0);
    pkt.extend_from_slice(&40u16.to_be_bytes()); // total length
    pkt.extend_from_slice(&[0; 4]); // ID + frag
    pkt.push(64); // TTL
    pkt.push(6); // TCP
    pkt.extend_from_slice(&[0; 2]); // checksum
    pkt.extend_from_slice(&[10, 0, 0, 1]); // src
    pkt.extend_from_slice(&[10, 0, 0, 2]); // dst

    // TCP header (20 bytes)
    pkt.extend_from_slice(&80u16.to_be_bytes()); // src port
    pkt.extend_from_slice(&443u16.to_be_bytes()); // dst port
    pkt.extend_from_slice(&[0; 8]); // seq + ack
    pkt.push(5 << 4); // data offset
    pkt.push(0x02); // SYN
    pkt.extend_from_slice(&65535u16.to_be_bytes()); // window
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
    pkt.extend_from_slice(&0u16.to_be_bytes()); // urgent

    let result = parse(&parser, &pkt).unwrap();
    assert_eq!(result.result, ParseResult::Okay);
    assert_eq!(
        result.metadata.protocols,
        vec!["Ethernet", "VLAN", "IPv4", "TCP"]
    );
}
