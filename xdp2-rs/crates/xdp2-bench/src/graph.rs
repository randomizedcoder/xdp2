//! Static parse graph for benchmarking.
//!
//! Builds an Ethernet → IP → Transport parse graph matching the protocol
//! coverage of the C flow_dissector benchmark. Uses protocol Ops from
//! xdp2-protocols with empty metadata for minimal overhead.
//!
//! ## Protocol Coverage
//!
//! ```text
//! Ethernet ──┬── 0x0800 → IPv4 ──┬── 6   → TCP
//!            │                    ├── 17  → UDP
//!            │                    ├── 1   → ICMPv4
//!            │                    ├── 132 → SCTP
//!            │                    ├── 4   → IP-in-IP ──→ (IPv4 dispatch)
//!            │                    └── 51  → AH ──→ (IPv4 dispatch)
//!            │
//!            ├── 0x86DD → IPv6 ──┬── 6   → TCP
//!            │                   ├── 17  → UDP
//!            │                   ├── 58  → ICMPv6
//!            │                   ├── 132 → SCTP
//!            │                   ├── 0   → IPv6 HBH EH ──→ (IPv6 dispatch)
//!            │                   ├── 60  → IPv6 Dest EH ──→ (IPv6 dispatch)
//!            │                   ├── 43  → IPv6 Routing EH
//!            │                   ├── 44  → IPv6 Fragment EH ──→ (IPv6 dispatch)
//!            │                   └── 51  → AH ──→ (IPv6 dispatch)
//!            │
//!            ├── 0x8100 → VLAN ──→ (Ethernet dispatch)
//!            ├── 0x88A8 → QinQ ──→ (Ethernet dispatch)
//!            └── 0x0806 → ARP
//! ```

use xdp2_core::{
    parse, ParseError, ParseNode, ParseNodeOps, ParseOutput,
    Parser, ParserConfig, ParserType, ProtoTable,
    proto_table,
};
use xdp2_protocols::ethernet::ether::EthernetOps;
use xdp2_protocols::ethernet::vlan::VlanOps;
use xdp2_protocols::ethernet::qinq::QinQOps;
use xdp2_protocols::ip::arp::ArpOps;
use xdp2_protocols::ip::ipv4::Ipv4Ops;
use xdp2_protocols::ip::ipv6::Ipv6Ops;
use xdp2_protocols::ip::ipv6_eh::{Ipv6EhOps, Ipv6FragOps};
use xdp2_protocols::ip::icmp::{IcmpV4Ops, IcmpV6Ops};
use xdp2_protocols::transport::tcp::TcpOps;
use xdp2_protocols::transport::udp::UdpOps;
use xdp2_protocols::transport::sctp::SctpOps;
use xdp2_protocols::tunnel::ip_in_ip::IpInIpOps;
use xdp2_protocols::security::ah::AhOps;

/// Empty metadata type for benchmarking — zero overhead.
#[derive(Default)]
pub struct BenchMeta;

// ── Leaf nodes (no proto_table, parsing stops here) ───────────────

static TCP_NODE: ParseNode<BenchMeta, TcpOps> = ParseNode {
    proto: TcpOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "tcp",
};

static UDP_NODE: ParseNode<BenchMeta, UdpOps> = ParseNode {
    proto: UdpOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "udp",
};

static ICMPV4_NODE: ParseNode<BenchMeta, IcmpV4Ops> = ParseNode {
    proto: IcmpV4Ops,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "icmpv4",
};

static ICMPV6_NODE: ParseNode<BenchMeta, IcmpV6Ops> = ParseNode {
    proto: IcmpV6Ops,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "icmpv6",
};

static SCTP_NODE: ParseNode<BenchMeta, SctpOps> = ParseNode {
    proto: SctpOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "sctp",
};

static ARP_NODE: ParseNode<BenchMeta, ArpOps> = ParseNode {
    proto: ArpOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: None,
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "arp",
};

// ── IPv4 dispatch ─────────────────────────────────────────────────

static IPV4_TABLE: ProtoTable<BenchMeta> = proto_table![
    (6, &TCP_NODE),       // IPPROTO_TCP
    (17, &UDP_NODE),      // IPPROTO_UDP
    (1, &ICMPV4_NODE),    // IPPROTO_ICMP
    (132, &SCTP_NODE),    // IPPROTO_SCTP
    (4, &IPIP_NODE),      // IPPROTO_IPIP
    (51, &AH_V4_NODE),    // IPPROTO_AH
];

static IPV4_NODE: ParseNode<BenchMeta, Ipv4Ops> = ParseNode {
    proto: Ipv4Ops,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&IPV4_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv4",
};

// ── IP-in-IP (protocol 4) — dispatches like IPv4 ──────────────────

static IPIP_TABLE: ProtoTable<BenchMeta> = proto_table![
    (6, &TCP_NODE),
    (17, &UDP_NODE),
    (1, &ICMPV4_NODE),
];

static IPIP_NODE: ParseNode<BenchMeta, IpInIpOps> = ParseNode {
    proto: IpInIpOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&IPIP_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ip-in-ip",
};

// ── AH (Authentication Header) — chains to next protocol ──────────

static AH_V4_NODE: ParseNode<BenchMeta, AhOps> = ParseNode {
    proto: AhOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&IPV4_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ah-v4",
};

static AH_V6_NODE: ParseNode<BenchMeta, AhOps> = ParseNode {
    proto: AhOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&IPV6_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ah-v6",
};

// ── IPv6 dispatch ─────────────────────────────────────────────────

static IPV6_TABLE: ProtoTable<BenchMeta> = proto_table![
    (6, &TCP_NODE),        // IPPROTO_TCP
    (17, &UDP_NODE),       // IPPROTO_UDP
    (58, &ICMPV6_NODE),    // IPPROTO_ICMPV6
    (132, &SCTP_NODE),     // IPPROTO_SCTP
    (0, &IPV6_HBH_NODE),  // IPPROTO_HOPOPTS
    (60, &IPV6_DST_NODE),  // IPPROTO_DSTOPTS
    (44, &IPV6_FRAG_NODE), // IPPROTO_FRAGMENT
    (51, &AH_V6_NODE),     // IPPROTO_AH
];

static IPV6_NODE: ParseNode<BenchMeta, Ipv6Ops> = ParseNode {
    proto: Ipv6Ops,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&IPV6_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv6",
};

// ── IPv6 extension headers ────────────────────────────────────────

static IPV6_HBH_NODE: ParseNode<BenchMeta, Ipv6EhOps> = ParseNode {
    proto: Ipv6EhOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&IPV6_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv6-hbh",
};

static IPV6_DST_NODE: ParseNode<BenchMeta, Ipv6EhOps> = ParseNode {
    proto: Ipv6EhOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&IPV6_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv6-dst",
};

static IPV6_FRAG_NODE: ParseNode<BenchMeta, Ipv6FragOps> = ParseNode {
    proto: Ipv6FragOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&IPV6_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ipv6-frag",
};

// ── Ethernet + VLAN dispatch ──────────────────────────────────────

static ETHER_TABLE: ProtoTable<BenchMeta> = proto_table![
    (0x0800, &IPV4_NODE),  // ETH_P_IP
    (0x86DD, &IPV6_NODE),  // ETH_P_IPV6
    (0x8100, &VLAN_NODE),  // ETH_P_8021Q
    (0x88A8, &QINQ_NODE),  // ETH_P_8021AD
    (0x0806, &ARP_NODE),   // ETH_P_ARP
];

static ETHER_NODE: ParseNode<BenchMeta, EthernetOps> = ParseNode {
    proto: EthernetOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "ethernet",
};

static VLAN_NODE: ParseNode<BenchMeta, VlanOps> = ParseNode {
    proto: VlanOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "vlan",
};

static QINQ_NODE: ParseNode<BenchMeta, QinQOps> = ParseNode {
    proto: QinQOps,
    ops: ParseNodeOps { extract_metadata: None, handler: None, post_handler: None },
    proto_table: Some(&ETHER_TABLE),
    wildcard_node: None,
    unknown_ret: ParseError::UnknownProto,
    name: "qinq",
};

// ── Parser entry point ────────────────────────────────────────────

/// Build the benchmark parser.
pub fn make_parser() -> Parser<BenchMeta> {
    Parser {
        name: "bench-flow-dissector",
        config: ParserConfig::default(),
        root_node: &ETHER_NODE,
        parser_type: ParserType::Generic,
    }
}

/// Parse a single packet, returning Ok or Err.
#[inline]
pub fn parse_packet(parser: &Parser<BenchMeta>, pkt: &[u8]) -> Result<ParseOutput<BenchMeta>, ParseError> {
    parse(parser, pkt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xdp2_core::ParseResult;

    /// Ethernet + IPv4 + TCP (54 bytes minimum).
    fn make_eth_ipv4_tcp() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]);            // MACs
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType: IPv4
        pkt.push((4 << 4) | 5);                       // IPv4 ver=4, IHL=5
        pkt.push(0);                                   // TOS
        pkt.extend_from_slice(&40u16.to_be_bytes());   // total length
        pkt.extend_from_slice(&[0; 4]);                // ID + frag
        pkt.push(64);                                  // TTL
        pkt.push(6);                                   // protocol = TCP
        pkt.extend_from_slice(&[0; 2]);                // checksum
        pkt.extend_from_slice(&[10, 0, 0, 1]);        // src IP
        pkt.extend_from_slice(&[10, 0, 0, 2]);        // dst IP
        // TCP header (20 bytes)
        pkt.extend_from_slice(&80u16.to_be_bytes());   // src port
        pkt.extend_from_slice(&443u16.to_be_bytes());  // dst port
        pkt.extend_from_slice(&[0; 8]);                // seq + ack
        pkt.push(5 << 4);                              // data offset=5
        pkt.push(0x02);                                // SYN
        pkt.extend_from_slice(&[0; 6]);                // window + cksum + urg
        pkt
    }

    #[test]
    fn parse_eth_ipv4_tcp() {
        let parser = make_parser();
        let pkt = make_eth_ipv4_tcp();
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_vlan_ipv4_tcp() {
        let parser = make_parser();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x8100u16.to_be_bytes()); // VLAN
        pkt.extend_from_slice(&100u16.to_be_bytes());    // TCI
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // inner: IPv4
        // IPv4 + TCP
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(6);
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 8]);
        pkt.push(5 << 4);
        pkt.push(0x02);
        pkt.extend_from_slice(&[0; 6]);

        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }
}
