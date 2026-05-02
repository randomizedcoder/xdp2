// FlowMeta fields and UdpDportOps are used in later phases (metadata extraction, tunnel dispatch).
#![allow(dead_code)]

//! Static parse graph for benchmarking.
//!
//! Builds an Ethernet → IP → Transport parse graph matching the protocol
//! coverage of the C flow_dissector benchmark. Uses protocol Ops from
//! xdp2-protocols with FlowMeta metadata extraction to match C's
//! `xdp2_metadata_all` for apples-to-apples benchmarking.
//!
//! ## Protocol Coverage
//!
//! **Ether table (28 entries):**
//! - Core L3: IPv4, IPv6 (via IP check overlay), ARP, RARP
//! - VLAN: 802.1Q, 802.1AD (QinQ) — with LLC detection (ethertype ≤ 1500)
//! - MPLS: unicast (0x8847), multicast (0x8848)
//! - Tunnels: PPPoE→PPP→IP, BATMAN, PBB, TRILL, HSR/PRP, NSH
//! - Management leaves: LLDP, SLOW, MAC_CONTROL, EAPOL, PTP, MVRP, CFM, FIP
//! - Security/storage leaves: MACsec, EtherCAT, TIPC, FCoE
//! - LLC: IEEE 802.2 dispatch (SNAP → ethertype re-dispatch, STP leaf)
//!
//! **IPv4/IPv6 tables (14/17 entries):**
//! TCP, UDP (tunnel dispatch), ICMP, IGMP, SCTP, DCCP, UDPLite,
//! GRE (flag-fields), ESP, AH, MPLS, IP-in-IP, L2TP
//!
//! **Tunnel dispatch:** UDP dport → VXLAN (4789), Geneve (6081)
//! **GRE v0:** flag-field sub-parsing (csum/key/seq) → IPv4/IPv6/TEB

pub(crate) use crate::flow_meta::*;

use crate::nodes::ETHER_NODE;
use xdp2_core::{parse, ParseError, ParseOutput, Parser, ParserConfig, ParserType};

// ── Parser entry point ────────────────────────────────────────────

/// Build the benchmark parser.
pub fn make_parser() -> Parser<FlowMeta> {
    Parser {
        name: "bench-flow-dissector",
        config: ParserConfig::default(),
        root_node: &ETHER_NODE,
        parser_type: ParserType::Generic,
    }
}

/// Parse a single packet, returning Ok or Err.
#[inline]
pub fn parse_packet(
    parser: &Parser<FlowMeta>,
    pkt: &[u8],
) -> Result<ParseOutput<FlowMeta>, ParseError> {
    parse(parser, pkt)
}

#[cfg(test)]
#[path = "graph_tests.rs"]
mod tests;
