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
mod tests {
    use super::*;
    use xdp2_core::ParseResult;

    /// Ethernet + IPv4 + TCP (54 bytes minimum).
    fn make_eth_ipv4_tcp() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]); // MACs
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType: IPv4
        pkt.push((4 << 4) | 5); // IPv4 ver=4, IHL=5
        pkt.push(0); // TOS
        pkt.extend_from_slice(&40u16.to_be_bytes()); // total length
        pkt.extend_from_slice(&[0; 4]); // ID + frag
        pkt.push(64); // TTL
        pkt.push(6); // protocol = TCP
        pkt.extend_from_slice(&[0; 2]); // checksum
        pkt.extend_from_slice(&[10, 0, 0, 1]); // src IP
        pkt.extend_from_slice(&[10, 0, 0, 2]); // dst IP
                                               // TCP header (20 bytes)
        pkt.extend_from_slice(&80u16.to_be_bytes()); // src port
        pkt.extend_from_slice(&443u16.to_be_bytes()); // dst port
        pkt.extend_from_slice(&[0; 8]); // seq + ack
        pkt.push(5 << 4); // data offset=5
        pkt.push(0x02); // SYN
        pkt.extend_from_slice(&[0; 6]); // window + cksum + urg
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
    fn parse_eth_ipv4_udp_non_tunnel() {
        // Regular UDP (non-tunnel port) should still parse via wildcard.
        let parser = make_parser();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]); // MACs
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        pkt.push((4 << 4) | 5); // ver=4, IHL=5
        pkt.push(0);
        pkt.extend_from_slice(&28u16.to_be_bytes()); // total length
        pkt.extend_from_slice(&[0; 4]); // ID + frag
        pkt.push(64); // TTL
        pkt.push(17); // protocol = UDP
        pkt.extend_from_slice(&[0; 2]); // checksum
        pkt.extend_from_slice(&[10, 0, 0, 1]); // src IP
        pkt.extend_from_slice(&[10, 0, 0, 2]); // dst IP
                                               // UDP header (8 bytes) — non-tunnel dport
        pkt.extend_from_slice(&1234u16.to_be_bytes()); // src port
        pkt.extend_from_slice(&5678u16.to_be_bytes()); // dst port (not a tunnel)
        pkt.extend_from_slice(&8u16.to_be_bytes()); // length
        pkt.extend_from_slice(&[0; 2]); // checksum
        let result = parse_packet(&parser, &pkt).unwrap();
        // Wildcard UDP_LEAF_NODE is hit, parse succeeds.
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_vxlan_inner_tcp() {
        // Eth → IPv4 → UDP(4789) → VXLAN → inner Eth → IPv4 → TCP
        let parser = make_parser();
        let mut pkt = Vec::new();
        // Outer Ethernet
        pkt.extend_from_slice(&[0u8; 12]); // MACs
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
                                                         // Outer IPv4
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&100u16.to_be_bytes()); // total length (unused by parser)
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(17); // UDP
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        // Outer UDP → VXLAN port
        pkt.extend_from_slice(&12345u16.to_be_bytes()); // src port
        pkt.extend_from_slice(&4789u16.to_be_bytes()); // dst port = VXLAN
        pkt.extend_from_slice(&80u16.to_be_bytes()); // length
        pkt.extend_from_slice(&[0; 2]); // checksum
                                        // VXLAN header (8 bytes)
        pkt.extend_from_slice(&[0x08, 0, 0, 0]); // flags (I bit set)
        pkt.extend_from_slice(&[0x12, 0x34, 0x56, 0]); // VNI
                                                       // Inner Ethernet
        pkt.extend_from_slice(&[0u8; 12]); // MACs
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
                                                         // Inner IPv4
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(6); // TCP
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[192, 168, 1, 1]);
        pkt.extend_from_slice(&[192, 168, 1, 2]);
        // Inner TCP (20 bytes)
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 8]);
        pkt.push(5 << 4);
        pkt.push(0x02);
        pkt.extend_from_slice(&[0; 6]);

        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_geneve_inner_tcp() {
        // Eth → IPv4 → UDP(6081) → Geneve → inner Eth → IPv4 → TCP
        let parser = make_parser();
        let mut pkt = Vec::new();
        // Outer Ethernet
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        // Outer IPv4
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&100u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(17); // UDP
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        // Outer UDP → Geneve port
        pkt.extend_from_slice(&12345u16.to_be_bytes());
        pkt.extend_from_slice(&6081u16.to_be_bytes()); // dst port = Geneve
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 2]);
        // Geneve header (8 bytes, no options)
        pkt.push(0x00); // ver=0, optlen=0
        pkt.push(0x00); // flags
        pkt.extend_from_slice(&0x6558u16.to_be_bytes()); // protocol = ETH_P_TEB
        pkt.extend_from_slice(&[0x12, 0x34, 0x56, 0]); // VNI
                                                       // Inner Ethernet
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        // Inner IPv4
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(6); // TCP
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[192, 168, 1, 1]);
        pkt.extend_from_slice(&[192, 168, 1, 2]);
        // Inner TCP
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 8]);
        pkt.push(5 << 4);
        pkt.push(0x02);
        pkt.extend_from_slice(&[0; 6]);

        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    /// Ethernet + IPv4 + GRE v0 (no flags) + IPv4 + TCP.
    fn make_gre_v0_ipv4_tcp(gre_flags: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Outer Ethernet
        pkt.extend_from_slice(&[0u8; 12]); // MACs
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
                                                         // Outer IPv4 (protocol=47 GRE)
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&100u16.to_be_bytes()); // total length
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(47); // IPPROTO_GRE
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        // GRE header: flags + protocol
        pkt.extend_from_slice(&gre_flags.to_be_bytes());
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // inner IPv4
                                                         // Optional flag fields
        if gre_flags & 0x8000 != 0 {
            pkt.extend_from_slice(&[0xAA, 0xBB, 0, 0]);
        } // csum+reserved
        if gre_flags & 0x2000 != 0 {
            pkt.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        } // key
        if gre_flags & 0x1000 != 0 {
            pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x42]);
        } // seq
          // Inner IPv4 + TCP
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(6); // TCP
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[192, 168, 1, 1]);
        pkt.extend_from_slice(&[192, 168, 1, 2]);
        // Inner TCP
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 8]);
        pkt.push(5 << 4);
        pkt.push(0x02);
        pkt.extend_from_slice(&[0; 6]);
        pkt
    }

    #[test]
    fn parse_gre_v0_no_flags() {
        let parser = make_parser();
        let pkt = make_gre_v0_ipv4_tcp(0x0000);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_gre_v0_with_key() {
        let parser = make_parser();
        let pkt = make_gre_v0_ipv4_tcp(0x2000); // key flag
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
        // Verify key was extracted via flag-field callback.
        let key_bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        let expected_key = u32::from_ne_bytes(key_bytes);
        assert_eq!(result.metadata.gre.keyid, expected_key);
        assert_eq!(result.metadata.keyid, expected_key);
    }

    #[test]
    fn parse_gre_v0_all_flags() {
        let parser = make_parser();
        let pkt = make_gre_v0_ipv4_tcp(0x8000 | 0x2000 | 0x1000); // csum+key+seq
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
        // Verify GRE flags were extracted.
        assert_eq!(result.metadata.gre.flags, 0x8000 | 0x2000 | 0x1000);
        // Verify checksum extracted.
        let expected_csum = u16::from_ne_bytes([0xAA, 0xBB]);
        assert_eq!(result.metadata.gre.csum, expected_csum);
        // Verify key extracted.
        let expected_key = u32::from_ne_bytes([0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(result.metadata.gre.keyid, expected_key);
        // Verify sequence extracted.
        let expected_seq = u32::from_ne_bytes([0x00, 0x00, 0x00, 0x42]);
        assert_eq!(result.metadata.gre.seq, expected_seq);
    }

    #[test]
    fn parse_gre_v0_inner_ethernet() {
        // GRE v0 carrying Ethernet (TEB) — used for NVGRE-like encapsulation.
        let parser = make_parser();
        let mut pkt = Vec::new();
        // Outer Ethernet + IPv4 (proto=47)
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&100u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(47);
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        // GRE: flags=key(0x2000), protocol=ETH_P_TEB(0x6558)
        pkt.extend_from_slice(&0x2000u16.to_be_bytes());
        pkt.extend_from_slice(&0x6558u16.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // key
                                                          // Inner Ethernet + IPv4 + TCP
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(6);
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[192, 168, 1, 1]);
        pkt.extend_from_slice(&[192, 168, 1, 2]);
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 8]);
        pkt.push(5 << 4);
        pkt.push(0x02);
        pkt.extend_from_slice(&[0; 6]);

        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn metadata_ipv4_tcp() {
        // Verify that metadata extractors populate FlowMeta correctly.
        let parser = make_parser();
        let pkt = make_eth_ipv4_tcp();
        let result = parse_packet(&parser, &pkt).unwrap();
        let m = &result.metadata;
        // Ethernet extractor: MACs + ethertype
        assert_eq!(m.eth_proto, 0x0800);
        // IPv4 extractor: addresses, protocol
        assert_eq!(m.addr_type, AddrType::Ipv4);
        assert_eq!(m.ip_proto, 6); // TCP
        assert_eq!(m.addrs.v4_src, u32::from_be_bytes([10, 0, 0, 1]));
        assert_eq!(m.addrs.v4_dst, u32::from_be_bytes([10, 0, 0, 2]));
        assert!(!m.is_fragment);
        // Port extractor: TCP ports
        assert_eq!(m.ports.src_port, 80);
        assert_eq!(m.ports.dst_port, 443);
    }

    #[test]
    fn metadata_vlan() {
        // Verify VLAN TCI extraction.
        let parser = make_parser();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xAA; 6]); // dst MAC
        pkt.extend_from_slice(&[0xBB; 6]); // src MAC
        pkt.extend_from_slice(&0x8100u16.to_be_bytes()); // VLAN
        pkt.extend_from_slice(&100u16.to_be_bytes()); // TCI = 100
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // inner: IPv4
                                                         // IPv4 + TCP (just enough)
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
        assert_eq!(result.metadata.vlan_count, 1);
        assert_eq!(result.metadata.vlan[0].tci, 100);
        assert_eq!(result.metadata.vlan[0].tpid, 0x8100);
    }

    #[test]
    fn metadata_icmpv4_echo() {
        // ICMPv4 echo request → type, code, id extracted.
        let parser = make_parser();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]); // MACs
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&28u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(1); // ICMP
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        // ICMP echo request
        pkt.push(8); // type = echo request
        pkt.push(0); // code
        pkt.extend_from_slice(&[0; 2]); // checksum
        pkt.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        pkt.extend_from_slice(&[0; 2]); // sequence

        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.metadata.icmp.icmp_type, 8);
        assert_eq!(result.metadata.icmp.code, 0);
        assert_eq!(result.metadata.icmp.id, 0x1234);
    }

    #[test]
    fn parse_vlan_ipv4_tcp() {
        let parser = make_parser();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x8100u16.to_be_bytes()); // VLAN
        pkt.extend_from_slice(&100u16.to_be_bytes()); // TCI
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

    // ── Phase 4: L2 leaf protocol tests ──

    /// Helper: build Eth frame with given ethertype + payload bytes.
    fn make_eth_l2(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]); // MACs
        pkt.extend_from_slice(&ethertype.to_be_bytes());
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn parse_lldp() {
        let parser = make_parser();
        // LLDP: MIN_LEN=2
        let pkt = make_eth_l2(0x88CC, &[0x02, 0x00, 0x07, 0x04, 0x00, 0x00]);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_slow() {
        let parser = make_parser();
        // SLOW (LACP/STP): MIN_LEN=1
        let pkt = make_eth_l2(0x8809, &[0x01, 0x01, 0x00, 0x00]);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_ptp() {
        let parser = make_parser();
        // PTP: MIN_LEN=34
        let pkt = make_eth_l2(0x88F7, &[0; 34]);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_eapol() {
        let parser = make_parser();
        // EAPOL (802.1X): MIN_LEN varies
        let pkt = make_eth_l2(0x888E, &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_mpls_in_ether() {
        let parser = make_parser();
        // MPLS unicast in Ethernet: ethertype 0x8847, MIN_LEN=8 (2 label entries)
        let mut payload = [0u8; 8];
        // Set BoS=1 on first label entry (byte 2, bit 0)
        payload[2] |= 0x01;
        let pkt = make_eth_l2(0x8847, &payload);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
        assert_eq!(result.metadata.mpls.bos, true);
    }

    #[test]
    fn parse_rarp() {
        let parser = make_parser();
        // RARP: MIN_LEN=28, validated via ArpOps::header_len().
        // Note: ArpOps only accepts op=1/2; RarpOps delegates to it.
        // Use op=1 to pass validation (xdp2-protocols bug: RARP ops 3/4 rejected).
        let mut payload = [0u8; 28];
        payload[0..2].copy_from_slice(&1u16.to_be_bytes()); // ar_hrd = ARPHRD_ETHER
        payload[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // ar_pro = IPv4
        payload[4] = 6; // ar_hln = ETH_ALEN
        payload[5] = 4; // ar_pln = 4
        payload[6..8].copy_from_slice(&1u16.to_be_bytes()); // ar_op = REQUEST (workaround)
        let pkt = make_eth_l2(0x8035, &payload);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_tipc() {
        let parser = make_parser();
        // TIPC: MIN_LEN=16, originating node at bytes 8-11
        let mut payload = [0u8; 16];
        payload[8..12].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        let pkt = make_eth_l2(0x88CA, &payload);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
        assert_eq!(result.metadata.addr_type, AddrType::Tipc);
        assert_eq!(result.metadata.addrs.tipc_key, 0xDEADBEEF);
    }

    #[test]
    fn parse_pppoe_ipv4_tcp() {
        // PPPoE → IPv4 → TCP
        let parser = make_parser();
        let mut pkt = Vec::new();
        // Ethernet
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x8864u16.to_be_bytes()); // ETH_P_PPP_SES
                                                         // PPPoE header (8 bytes): ver=1, type=1, code=0, session_id, length, ppp_proto
        pkt.push(0x11); // ver=1, type=1
        pkt.push(0x00); // code=0 (session data)
        pkt.extend_from_slice(&[0x00, 0x01]); // session ID
        pkt.extend_from_slice(&44u16.to_be_bytes()); // length
        pkt.extend_from_slice(&0x0021u16.to_be_bytes()); // PPP protocol = IPv4
                                                         // IPv4 + TCP
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(6); // TCP
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        // TCP header
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 8]);
        pkt.push(5 << 4);
        pkt.push(0x02);
        pkt.extend_from_slice(&[0; 6]);

        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
        assert_eq!(result.metadata.addr_type, AddrType::Ipv4);
        assert_eq!(result.metadata.ports.src_port, 80);
    }

    #[test]
    fn parse_macsec() {
        let parser = make_parser();
        let pkt = make_eth_l2(0x88E5, &[0; 16]);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }

    #[test]
    fn parse_ethercat() {
        let parser = make_parser();
        let pkt = make_eth_l2(0x88A4, &[0; 8]);
        let result = parse_packet(&parser, &pkt).unwrap();
        assert_eq!(result.result, ParseResult::Okay);
    }
}
