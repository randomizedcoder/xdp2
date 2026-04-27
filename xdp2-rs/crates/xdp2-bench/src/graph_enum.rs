//! Enum-dispatch graph benchmark — proof-of-concept for Option A from
//! `docs/performance-next-steps.md`.
//!
//! This mode is gated behind the `graph-enum` cargo feature (on by default
//! in xdp2-bench so it builds out of the box, but fully opt-out-able and
//! never disturbs the dyn-dispatch `graph` mode).
//!
//! ## Scope
//!
//! Minimal graph covering Ether → IPv4 → {TCP, UDP, ICMPv4} — enough to
//! parse `tcp_ipv4.pcap` and demonstrate a like-for-like A/B comparison
//! against `ParserMode::Graph` (which uses the full dyn-dispatch graph).
//! We deliberately keep the enum small: the goal for this session is to
//! prove the compile-time switch and measure the dispatch overhead on the
//! hottest protocol chain. Broader protocol coverage is follow-up work.
//!
//! ## How it differs from `graph.rs`
//!
//! - Root is a `BenchNode` enum; dispatch is a `match` at each step.
//! - Tables are `ProtoTableEnum` (static-dispatch variant) instead of
//!   `ProtoTable` (which stores `&dyn ParseNodeDyn`).
//! - The engine is [`xdp2_core::enum_dispatch::parse_enum`], a monomorphic
//!   twin of the default `parse()` loop.

#![cfg(feature = "graph-enum")]
// Items are consumed from main.rs; the library target doesn't reference them.
#![allow(dead_code)]

use xdp2_core::enum_dispatch::{parse_enum, NodeOps, ProtoTableEnum};
use xdp2_core::{
    proto_table_enum, CtrlData, NodeType, ParseError, ParseOutput, ParserConfig, ProtocolOps,
};
use xdp2_protocols::ip::icmp::IcmpV4Ops;
use xdp2_protocols::ip::ipv4::Ipv4Ops;
use xdp2_protocols::transport::tcp::TcpOps;

use crate::extractors::{
    extract_ether_metadata, extract_icmp_metadata, extract_ipv4_metadata, extract_ports_metadata,
    extract_tcp_metadata,
};
use crate::flow_meta::FlowMeta;

// ── Bench-local Ops types (minimal stand-ins for their dyn counterparts) ──

/// Ethernet 14-byte header — returns raw ethertype (no LLC detection in this
/// minimal graph; tcp_ipv4.pcap is pure Ether/IPv4/TCP).
struct EtherOps;
impl ProtocolOps for EtherOps {
    const MIN_LEN: usize = 14;
    const NAME: &'static str = "Ether";
    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        Ok(u16::from_be_bytes([hdr[12], hdr[13]]) as i32)
    }
}

/// UDP 8-byte header — returns dport, but the minimal graph treats UDP as a
/// leaf (no tunnel table) so this is unused at runtime.
struct UdpOps;
impl ProtocolOps for UdpOps {
    const MIN_LEN: usize = 8;
    const NAME: &'static str = "UDP";
    #[inline]
    fn next_proto(&self, _hdr: &[u8]) -> Result<i32, ParseError> {
        Err(ParseError::UnknownProto)
    }
}

// ── Node enum ────────────────────────────────────────────────────────────
//
// Each variant is a unit marker — the engine identifies protocols by the
// discriminant alone. All parsing state comes from `&[u8]` and `&mut
// FlowMeta`. This keeps the enum small (a single byte) so the `match` in
// `NodeOps` lowers to a jump table.

#[derive(Clone, Copy)]
pub(crate) enum BenchNode {
    Ether,
    Ipv4,
    Tcp,
    Udp,
    IcmpV4,
}

// ── Static nodes, one per variant ─────────────────────────────────────────
//
// These are bare `BenchNode` values; `&'static BenchNode::Ipv4` etc. are
// what the ProtoTableEnum entries point at.

static ETHER: BenchNode = BenchNode::Ether;
static IPV4: BenchNode = BenchNode::Ipv4;
static TCP: BenchNode = BenchNode::Tcp;
static UDP: BenchNode = BenchNode::Udp;
static ICMPV4: BenchNode = BenchNode::IcmpV4;

// ── Protocol tables ──────────────────────────────────────────────────────

static ETHER_TABLE: ProtoTableEnum<FlowMeta, BenchNode> = proto_table_enum![(0x0800, &IPV4),];

static IPV4_TABLE: ProtoTableEnum<FlowMeta, BenchNode> =
    proto_table_enum![(6, &TCP), (17, &UDP), (1, &ICMPV4),];

// ── NodeOps impl — the match-dispatch core ───────────────────────────────

impl NodeOps<FlowMeta> for BenchNode {
    #[inline]
    fn min_len(&self) -> usize {
        match self {
            BenchNode::Ether => EtherOps::MIN_LEN,
            BenchNode::Ipv4 => Ipv4Ops::MIN_LEN,
            BenchNode::Tcp => TcpOps::MIN_LEN,
            BenchNode::Udp => UdpOps::MIN_LEN,
            BenchNode::IcmpV4 => IcmpV4Ops::MIN_LEN,
        }
    }

    #[inline]
    fn name(&self) -> &'static str {
        match self {
            BenchNode::Ether => "ether",
            BenchNode::Ipv4 => "ipv4",
            BenchNode::Tcp => "tcp",
            BenchNode::Udp => "udp",
            BenchNode::IcmpV4 => "icmpv4",
        }
    }

    #[inline]
    fn node_type(&self) -> NodeType {
        NodeType::Plain
    }

    #[inline]
    fn is_encap(&self) -> bool {
        false
    }

    #[inline]
    fn is_overlay(&self) -> bool {
        false
    }

    #[inline]
    fn header_len(&self, hdr: &[u8], maxlen: usize) -> Result<usize, ParseError> {
        match self {
            BenchNode::Ether => EtherOps.header_len(hdr, maxlen),
            BenchNode::Ipv4 => Ipv4Ops.header_len(hdr, maxlen),
            BenchNode::Tcp => TcpOps.header_len(hdr, maxlen),
            BenchNode::Udp => UdpOps.header_len(hdr, maxlen),
            BenchNode::IcmpV4 => IcmpV4Ops.header_len(hdr, maxlen),
        }
    }

    #[inline]
    fn next_proto(&self, hdr: &[u8]) -> Result<i32, ParseError> {
        match self {
            BenchNode::Ether => EtherOps.next_proto(hdr),
            BenchNode::Ipv4 => Ipv4Ops.next_proto(hdr),
            BenchNode::Tcp => Err(ParseError::UnknownProto),
            BenchNode::Udp => Err(ParseError::UnknownProto),
            BenchNode::IcmpV4 => Err(ParseError::UnknownProto),
        }
    }

    #[inline]
    fn extract_metadata(
        &self,
        hdr: &[u8],
        hdr_len: usize,
        metadata: &mut FlowMeta,
        ctrl: &CtrlData,
    ) {
        match self {
            BenchNode::Ether => extract_ether_metadata(hdr, hdr_len, metadata, ctrl),
            BenchNode::Ipv4 => extract_ipv4_metadata(hdr, hdr_len, metadata, ctrl),
            BenchNode::Tcp => extract_tcp_metadata(hdr, hdr_len, metadata, ctrl),
            BenchNode::Udp => extract_ports_metadata(hdr, hdr_len, metadata, ctrl),
            BenchNode::IcmpV4 => extract_icmp_metadata(hdr, hdr_len, metadata, ctrl),
        }
    }

    #[inline]
    fn handler(
        &self,
        _hdr: &[u8],
        _hdr_len: usize,
        _metadata: &mut FlowMeta,
        _ctrl: &CtrlData,
    ) -> Result<(), ParseError> {
        Ok(())
    }

    #[inline]
    fn post_handler(
        &self,
        _hdr: &[u8],
        _hdr_len: usize,
        _metadata: &mut FlowMeta,
        _ctrl: &CtrlData,
    ) -> Result<(), ParseError> {
        Ok(())
    }

    #[inline]
    fn proto_table(&self) -> Option<&'static ProtoTableEnum<FlowMeta, Self>> {
        match self {
            BenchNode::Ether => Some(&ETHER_TABLE),
            BenchNode::Ipv4 => Some(&IPV4_TABLE),
            BenchNode::Tcp | BenchNode::Udp | BenchNode::IcmpV4 => None,
        }
    }

    #[inline]
    fn wildcard_node(&self) -> Option<&'static Self> {
        None
    }

    #[inline]
    fn unknown_ret(&self) -> ParseError {
        ParseError::UnknownProto
    }
}

// ── Public bench API ─────────────────────────────────────────────────────

pub(crate) fn make_config() -> ParserConfig<FlowMeta> {
    ParserConfig::default()
}

#[inline]
pub(crate) fn parse_packet(
    config: &ParserConfig<FlowMeta>,
    pkt: &[u8],
) -> Result<ParseOutput<FlowMeta>, ParseError> {
    parse_enum(&ETHER, config, pkt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xdp2_core::ParseResult;

    fn make_eth_ipv4_tcp() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
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
        pkt
    }

    #[test]
    fn parses_eth_ipv4_tcp() {
        let pkt = make_eth_ipv4_tcp();
        let cfg = make_config();
        let out = parse_packet(&cfg, &pkt).expect("parse should succeed");
        assert!(matches!(
            out.result,
            ParseResult::Okay | ParseResult::StopOkay
        ));
        assert_eq!(out.metadata.eth_proto, 0x0800);
        assert_eq!(out.metadata.ip_proto, 6);
    }

    /// A/B correctness test: for every packet in `tcp_ipv4.pcap`, the
    /// enum-dispatch engine must extract the same `FlowMeta` as the
    /// dyn-dispatch engine. The minimal graph-enum node set covers this
    /// PCAP's protocol chain (Ether → IPv4 → TCP) entirely.
    #[test]
    fn matches_graph_on_tcp_ipv4_pcap() {
        use crate::{graph, pcap};
        use std::path::PathBuf;

        // Resolution order (needed so the test runs in the Nix sandbox too):
        //   1. $XDP2_TEST_PCAPS/tcp_ipv4.pcap  (set by Nix test targets)
        //   2. <CARGO_MANIFEST_DIR>/../../../data/pcaps/tcp_ipv4.pcap  (repo checkout)
        let pcap_path = match std::env::var_os("XDP2_TEST_PCAPS") {
            Some(dir) => PathBuf::from(dir).join("tcp_ipv4.pcap"),
            None => {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../data/pcaps/tcp_ipv4.pcap")
            }
        };
        if !pcap_path.exists() {
            eprintln!(
                "skip: {} not found (set XDP2_TEST_PCAPS or run from a repo checkout)",
                pcap_path.display()
            );
            return;
        }

        let packets = pcap::load_pcap(&pcap_path).expect("load pcap");
        assert!(!packets.is_empty(), "expected packets in tcp_ipv4.pcap");

        let parser = graph::make_parser();
        let cfg = make_config();

        for (i, pkt) in packets.iter().enumerate() {
            let dyn_out = graph::parse_packet(&parser, &pkt.data)
                .unwrap_or_else(|e| panic!("graph parse failed on pkt {i}: {e:?}"));
            let enum_out = parse_packet(&cfg, &pkt.data)
                .unwrap_or_else(|e| panic!("graph-enum parse failed on pkt {i}: {e:?}"));
            assert_eq!(
                dyn_out.metadata, enum_out.metadata,
                "FlowMeta mismatch on packet {i}"
            );
        }
    }
}
