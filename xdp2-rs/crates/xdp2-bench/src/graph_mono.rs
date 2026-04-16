//! Hand-rolled, fully-monomorphized parser for the benchmark protocol set.
//!
//! This is the Step 2 proof-of-concept from `performance-maximization-plan.md`.
//! It replicates the topology of `graph.rs` but calls `ProtocolOps::header_len`
//! / `next_proto` directly on zero-sized protocol structs instead of going
//! through `&dyn ParseNodeDyn`. Every branch becomes a `match` the compiler
//! can lower to a jump table, with no vtable loads and no linear-search
//! `ProtoTable` lookups.
//!
//! The public API mirrors `graph.rs`:
//!
//! - `parse_packet_mono(pkt, meta)` — parse a single packet, populate metadata
//!
//! Success is reported as `Ok(())`; errors as the usual `ParseError`.

use xdp2_core::{ParseError, ProtocolOps};
use xdp2_protocols::ethernet::ether::EthernetOps;
use xdp2_protocols::ethernet::llc::LlcSnapOps;
use xdp2_protocols::ethernet::pbb::PbbOps;
use xdp2_protocols::ethernet::qinq::QinQOps;
use xdp2_protocols::ethernet::vlan::VlanOps;
use xdp2_protocols::ip::arp::ArpOps;
use xdp2_protocols::ip::icmp::{IcmpV4Ops, IcmpV6Ops};
use xdp2_protocols::ip::igmp::IgmpOps;
use xdp2_protocols::ip::ipv4::Ipv4Ops;
use xdp2_protocols::ip::ipv6::Ipv6Ops;
use xdp2_protocols::ip::ipv6_eh::{Ipv6EhOps, Ipv6FragOps};
use xdp2_protocols::legacy::BatmanOps;
use xdp2_protocols::management::{
    CfmOps, FipOps, LldpOps, MacControlOps, MvrpOps, PtpOps, SlowOps,
};
use xdp2_protocols::management::trill::TrillOps;
use xdp2_protocols::security::ah::AhOps;
use xdp2_protocols::security::{EapolOps, EspOps, MacsecOps};
use xdp2_protocols::storage::fc::FcoeOps;
use xdp2_protocols::storage::misc::EthercatOps;
use xdp2_protocols::transport::dccp::DccpOps;
use xdp2_protocols::transport::sctp::SctpOps;
use xdp2_protocols::transport::tcp::TcpOps;
use xdp2_protocols::transport::tipc::TipcOps;
use xdp2_protocols::transport::udp::UdpOps;
use xdp2_protocols::transport::udplite::UdpLiteOps;
use xdp2_protocols::tunnel::geneve::GeneveV0Ops;
use xdp2_protocols::tunnel::gre::{GreBaseOps, GreV0Ops};
use xdp2_protocols::tunnel::{HsrOps, PppoeOps};
use xdp2_protocols::tunnel::mpls::MplsOps;
use xdp2_protocols::tunnel::nsh::NshOps;
use xdp2_protocols::tunnel::vxlan::VxlanOps;

use crate::graph::{AddrType, FlowMeta};

/// Cap on Ethernet-layer recursion (VLAN/QinQ/tunnel nesting).
const MAX_ETH_DEPTH: u32 = 8;
/// Cap on IPv6 extension-header chain length.
const MAX_EH_DEPTH: u32 = 8;

/// Parse one packet through the monomorphic graph, populating metadata.
#[inline]
pub fn parse_packet_mono(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    parse_eth(pkt, 0, meta)
}

/// Length check + header-length fetch.
#[inline]
fn hdr_len<P: ProtocolOps>(proto: &P, hdr: &[u8]) -> Result<usize, ParseError> {
    if hdr.len() < P::MIN_LEN {
        return Err(ParseError::Length);
    }
    let hlen = proto.header_len(hdr, hdr.len())?;
    if hlen < P::MIN_LEN || hlen > hdr.len() {
        return Err(ParseError::Length);
    }
    Ok(hlen)
}

/// Interpret next-protocol: Ok(Some(proto)) to continue, Ok(None) to stop.
#[inline]
fn next_or_stop(r: Result<i32, ParseError>) -> Result<Option<i32>, ParseError> {
    match r {
        Ok(p) if p < 0 => Ok(None),
        Ok(p) => Ok(Some(p)),
        Err(ParseError::UnknownProto) => Ok(None),
        Err(e) => Err(e),
    }
}

// ── Leaf helper ──────────────────────────────────────────────────────

#[inline]
fn parse_leaf<P: ProtocolOps>(proto: &P, pkt: &[u8]) -> Result<(), ParseError> {
    let _ = hdr_len(proto, pkt)?;
    Ok(())
}

// ── Ethernet dispatch (28 ethertypes + LLC) ─────────────────────────

/// Shared ethertype dispatch — called by parse_eth, parse_vlan, parse_qinq,
/// and chainable L2 nodes (HSR, BATMAN, PBB, TRILL).
fn dispatch_ether(next: i32, rest: &[u8], depth: u32, meta: &mut FlowMeta) -> Result<(), ParseError> {
    // LLC detection: ethertype ≤ 1500 means IEEE 802.3 length field
    if next > 0 && next <= 1500 {
        return parse_llc(rest, meta);
    }
    match next {
        // Core L3
        0x0800 | 0x86DD => parse_ip_check(rest, meta),
        0x0806 => { // ARP
            let _ = hdr_len(&ArpOps, rest)?;
            // extract_arp_metadata
            meta.arp.op = (u16::from_be_bytes([rest[6], rest[7]]) & 0xFF) as u8;
            meta.arp.sha.copy_from_slice(&rest[8..14]);
            meta.arp.spa = u32::from_be_bytes([rest[14], rest[15], rest[16], rest[17]]);
            meta.arp.tha.copy_from_slice(&rest[18..24]);
            meta.arp.tpa = u32::from_be_bytes([rest[24], rest[25], rest[26], rest[27]]);
            Ok(())
        }
        0x8035 => { // RARP — same metadata as ARP
            let _ = hdr_len(&ArpOps, rest)?;
            meta.arp.op = (u16::from_be_bytes([rest[6], rest[7]]) & 0xFF) as u8;
            meta.arp.sha.copy_from_slice(&rest[8..14]);
            meta.arp.spa = u32::from_be_bytes([rest[14], rest[15], rest[16], rest[17]]);
            meta.arp.tha.copy_from_slice(&rest[18..24]);
            meta.arp.tpa = u32::from_be_bytes([rest[24], rest[25], rest[26], rest[27]]);
            Ok(())
        }
        // VLAN
        0x8100 => parse_vlan(rest, depth + 1, meta),
        0x88A8 => parse_qinq(rest, depth + 1, meta),
        // MPLS
        0x8847 | 0x8848 => {
            let _ = hdr_len(&MplsOps, rest)?;
            // extract_mpls_metadata
            let w = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
            meta.mpls.label = w >> 12;
            meta.mpls.tc = ((w >> 9) & 0x7) as u8;
            meta.mpls.bos = ((w >> 8) & 0x1) != 0;
            meta.mpls.ttl = (w & 0xFF) as u8;
            Ok(())
        }
        // Tunnels / encapsulation
        0x8864 => parse_pppoe(rest, meta),
        0x4305 => parse_batman(rest, depth + 1, meta),
        0x88E7 => parse_pbb(rest, depth + 1, meta),
        0x22F3 => parse_trill(rest, depth + 1, meta),
        0x892F | 0x88FB => parse_hsr(rest, depth + 1, meta), // HSR + PRP
        0x894F => parse_nsh(rest, meta),
        // Management / L2 leaves (no metadata)
        0x88CC => parse_leaf(&LldpOps, rest),
        0x8809 => parse_leaf(&SlowOps, rest),
        0x8808 => parse_leaf(&MacControlOps, rest),
        0x888E => parse_leaf(&EapolOps, rest),
        0x88F7 => parse_leaf(&PtpOps, rest),
        0x88F5 => parse_leaf(&MvrpOps, rest),
        0x8902 => parse_leaf(&CfmOps, rest),
        0x8914 => parse_leaf(&FipOps, rest),
        0x88E5 => parse_leaf(&MacsecOps, rest),
        0x88A4 => parse_leaf(&EthercatOps, rest),
        0x88CA => { // TIPC — has metadata
            let _ = hdr_len(&TipcOps, rest)?;
            meta.addr_type = AddrType::Tipc;
            meta.addrs.tipc_key = u32::from_be_bytes([rest[8], rest[9], rest[10], rest[11]]);
            Ok(())
        }
        0x8906 => parse_leaf(&FcoeOps, rest),     // FCoE
        _ => Err(ParseError::UnknownProto),
    }
}

fn parse_eth(pkt: &[u8], depth: u32, meta: &mut FlowMeta) -> Result<(), ParseError> {
    if depth >= MAX_ETH_DEPTH {
        return Err(ParseError::MaxNodes);
    }
    let proto = EthernetOps;
    let hlen = hdr_len(&proto, pkt)?;
    // extract_ether_metadata
    meta.eth_addrs[..12].copy_from_slice(&pkt[0..12]);
    meta.eth_proto = u16::from_be_bytes([pkt[12], pkt[13]]);
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    // LLC-aware dispatch: ethertype ≤ 1500 → LLC
    let next = if next > 0 && next <= 1500 { 0x0004 } else { next };
    dispatch_ether(next, &pkt[hlen..], depth, meta)
}

fn parse_vlan(pkt: &[u8], depth: u32, meta: &mut FlowMeta) -> Result<(), ParseError> {
    if depth >= MAX_ETH_DEPTH {
        return Err(ParseError::MaxNodes);
    }
    let proto = VlanOps;
    let hlen = hdr_len(&proto, pkt)?;
    // extract_vlan_8021q_metadata
    let idx = if meta.vlan_count < 2 { meta.vlan_count as usize } else { 1 };
    if meta.vlan_count < 2 { meta.vlan_count += 1; }
    meta.vlan[idx].tci = u16::from_be_bytes([pkt[0], pkt[1]]);
    meta.vlan[idx].tpid = 0x8100;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let next = if next > 0 && next <= 1500 { 0x0004 } else { next };
    dispatch_ether(next, &pkt[hlen..], depth, meta)
}

fn parse_qinq(pkt: &[u8], depth: u32, meta: &mut FlowMeta) -> Result<(), ParseError> {
    if depth >= MAX_ETH_DEPTH {
        return Err(ParseError::MaxNodes);
    }
    let proto = QinQOps;
    let hlen = hdr_len(&proto, pkt)?;
    // extract_vlan_8021ad_metadata
    let idx = if meta.vlan_count < 2 { meta.vlan_count as usize } else { 1 };
    if meta.vlan_count < 2 { meta.vlan_count += 1; }
    meta.vlan[idx].tci = u16::from_be_bytes([pkt[0], pkt[1]]);
    meta.vlan[idx].tpid = 0x88A8;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let next = if next > 0 && next <= 1500 { 0x0004 } else { next };
    dispatch_ether(next, &pkt[hlen..], depth, meta)
}

// ── IP version overlay ───────────────────────────────────────────────

/// IP version check — reads version nibble, dispatches to IPv4/IPv6.
/// Overlay: does not consume bytes (mirrors IP_CHECK_NODE).
fn parse_ip_check(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    if pkt.is_empty() {
        return Err(ParseError::Length);
    }
    match pkt[0] >> 4 {
        4 => parse_ipv4(pkt, meta),
        6 => parse_ipv6(pkt, meta),
        _ => Err(ParseError::UnknownProto),
    }
}

// ── IPv4 dispatch ────────────────────────────────────────────────────

fn parse_ipv4(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    let proto = Ipv4Ops;
    let hlen = hdr_len(&proto, pkt)?;
    // extract_ipv4_metadata
    let frag_off = u16::from_be_bytes([pkt[6], pkt[7]]);
    const IP_MF: u16 = 0x2000;
    const IP_OFFSET: u16 = 0x1FFF;
    if (frag_off & (IP_MF | IP_OFFSET)) != 0 {
        meta.is_fragment = true;
        meta.first_frag = (frag_off & IP_OFFSET) == 0;
    }
    meta.addr_type = AddrType::Ipv4;
    meta.ip_proto = pkt[9];
    meta.addrs.v4_src = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
    meta.addrs.v4_dst = u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    dispatch_ipv4(next, &pkt[hlen..], meta)
}

#[inline]
fn dispatch_ipv4(next: i32, rest: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    match next {
        6 => { // TCP
            let _ = hdr_len(&TcpOps, rest)?;
            meta.ports.src_port = u16::from_be_bytes([rest[0], rest[1]]);
            meta.ports.dst_port = u16::from_be_bytes([rest[2], rest[3]]);
            Ok(())
        }
        17 => parse_udp_tunnel(rest, meta),
        1 => { // ICMPv4
            let _ = hdr_len(&IcmpV4Ops, rest)?;
            meta.icmp.icmp_type = rest[0];
            meta.icmp.code = rest[1];
            let t = rest[0];
            if t == 0 || t == 8 { meta.icmp.id = u16::from_be_bytes([rest[4], rest[5]]); }
            Ok(())
        }
        2 => parse_leaf(&IgmpOps, rest),
        4 | 41 => parse_ip_check(rest, meta),     // IP-in-IP / IPv6-in-IPv4
        33 => { // DCCP
            let _ = hdr_len(&DccpOps, rest)?;
            meta.ports.src_port = u16::from_be_bytes([rest[0], rest[1]]);
            meta.ports.dst_port = u16::from_be_bytes([rest[2], rest[3]]);
            Ok(())
        }
        47 => parse_gre_base(rest, meta),
        50 => { // ESP
            let _ = hdr_len(&EspOps, rest)?;
            meta.esp_spi = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
            Ok(())
        }
        51 => parse_ah_v4(rest, meta),
        132 => { // SCTP
            let _ = hdr_len(&SctpOps, rest)?;
            meta.ports.src_port = u16::from_be_bytes([rest[0], rest[1]]);
            meta.ports.dst_port = u16::from_be_bytes([rest[2], rest[3]]);
            Ok(())
        }
        115 => { // L2TPv3
            if rest.len() < 4 { return Err(ParseError::Length); }
            meta.l2tp_session_id = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
            Ok(())
        }
        136 => { // UDPLite
            let _ = hdr_len(&UdpLiteOps, rest)?;
            meta.ports.src_port = u16::from_be_bytes([rest[0], rest[1]]);
            meta.ports.dst_port = u16::from_be_bytes([rest[2], rest[3]]);
            Ok(())
        }
        137 => { // MPLS
            let _ = hdr_len(&MplsOps, rest)?;
            let w = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
            meta.mpls.label = w >> 12;
            meta.mpls.tc = ((w >> 9) & 0x7) as u8;
            meta.mpls.bos = ((w >> 8) & 0x1) != 0;
            meta.mpls.ttl = (w & 0xFF) as u8;
            Ok(())
        }
        _ => Err(ParseError::UnknownProto),
    }
}

// ── IPv6 dispatch (with EH chain) ────────────────────────────────────

fn parse_ipv6(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    let proto = Ipv6Ops;
    let hlen = hdr_len(&proto, pkt)?;
    // extract_ipv6_metadata
    meta.addr_type = AddrType::Ipv6;
    meta.ip_proto = pkt[6];
    meta.flow_label = ((pkt[1] as u32 & 0x0F) << 16) | ((pkt[2] as u32) << 8) | (pkt[3] as u32);
    meta.addrs.v6_src.copy_from_slice(&pkt[8..24]);
    meta.addrs.v6_dst.copy_from_slice(&pkt[24..40]);
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    dispatch_ipv6(next, &pkt[hlen..], 0, meta)
}

fn dispatch_ipv6(mut next: i32, mut rest: &[u8], mut depth: u32, meta: &mut FlowMeta) -> Result<(), ParseError> {
    loop {
        match next {
            6 => { // TCP
                let _ = hdr_len(&TcpOps, rest)?;
                meta.ports.src_port = u16::from_be_bytes([rest[0], rest[1]]);
                meta.ports.dst_port = u16::from_be_bytes([rest[2], rest[3]]);
                return Ok(());
            }
            17 => return parse_udp_tunnel(rest, meta),
            58 => { // ICMPv6
                let _ = hdr_len(&IcmpV6Ops, rest)?;
                meta.icmp.icmp_type = rest[0];
                meta.icmp.code = rest[1];
                let t = rest[0];
                if t == 128 || t == 129 { meta.icmp.id = u16::from_be_bytes([rest[4], rest[5]]); }
                return Ok(());
            }
            132 => { // SCTP
                let _ = hdr_len(&SctpOps, rest)?;
                meta.ports.src_port = u16::from_be_bytes([rest[0], rest[1]]);
                meta.ports.dst_port = u16::from_be_bytes([rest[2], rest[3]]);
                return Ok(());
            }
            33 => { // DCCP
                let _ = hdr_len(&DccpOps, rest)?;
                meta.ports.src_port = u16::from_be_bytes([rest[0], rest[1]]);
                meta.ports.dst_port = u16::from_be_bytes([rest[2], rest[3]]);
                return Ok(());
            }
            136 => { // UDPLite
                let _ = hdr_len(&UdpLiteOps, rest)?;
                meta.ports.src_port = u16::from_be_bytes([rest[0], rest[1]]);
                meta.ports.dst_port = u16::from_be_bytes([rest[2], rest[3]]);
                return Ok(());
            }
            137 => { // MPLS
                let _ = hdr_len(&MplsOps, rest)?;
                let w = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
                meta.mpls.label = w >> 12;
                meta.mpls.tc = ((w >> 9) & 0x7) as u8;
                meta.mpls.bos = ((w >> 8) & 0x1) != 0;
                meta.mpls.ttl = (w & 0xFF) as u8;
                return Ok(());
            }
            4 | 41 => return parse_ip_check(rest, meta), // IP-in-IP
            47 => return parse_gre_base(rest, meta),
            50 => { // ESP
                let _ = hdr_len(&EspOps, rest)?;
                meta.esp_spi = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
                return Ok(());
            }
            115 => { // L2TPv3
                if rest.len() < 4 { return Err(ParseError::Length); }
                meta.l2tp_session_id = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
                return Ok(());
            }
            0 | 60 => {
                // HBH / DST extension headers
                if depth >= MAX_EH_DEPTH {
                    return Err(ParseError::MaxNodes);
                }
                let proto = Ipv6EhOps;
                let hlen = hdr_len(&proto, rest)?;
                // extract_ipv6_eh_metadata
                meta.ip_proto = rest[0];
                next = match next_or_stop(proto.next_proto(&rest[..hlen]))? {
                    Some(p) => p,
                    None => return Ok(()),
                };
                rest = &rest[hlen..];
                depth += 1;
            }
            43 => {
                // Routing extension header
                if depth >= MAX_EH_DEPTH {
                    return Err(ParseError::MaxNodes);
                }
                let proto = Ipv6EhOps;
                let hlen = hdr_len(&proto, rest)?;
                meta.ip_proto = rest[0];
                next = match next_or_stop(proto.next_proto(&rest[..hlen]))? {
                    Some(p) => p,
                    None => return Ok(()),
                };
                rest = &rest[hlen..];
                depth += 1;
            }
            44 => {
                // Fragment extension header
                if depth >= MAX_EH_DEPTH {
                    return Err(ParseError::MaxNodes);
                }
                let proto = Ipv6FragOps;
                let hlen = hdr_len(&proto, rest)?;
                // extract_ipv6_frag_metadata
                meta.ip_proto = rest[0];
                let frag_off = u16::from_be_bytes([rest[2], rest[3]]);
                const IP6_OFFSET: u16 = 0xFFF8;
                meta.is_fragment = true;
                meta.first_frag = (frag_off & IP6_OFFSET) == 0;
                next = match next_or_stop(proto.next_proto(&rest[..hlen]))? {
                    Some(p) => p,
                    None => return Ok(()),
                };
                rest = &rest[hlen..];
                depth += 1;
            }
            51 => {
                // AH (chains back to IPv6 table)
                if depth >= MAX_EH_DEPTH {
                    return Err(ParseError::MaxNodes);
                }
                let proto = AhOps;
                let hlen = hdr_len(&proto, rest)?;
                // extract_ah_metadata
                meta.ah_spi = u32::from_be_bytes([rest[4], rest[5], rest[6], rest[7]]);
                next = match next_or_stop(proto.next_proto(&rest[..hlen]))? {
                    Some(p) => p,
                    None => return Ok(()),
                };
                rest = &rest[hlen..];
                depth += 1;
            }
            _ => return Err(ParseError::UnknownProto),
        }
    }
}

// ── AH (Authentication Header, IPv4 path) ──────────────────────────

fn parse_ah_v4(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    let proto = AhOps;
    let hlen = hdr_len(&proto, pkt)?;
    // extract_ah_metadata
    meta.ah_spi = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    dispatch_ipv4(next, &pkt[hlen..], meta)
}

// ── UDP with tunnel dispatch ─────────────────────────────────────────

fn parse_udp_tunnel(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    let proto = UdpOps;
    let hlen = hdr_len(&proto, pkt)?;
    // extract_ports_metadata
    meta.ports.src_port = u16::from_be_bytes([pkt[0], pkt[1]]);
    meta.ports.dst_port = u16::from_be_bytes([pkt[2], pkt[3]]);
    let dport = meta.ports.dst_port;
    let rest = &pkt[hlen..];
    match dport {
        4789 => parse_vxlan(rest, meta),
        6081 => parse_geneve(rest, meta),
        _ => Ok(()), // stop-leaf: non-tunnel UDP succeeds
    }
}

// ── Tunnel nodes ─────────────────────────────────────────────────────

fn parse_vxlan(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    let proto = VxlanOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    match next {
        0x6558 => parse_eth(rest, 0, meta), // ETH_P_TEB: inner Ethernet
        _ => Err(ParseError::UnknownProto),
    }
}

fn parse_geneve(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    let proto = GeneveV0Ops;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    match next {
        0x6558 => parse_eth(rest, 0, meta),
        0x0800 | 0x86DD => parse_ip_check(rest, meta),
        _ => Err(ParseError::UnknownProto),
    }
}

// ── GRE ──────────────────────────────────────────────────────────────

fn parse_gre_base(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    // Overlay: GreBaseOps reads version but doesn't consume bytes.
    if pkt.len() < GreBaseOps::MIN_LEN {
        return Err(ParseError::Length);
    }
    let version = GreBaseOps.next_proto(pkt).map_err(|_| ParseError::Fail)?;
    match version {
        0 => parse_gre_v0(pkt, meta),
        _ => Ok(()), // GRE v1 → stop-leaf
    }
}

fn parse_gre_v0(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    let proto = GreV0Ops;
    let hlen = hdr_len(&proto, pkt)?;
    // extract GRE metadata (flags + optional fields)
    let flags = u16::from_be_bytes([pkt[0], pkt[1]]);
    meta.gre.flags = flags as u32;
    let mut off = 4;
    if flags & 0x8000 != 0 { // checksum present
        meta.gre.csum = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
        off += 4;
    }
    if flags & 0x2000 != 0 { // key present
        meta.gre.keyid = u32::from_be_bytes([pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]]);
        meta.keyid = meta.gre.keyid;
        off += 4;
    }
    if flags & 0x1000 != 0 { // sequence present
        meta.gre.seq = u32::from_be_bytes([pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]]);
    }
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    match next {
        0x0800 | 0x86DD => parse_ip_check(rest, meta),
        0x6558 => parse_eth(rest, 0, meta), // ETH_P_TEB
        _ => Err(ParseError::UnknownProto),
    }
}

// ── PPPoE → PPP → IP ────────────────────────────────────────────────

fn parse_pppoe(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    let proto = PppoeOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    match next {
        0x0021 | 0x0057 => parse_ip_check(rest, meta), // PPP_IP / PPP_IPV6
        _ => Err(ParseError::UnknownProto),
    }
}

// ── Chainable L2 nodes ──────────────────────────────────────────────

fn parse_hsr(pkt: &[u8], depth: u32, meta: &mut FlowMeta) -> Result<(), ParseError> {
    if depth >= MAX_ETH_DEPTH {
        return Err(ParseError::MaxNodes);
    }
    let proto = HsrOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    dispatch_ether(next, &pkt[hlen..], depth, meta)
}

fn parse_batman(pkt: &[u8], depth: u32, meta: &mut FlowMeta) -> Result<(), ParseError> {
    if depth >= MAX_ETH_DEPTH {
        return Err(ParseError::MaxNodes);
    }
    let proto = BatmanOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    dispatch_ether(next, &pkt[hlen..], depth, meta)
}

fn parse_pbb(pkt: &[u8], depth: u32, meta: &mut FlowMeta) -> Result<(), ParseError> {
    if depth >= MAX_ETH_DEPTH {
        return Err(ParseError::MaxNodes);
    }
    let proto = PbbOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    dispatch_ether(next, &pkt[hlen..], depth, meta)
}

fn parse_trill(pkt: &[u8], depth: u32, meta: &mut FlowMeta) -> Result<(), ParseError> {
    if depth >= MAX_ETH_DEPTH {
        return Err(ParseError::MaxNodes);
    }
    let proto = TrillOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    dispatch_ether(next, &pkt[hlen..], depth, meta)
}

fn parse_nsh(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    let proto = NshOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    match next {
        0x0800 | 0x86DD => parse_ip_check(rest, meta),
        0x6558 => parse_eth(rest, 0, meta),
        0x8847 => {
            let _ = hdr_len(&MplsOps, rest)?;
            let w = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
            meta.mpls.label = w >> 12;
            meta.mpls.tc = ((w >> 9) & 0x7) as u8;
            meta.mpls.bos = ((w >> 8) & 0x1) != 0;
            meta.mpls.ttl = (w & 0xFF) as u8;
            Ok(())
        }
        _ => Err(ParseError::UnknownProto),
    }
}

// ── LLC/SNAP dispatch ───────────────────────────────────────────────

fn parse_llc(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    if pkt.len() < 3 {
        return Err(ParseError::Length);
    }
    let dsap = pkt[0];
    match dsap {
        0xAA => parse_snap(pkt, meta), // LLC/SNAP — re-dispatch encapsulated ethertype
        0x42 => Ok(()),          // STP BPDU — leaf (3-byte LLC header is sufficient)
        _ => Err(ParseError::UnknownProto),
    }
}

fn parse_snap(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    let proto = LlcSnapOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    // Re-dispatch through ethertype space (depth=0 since we're starting fresh)
    dispatch_ether(next, &pkt[hlen..], 0, meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_eth_ipv4_tcp() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet: dst=00:..., src=00:..., ethertype=0x0800
        pkt.extend_from_slice(&[0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);    // src
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        // IPv4: IHL=5, proto=TCP(6), src=10.0.0.1, dst=10.0.0.2
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(6);
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        // TCP: src=80, dst=443
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 8]);
        pkt.push(5 << 4);
        pkt.push(0x02);
        pkt.extend_from_slice(&[0; 6]);
        pkt
    }

    #[test]
    fn mono_parses_eth_ipv4_tcp() {
        let pkt = make_eth_ipv4_tcp();
        let mut meta = FlowMeta::default();
        parse_packet_mono(&pkt, &mut meta).unwrap();
        // Verify metadata was populated
        assert_eq!(meta.eth_proto, 0x0800);
        assert_eq!(meta.addr_type, AddrType::Ipv4);
        assert_eq!(meta.ip_proto, 6);
        assert_eq!(meta.addrs.v4_src, u32::from_be_bytes([10, 0, 0, 1]));
        assert_eq!(meta.addrs.v4_dst, u32::from_be_bytes([10, 0, 0, 2]));
        assert_eq!(meta.ports.src_port, 80);
        assert_eq!(meta.ports.dst_port, 443);
        assert_eq!(meta.eth_addrs[0], 0xAA); // dst MAC first byte
        assert_eq!(meta.eth_addrs[6], 0x11); // src MAC first byte
    }

    #[test]
    fn mono_rejects_empty() {
        let mut meta = FlowMeta::default();
        assert!(parse_packet_mono(&[], &mut meta).is_err());
    }

    #[test]
    fn mono_parses_lldp() {
        let mut pkt = vec![0u8; 12];
        pkt.extend_from_slice(&0x88CCu16.to_be_bytes());
        pkt.extend_from_slice(&[0x02, 0x00, 0x07, 0x04]);
        let mut meta = FlowMeta::default();
        parse_packet_mono(&pkt, &mut meta).unwrap();
        assert_eq!(meta.eth_proto, 0x88CC);
    }

    #[test]
    fn mono_parses_vxlan_inner_tcp() {
        let mut pkt = Vec::new();
        // Outer Ethernet + IPv4 + UDP(4789) + VXLAN + inner Ethernet + IPv4 + TCP
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&100u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(17); // UDP
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        pkt.extend_from_slice(&12345u16.to_be_bytes());
        pkt.extend_from_slice(&4789u16.to_be_bytes());
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 2]);
        // VXLAN (8 bytes)
        pkt.extend_from_slice(&[0x08, 0, 0, 0, 0x12, 0x34, 0x56, 0]);
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

        let mut meta = FlowMeta::default();
        parse_packet_mono(&pkt, &mut meta).unwrap();
    }

    #[test]
    fn mono_parses_gre_v0_ipv4_tcp() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        pkt.push((4 << 4) | 5);
        pkt.push(0);
        pkt.extend_from_slice(&100u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(47); // GRE
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        // GRE: flags=0, proto=IPv4
        pkt.extend_from_slice(&0x0000u16.to_be_bytes());
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        // Inner IPv4 + TCP
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

        let mut meta = FlowMeta::default();
        parse_packet_mono(&pkt, &mut meta).unwrap();
    }

    #[test]
    fn mono_parses_pppoe_ipv4_tcp() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x8864u16.to_be_bytes());
        // PPPoE header
        pkt.push(0x11); // ver=1, type=1
        pkt.push(0x00); // code=0
        pkt.extend_from_slice(&[0x00, 0x01]); // session ID
        pkt.extend_from_slice(&44u16.to_be_bytes()); // length
        pkt.extend_from_slice(&0x0021u16.to_be_bytes()); // PPP_IP
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

        let mut meta = FlowMeta::default();
        parse_packet_mono(&pkt, &mut meta).unwrap();
    }
}
