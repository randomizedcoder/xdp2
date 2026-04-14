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
//! - `parse_packet_mono(pkt)` — parse a single packet
//!
//! Success is reported as `Ok(())`; errors as the usual `ParseError`.
//! Metadata is not populated — the mono parser benchmarks parse speed only.

use xdp2_core::{ParseError, ProtocolOps};
use xdp2_protocols::ethernet::ether::EthernetOps;
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
use xdp2_protocols::management::misc::{
    CfmOps, FipOps, LldpOps, MacControlOps, MvrpOps, PtpOps, SlowOps,
};
use xdp2_protocols::management::trill::TrillOps;
use xdp2_protocols::security::ah::AhOps;
use xdp2_protocols::security::misc::{EapolOps, EspOps, MacsecOps};
use xdp2_protocols::storage::misc::EthercatOps;
use xdp2_protocols::transport::dccp::DccpOps;
use xdp2_protocols::transport::sctp::SctpOps;
use xdp2_protocols::transport::tcp::TcpOps;
use xdp2_protocols::transport::tipc::TipcOps;
use xdp2_protocols::transport::udp::UdpOps;
use xdp2_protocols::transport::udplite::UdpLiteOps;
use xdp2_protocols::tunnel::geneve::GeneveV0Ops;
use xdp2_protocols::tunnel::gre::{GreBaseOps, GreV0Ops};
use xdp2_protocols::tunnel::misc::{HsrOps, PppoeOps};
use xdp2_protocols::tunnel::mpls::MplsOps;
use xdp2_protocols::tunnel::nsh::NshOps;
use xdp2_protocols::tunnel::vxlan::VxlanOps;

/// Cap on Ethernet-layer recursion (VLAN/QinQ/tunnel nesting).
const MAX_ETH_DEPTH: u32 = 8;
/// Cap on IPv6 extension-header chain length.
const MAX_EH_DEPTH: u32 = 8;

/// Parse one packet through the monomorphic graph.
#[inline]
pub fn parse_packet_mono(pkt: &[u8]) -> Result<(), ParseError> {
    parse_eth(pkt, 0)
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

// ── Ethernet dispatch (26 ethertypes) ────────────────────────────────

/// Shared ethertype dispatch — called by parse_eth, parse_vlan, parse_qinq,
/// and chainable L2 nodes (HSR, BATMAN, PBB, TRILL).
fn dispatch_ether(next: i32, rest: &[u8], depth: u32) -> Result<(), ParseError> {
    match next {
        // Core L3
        0x0800 | 0x86DD => parse_ip_check(rest),
        0x0806 => parse_leaf(&ArpOps, rest),
        0x8035 => parse_leaf(&ArpOps, rest), // RARP — same validation as ARP
        // VLAN
        0x8100 => parse_vlan(rest, depth + 1),
        0x88A8 => parse_qinq(rest, depth + 1),
        // MPLS
        0x8847 | 0x8848 => parse_leaf(&MplsOps, rest),
        // Tunnels / encapsulation
        0x8864 => parse_pppoe(rest),
        0x4305 => parse_batman(rest, depth + 1),
        0x88E7 => parse_pbb(rest, depth + 1),
        0x22F3 => parse_trill(rest, depth + 1),
        0x892F | 0x88FB => parse_hsr(rest, depth + 1), // HSR + PRP
        0x894F => parse_nsh(rest),
        // Management / L2 leaves
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
        0x88CA => parse_leaf(&TipcOps, rest),
        _ => Err(ParseError::UnknownProto),
    }
}

fn parse_eth(pkt: &[u8], depth: u32) -> Result<(), ParseError> {
    if depth >= MAX_ETH_DEPTH {
        return Err(ParseError::MaxNodes);
    }
    let proto = EthernetOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    dispatch_ether(next, &pkt[hlen..], depth)
}

fn parse_vlan(pkt: &[u8], depth: u32) -> Result<(), ParseError> {
    if depth >= MAX_ETH_DEPTH {
        return Err(ParseError::MaxNodes);
    }
    let proto = VlanOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    dispatch_ether(next, &pkt[hlen..], depth)
}

fn parse_qinq(pkt: &[u8], depth: u32) -> Result<(), ParseError> {
    if depth >= MAX_ETH_DEPTH {
        return Err(ParseError::MaxNodes);
    }
    let proto = QinQOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    dispatch_ether(next, &pkt[hlen..], depth)
}

// ── IP version overlay ───────────────────────────────────────────────

/// IP version check — reads version nibble, dispatches to IPv4/IPv6.
/// Overlay: does not consume bytes (mirrors IP_CHECK_NODE).
fn parse_ip_check(pkt: &[u8]) -> Result<(), ParseError> {
    if pkt.is_empty() {
        return Err(ParseError::Length);
    }
    match pkt[0] >> 4 {
        4 => parse_ipv4(pkt),
        6 => parse_ipv6(pkt),
        _ => Err(ParseError::UnknownProto),
    }
}

// ── IPv4 dispatch ────────────────────────────────────────────────────

fn parse_ipv4(pkt: &[u8]) -> Result<(), ParseError> {
    let proto = Ipv4Ops;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    dispatch_ipv4(next, &pkt[hlen..])
}

#[inline]
fn dispatch_ipv4(next: i32, rest: &[u8]) -> Result<(), ParseError> {
    match next {
        6 => parse_leaf(&TcpOps, rest),
        17 => parse_udp_tunnel(rest),
        1 => parse_leaf(&IcmpV4Ops, rest),
        2 => parse_leaf(&IgmpOps, rest),
        4 | 41 => parse_ip_check(rest),     // IP-in-IP / IPv6-in-IPv4
        33 => parse_leaf(&DccpOps, rest),
        47 => parse_gre_base(rest),
        50 => parse_leaf(&EspOps, rest),
        51 => parse_ah(rest, dispatch_ipv4),
        132 => parse_leaf(&SctpOps, rest),
        136 => parse_leaf(&UdpLiteOps, rest),
        137 => parse_leaf(&MplsOps, rest),
        _ => Err(ParseError::UnknownProto),
    }
}

// ── IPv6 dispatch (with EH chain) ────────────────────────────────────

fn parse_ipv6(pkt: &[u8]) -> Result<(), ParseError> {
    let proto = Ipv6Ops;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    dispatch_ipv6(next, &pkt[hlen..], 0)
}

fn dispatch_ipv6(mut next: i32, mut rest: &[u8], mut depth: u32) -> Result<(), ParseError> {
    loop {
        match next {
            6 => return parse_leaf(&TcpOps, rest),
            17 => return parse_udp_tunnel(rest),
            58 => return parse_leaf(&IcmpV6Ops, rest),
            132 => return parse_leaf(&SctpOps, rest),
            33 => return parse_leaf(&DccpOps, rest),
            136 => return parse_leaf(&UdpLiteOps, rest),
            137 => return parse_leaf(&MplsOps, rest),
            4 | 41 => return parse_ip_check(rest), // IP-in-IP
            47 => return parse_gre_base(rest),
            50 => return parse_leaf(&EspOps, rest),
            0 | 60 => {
                // HBH / DST extension headers
                if depth >= MAX_EH_DEPTH {
                    return Err(ParseError::MaxNodes);
                }
                let proto = Ipv6EhOps;
                let hlen = hdr_len(&proto, rest)?;
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

// ── AH (Authentication Header) ──────────────────────────────────────

fn parse_ah(
    pkt: &[u8],
    dispatch: fn(i32, &[u8]) -> Result<(), ParseError>,
) -> Result<(), ParseError> {
    let proto = AhOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    dispatch(next, &pkt[hlen..])
}

// ── UDP with tunnel dispatch ─────────────────────────────────────────

fn parse_udp_tunnel(pkt: &[u8]) -> Result<(), ParseError> {
    let proto = UdpOps;
    let hlen = hdr_len(&proto, pkt)?;
    // Read dport for tunnel dispatch (matches UdpDportOps in graph.rs)
    let dport = u16::from_be_bytes([pkt[2], pkt[3]]);
    let rest = &pkt[hlen..];
    match dport {
        4789 => parse_vxlan(rest),
        6081 => parse_geneve(rest),
        _ => Ok(()), // stop-leaf: non-tunnel UDP succeeds
    }
}

// ── Tunnel nodes ─────────────────────────────────────────────────────

fn parse_vxlan(pkt: &[u8]) -> Result<(), ParseError> {
    let proto = VxlanOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    match next {
        0x6558 => parse_eth(rest, 0), // ETH_P_TEB: inner Ethernet
        _ => Err(ParseError::UnknownProto),
    }
}

fn parse_geneve(pkt: &[u8]) -> Result<(), ParseError> {
    let proto = GeneveV0Ops;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    match next {
        0x6558 => parse_eth(rest, 0),
        0x0800 | 0x86DD => parse_ip_check(rest),
        _ => Err(ParseError::UnknownProto),
    }
}

// ── GRE ──────────────────────────────────────────────────────────────

fn parse_gre_base(pkt: &[u8]) -> Result<(), ParseError> {
    // Overlay: GreBaseOps reads version but doesn't consume bytes.
    if pkt.len() < GreBaseOps::MIN_LEN {
        return Err(ParseError::Length);
    }
    let version = GreBaseOps.next_proto(pkt).map_err(|_| ParseError::Fail)?;
    match version {
        0 => parse_gre_v0(pkt),
        _ => Ok(()), // GRE v1 → stop-leaf
    }
}

fn parse_gre_v0(pkt: &[u8]) -> Result<(), ParseError> {
    let proto = GreV0Ops;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    match next {
        0x0800 | 0x86DD => parse_ip_check(rest),
        0x6558 => parse_eth(rest, 0), // ETH_P_TEB
        _ => Err(ParseError::UnknownProto),
    }
}

// ── PPPoE → PPP → IP ────────────────────────────────────────────────

fn parse_pppoe(pkt: &[u8]) -> Result<(), ParseError> {
    let proto = PppoeOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    match next {
        0x0021 | 0x0057 => parse_ip_check(rest), // PPP_IP / PPP_IPV6
        _ => Err(ParseError::UnknownProto),
    }
}

// ── Chainable L2 nodes ──────────────────────────────────────────────

fn parse_hsr(pkt: &[u8], depth: u32) -> Result<(), ParseError> {
    if depth >= MAX_ETH_DEPTH {
        return Err(ParseError::MaxNodes);
    }
    let proto = HsrOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    dispatch_ether(next, &pkt[hlen..], depth)
}

fn parse_batman(pkt: &[u8], depth: u32) -> Result<(), ParseError> {
    if depth >= MAX_ETH_DEPTH {
        return Err(ParseError::MaxNodes);
    }
    let proto = BatmanOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    dispatch_ether(next, &pkt[hlen..], depth)
}

fn parse_pbb(pkt: &[u8], depth: u32) -> Result<(), ParseError> {
    if depth >= MAX_ETH_DEPTH {
        return Err(ParseError::MaxNodes);
    }
    let proto = PbbOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    dispatch_ether(next, &pkt[hlen..], depth)
}

fn parse_trill(pkt: &[u8], depth: u32) -> Result<(), ParseError> {
    if depth >= MAX_ETH_DEPTH {
        return Err(ParseError::MaxNodes);
    }
    let proto = TrillOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    dispatch_ether(next, &pkt[hlen..], depth)
}

fn parse_nsh(pkt: &[u8]) -> Result<(), ParseError> {
    let proto = NshOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    match next {
        0x0800 | 0x86DD => parse_ip_check(rest),
        0x6558 => parse_eth(rest, 0),
        0x8847 => parse_leaf(&MplsOps, rest),
        _ => Err(ParseError::UnknownProto),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn mono_parses_eth_ipv4_tcp() {
        let pkt = make_eth_ipv4_tcp();
        parse_packet_mono(&pkt).unwrap();
    }

    #[test]
    fn mono_rejects_empty() {
        assert!(parse_packet_mono(&[]).is_err());
    }

    #[test]
    fn mono_parses_lldp() {
        let mut pkt = vec![0u8; 12];
        pkt.extend_from_slice(&0x88CCu16.to_be_bytes());
        pkt.extend_from_slice(&[0x02, 0x00, 0x07, 0x04]);
        parse_packet_mono(&pkt).unwrap();
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

        parse_packet_mono(&pkt).unwrap();
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

        parse_packet_mono(&pkt).unwrap();
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

        parse_packet_mono(&pkt).unwrap();
    }
}
