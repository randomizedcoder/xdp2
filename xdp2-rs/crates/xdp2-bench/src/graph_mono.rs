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
//! `BenchMeta` is not populated here — the benchmark ignores metadata,
//! and none of the protocol Ops in this graph have `extract_metadata`
//! callbacks, so it would be a no-op either way.
//!
//! If this version measurably beats the graph-dispatched version, it is
//! evidence that the `xdp2-compiler` codegen pass is the right next step.

use xdp2_core::{ParseError, ProtocolOps};
use xdp2_protocols::ethernet::ether::EthernetOps;
use xdp2_protocols::ethernet::qinq::QinQOps;
use xdp2_protocols::ethernet::vlan::VlanOps;
use xdp2_protocols::ip::arp::ArpOps;
use xdp2_protocols::ip::icmp::{IcmpV4Ops, IcmpV6Ops};
use xdp2_protocols::ip::ipv4::Ipv4Ops;
use xdp2_protocols::ip::ipv6::Ipv6Ops;
use xdp2_protocols::ip::ipv6_eh::{Ipv6EhOps, Ipv6FragOps};
use xdp2_protocols::security::ah::AhOps;
use xdp2_protocols::transport::sctp::SctpOps;
use xdp2_protocols::transport::tcp::TcpOps;
use xdp2_protocols::transport::udp::UdpOps;
use xdp2_protocols::tunnel::ip_in_ip::IpInIpOps;

/// Cap on Ethernet-layer recursion (VLAN/QinQ nesting). Matches the
/// default `max_nodes` behavior of the graph engine.
const MAX_ETH_DEPTH: u32 = 8;
/// Cap on IPv6 extension-header chain length.
const MAX_EH_DEPTH: u32 = 8;

/// Parse one packet through the monomorphic graph.
///
/// Returns `Ok(())` for any terminal state the graph engine would accept
/// (Okay or StopOkay). Returns an appropriate `ParseError` otherwise.
#[inline]
pub fn parse_packet_mono(pkt: &[u8]) -> Result<(), ParseError> {
    parse_eth(pkt, 0)
}

/// Length check + fixed-header-length fetch.
///
/// Mirrors the engine's length-check sequence: `remaining >= MIN_LEN`, then
/// `header_len()`, then `hdr_len >= MIN_LEN && hdr_len <= remaining`.
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

/// Interpret a next-protocol result, returning `Ok(Some(proto))` to continue,
/// `Ok(None)` to stop (StopOkay or UnknownProto at leaf), or `Err` on real failure.
#[inline]
fn next_or_stop(r: Result<i32, ParseError>) -> Result<Option<i32>, ParseError> {
    match r {
        Ok(p) if p < 0 => Ok(None), // StopOkay / UseWild / error codes — treat as terminal for bench
        Ok(p) => Ok(Some(p)),
        Err(ParseError::UnknownProto) => Ok(None),
        Err(e) => Err(e),
    }
}

// ── Ethernet layer ────────────────────────────────────────────────────

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
    let rest = &pkt[hlen..];

    match next {
        0x0800 => parse_ipv4(rest),
        0x86DD => parse_ipv6(rest),
        0x8100 => parse_vlan(rest, depth + 1),
        0x88A8 => parse_qinq(rest, depth + 1),
        0x0806 => parse_arp(rest),
        _ => Err(ParseError::UnknownProto),
    }
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
    let rest = &pkt[hlen..];

    match next {
        0x0800 => parse_ipv4(rest),
        0x86DD => parse_ipv6(rest),
        0x8100 => parse_vlan(rest, depth + 1),
        0x88A8 => parse_qinq(rest, depth + 1),
        0x0806 => parse_arp(rest),
        _ => Err(ParseError::UnknownProto),
    }
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
    let rest = &pkt[hlen..];

    match next {
        0x0800 => parse_ipv4(rest),
        0x86DD => parse_ipv6(rest),
        0x8100 => parse_vlan(rest, depth + 1),
        0x88A8 => parse_qinq(rest, depth + 1),
        0x0806 => parse_arp(rest),
        _ => Err(ParseError::UnknownProto),
    }
}

// ── IPv4 layer ────────────────────────────────────────────────────────

fn parse_ipv4(pkt: &[u8]) -> Result<(), ParseError> {
    let proto = Ipv4Ops;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    dispatch_ipv4(next, rest)
}

#[inline]
fn dispatch_ipv4(next: i32, rest: &[u8]) -> Result<(), ParseError> {
    match next {
        6 => parse_leaf(&TcpOps, rest),
        17 => parse_leaf(&UdpOps, rest),
        1 => parse_leaf(&IcmpV4Ops, rest),
        132 => parse_leaf(&SctpOps, rest),
        4 => parse_ipip(rest),
        51 => parse_ah_v4(rest),
        _ => Err(ParseError::UnknownProto),
    }
}

fn parse_ipip(pkt: &[u8]) -> Result<(), ParseError> {
    // IP-in-IP wraps an inner IPv4 packet, so continue into IPv4.
    let proto = IpInIpOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    match next {
        6 => parse_leaf(&TcpOps, rest),
        17 => parse_leaf(&UdpOps, rest),
        1 => parse_leaf(&IcmpV4Ops, rest),
        _ => Err(ParseError::UnknownProto),
    }
}

fn parse_ah_v4(pkt: &[u8]) -> Result<(), ParseError> {
    let proto = AhOps;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    dispatch_ipv4(next, rest)
}

// ── IPv6 layer (with EH chain) ────────────────────────────────────────

fn parse_ipv6(pkt: &[u8]) -> Result<(), ParseError> {
    let proto = Ipv6Ops;
    let hlen = hdr_len(&proto, pkt)?;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    dispatch_ipv6(next, rest, 0)
}

fn dispatch_ipv6(mut next: i32, mut rest: &[u8], mut depth: u32) -> Result<(), ParseError> {
    // Walk the IPv6 extension-header chain iteratively — each EH reports the
    // next protocol number and advances past its own length.
    loop {
        match next {
            6 => return parse_leaf(&TcpOps, rest),
            17 => return parse_leaf(&UdpOps, rest),
            58 => return parse_leaf(&IcmpV6Ops, rest),
            132 => return parse_leaf(&SctpOps, rest),
            0 | 60 => {
                // HBH / DST — same Ipv6EhOps shape
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

// ── Leaf nodes (no next protocol) ─────────────────────────────────────

#[inline]
fn parse_leaf<P: ProtocolOps>(proto: &P, pkt: &[u8]) -> Result<(), ParseError> {
    let _ = hdr_len(proto, pkt)?;
    Ok(())
}

fn parse_arp(pkt: &[u8]) -> Result<(), ParseError> {
    parse_leaf(&ArpOps, pkt)
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
}
