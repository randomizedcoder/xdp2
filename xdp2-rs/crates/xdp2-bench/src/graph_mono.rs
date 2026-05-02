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
use xdp2_protocols::management::trill::TrillOps;
use xdp2_protocols::management::{
    CfmOps, FipOps, LldpOps, MacControlOps, MvrpOps, PtpOps, SlowOps,
};
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
use xdp2_protocols::tunnel::mpls::MplsOps;
use xdp2_protocols::tunnel::nsh::NshOps;
use xdp2_protocols::tunnel::vxlan::VxlanOps;
use xdp2_protocols::tunnel::{HsrOps, PppoeOps};

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

/// Bare minimum-length leaf check (no ProtocolOps needed).
#[inline]
fn leaf(pkt: &[u8], min_len: usize) -> Result<(), ParseError> {
    if pkt.len() < min_len {
        return Err(ParseError::Length);
    }
    Ok(())
}

// ── Ethernet dispatch (28 ethertypes + LLC) ─────────────────────────

/// Shared ethertype dispatch — called by parse_eth, parse_vlan, parse_qinq,
/// and chainable L2 nodes (HSR, BATMAN, PBB, TRILL).
fn dispatch_ether(
    next: i32,
    rest: &[u8],
    depth: u32,
    meta: &mut FlowMeta,
) -> Result<(), ParseError> {
    // LLC detection: ethertype ≤ 1500 means IEEE 802.3 length field
    if next > 0 && next <= 1500 {
        return parse_llc(rest, meta);
    }
    match next {
        // Core L3
        0x0800 | 0x86DD => parse_ip_check(rest, meta),
        0x0806 => {
            // ARP
            let _ = hdr_len(&ArpOps, rest)?;
            // extract_arp_metadata
            meta.arp.op = (u16::from_be_bytes([rest[6], rest[7]]) & 0xFF) as u8;
            meta.arp.sha.copy_from_slice(&rest[8..14]);
            meta.arp.spa = u32::from_be_bytes([rest[14], rest[15], rest[16], rest[17]]);
            meta.arp.tha.copy_from_slice(&rest[18..24]);
            meta.arp.tpa = u32::from_be_bytes([rest[24], rest[25], rest[26], rest[27]]);
            Ok(())
        }
        0x8035 => {
            // RARP — same metadata as ARP
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
        0x88CA => {
            // TIPC — has metadata
            let _ = hdr_len(&TipcOps, rest)?;
            meta.addr_type = AddrType::Tipc;
            meta.addrs.tipc_key = u32::from_be_bytes([rest[8], rest[9], rest[10], rest[11]]);
            Ok(())
        }
        0x8906 => parse_leaf(&FcoeOps, rest), // FCoE
        _ => Ok(()),                         // unknown ethertype — stop with partial metadata
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
    let next = if next > 0 && next <= 1500 {
        0x0004
    } else {
        next
    };
    dispatch_ether(next, &pkt[hlen..], depth, meta)
}

fn parse_vlan(pkt: &[u8], depth: u32, meta: &mut FlowMeta) -> Result<(), ParseError> {
    if depth >= MAX_ETH_DEPTH {
        return Err(ParseError::MaxNodes);
    }
    let proto = VlanOps;
    let hlen = hdr_len(&proto, pkt)?;
    // extract_vlan_8021q_metadata
    let idx = if meta.vlan_count < 2 {
        meta.vlan_count as usize
    } else {
        1
    };
    if meta.vlan_count < 2 {
        meta.vlan_count += 1;
    }
    meta.vlan[idx].tci = u16::from_be_bytes([pkt[0], pkt[1]]);
    meta.vlan[idx].tpid = 0x8100;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let next = if next > 0 && next <= 1500 {
        0x0004
    } else {
        next
    };
    dispatch_ether(next, &pkt[hlen..], depth, meta)
}

fn parse_qinq(pkt: &[u8], depth: u32, meta: &mut FlowMeta) -> Result<(), ParseError> {
    if depth >= MAX_ETH_DEPTH {
        return Err(ParseError::MaxNodes);
    }
    let proto = QinQOps;
    let hlen = hdr_len(&proto, pkt)?;
    // extract_vlan_8021ad_metadata
    let idx = if meta.vlan_count < 2 {
        meta.vlan_count as usize
    } else {
        1
    };
    if meta.vlan_count < 2 {
        meta.vlan_count += 1;
    }
    meta.vlan[idx].tci = u16::from_be_bytes([pkt[0], pkt[1]]);
    meta.vlan[idx].tpid = 0x88A8;
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let next = if next > 0 && next <= 1500 {
        0x0004
    } else {
        next
    };
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
    meta.ip_tos = pkt[1];   // DSCP + ECN
    meta.ip_ttl = pkt[8];   // TTL
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
        6 => {
            // TCP with dport dispatch
            let tcp_hlen = hdr_len(&TcpOps, rest)?;
            meta.ports.src_port = u16::from_be_bytes([rest[0], rest[1]]);
            meta.ports.dst_port = u16::from_be_bytes([rest[2], rest[3]]);
            meta.tcp_flags = rest[13]; // SYN/ACK/FIN/RST/PSH/URG
            let payload = &rest[tcp_hlen..];
            match meta.ports.dst_port {
                3260 => leaf(payload, 48),  // iSCSI
                4420 => leaf(payload, 8),   // NVMe/TCP
                7471 => leaf(payload, 18),  // STT
                53 => leaf(payload, 12),    // DNS
                80 => leaf(payload, 1),     // HTTP
                443 => leaf(payload, 5),    // TLS
                8080 => leaf(payload, 9),   // HTTP/2
                22 => leaf(payload, 1),     // SSH
                23 => leaf(payload, 1),     // Telnet
                21 => leaf(payload, 1),     // FTP
                25 => leaf(payload, 1),     // SMTP
                143 => leaf(payload, 1),    // IMAP
                179 => leaf(payload, 19),   // BGP
                646 => leaf(payload, 10),   // LDP
                639 => leaf(payload, 3),    // MSDP
                389 => leaf(payload, 1),    // LDAP
                88 => leaf(payload, 4),     // Kerberos
                49 => leaf(payload, 12),    // TACACS+
                111 => leaf(payload, 24),   // ONC-RPC
                2049 => leaf(payload, 4),   // NFS
                445 => leaf(payload, 4),    // SMB
                6379 => leaf(payload, 1),   // Redis
                9092 => leaf(payload, 12),  // Kafka
                1883 => leaf(payload, 2),   // MQTT
                5672 => leaf(payload, 8),   // AMQP
                11211 => leaf(payload, 1),  // Memcached
                5555 => leaf(payload, 1),   // ZeroMQ
                502 => leaf(payload, 7),    // Modbus/TCP
                20000 => leaf(payload, 10), // DNP3
                44818 => leaf(payload, 24), // EtherNet/IP
                4840 => leaf(payload, 8),   // OPC-UA
                3868 => leaf(payload, 20),  // Diameter
                554 => leaf(payload, 1),    // RTSP
                2000 => leaf(payload, 8),   // Skinny/SCCP
                1723 => leaf(payload, 12),  // PPTP
                6653 => leaf(payload, 8),   // OpenFlow
                4500 => leaf(payload, 28),  // IKEv2/TCP
                _ => Ok(()),               // stop-leaf
            }
        }
        17 => parse_udp_tunnel(rest, meta),
        1 => {
            // ICMPv4
            let _ = hdr_len(&IcmpV4Ops, rest)?;
            meta.icmp.icmp_type = rest[0];
            meta.icmp.code = rest[1];
            let t = rest[0];
            if t == 0 || t == 8 {
                meta.icmp.id = u16::from_be_bytes([rest[4], rest[5]]);
            }
            Ok(())
        }
        2 => parse_leaf(&IgmpOps, rest),
        4 | 41 => parse_ip_check(rest, meta), // IP-in-IP / IPv6-in-IPv4
        33 => {
            // DCCP
            let _ = hdr_len(&DccpOps, rest)?;
            meta.ports.src_port = u16::from_be_bytes([rest[0], rest[1]]);
            meta.ports.dst_port = u16::from_be_bytes([rest[2], rest[3]]);
            Ok(())
        }
        47 => parse_gre_base(rest, meta),
        50 => {
            // ESP
            let _ = hdr_len(&EspOps, rest)?;
            meta.esp_spi = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
            Ok(())
        }
        51 => parse_ah_v4(rest, meta),
        132 => {
            // SCTP
            let _ = hdr_len(&SctpOps, rest)?;
            meta.ports.src_port = u16::from_be_bytes([rest[0], rest[1]]);
            meta.ports.dst_port = u16::from_be_bytes([rest[2], rest[3]]);
            Ok(())
        }
        115 => {
            // L2TPv3
            if rest.len() < 4 {
                return Err(ParseError::Length);
            }
            meta.l2tp_session_id = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
            Ok(())
        }
        136 => {
            // UDPLite
            let _ = hdr_len(&UdpLiteOps, rest)?;
            meta.ports.src_port = u16::from_be_bytes([rest[0], rest[1]]);
            meta.ports.dst_port = u16::from_be_bytes([rest[2], rest[3]]);
            Ok(())
        }
        137 => {
            // MPLS
            let _ = hdr_len(&MplsOps, rest)?;
            let w = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
            meta.mpls.label = w >> 12;
            meta.mpls.tc = ((w >> 9) & 0x7) as u8;
            meta.mpls.bos = ((w >> 8) & 0x1) != 0;
            meta.mpls.ttl = (w & 0xFF) as u8;
            Ok(())
        }
        // ── Routing / FHRP / misc IP protocols ──
        89 => leaf(rest, 16),   // OSPF
        88 => leaf(rest, 20),   // EIGRP
        112 => leaf(rest, 7),   // VRRP
        103 => leaf(rest, 4),   // PIM
        46 => leaf(rest, 8),    // RSVP
        108 => leaf(rest, 4),   // IPComp
        113 => leaf(rest, 16),  // PGM
        97 => leaf(rest, 2),    // EtherIP
        _ => Ok(()),                   // unknown IPv4 protocol — stop with partial metadata
    }
}

// ── IPv6 dispatch (with EH chain) ────────────────────────────────────

fn parse_ipv6(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    let proto = Ipv6Ops;
    let hlen = hdr_len(&proto, pkt)?;
    // extract_ipv6_metadata
    meta.addr_type = AddrType::Ipv6;
    meta.ip_tos = ((pkt[0] & 0x0F) << 4) | (pkt[1] >> 4); // traffic class
    meta.ip_ttl = pkt[7]; // Hop Limit
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

fn dispatch_ipv6(
    mut next: i32,
    mut rest: &[u8],
    mut depth: u32,
    meta: &mut FlowMeta,
) -> Result<(), ParseError> {
    loop {
        match next {
            6 => {
                // TCP with dport dispatch
                let tcp_hlen = hdr_len(&TcpOps, rest)?;
                meta.ports.src_port = u16::from_be_bytes([rest[0], rest[1]]);
                meta.ports.dst_port = u16::from_be_bytes([rest[2], rest[3]]);
                meta.tcp_flags = rest[13]; // SYN/ACK/FIN/RST/PSH/URG
                let payload = &rest[tcp_hlen..];
                return match meta.ports.dst_port {
                    3260 => leaf(payload, 48),  // iSCSI
                    4420 => leaf(payload, 8),   // NVMe/TCP
                    7471 => leaf(payload, 18),  // STT
                    53 => leaf(payload, 12),    // DNS
                    80 => leaf(payload, 1),     // HTTP
                    443 => leaf(payload, 5),    // TLS
                    8080 => leaf(payload, 9),   // HTTP/2
                    22 => leaf(payload, 1),     // SSH
                    23 => leaf(payload, 1),     // Telnet
                    21 => leaf(payload, 1),     // FTP
                    25 => leaf(payload, 1),     // SMTP
                    143 => leaf(payload, 1),    // IMAP
                    179 => leaf(payload, 19),   // BGP
                    646 => leaf(payload, 10),   // LDP
                    639 => leaf(payload, 3),    // MSDP
                    389 => leaf(payload, 1),    // LDAP
                    88 => leaf(payload, 4),     // Kerberos
                    49 => leaf(payload, 12),    // TACACS+
                    111 => leaf(payload, 24),   // ONC-RPC
                    2049 => leaf(payload, 4),   // NFS
                    445 => leaf(payload, 4),    // SMB
                    6379 => leaf(payload, 1),   // Redis
                    9092 => leaf(payload, 12),  // Kafka
                    1883 => leaf(payload, 2),   // MQTT
                    5672 => leaf(payload, 8),   // AMQP
                    11211 => leaf(payload, 1),  // Memcached
                    5555 => leaf(payload, 1),   // ZeroMQ
                    502 => leaf(payload, 7),    // Modbus/TCP
                    20000 => leaf(payload, 10), // DNP3
                    44818 => leaf(payload, 24), // EtherNet/IP
                    4840 => leaf(payload, 8),   // OPC-UA
                    3868 => leaf(payload, 20),  // Diameter
                    554 => leaf(payload, 1),    // RTSP
                    2000 => leaf(payload, 8),   // Skinny/SCCP
                    1723 => leaf(payload, 12),  // PPTP
                    6653 => leaf(payload, 8),   // OpenFlow
                    4500 => leaf(payload, 28),  // IKEv2/TCP
                    _ => Ok(()),               // stop-leaf
                };
            }
            17 => return parse_udp_tunnel(rest, meta),
            58 => {
                // ICMPv6
                let _ = hdr_len(&IcmpV6Ops, rest)?;
                meta.icmp.icmp_type = rest[0];
                meta.icmp.code = rest[1];
                let t = rest[0];
                if t == 128 || t == 129 {
                    meta.icmp.id = u16::from_be_bytes([rest[4], rest[5]]);
                }
                return Ok(());
            }
            132 => {
                // SCTP
                let _ = hdr_len(&SctpOps, rest)?;
                meta.ports.src_port = u16::from_be_bytes([rest[0], rest[1]]);
                meta.ports.dst_port = u16::from_be_bytes([rest[2], rest[3]]);
                return Ok(());
            }
            33 => {
                // DCCP
                let _ = hdr_len(&DccpOps, rest)?;
                meta.ports.src_port = u16::from_be_bytes([rest[0], rest[1]]);
                meta.ports.dst_port = u16::from_be_bytes([rest[2], rest[3]]);
                return Ok(());
            }
            136 => {
                // UDPLite
                let _ = hdr_len(&UdpLiteOps, rest)?;
                meta.ports.src_port = u16::from_be_bytes([rest[0], rest[1]]);
                meta.ports.dst_port = u16::from_be_bytes([rest[2], rest[3]]);
                return Ok(());
            }
            137 => {
                // MPLS
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
            50 => {
                // ESP
                let _ = hdr_len(&EspOps, rest)?;
                meta.esp_spi = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
                return Ok(());
            }
            115 => {
                // L2TPv3
                if rest.len() < 4 {
                    return Err(ParseError::Length);
                }
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
            // ── Routing / FHRP / misc IP protocols ──
            89 => return leaf(rest, 16),   // OSPFv3
            88 => return leaf(rest, 20),   // EIGRP
            112 => return leaf(rest, 8),   // VRRPv3
            103 => return leaf(rest, 4),   // PIM
            46 => return leaf(rest, 8),    // RSVP
            108 => return leaf(rest, 4),   // IPComp
            113 => return leaf(rest, 16),  // PGM
            _ => return Ok(()),                // unknown IPv6 protocol — stop with partial metadata
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
        // ── Tunnels (inner dispatch) ──
        4789 => parse_vxlan(rest, meta),
        6081 => parse_geneve(rest, meta),
        // ── Tunnel leaves ──
        2152 => leaf(rest, 8),   // GTP-U
        2123 => leaf(rest, 8),   // GTPv2-C
        4790 => leaf(rest, 8),   // VXLAN-GPE
        3544 => leaf(rest, 4),   // Teredo
        4341 => leaf(rest, 8),   // LISP
        5247 => leaf(rest, 4),   // CAPWAP
        6080 => leaf(rest, 4),   // GUE
        37008 => leaf(rest, 4),  // TZSP
        // ── DNS / naming ──
        53 => leaf(rest, 12),    // DNS
        137 => leaf(rest, 12),   // NBNS
        5353 => leaf(rest, 12),  // mDNS
        5355 => leaf(rest, 12),  // LLMNR
        // ── DHCP ──
        67 | 68 => leaf(rest, 236),   // DHCP
        546 | 547 => leaf(rest, 4),   // DHCPv6
        // ── NTP / SNMP / TFTP / Syslog ──
        123 => leaf(rest, 48),   // NTP
        161 | 162 => leaf(rest, 2), // SNMP
        69 => leaf(rest, 4),     // TFTP
        514 => leaf(rest, 1),    // Syslog
        // ── Routing ──
        520 => leaf(rest, 4),    // RIP
        521 => leaf(rest, 4),    // RIPng
        // ── Security / VPN ──
        500 => leaf(rest, 28),   // IKEv2
        4500 => leaf(rest, 28),  // IKEv2/NAT-T
        51820 => leaf(rest, 4),  // WireGuard
        4433 => leaf(rest, 13),  // DTLS
        // ── AAA / FHRP ──
        1812 | 1813 => leaf(rest, 20), // RADIUS
        1985 => leaf(rest, 8),   // HSRP
        3222 => leaf(rest, 4),   // GLBP
        // ── Voice / media ──
        5060 => leaf(rest, 1),   // SIP
        5004 => leaf(rest, 12),  // RTP
        5005 => leaf(rest, 8),   // RTCP
        2427 => leaf(rest, 1),   // MGCP
        // ── Telemetry / monitoring ──
        5683 => leaf(rest, 4),   // CoAP
        3784 => leaf(rest, 24),  // BFD
        3478 => leaf(rest, 20),  // STUN
        862 => leaf(rest, 16),   // TWAMP
        8805 => leaf(rest, 8),   // PFCP
        6343 => leaf(rest, 4),   // sFlow
        2055 => leaf(rest, 4),   // CFLOW
        4739 => leaf(rest, 16),  // IPFIX
        // ── Application / misc ──
        443 => leaf(rest, 1),    // QUIC
        9 => leaf(rest, 6),      // WOL
        47808 => leaf(rest, 4),  // BACnet
        1935 => leaf(rest, 16),  // SRT
        1234 => leaf(rest, 4),   // MPEG-TS
        _ => Ok(()), // stop-leaf: non-tunnel UDP succeeds
    }
}

// ── Tunnel nodes ─────────────────────────────────────────────────────

fn parse_vxlan(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    let proto = VxlanOps;
    let hlen = hdr_len(&proto, pkt)?;
    // Extract VNI (bytes 4-6)
    meta.keyid = ((pkt[4] as u32) << 16) | ((pkt[5] as u32) << 8) | (pkt[6] as u32);
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    match next {
        0x6558 => parse_eth(rest, 0, meta), // ETH_P_TEB: inner Ethernet
        _ => Ok(()), // stop-leaf: unknown VXLAN inner
    }
}

fn parse_geneve(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ParseError> {
    let proto = GeneveV0Ops;
    let hlen = hdr_len(&proto, pkt)?;
    // Extract VNI (bytes 4-6)
    meta.keyid = ((pkt[4] as u32) << 16) | ((pkt[5] as u32) << 8) | (pkt[6] as u32);
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    match next {
        0x6558 => parse_eth(rest, 0, meta),
        0x0800 | 0x86DD => parse_ip_check(rest, meta),
        _ => Ok(()),                         // unknown Geneve inner — stop
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
    if flags & 0x8000 != 0 {
        // checksum present
        meta.gre.csum = u16::from_ne_bytes([pkt[off], pkt[off + 1]]);
        off += 4;
    }
    if flags & 0x2000 != 0 {
        // key present
        meta.gre.keyid = u32::from_ne_bytes([pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]]);
        meta.keyid = meta.gre.keyid;
        off += 4;
    }
    if flags & 0x1000 != 0 {
        // sequence present
        meta.gre.seq = u32::from_ne_bytes([pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]]);
    }
    let next = match next_or_stop(proto.next_proto(&pkt[..hlen]))? {
        Some(p) => p,
        None => return Ok(()),
    };
    let rest = &pkt[hlen..];
    match next {
        0x0800 | 0x86DD => parse_ip_check(rest, meta),
        0x6558 => parse_eth(rest, 0, meta), // ETH_P_TEB
        _ => Ok(()),                        // unknown GRE inner — stop
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
        _ => Ok(()),                                    // unknown PPP protocol — stop
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
        _ => Ok(()),                         // unknown NSH inner protocol — stop
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
        0x42 => Ok(()),                // STP BPDU — leaf (3-byte LLC header is sufficient)
        _ => Ok(()),                   // unknown LLC DSAP — stop
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
#[path = "graph_mono_tests.rs"]
mod tests;
