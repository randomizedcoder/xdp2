//! Hardware-classified template extraction.
//!
//! When the NIC has already classified a packet (via ntuple/Flow Director),
//! all header field offsets are compile-time constants.  No branches, no
//! graph walk — just one bounds check and fixed-offset reads.
//!
//! Template extractors populate the **same `FlowMeta`** structure as
//! graph, mono, and compiled modes.  The speedup comes from eliminating
//! protocol-graph traversal and branch misprediction, not from doing
//! less work.
//!
//! ## Coverage
//!
//! Templates exist for every fixed-offset header stack:
//! - Plain:  Eth/{IPv4,IPv6}/{TCP,UDP,ICMP,SCTP,Other} + Eth/ARP
//! - VLAN:   Eth/VLAN/{IPv4,IPv6}/{TCP,UDP,ICMP,SCTP,Other} + Eth/VLAN/ARP
//! - QinQ:   Eth/802.1ad/VLAN/{IPv4,IPv6}/{TCP,UDP,ICMP,SCTP,Other} + Eth/QinQ/ARP
//! - GRE:    {Plain,VLAN,QinQ}/IPv4/GRE(basic)/{IPv4,IPv6}/{TCP,UDP,ICMP}
//! - 2xGRE:  Eth/IPv4/GRE/IPv4/GRE/IPv4/{TCP,UDP,ICMP}
//! - IP-in-IP: {Plain,VLAN,QinQ}/IPv4/IPv4/{TCP,UDP,ICMP}
//!
//! Variable-length headers (IPv4 options, IPv6 extension headers, GRE
//! with flags, MPLS) cannot have templates and fall back to compiled parsing.

use crate::flow_meta::{AddrType, FlowMeta};

pub(crate) use crate::template_plain::*;
pub(crate) use crate::template_vlan::*;
pub(crate) use crate::template_qinq::*;
pub(crate) use crate::template_gre::*;
pub(crate) use crate::template_ipip::*;

// ── Inline helpers ─────────────────────────────────────────────
//
// Each helper extracts one protocol layer at a known byte offset.
// All are #[inline(always)] so the compiler folds them into the
// caller, producing the same code as hand-written literal offsets.
//
// pub(crate) so template_plain/vlan/qinq/gre/ipip modules can call them.

#[inline(always)]
pub(crate) fn extract_eth(pkt: &[u8], meta: &mut FlowMeta) {
    meta.eth_addrs[..12].copy_from_slice(&pkt[0..12]);
    meta.eth_proto = u16::from_be_bytes([pkt[12], pkt[13]]);
}

#[inline(always)]
pub(crate) fn extract_ipv4(pkt: &[u8], off: usize, meta: &mut FlowMeta) {
    let frag_off = u16::from_be_bytes([pkt[off + 6], pkt[off + 7]]);
    const IP_MF: u16 = 0x2000;
    const IP_OFFSET: u16 = 0x1FFF;
    if (frag_off & (IP_MF | IP_OFFSET)) != 0 {
        meta.is_fragment = true;
        meta.first_frag = (frag_off & IP_OFFSET) == 0;
    }
    meta.addr_type = AddrType::Ipv4;
    meta.ip_proto = pkt[off + 9];
    meta.addrs.v4_src = u32::from_be_bytes([
        pkt[off + 12], pkt[off + 13], pkt[off + 14], pkt[off + 15],
    ]);
    meta.addrs.v4_dst = u32::from_be_bytes([
        pkt[off + 16], pkt[off + 17], pkt[off + 18], pkt[off + 19],
    ]);
}

#[inline(always)]
pub(crate) fn extract_ipv6(pkt: &[u8], off: usize, meta: &mut FlowMeta) {
    meta.addr_type = AddrType::Ipv6;
    meta.ip_proto = pkt[off + 6];
    meta.flow_label = ((pkt[off + 1] as u32 & 0x0F) << 16)
        | ((pkt[off + 2] as u32) << 8)
        | (pkt[off + 3] as u32);
    meta.addrs.v6_src.copy_from_slice(&pkt[off + 8..off + 24]);
    meta.addrs.v6_dst.copy_from_slice(&pkt[off + 24..off + 40]);
}

#[inline(always)]
pub(crate) fn extract_ports(pkt: &[u8], off: usize, meta: &mut FlowMeta) {
    meta.ports.src_port = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
    meta.ports.dst_port = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
}

#[inline(always)]
pub(crate) fn extract_icmp(pkt: &[u8], off: usize, meta: &mut FlowMeta) {
    meta.icmp.icmp_type = pkt[off];
    meta.icmp.code = pkt[off + 1];
    let t = pkt[off];
    if t == 0 || t == 8 || t == 128 || t == 129 {
        meta.icmp.id = u16::from_be_bytes([pkt[off + 4], pkt[off + 5]]);
    }
}

#[inline(always)]
pub(crate) fn extract_vlan(pkt: &[u8], off: usize, tpid: u16, meta: &mut FlowMeta) {
    let idx = meta.vlan_count as usize;
    if idx < 2 {
        meta.vlan[idx].tci = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
        meta.vlan[idx].tpid = tpid;
        meta.vlan_count += 1;
    }
}

#[inline(always)]
pub(crate) fn extract_arp(pkt: &[u8], off: usize, meta: &mut FlowMeta) {
    meta.l3_off = off as u16;
    meta.arp.op = (u16::from_be_bytes([pkt[off + 6], pkt[off + 7]]) & 0xFF) as u8;
    meta.arp.sha.copy_from_slice(&pkt[off + 8..off + 14]);
    meta.arp.spa = u32::from_be_bytes([pkt[off + 14], pkt[off + 15], pkt[off + 16], pkt[off + 17]]);
    meta.arp.tha.copy_from_slice(&pkt[off + 18..off + 24]);
    meta.arp.tpa = u32::from_be_bytes([pkt[off + 24], pkt[off + 25], pkt[off + 26], pkt[off + 27]]);
}

// ── Template IDs ───────────────────────────────────────────────

/// Template ID for pre-selected packets.
#[derive(Clone, Copy, Debug)]
pub enum TemplateId {
    // ── Plain (no encapsulation) ──
    EthIpv4Tcp, EthIpv4Udp, EthIpv4Icmp, EthIpv4Sctp, EthIpv4Other,
    EthIpv6Tcp, EthIpv6Udp, EthIpv6Icmpv6, EthIpv6Sctp, EthIpv6Other,
    EthArp,
    // ── Single VLAN (802.1Q) ──
    EthVlanIpv4Tcp, EthVlanIpv4Udp, EthVlanIpv4Icmp, EthVlanIpv4Sctp, EthVlanIpv4Other,
    EthVlanIpv6Tcp, EthVlanIpv6Udp, EthVlanIpv6Icmpv6, EthVlanIpv6Sctp, EthVlanIpv6Other,
    EthVlanArp,
    // ── QinQ (802.1ad + 802.1Q) ──
    EthQinQIpv4Tcp, EthQinQIpv4Udp, EthQinQIpv4Icmp, EthQinQIpv4Sctp, EthQinQIpv4Other,
    EthQinQIpv6Tcp, EthQinQIpv6Udp, EthQinQIpv6Icmpv6, EthQinQIpv6Sctp, EthQinQIpv6Other,
    EthQinQArp,
    // ── GRE (basic, no optional fields) ──
    EthIpv4GreIpv4Tcp, EthIpv4GreIpv4Udp, EthIpv4GreIpv4Icmp,
    EthIpv4GreIpv6Tcp, EthIpv4GreIpv6Udp, EthIpv4GreIpv6Icmpv6,
    // ── Double GRE ──
    EthIpv4GreIpv4GreIpv4Tcp, EthIpv4GreIpv4GreIpv4Udp, EthIpv4GreIpv4GreIpv4Icmp,
    // ── VLAN + GRE ──
    EthVlanIpv4GreIpv4Tcp, EthVlanIpv4GreIpv4Udp, EthVlanIpv4GreIpv4Icmp,
    EthVlanIpv4GreIpv6Tcp, EthVlanIpv4GreIpv6Udp, EthVlanIpv4GreIpv6Icmpv6,
    // ── QinQ + GRE ──
    EthQinQIpv4GreIpv4Tcp, EthQinQIpv4GreIpv4Udp, EthQinQIpv4GreIpv4Icmp,
    EthQinQIpv4GreIpv6Tcp, EthQinQIpv4GreIpv6Udp, EthQinQIpv4GreIpv6Icmpv6,
    // ── IP-in-IP (proto 4) ──
    EthIpv4Ipv4Tcp, EthIpv4Ipv4Udp, EthIpv4Ipv4Icmp,
    // ── VLAN + IP-in-IP ──
    EthVlanIpv4Ipv4Tcp, EthVlanIpv4Ipv4Udp, EthVlanIpv4Ipv4Icmp,
    // ── QinQ + IP-in-IP ──
    EthQinQIpv4Ipv4Tcp, EthQinQIpv4Ipv4Udp, EthQinQIpv4Ipv4Icmp,
}

/// Dispatch to the specialized extractor for a pre-selected template.
#[inline]
pub fn extract_by_id(pkt: &[u8], id: TemplateId, meta: &mut FlowMeta) -> Result<(), ()> {
    use TemplateId::*;
    match id {
        // Plain
        EthIpv4Tcp       => extract_eth_ipv4_tcp(pkt, meta),
        EthIpv4Udp       => extract_eth_ipv4_udp(pkt, meta),
        EthIpv4Icmp      => extract_eth_ipv4_icmp(pkt, meta),
        EthIpv4Sctp      => extract_eth_ipv4_sctp(pkt, meta),
        EthIpv4Other     => extract_eth_ipv4_other(pkt, meta),
        EthIpv6Tcp       => extract_eth_ipv6_tcp(pkt, meta),
        EthIpv6Udp       => extract_eth_ipv6_udp(pkt, meta),
        EthIpv6Icmpv6    => extract_eth_ipv6_icmpv6(pkt, meta),
        EthIpv6Sctp      => extract_eth_ipv6_sctp(pkt, meta),
        EthIpv6Other     => extract_eth_ipv6_other(pkt, meta),
        EthArp           => extract_eth_arp(pkt, meta),
        // VLAN
        EthVlanIpv4Tcp    => extract_vlan_ipv4_tcp(pkt, meta),
        EthVlanIpv4Udp    => extract_vlan_ipv4_udp(pkt, meta),
        EthVlanIpv4Icmp   => extract_vlan_ipv4_icmp(pkt, meta),
        EthVlanIpv4Sctp   => extract_vlan_ipv4_sctp(pkt, meta),
        EthVlanIpv4Other  => extract_vlan_ipv4_other(pkt, meta),
        EthVlanIpv6Tcp    => extract_vlan_ipv6_tcp(pkt, meta),
        EthVlanIpv6Udp    => extract_vlan_ipv6_udp(pkt, meta),
        EthVlanIpv6Icmpv6 => extract_vlan_ipv6_icmpv6(pkt, meta),
        EthVlanIpv6Sctp   => extract_vlan_ipv6_sctp(pkt, meta),
        EthVlanIpv6Other  => extract_vlan_ipv6_other(pkt, meta),
        EthVlanArp        => extract_vlan_arp(pkt, meta),
        // QinQ
        EthQinQIpv4Tcp    => extract_qinq_ipv4_tcp(pkt, meta),
        EthQinQIpv4Udp    => extract_qinq_ipv4_udp(pkt, meta),
        EthQinQIpv4Icmp   => extract_qinq_ipv4_icmp(pkt, meta),
        EthQinQIpv4Sctp   => extract_qinq_ipv4_sctp(pkt, meta),
        EthQinQIpv4Other  => extract_qinq_ipv4_other(pkt, meta),
        EthQinQIpv6Tcp    => extract_qinq_ipv6_tcp(pkt, meta),
        EthQinQIpv6Udp    => extract_qinq_ipv6_udp(pkt, meta),
        EthQinQIpv6Icmpv6 => extract_qinq_ipv6_icmpv6(pkt, meta),
        EthQinQIpv6Sctp   => extract_qinq_ipv6_sctp(pkt, meta),
        EthQinQIpv6Other  => extract_qinq_ipv6_other(pkt, meta),
        EthQinQArp        => extract_qinq_arp(pkt, meta),
        // GRE (plain)
        EthIpv4GreIpv4Tcp     => extract_gre_ipv4_tcp(pkt, meta),
        EthIpv4GreIpv4Udp     => extract_gre_ipv4_udp(pkt, meta),
        EthIpv4GreIpv4Icmp    => extract_gre_ipv4_icmp(pkt, meta),
        EthIpv4GreIpv6Tcp     => extract_gre_ipv6_tcp(pkt, meta),
        EthIpv4GreIpv6Udp     => extract_gre_ipv6_udp(pkt, meta),
        EthIpv4GreIpv6Icmpv6  => extract_gre_ipv6_icmpv6(pkt, meta),
        // Double GRE
        EthIpv4GreIpv4GreIpv4Tcp  => extract_gre2_ipv4_tcp(pkt, meta),
        EthIpv4GreIpv4GreIpv4Udp  => extract_gre2_ipv4_udp(pkt, meta),
        EthIpv4GreIpv4GreIpv4Icmp => extract_gre2_ipv4_icmp(pkt, meta),
        // VLAN+GRE
        EthVlanIpv4GreIpv4Tcp     => extract_vlan_gre_ipv4_tcp(pkt, meta),
        EthVlanIpv4GreIpv4Udp     => extract_vlan_gre_ipv4_udp(pkt, meta),
        EthVlanIpv4GreIpv4Icmp    => extract_vlan_gre_ipv4_icmp(pkt, meta),
        EthVlanIpv4GreIpv6Tcp     => extract_vlan_gre_ipv6_tcp(pkt, meta),
        EthVlanIpv4GreIpv6Udp     => extract_vlan_gre_ipv6_udp(pkt, meta),
        EthVlanIpv4GreIpv6Icmpv6  => extract_vlan_gre_ipv6_icmpv6(pkt, meta),
        // QinQ+GRE
        EthQinQIpv4GreIpv4Tcp     => extract_qinq_gre_ipv4_tcp(pkt, meta),
        EthQinQIpv4GreIpv4Udp     => extract_qinq_gre_ipv4_udp(pkt, meta),
        EthQinQIpv4GreIpv4Icmp    => extract_qinq_gre_ipv4_icmp(pkt, meta),
        EthQinQIpv4GreIpv6Tcp     => extract_qinq_gre_ipv6_tcp(pkt, meta),
        EthQinQIpv4GreIpv6Udp     => extract_qinq_gre_ipv6_udp(pkt, meta),
        EthQinQIpv4GreIpv6Icmpv6  => extract_qinq_gre_ipv6_icmpv6(pkt, meta),
        // IP-in-IP (plain)
        EthIpv4Ipv4Tcp  => extract_ipip_tcp(pkt, meta),
        EthIpv4Ipv4Udp  => extract_ipip_udp(pkt, meta),
        EthIpv4Ipv4Icmp => extract_ipip_icmp(pkt, meta),
        // VLAN+IP-in-IP
        EthVlanIpv4Ipv4Tcp  => extract_vlan_ipip_tcp(pkt, meta),
        EthVlanIpv4Ipv4Udp  => extract_vlan_ipip_udp(pkt, meta),
        EthVlanIpv4Ipv4Icmp => extract_vlan_ipip_icmp(pkt, meta),
        // QinQ+IP-in-IP
        EthQinQIpv4Ipv4Tcp  => extract_qinq_ipip_tcp(pkt, meta),
        EthQinQIpv4Ipv4Udp  => extract_qinq_ipip_udp(pkt, meta),
        EthQinQIpv4Ipv4Icmp => extract_qinq_ipip_icmp(pkt, meta),
    }
}

// ═══════════════════════════════════════════════════════════════
//  Classifier — in production this is the NIC queue number
// ═══════════════════════════════════════════════════════════════

const PLAIN_L3: usize = 14;
const VLAN_L3: usize = 18;
const QINQ_L3: usize = 22;

/// Returns true if basic GRE (no optional fields, version 0).
#[inline]
fn is_basic_gre(pkt: &[u8], off: usize) -> bool {
    pkt[off] & 0xB0 == 0 && pkt[off + 1] & 0x07 == 0
}

/// Returns true if IPv4 with IHL=5 (no options).
#[inline]
fn is_ipv4_ihl5(pkt: &[u8], off: usize) -> bool {
    pkt[off] & 0x0F == 5
}

/// Select template ID for a packet by sniffing headers.
pub fn select_template_id(pkt: &[u8]) -> Option<TemplateId> {
    if pkt.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
    match ethertype {
        0x0800 => classify_ipv4(pkt, PLAIN_L3, L2Kind::Plain),
        0x86DD => classify_ipv6(pkt, PLAIN_L3, L2Kind::Plain),
        0x0806 | 0x8035 => classify_arp(pkt, PLAIN_L3, L2Kind::Plain),
        0x8100 => classify_vlan(pkt),
        0x88A8 | 0x9100 => classify_qinq(pkt),
        _ => None,
    }
}

/// L2 encapsulation variant for classifier dispatch.
#[derive(Clone, Copy)]
enum L2Kind { Plain, Vlan, QinQ }

fn classify_vlan(pkt: &[u8]) -> Option<TemplateId> {
    if pkt.len() < VLAN_L3 + 2 {
        return None;
    }
    let inner_et = u16::from_be_bytes([pkt[16], pkt[17]]);
    match inner_et {
        0x0800 => classify_ipv4(pkt, VLAN_L3, L2Kind::Vlan),
        0x86DD => classify_ipv6(pkt, VLAN_L3, L2Kind::Vlan),
        0x0806 | 0x8035 => classify_arp(pkt, VLAN_L3, L2Kind::Vlan),
        _ => None,
    }
}

fn classify_qinq(pkt: &[u8]) -> Option<TemplateId> {
    if pkt.len() < QINQ_L3 + 2 {
        return None;
    }
    let inner_vlan_et = u16::from_be_bytes([pkt[16], pkt[17]]);
    if inner_vlan_et != 0x8100 {
        return None;
    }
    let inner_et = u16::from_be_bytes([pkt[20], pkt[21]]);
    match inner_et {
        0x0800 => classify_ipv4(pkt, QINQ_L3, L2Kind::QinQ),
        0x86DD => classify_ipv6(pkt, QINQ_L3, L2Kind::QinQ),
        0x0806 | 0x8035 => classify_arp(pkt, QINQ_L3, L2Kind::QinQ),
        _ => None,
    }
}

fn classify_arp(pkt: &[u8], l3_off: usize, kind: L2Kind) -> Option<TemplateId> {
    if pkt.len() < l3_off + 28 {
        return None;
    }
    Some(match kind {
        L2Kind::Plain => TemplateId::EthArp,
        L2Kind::Vlan  => TemplateId::EthVlanArp,
        L2Kind::QinQ  => TemplateId::EthQinQArp,
    })
}

fn classify_ipv4(pkt: &[u8], l3_off: usize, kind: L2Kind) -> Option<TemplateId> {
    if pkt.len() < l3_off + 20 {
        return None;
    }
    if !is_ipv4_ihl5(pkt, l3_off) {
        return None;
    }
    let proto = pkt[l3_off + 9];
    match proto {
        6 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv4Tcp,
            L2Kind::Vlan  => TemplateId::EthVlanIpv4Tcp,
            L2Kind::QinQ  => TemplateId::EthQinQIpv4Tcp,
        }),
        17 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv4Udp,
            L2Kind::Vlan  => TemplateId::EthVlanIpv4Udp,
            L2Kind::QinQ  => TemplateId::EthQinQIpv4Udp,
        }),
        1 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv4Icmp,
            L2Kind::Vlan  => TemplateId::EthVlanIpv4Icmp,
            L2Kind::QinQ  => TemplateId::EthQinQIpv4Icmp,
        }),
        132 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv4Sctp,
            L2Kind::Vlan  => TemplateId::EthVlanIpv4Sctp,
            L2Kind::QinQ  => TemplateId::EthQinQIpv4Sctp,
        }),
        47 => classify_gre(pkt, l3_off + 20, kind),
        4 => classify_ipip(pkt, l3_off + 20, kind),
        _ => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv4Other,
            L2Kind::Vlan  => TemplateId::EthVlanIpv4Other,
            L2Kind::QinQ  => TemplateId::EthQinQIpv4Other,
        }),
    }
}

fn classify_ipv6(pkt: &[u8], l3_off: usize, kind: L2Kind) -> Option<TemplateId> {
    if pkt.len() < l3_off + 40 + 4 {
        return None;
    }
    let next_hdr = pkt[l3_off + 6];
    match next_hdr {
        6 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv6Tcp,
            L2Kind::Vlan  => TemplateId::EthVlanIpv6Tcp,
            L2Kind::QinQ  => TemplateId::EthQinQIpv6Tcp,
        }),
        17 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv6Udp,
            L2Kind::Vlan  => TemplateId::EthVlanIpv6Udp,
            L2Kind::QinQ  => TemplateId::EthQinQIpv6Udp,
        }),
        58 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv6Icmpv6,
            L2Kind::Vlan  => TemplateId::EthVlanIpv6Icmpv6,
            L2Kind::QinQ  => TemplateId::EthQinQIpv6Icmpv6,
        }),
        132 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv6Sctp,
            L2Kind::Vlan  => TemplateId::EthVlanIpv6Sctp,
            L2Kind::QinQ  => TemplateId::EthQinQIpv6Sctp,
        }),
        // IPv6 extension headers (0,43,44,51,50,60,135) have variable length — fall back.
        0 | 43 | 44 | 50 | 51 | 60 | 135 => None,
        _ => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv6Other,
            L2Kind::Vlan  => TemplateId::EthVlanIpv6Other,
            L2Kind::QinQ  => TemplateId::EthQinQIpv6Other,
        }),
    }
}

fn classify_gre(pkt: &[u8], gre_off: usize, kind: L2Kind) -> Option<TemplateId> {
    if pkt.len() < gre_off + 4 {
        return None;
    }
    if !is_basic_gre(pkt, gre_off) {
        return None;
    }
    let gre_proto = u16::from_be_bytes([pkt[gre_off + 2], pkt[gre_off + 3]]);
    let inner = gre_off + 4;
    match gre_proto {
        0x0800 => {
            if pkt.len() < inner + 20 {
                return None;
            }
            if !is_ipv4_ihl5(pkt, inner) {
                return None;
            }
            let inner_proto = pkt[inner + 9];
            match inner_proto {
                6 => Some(match kind {
                    L2Kind::Plain => TemplateId::EthIpv4GreIpv4Tcp,
                    L2Kind::Vlan  => TemplateId::EthVlanIpv4GreIpv4Tcp,
                    L2Kind::QinQ  => TemplateId::EthQinQIpv4GreIpv4Tcp,
                }),
                17 => Some(match kind {
                    L2Kind::Plain => TemplateId::EthIpv4GreIpv4Udp,
                    L2Kind::Vlan  => TemplateId::EthVlanIpv4GreIpv4Udp,
                    L2Kind::QinQ  => TemplateId::EthQinQIpv4GreIpv4Udp,
                }),
                1 => Some(match kind {
                    L2Kind::Plain => TemplateId::EthIpv4GreIpv4Icmp,
                    L2Kind::Vlan  => TemplateId::EthVlanIpv4GreIpv4Icmp,
                    L2Kind::QinQ  => TemplateId::EthQinQIpv4GreIpv4Icmp,
                }),
                // Double GRE only for plain (no VLAN/QinQ double-GRE)
                47 if matches!(kind, L2Kind::Plain) => classify_gre2(pkt, inner + 20),
                _ => None,
            }
        }
        0x86DD => {
            if pkt.len() < inner + 40 + 4 {
                return None;
            }
            let next_hdr = pkt[inner + 6];
            match next_hdr {
                6 => Some(match kind {
                    L2Kind::Plain => TemplateId::EthIpv4GreIpv6Tcp,
                    L2Kind::Vlan  => TemplateId::EthVlanIpv4GreIpv6Tcp,
                    L2Kind::QinQ  => TemplateId::EthQinQIpv4GreIpv6Tcp,
                }),
                17 => Some(match kind {
                    L2Kind::Plain => TemplateId::EthIpv4GreIpv6Udp,
                    L2Kind::Vlan  => TemplateId::EthVlanIpv4GreIpv6Udp,
                    L2Kind::QinQ  => TemplateId::EthQinQIpv4GreIpv6Udp,
                }),
                58 => Some(match kind {
                    L2Kind::Plain => TemplateId::EthIpv4GreIpv6Icmpv6,
                    L2Kind::Vlan  => TemplateId::EthVlanIpv4GreIpv6Icmpv6,
                    L2Kind::QinQ  => TemplateId::EthQinQIpv4GreIpv6Icmpv6,
                }),
                _ => None,
            }
        }
        _ => None,
    }
}

fn classify_gre2(pkt: &[u8], gre_off: usize) -> Option<TemplateId> {
    if pkt.len() < gre_off + 4 {
        return None;
    }
    if !is_basic_gre(pkt, gre_off) {
        return None;
    }
    let gre_proto = u16::from_be_bytes([pkt[gre_off + 2], pkt[gre_off + 3]]);
    if gre_proto != 0x0800 {
        return None;
    }
    let inner = gre_off + 4;
    if pkt.len() < inner + 20 {
        return None;
    }
    if !is_ipv4_ihl5(pkt, inner) {
        return None;
    }
    match pkt[inner + 9] {
        6  => Some(TemplateId::EthIpv4GreIpv4GreIpv4Tcp),
        17 => Some(TemplateId::EthIpv4GreIpv4GreIpv4Udp),
        1  => Some(TemplateId::EthIpv4GreIpv4GreIpv4Icmp),
        _  => None,
    }
}

fn classify_ipip(pkt: &[u8], inner_off: usize, kind: L2Kind) -> Option<TemplateId> {
    if pkt.len() < inner_off + 20 {
        return None;
    }
    if !is_ipv4_ihl5(pkt, inner_off) {
        return None;
    }
    match pkt[inner_off + 9] {
        6 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv4Ipv4Tcp,
            L2Kind::Vlan  => TemplateId::EthVlanIpv4Ipv4Tcp,
            L2Kind::QinQ  => TemplateId::EthQinQIpv4Ipv4Tcp,
        }),
        17 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv4Ipv4Udp,
            L2Kind::Vlan  => TemplateId::EthVlanIpv4Ipv4Udp,
            L2Kind::QinQ  => TemplateId::EthQinQIpv4Ipv4Udp,
        }),
        1 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv4Ipv4Icmp,
            L2Kind::Vlan  => TemplateId::EthVlanIpv4Ipv4Icmp,
            L2Kind::QinQ  => TemplateId::EthQinQIpv4Ipv4Icmp,
        }),
        _ => None,
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Eth/IPv4/TCP packet (54 bytes).
    fn make_eth_ipv4_tcp() -> Vec<u8> {
        let mut pkt = vec![0u8; 54];
        pkt[0..6].copy_from_slice(&[0xAA; 6]);
        pkt[6..12].copy_from_slice(&[0xBB; 6]);
        pkt[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        pkt[14] = 0x45; // IPv4, IHL=5
        pkt[23] = 6;    // TCP
        pkt[26..30].copy_from_slice(&[10, 0, 0, 1]);
        pkt[30..34].copy_from_slice(&[10, 0, 0, 2]);
        pkt[34..36].copy_from_slice(&80u16.to_be_bytes());
        pkt[36..38].copy_from_slice(&443u16.to_be_bytes());
        pkt
    }

    // ── Classifier tests ─────────────────────────────────────────

    #[test]
    fn classify_eth_ipv4_tcp() {
        let pkt = make_eth_ipv4_tcp();
        assert!(matches!(select_template_id(&pkt), Some(TemplateId::EthIpv4Tcp)));
    }

    #[test]
    fn classify_eth_ipv4_udp() {
        let mut pkt = make_eth_ipv4_tcp();
        pkt[23] = 17;
        assert!(matches!(select_template_id(&pkt), Some(TemplateId::EthIpv4Udp)));
    }

    #[test]
    fn classify_eth_ipv4_icmp() {
        let mut pkt = make_eth_ipv4_tcp();
        pkt[23] = 1;
        assert!(matches!(select_template_id(&pkt), Some(TemplateId::EthIpv4Icmp)));
    }

    #[test]
    fn classify_eth_ipv4_sctp() {
        let mut pkt = vec![0u8; 46];
        pkt[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        pkt[14] = 0x45;
        pkt[23] = 132;
        assert!(matches!(select_template_id(&pkt), Some(TemplateId::EthIpv4Sctp)));
    }

    #[test]
    fn classify_eth_ipv6_tcp() {
        let mut pkt = vec![0u8; 74];
        pkt[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
        pkt[14] = 0x60;
        pkt[20] = 6;
        assert!(matches!(select_template_id(&pkt), Some(TemplateId::EthIpv6Tcp)));
    }

    #[test]
    fn classify_eth_arp() {
        let mut pkt = vec![0u8; 42];
        pkt[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        assert!(matches!(select_template_id(&pkt), Some(TemplateId::EthArp)));
    }

    #[test]
    fn classify_vlan_ipv4_tcp() {
        let mut pkt = vec![0u8; 58];
        pkt[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        pkt[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
        pkt[18] = 0x45;
        pkt[27] = 6;
        assert!(matches!(select_template_id(&pkt), Some(TemplateId::EthVlanIpv4Tcp)));
    }

    #[test]
    fn classify_qinq_ipv4_tcp() {
        let mut pkt = vec![0u8; 62];
        pkt[12..14].copy_from_slice(&0x88A8u16.to_be_bytes());
        pkt[16..18].copy_from_slice(&0x8100u16.to_be_bytes());
        pkt[20..22].copy_from_slice(&0x0800u16.to_be_bytes());
        pkt[22] = 0x45;
        pkt[31] = 6;
        assert!(matches!(select_template_id(&pkt), Some(TemplateId::EthQinQIpv4Tcp)));
    }

    #[test]
    fn classify_ipv4_with_options_returns_none() {
        let mut pkt = make_eth_ipv4_tcp();
        pkt[14] = 0x46; // IHL=6
        assert!(select_template_id(&pkt).is_none());
    }

    #[test]
    fn classify_too_short_returns_none() {
        let pkt = vec![0u8; 10];
        assert!(select_template_id(&pkt).is_none());
    }

    #[test]
    fn classify_unknown_ethertype_returns_none() {
        let mut pkt = vec![0u8; 64];
        pkt[12..14].copy_from_slice(&0x1234u16.to_be_bytes());
        assert!(select_template_id(&pkt).is_none());
    }

    #[test]
    fn classify_ipv6_ext_header_returns_none() {
        let mut pkt = vec![0u8; 74];
        pkt[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
        pkt[14] = 0x60;
        pkt[20] = 0; // Hop-by-Hop
        assert!(select_template_id(&pkt).is_none());
    }

    // ── Extractor tests ──────────────────────────────────────────

    #[test]
    fn extract_eth_ipv4_tcp_populates_meta() {
        let pkt = make_eth_ipv4_tcp();
        let mut meta = FlowMeta::default();
        assert!(extract_eth_ipv4_tcp(&pkt, &mut meta).is_ok());
        assert_eq!(meta.addr_type, AddrType::Ipv4);
        assert_eq!(meta.ip_proto, 6);
        assert_eq!(meta.addrs.v4_src, u32::from_be_bytes([10, 0, 0, 1]));
        assert_eq!(meta.addrs.v4_dst, u32::from_be_bytes([10, 0, 0, 2]));
        assert_eq!(meta.ports.src_port, 80);
        assert_eq!(meta.ports.dst_port, 443);
        assert_eq!(meta.eth_proto, 0x0800);
        assert_eq!(meta.l3_off, 14);
        assert_eq!(meta.l4_off, 34);
    }

    #[test]
    fn extract_eth_ipv4_tcp_too_short() {
        let pkt = vec![0u8; 53];
        let mut meta = FlowMeta::default();
        assert!(extract_eth_ipv4_tcp(&pkt, &mut meta).is_err());
    }

    #[test]
    fn extract_eth_ipv6_tcp_populates_meta() {
        let mut pkt = vec![0u8; 74];
        pkt[0..6].copy_from_slice(&[0xCC; 6]);
        pkt[6..12].copy_from_slice(&[0xDD; 6]);
        pkt[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
        pkt[14] = 0x60;
        pkt[15] = 0x0A;
        pkt[16] = 0xBC;
        pkt[17] = 0xDE;
        pkt[20] = 6;
        pkt[22..38].copy_from_slice(&[1; 16]);
        pkt[38..54].copy_from_slice(&[2; 16]);
        pkt[54..56].copy_from_slice(&8080u16.to_be_bytes());
        pkt[56..58].copy_from_slice(&443u16.to_be_bytes());
        let mut meta = FlowMeta::default();
        assert!(extract_eth_ipv6_tcp(&pkt, &mut meta).is_ok());
        assert_eq!(meta.addr_type, AddrType::Ipv6);
        assert_eq!(meta.flow_label, 0xABCDE);
        assert_eq!(meta.ports.src_port, 8080);
        assert_eq!(meta.ports.dst_port, 443);
    }

    #[test]
    fn extract_vlan_ipv4_tcp_populates_vlan() {
        let mut pkt = vec![0u8; 58];
        pkt[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        pkt[14..16].copy_from_slice(&100u16.to_be_bytes());
        pkt[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
        pkt[18] = 0x45;
        pkt[27] = 6;
        pkt[30..34].copy_from_slice(&[192, 168, 1, 1]);
        pkt[34..38].copy_from_slice(&[192, 168, 1, 2]);
        pkt[38..40].copy_from_slice(&22u16.to_be_bytes());
        pkt[40..42].copy_from_slice(&12345u16.to_be_bytes());
        let mut meta = FlowMeta::default();
        assert!(extract_vlan_ipv4_tcp(&pkt, &mut meta).is_ok());
        assert_eq!(meta.vlan_count, 1);
        assert_eq!(meta.vlan[0].tci, 100);
        assert_eq!(meta.vlan[0].tpid, 0x8100);
        assert_eq!(meta.ports.src_port, 22);
        assert_eq!(meta.ports.dst_port, 12345);
    }

    #[test]
    fn extract_by_id_dispatch_matches_direct() {
        let pkt = make_eth_ipv4_tcp();
        let mut meta1 = FlowMeta::default();
        let mut meta2 = FlowMeta::default();
        extract_eth_ipv4_tcp(&pkt, &mut meta1).unwrap();
        extract_by_id(&pkt, TemplateId::EthIpv4Tcp, &mut meta2).unwrap();
        assert_eq!(meta1.ports.src_port, meta2.ports.src_port);
        assert_eq!(meta1.ports.dst_port, meta2.ports.dst_port);
        assert_eq!(meta1.addrs.v4_src, meta2.addrs.v4_src);
    }

    #[test]
    fn extract_eth_arp_populates_arp_meta() {
        let mut pkt = vec![0u8; 42];
        pkt[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        pkt[20..22].copy_from_slice(&1u16.to_be_bytes());
        pkt[22..28].copy_from_slice(&[0xAA; 6]);
        pkt[28..32].copy_from_slice(&[192, 168, 1, 1]);
        pkt[32..38].copy_from_slice(&[0x00; 6]);
        pkt[38..42].copy_from_slice(&[192, 168, 1, 2]);
        let mut meta = FlowMeta::default();
        assert!(extract_eth_arp(&pkt, &mut meta).is_ok());
        assert_eq!(meta.arp.op, 1);
        assert_eq!(meta.arp.sha, [0xAA; 6]);
        assert_eq!(meta.arp.spa, u32::from_be_bytes([192, 168, 1, 1]));
        assert_eq!(meta.arp.tpa, u32::from_be_bytes([192, 168, 1, 2]));
    }
}
