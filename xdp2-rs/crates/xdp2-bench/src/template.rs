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

pub(crate) use crate::template_gre::*;
pub(crate) use crate::template_ipip::*;
pub(crate) use crate::template_plain::*;
pub(crate) use crate::template_qinq::*;
pub(crate) use crate::template_vlan::*;

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
    meta.addrs.v4_src =
        u32::from_be_bytes([pkt[off + 12], pkt[off + 13], pkt[off + 14], pkt[off + 15]]);
    meta.addrs.v4_dst =
        u32::from_be_bytes([pkt[off + 16], pkt[off + 17], pkt[off + 18], pkt[off + 19]]);
}

#[inline(always)]
pub(crate) fn extract_ipv6(pkt: &[u8], off: usize, meta: &mut FlowMeta) {
    meta.addr_type = AddrType::Ipv6;
    meta.ip_proto = pkt[off + 6];
    meta.flow_label =
        ((pkt[off + 1] as u32 & 0x0F) << 16) | ((pkt[off + 2] as u32) << 8) | (pkt[off + 3] as u32);
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
        // Sentinel: wire id=0 → 1 (see extractors.rs).
        let id_val = u16::from_be_bytes([pkt[off + 4], pkt[off + 5]]);
        meta.icmp.id = if id_val == 0 { 1 } else { id_val };
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
    EthIpv4Tcp,
    EthIpv4Udp,
    EthIpv4Icmp,
    EthIpv4Sctp,
    EthIpv4Other,
    EthIpv6Tcp,
    EthIpv6Udp,
    EthIpv6Icmpv6,
    EthIpv6Sctp,
    EthIpv6Other,
    EthArp,
    // ── Single VLAN (802.1Q) ──
    EthVlanIpv4Tcp,
    EthVlanIpv4Udp,
    EthVlanIpv4Icmp,
    EthVlanIpv4Sctp,
    EthVlanIpv4Other,
    EthVlanIpv6Tcp,
    EthVlanIpv6Udp,
    EthVlanIpv6Icmpv6,
    EthVlanIpv6Sctp,
    EthVlanIpv6Other,
    EthVlanArp,
    // ── QinQ (802.1ad + 802.1Q) ──
    EthQinQIpv4Tcp,
    EthQinQIpv4Udp,
    EthQinQIpv4Icmp,
    EthQinQIpv4Sctp,
    EthQinQIpv4Other,
    EthQinQIpv6Tcp,
    EthQinQIpv6Udp,
    EthQinQIpv6Icmpv6,
    EthQinQIpv6Sctp,
    EthQinQIpv6Other,
    EthQinQArp,
    // ── GRE (basic, no optional fields) ──
    EthIpv4GreIpv4Tcp,
    EthIpv4GreIpv4Udp,
    EthIpv4GreIpv4Icmp,
    EthIpv4GreIpv6Tcp,
    EthIpv4GreIpv6Udp,
    EthIpv4GreIpv6Icmpv6,
    // ── Double GRE ──
    EthIpv4GreIpv4GreIpv4Tcp,
    EthIpv4GreIpv4GreIpv4Udp,
    EthIpv4GreIpv4GreIpv4Icmp,
    // ── VLAN + GRE ──
    EthVlanIpv4GreIpv4Tcp,
    EthVlanIpv4GreIpv4Udp,
    EthVlanIpv4GreIpv4Icmp,
    EthVlanIpv4GreIpv6Tcp,
    EthVlanIpv4GreIpv6Udp,
    EthVlanIpv4GreIpv6Icmpv6,
    // ── QinQ + GRE ──
    EthQinQIpv4GreIpv4Tcp,
    EthQinQIpv4GreIpv4Udp,
    EthQinQIpv4GreIpv4Icmp,
    EthQinQIpv4GreIpv6Tcp,
    EthQinQIpv4GreIpv6Udp,
    EthQinQIpv4GreIpv6Icmpv6,
    // ── IP-in-IP (proto 4) ──
    EthIpv4Ipv4Tcp,
    EthIpv4Ipv4Udp,
    EthIpv4Ipv4Icmp,
    // ── VLAN + IP-in-IP ──
    EthVlanIpv4Ipv4Tcp,
    EthVlanIpv4Ipv4Udp,
    EthVlanIpv4Ipv4Icmp,
    // ── QinQ + IP-in-IP ──
    EthQinQIpv4Ipv4Tcp,
    EthQinQIpv4Ipv4Udp,
    EthQinQIpv4Ipv4Icmp,
}

/// Dispatch to the specialized extractor for a pre-selected template.
#[inline]
pub fn extract_by_id(pkt: &[u8], id: TemplateId, meta: &mut FlowMeta) -> Result<(), ()> {
    use TemplateId::*;
    match id {
        // Plain
        EthIpv4Tcp => extract_eth_ipv4_tcp(pkt, meta),
        EthIpv4Udp => extract_eth_ipv4_udp(pkt, meta),
        EthIpv4Icmp => extract_eth_ipv4_icmp(pkt, meta),
        EthIpv4Sctp => extract_eth_ipv4_sctp(pkt, meta),
        EthIpv4Other => extract_eth_ipv4_other(pkt, meta),
        EthIpv6Tcp => extract_eth_ipv6_tcp(pkt, meta),
        EthIpv6Udp => extract_eth_ipv6_udp(pkt, meta),
        EthIpv6Icmpv6 => extract_eth_ipv6_icmpv6(pkt, meta),
        EthIpv6Sctp => extract_eth_ipv6_sctp(pkt, meta),
        EthIpv6Other => extract_eth_ipv6_other(pkt, meta),
        EthArp => extract_eth_arp(pkt, meta),
        // VLAN
        EthVlanIpv4Tcp => extract_vlan_ipv4_tcp(pkt, meta),
        EthVlanIpv4Udp => extract_vlan_ipv4_udp(pkt, meta),
        EthVlanIpv4Icmp => extract_vlan_ipv4_icmp(pkt, meta),
        EthVlanIpv4Sctp => extract_vlan_ipv4_sctp(pkt, meta),
        EthVlanIpv4Other => extract_vlan_ipv4_other(pkt, meta),
        EthVlanIpv6Tcp => extract_vlan_ipv6_tcp(pkt, meta),
        EthVlanIpv6Udp => extract_vlan_ipv6_udp(pkt, meta),
        EthVlanIpv6Icmpv6 => extract_vlan_ipv6_icmpv6(pkt, meta),
        EthVlanIpv6Sctp => extract_vlan_ipv6_sctp(pkt, meta),
        EthVlanIpv6Other => extract_vlan_ipv6_other(pkt, meta),
        EthVlanArp => extract_vlan_arp(pkt, meta),
        // QinQ
        EthQinQIpv4Tcp => extract_qinq_ipv4_tcp(pkt, meta),
        EthQinQIpv4Udp => extract_qinq_ipv4_udp(pkt, meta),
        EthQinQIpv4Icmp => extract_qinq_ipv4_icmp(pkt, meta),
        EthQinQIpv4Sctp => extract_qinq_ipv4_sctp(pkt, meta),
        EthQinQIpv4Other => extract_qinq_ipv4_other(pkt, meta),
        EthQinQIpv6Tcp => extract_qinq_ipv6_tcp(pkt, meta),
        EthQinQIpv6Udp => extract_qinq_ipv6_udp(pkt, meta),
        EthQinQIpv6Icmpv6 => extract_qinq_ipv6_icmpv6(pkt, meta),
        EthQinQIpv6Sctp => extract_qinq_ipv6_sctp(pkt, meta),
        EthQinQIpv6Other => extract_qinq_ipv6_other(pkt, meta),
        EthQinQArp => extract_qinq_arp(pkt, meta),
        // GRE (plain)
        EthIpv4GreIpv4Tcp => extract_gre_ipv4_tcp(pkt, meta),
        EthIpv4GreIpv4Udp => extract_gre_ipv4_udp(pkt, meta),
        EthIpv4GreIpv4Icmp => extract_gre_ipv4_icmp(pkt, meta),
        EthIpv4GreIpv6Tcp => extract_gre_ipv6_tcp(pkt, meta),
        EthIpv4GreIpv6Udp => extract_gre_ipv6_udp(pkt, meta),
        EthIpv4GreIpv6Icmpv6 => extract_gre_ipv6_icmpv6(pkt, meta),
        // Double GRE
        EthIpv4GreIpv4GreIpv4Tcp => extract_gre2_ipv4_tcp(pkt, meta),
        EthIpv4GreIpv4GreIpv4Udp => extract_gre2_ipv4_udp(pkt, meta),
        EthIpv4GreIpv4GreIpv4Icmp => extract_gre2_ipv4_icmp(pkt, meta),
        // VLAN+GRE
        EthVlanIpv4GreIpv4Tcp => extract_vlan_gre_ipv4_tcp(pkt, meta),
        EthVlanIpv4GreIpv4Udp => extract_vlan_gre_ipv4_udp(pkt, meta),
        EthVlanIpv4GreIpv4Icmp => extract_vlan_gre_ipv4_icmp(pkt, meta),
        EthVlanIpv4GreIpv6Tcp => extract_vlan_gre_ipv6_tcp(pkt, meta),
        EthVlanIpv4GreIpv6Udp => extract_vlan_gre_ipv6_udp(pkt, meta),
        EthVlanIpv4GreIpv6Icmpv6 => extract_vlan_gre_ipv6_icmpv6(pkt, meta),
        // QinQ+GRE
        EthQinQIpv4GreIpv4Tcp => extract_qinq_gre_ipv4_tcp(pkt, meta),
        EthQinQIpv4GreIpv4Udp => extract_qinq_gre_ipv4_udp(pkt, meta),
        EthQinQIpv4GreIpv4Icmp => extract_qinq_gre_ipv4_icmp(pkt, meta),
        EthQinQIpv4GreIpv6Tcp => extract_qinq_gre_ipv6_tcp(pkt, meta),
        EthQinQIpv4GreIpv6Udp => extract_qinq_gre_ipv6_udp(pkt, meta),
        EthQinQIpv4GreIpv6Icmpv6 => extract_qinq_gre_ipv6_icmpv6(pkt, meta),
        // IP-in-IP (plain)
        EthIpv4Ipv4Tcp => extract_ipip_tcp(pkt, meta),
        EthIpv4Ipv4Udp => extract_ipip_udp(pkt, meta),
        EthIpv4Ipv4Icmp => extract_ipip_icmp(pkt, meta),
        // VLAN+IP-in-IP
        EthVlanIpv4Ipv4Tcp => extract_vlan_ipip_tcp(pkt, meta),
        EthVlanIpv4Ipv4Udp => extract_vlan_ipip_udp(pkt, meta),
        EthVlanIpv4Ipv4Icmp => extract_vlan_ipip_icmp(pkt, meta),
        // QinQ+IP-in-IP
        EthQinQIpv4Ipv4Tcp => extract_qinq_ipip_tcp(pkt, meta),
        EthQinQIpv4Ipv4Udp => extract_qinq_ipip_udp(pkt, meta),
        EthQinQIpv4Ipv4Icmp => extract_qinq_ipip_icmp(pkt, meta),
    }
}

// Re-export classifier so callers can use template::select_template_id
pub use crate::template_classify::*;

#[cfg(test)]
#[path = "template_tests.rs"]
mod tests;
