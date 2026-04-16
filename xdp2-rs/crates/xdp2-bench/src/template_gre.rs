//! GRE tunnel template extractors.
//!
//! Covers plain GRE, double GRE, VLAN+GRE, and QinQ+GRE.
//! All GRE headers must be basic (no optional fields, version 0).

use crate::flow_meta::FlowMeta;
use crate::template::{
    extract_eth, extract_icmp, extract_ipv4, extract_ipv6, extract_ports, extract_vlan,
};

// ── Plain GRE — Eth(14) + IPv4(20) + GRE(4) + inner ─────────

const GRE_INNER: usize = 14 + 20 + 4; // 38

#[inline]
pub(crate) fn extract_gre_ipv4_tcp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 78 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = GRE_INNER as u16; meta.l4_off = (GRE_INNER + 20) as u16;
    extract_ipv4(pkt, GRE_INNER, meta);
    extract_ports(pkt, GRE_INNER + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_gre_ipv4_udp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 66 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = GRE_INNER as u16; meta.l4_off = (GRE_INNER + 20) as u16;
    extract_ipv4(pkt, GRE_INNER, meta);
    extract_ports(pkt, GRE_INNER + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_gre_ipv4_icmp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 66 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = GRE_INNER as u16; meta.l4_off = (GRE_INNER + 20) as u16;
    extract_ipv4(pkt, GRE_INNER, meta);
    extract_icmp(pkt, GRE_INNER + 20, meta);
    Ok(())
}

// GRE + IPv6 inner (L3 at 38, L4 at 78)
const GRE_IPV6_L4: usize = GRE_INNER + 40; // 78

#[inline]
pub(crate) fn extract_gre_ipv6_tcp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 98 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = GRE_INNER as u16; meta.l4_off = GRE_IPV6_L4 as u16;
    extract_ipv6(pkt, GRE_INNER, meta);
    extract_ports(pkt, GRE_IPV6_L4, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_gre_ipv6_udp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 86 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = GRE_INNER as u16; meta.l4_off = GRE_IPV6_L4 as u16;
    extract_ipv6(pkt, GRE_INNER, meta);
    extract_ports(pkt, GRE_IPV6_L4, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_gre_ipv6_icmpv6(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 86 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = GRE_INNER as u16; meta.l4_off = GRE_IPV6_L4 as u16;
    extract_ipv6(pkt, GRE_INNER, meta);
    extract_icmp(pkt, GRE_IPV6_L4, meta);
    Ok(())
}

// ── Double GRE — Eth(14) + IPv4(20) + GRE(4) + IPv4(20) + GRE(4) + inner ──

const GRE2_INNER: usize = 14 + 20 + 4 + 20 + 4; // 62

#[inline]
pub(crate) fn extract_gre2_ipv4_tcp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 102 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = GRE2_INNER as u16; meta.l4_off = (GRE2_INNER + 20) as u16;
    extract_ipv4(pkt, GRE2_INNER, meta);
    extract_ports(pkt, GRE2_INNER + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_gre2_ipv4_udp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 90 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = GRE2_INNER as u16; meta.l4_off = (GRE2_INNER + 20) as u16;
    extract_ipv4(pkt, GRE2_INNER, meta);
    extract_ports(pkt, GRE2_INNER + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_gre2_ipv4_icmp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 90 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = GRE2_INNER as u16; meta.l4_off = (GRE2_INNER + 20) as u16;
    extract_ipv4(pkt, GRE2_INNER, meta);
    extract_icmp(pkt, GRE2_INNER + 20, meta);
    Ok(())
}

// ── VLAN + GRE — Eth(14) + VLAN(4) + IPv4(20) + GRE(4) + inner ─────

const VLAN_GRE_INNER: usize = 14 + 4 + 20 + 4; // 42

#[inline]
pub(crate) fn extract_vlan_gre_ipv4_tcp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 82 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = VLAN_GRE_INNER as u16; meta.l4_off = (VLAN_GRE_INNER + 20) as u16;
    extract_ipv4(pkt, VLAN_GRE_INNER, meta);
    extract_ports(pkt, VLAN_GRE_INNER + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_vlan_gre_ipv4_udp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 70 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = VLAN_GRE_INNER as u16; meta.l4_off = (VLAN_GRE_INNER + 20) as u16;
    extract_ipv4(pkt, VLAN_GRE_INNER, meta);
    extract_ports(pkt, VLAN_GRE_INNER + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_vlan_gre_ipv4_icmp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 70 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = VLAN_GRE_INNER as u16; meta.l4_off = (VLAN_GRE_INNER + 20) as u16;
    extract_ipv4(pkt, VLAN_GRE_INNER, meta);
    extract_icmp(pkt, VLAN_GRE_INNER + 20, meta);
    Ok(())
}

// VLAN + GRE + IPv6 inner
const VLAN_GRE_IPV6_L4: usize = VLAN_GRE_INNER + 40; // 82

#[inline]
pub(crate) fn extract_vlan_gre_ipv6_tcp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 102 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = VLAN_GRE_INNER as u16; meta.l4_off = VLAN_GRE_IPV6_L4 as u16;
    extract_ipv6(pkt, VLAN_GRE_INNER, meta);
    extract_ports(pkt, VLAN_GRE_IPV6_L4, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_vlan_gre_ipv6_udp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 90 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = VLAN_GRE_INNER as u16; meta.l4_off = VLAN_GRE_IPV6_L4 as u16;
    extract_ipv6(pkt, VLAN_GRE_INNER, meta);
    extract_ports(pkt, VLAN_GRE_IPV6_L4, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_vlan_gre_ipv6_icmpv6(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 90 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = VLAN_GRE_INNER as u16; meta.l4_off = VLAN_GRE_IPV6_L4 as u16;
    extract_ipv6(pkt, VLAN_GRE_INNER, meta);
    extract_icmp(pkt, VLAN_GRE_IPV6_L4, meta);
    Ok(())
}

// ── QinQ + GRE — Eth(14) + 802.1ad(4) + 802.1Q(4) + IPv4(20) + GRE(4) + inner ──

const QINQ_GRE_INNER: usize = 14 + 4 + 4 + 20 + 4; // 46

#[inline]
pub(crate) fn extract_qinq_gre_ipv4_tcp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 86 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_GRE_INNER as u16; meta.l4_off = (QINQ_GRE_INNER + 20) as u16;
    extract_ipv4(pkt, QINQ_GRE_INNER, meta);
    extract_ports(pkt, QINQ_GRE_INNER + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_qinq_gre_ipv4_udp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 74 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_GRE_INNER as u16; meta.l4_off = (QINQ_GRE_INNER + 20) as u16;
    extract_ipv4(pkt, QINQ_GRE_INNER, meta);
    extract_ports(pkt, QINQ_GRE_INNER + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_qinq_gre_ipv4_icmp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 74 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_GRE_INNER as u16; meta.l4_off = (QINQ_GRE_INNER + 20) as u16;
    extract_ipv4(pkt, QINQ_GRE_INNER, meta);
    extract_icmp(pkt, QINQ_GRE_INNER + 20, meta);
    Ok(())
}

// QinQ + GRE + IPv6 inner
const QINQ_GRE_IPV6_L4: usize = QINQ_GRE_INNER + 40; // 86

#[inline]
pub(crate) fn extract_qinq_gre_ipv6_tcp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 106 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_GRE_INNER as u16; meta.l4_off = QINQ_GRE_IPV6_L4 as u16;
    extract_ipv6(pkt, QINQ_GRE_INNER, meta);
    extract_ports(pkt, QINQ_GRE_IPV6_L4, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_qinq_gre_ipv6_udp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 94 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_GRE_INNER as u16; meta.l4_off = QINQ_GRE_IPV6_L4 as u16;
    extract_ipv6(pkt, QINQ_GRE_INNER, meta);
    extract_ports(pkt, QINQ_GRE_IPV6_L4, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_qinq_gre_ipv6_icmpv6(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 94 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_GRE_INNER as u16; meta.l4_off = QINQ_GRE_IPV6_L4 as u16;
    extract_ipv6(pkt, QINQ_GRE_INNER, meta);
    extract_icmp(pkt, QINQ_GRE_IPV6_L4, meta);
    Ok(())
}
