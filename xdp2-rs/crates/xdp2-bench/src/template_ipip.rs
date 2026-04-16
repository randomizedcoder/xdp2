//! IP-in-IP tunnel template extractors.
//!
//! Covers plain IP-in-IP (proto 4), VLAN+IP-in-IP, and QinQ+IP-in-IP.

use crate::flow_meta::FlowMeta;
use crate::template::{extract_eth, extract_icmp, extract_ipv4, extract_ports, extract_vlan};

// ── Plain IP-in-IP — Eth(14) + outer IPv4(20) + inner IPv4(20) + L4 ──

const IPIP_INNER: usize = 14 + 20; // 34

#[inline]
pub(crate) fn extract_ipip_tcp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 74 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = IPIP_INNER as u16; meta.l4_off = (IPIP_INNER + 20) as u16;
    extract_ipv4(pkt, IPIP_INNER, meta);
    extract_ports(pkt, IPIP_INNER + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_ipip_udp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 62 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = IPIP_INNER as u16; meta.l4_off = (IPIP_INNER + 20) as u16;
    extract_ipv4(pkt, IPIP_INNER, meta);
    extract_ports(pkt, IPIP_INNER + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_ipip_icmp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 62 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = IPIP_INNER as u16; meta.l4_off = (IPIP_INNER + 20) as u16;
    extract_ipv4(pkt, IPIP_INNER, meta);
    extract_icmp(pkt, IPIP_INNER + 20, meta);
    Ok(())
}

// ── VLAN + IP-in-IP — Eth(14) + VLAN(4) + outer IPv4(20) + inner IPv4(20) + L4 ──

const VLAN_IPIP_INNER: usize = 14 + 4 + 20; // 38

#[inline]
pub(crate) fn extract_vlan_ipip_tcp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 78 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = VLAN_IPIP_INNER as u16; meta.l4_off = (VLAN_IPIP_INNER + 20) as u16;
    extract_ipv4(pkt, VLAN_IPIP_INNER, meta);
    extract_ports(pkt, VLAN_IPIP_INNER + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_vlan_ipip_udp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 66 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = VLAN_IPIP_INNER as u16; meta.l4_off = (VLAN_IPIP_INNER + 20) as u16;
    extract_ipv4(pkt, VLAN_IPIP_INNER, meta);
    extract_ports(pkt, VLAN_IPIP_INNER + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_vlan_ipip_icmp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 66 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = VLAN_IPIP_INNER as u16; meta.l4_off = (VLAN_IPIP_INNER + 20) as u16;
    extract_ipv4(pkt, VLAN_IPIP_INNER, meta);
    extract_icmp(pkt, VLAN_IPIP_INNER + 20, meta);
    Ok(())
}

// ── QinQ + IP-in-IP — Eth(14) + 802.1ad(4) + 802.1Q(4) + outer IPv4(20) + inner IPv4(20) + L4 ──

const QINQ_IPIP_INNER: usize = 14 + 4 + 4 + 20; // 42

#[inline]
pub(crate) fn extract_qinq_ipip_tcp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 82 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_IPIP_INNER as u16; meta.l4_off = (QINQ_IPIP_INNER + 20) as u16;
    extract_ipv4(pkt, QINQ_IPIP_INNER, meta);
    extract_ports(pkt, QINQ_IPIP_INNER + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_qinq_ipip_udp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 70 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_IPIP_INNER as u16; meta.l4_off = (QINQ_IPIP_INNER + 20) as u16;
    extract_ipv4(pkt, QINQ_IPIP_INNER, meta);
    extract_ports(pkt, QINQ_IPIP_INNER + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_qinq_ipip_icmp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 70 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_IPIP_INNER as u16; meta.l4_off = (QINQ_IPIP_INNER + 20) as u16;
    extract_ipv4(pkt, QINQ_IPIP_INNER, meta);
    extract_icmp(pkt, QINQ_IPIP_INNER + 20, meta);
    Ok(())
}
