//! QinQ (802.1ad + 802.1Q) template extractors.
//!
//! Header stack: Eth(14) + 802.1ad(4) + 802.1Q(4) + L3 + L4.

use crate::flow_meta::FlowMeta;
use crate::template::{
    extract_arp, extract_eth, extract_icmp, extract_ipv4, extract_ipv6, extract_ports, extract_vlan,
};

const QINQ_L3: usize = 22;

#[inline]
pub(crate) fn extract_qinq_ipv4_tcp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 62 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_L3 as u16; meta.l4_off = (QINQ_L3 + 20) as u16;
    extract_ipv4(pkt, QINQ_L3, meta);
    extract_ports(pkt, QINQ_L3 + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_qinq_ipv4_udp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 50 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_L3 as u16; meta.l4_off = (QINQ_L3 + 20) as u16;
    extract_ipv4(pkt, QINQ_L3, meta);
    extract_ports(pkt, QINQ_L3 + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_qinq_ipv4_icmp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 50 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_L3 as u16; meta.l4_off = (QINQ_L3 + 20) as u16;
    extract_ipv4(pkt, QINQ_L3, meta);
    extract_icmp(pkt, QINQ_L3 + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_qinq_ipv4_sctp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 54 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_L3 as u16; meta.l4_off = (QINQ_L3 + 20) as u16;
    extract_ipv4(pkt, QINQ_L3, meta);
    extract_ports(pkt, QINQ_L3 + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_qinq_ipv4_other(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 42 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_L3 as u16; meta.l4_off = (QINQ_L3 + 20) as u16;
    extract_ipv4(pkt, QINQ_L3, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_qinq_ipv6_tcp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 82 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_L3 as u16; meta.l4_off = (QINQ_L3 + 40) as u16;
    extract_ipv6(pkt, QINQ_L3, meta);
    extract_ports(pkt, QINQ_L3 + 40, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_qinq_ipv6_udp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 70 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_L3 as u16; meta.l4_off = (QINQ_L3 + 40) as u16;
    extract_ipv6(pkt, QINQ_L3, meta);
    extract_ports(pkt, QINQ_L3 + 40, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_qinq_ipv6_icmpv6(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 70 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_L3 as u16; meta.l4_off = (QINQ_L3 + 40) as u16;
    extract_ipv6(pkt, QINQ_L3, meta);
    extract_icmp(pkt, QINQ_L3 + 40, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_qinq_ipv6_sctp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 74 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_L3 as u16; meta.l4_off = (QINQ_L3 + 40) as u16;
    extract_ipv6(pkt, QINQ_L3, meta);
    extract_ports(pkt, QINQ_L3 + 40, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_qinq_ipv6_other(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 62 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0; meta.l3_off = QINQ_L3 as u16; meta.l4_off = (QINQ_L3 + 40) as u16;
    extract_ipv6(pkt, QINQ_L3, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_qinq_arp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 50 { return Err(()); }
    extract_eth(pkt, meta);
    extract_vlan(pkt, 14, 0x88A8, meta);
    extract_vlan(pkt, 18, 0x8100, meta);
    meta.l2_off = 0;
    extract_arp(pkt, QINQ_L3, meta);
    Ok(())
}
