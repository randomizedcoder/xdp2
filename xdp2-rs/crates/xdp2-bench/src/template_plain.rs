//! Plain (no encapsulation) template extractors.
//!
//! Header stack: Eth(14) + L3 + L4.

use crate::flow_meta::FlowMeta;
use crate::template::{extract_arp, extract_eth, extract_icmp, extract_ipv4, extract_ipv6, extract_ports};

const PLAIN_L3: usize = 14;

#[inline]
pub(crate) fn extract_eth_ipv4_tcp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 54 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = PLAIN_L3 as u16; meta.l4_off = (PLAIN_L3 + 20) as u16;
    extract_ipv4(pkt, PLAIN_L3, meta);
    extract_ports(pkt, PLAIN_L3 + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_eth_ipv4_udp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 42 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = PLAIN_L3 as u16; meta.l4_off = (PLAIN_L3 + 20) as u16;
    extract_ipv4(pkt, PLAIN_L3, meta);
    extract_ports(pkt, PLAIN_L3 + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_eth_ipv4_icmp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 42 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = PLAIN_L3 as u16; meta.l4_off = (PLAIN_L3 + 20) as u16;
    extract_ipv4(pkt, PLAIN_L3, meta);
    extract_icmp(pkt, PLAIN_L3 + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_eth_ipv4_sctp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 46 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = PLAIN_L3 as u16; meta.l4_off = (PLAIN_L3 + 20) as u16;
    extract_ipv4(pkt, PLAIN_L3, meta);
    extract_ports(pkt, PLAIN_L3 + 20, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_eth_ipv4_other(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 34 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = PLAIN_L3 as u16; meta.l4_off = (PLAIN_L3 + 20) as u16;
    extract_ipv4(pkt, PLAIN_L3, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_eth_ipv6_tcp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 74 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = PLAIN_L3 as u16; meta.l4_off = (PLAIN_L3 + 40) as u16;
    extract_ipv6(pkt, PLAIN_L3, meta);
    extract_ports(pkt, PLAIN_L3 + 40, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_eth_ipv6_udp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 62 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = PLAIN_L3 as u16; meta.l4_off = (PLAIN_L3 + 40) as u16;
    extract_ipv6(pkt, PLAIN_L3, meta);
    extract_ports(pkt, PLAIN_L3 + 40, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_eth_ipv6_icmpv6(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 62 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = PLAIN_L3 as u16; meta.l4_off = (PLAIN_L3 + 40) as u16;
    extract_ipv6(pkt, PLAIN_L3, meta);
    extract_icmp(pkt, PLAIN_L3 + 40, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_eth_ipv6_sctp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 66 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = PLAIN_L3 as u16; meta.l4_off = (PLAIN_L3 + 40) as u16;
    extract_ipv6(pkt, PLAIN_L3, meta);
    extract_ports(pkt, PLAIN_L3 + 40, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_eth_ipv6_other(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 54 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0; meta.l3_off = PLAIN_L3 as u16; meta.l4_off = (PLAIN_L3 + 40) as u16;
    extract_ipv6(pkt, PLAIN_L3, meta);
    Ok(())
}

#[inline]
pub(crate) fn extract_eth_arp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 42 { return Err(()); }
    extract_eth(pkt, meta);
    meta.l2_off = 0;
    extract_arp(pkt, PLAIN_L3, meta);
    Ok(())
}
