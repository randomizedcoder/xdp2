//! Step 12a/b: Hardware-classified template extraction.
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
//! See `docs/hardware-classified-extraction.md` for the full concept.

use crate::graph::{AddrType, FlowMeta};

/// Template ID for pre-selected packets.
#[derive(Clone, Copy, Debug)]
pub enum TemplateId {
    EthIpv4Tcp,
    EthIpv4Udp,
    EthIpv6Tcp,
}

/// Dispatch to the specialized extractor for a pre-selected template.
/// Populates `meta` with the same fields as graph/compiled modes.
#[inline]
pub fn extract_by_id(pkt: &[u8], id: TemplateId, meta: &mut FlowMeta) -> Result<(), ()> {
    match id {
        TemplateId::EthIpv4Tcp => extract_eth_ipv4_tcp(pkt, meta),
        TemplateId::EthIpv4Udp => extract_eth_ipv4_udp(pkt, meta),
        TemplateId::EthIpv6Tcp => extract_eth_ipv6_tcp(pkt, meta),
    }
}

/// Eth/IPv4(IHL=5)/TCP — 54 bytes minimum.
///
/// Extracts the same metadata as graph mode's extract_ether_metadata +
/// extract_ipv4_metadata + extract_ports_metadata, but at fixed offsets
/// from packet start.
#[inline]
pub fn extract_eth_ipv4_tcp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 54 {
        return Err(());
    }

    // Ethernet: MACs + ethertype (same as extract_ether_metadata)
    meta.eth_addrs[..12].copy_from_slice(&pkt[0..12]);
    meta.eth_proto = u16::from_be_bytes([pkt[12], pkt[13]]);
    meta.l2_off = 0;
    meta.l3_off = 14;
    meta.l4_off = 34; // 14 (eth) + 20 (ipv4 IHL=5)

    // IPv4: fragment info, addresses, protocol (same as extract_ipv4_metadata)
    let frag_off = u16::from_be_bytes([pkt[20], pkt[21]]);
    const IP_MF: u16 = 0x2000;
    const IP_OFFSET: u16 = 0x1FFF;
    if (frag_off & (IP_MF | IP_OFFSET)) != 0 {
        meta.is_fragment = true;
        meta.first_frag = (frag_off & IP_OFFSET) == 0;
    }
    meta.addr_type = AddrType::Ipv4;
    meta.ip_proto = pkt[23];
    meta.addrs.v4_src = u32::from_be_bytes([pkt[26], pkt[27], pkt[28], pkt[29]]);
    meta.addrs.v4_dst = u32::from_be_bytes([pkt[30], pkt[31], pkt[32], pkt[33]]);

    // TCP: ports (same as extract_ports_metadata)
    meta.ports.src_port = u16::from_be_bytes([pkt[34], pkt[35]]);
    meta.ports.dst_port = u16::from_be_bytes([pkt[36], pkt[37]]);

    Ok(())
}

/// Eth/IPv4(IHL=5)/UDP — 42 bytes minimum.
#[inline]
pub fn extract_eth_ipv4_udp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 42 {
        return Err(());
    }

    // Ethernet
    meta.eth_addrs[..12].copy_from_slice(&pkt[0..12]);
    meta.eth_proto = u16::from_be_bytes([pkt[12], pkt[13]]);
    meta.l2_off = 0;
    meta.l3_off = 14;
    meta.l4_off = 34;

    // IPv4
    let frag_off = u16::from_be_bytes([pkt[20], pkt[21]]);
    const IP_MF: u16 = 0x2000;
    const IP_OFFSET: u16 = 0x1FFF;
    if (frag_off & (IP_MF | IP_OFFSET)) != 0 {
        meta.is_fragment = true;
        meta.first_frag = (frag_off & IP_OFFSET) == 0;
    }
    meta.addr_type = AddrType::Ipv4;
    meta.ip_proto = pkt[23];
    meta.addrs.v4_src = u32::from_be_bytes([pkt[26], pkt[27], pkt[28], pkt[29]]);
    meta.addrs.v4_dst = u32::from_be_bytes([pkt[30], pkt[31], pkt[32], pkt[33]]);

    // UDP: ports
    meta.ports.src_port = u16::from_be_bytes([pkt[34], pkt[35]]);
    meta.ports.dst_port = u16::from_be_bytes([pkt[36], pkt[37]]);

    Ok(())
}

/// Eth/IPv6/TCP — 74 bytes minimum.
#[inline]
pub fn extract_eth_ipv6_tcp(pkt: &[u8], meta: &mut FlowMeta) -> Result<(), ()> {
    if pkt.len() < 74 {
        return Err(());
    }

    // Ethernet
    meta.eth_addrs[..12].copy_from_slice(&pkt[0..12]);
    meta.eth_proto = u16::from_be_bytes([pkt[12], pkt[13]]);
    meta.l2_off = 0;
    meta.l3_off = 14;
    meta.l4_off = 54; // 14 (eth) + 40 (ipv6)

    // IPv6 (same as extract_ipv6_metadata, header at offset 14)
    meta.addr_type = AddrType::Ipv6;
    meta.ip_proto = pkt[20]; // next header
    meta.flow_label =
        ((pkt[15] as u32 & 0x0F) << 16) | ((pkt[16] as u32) << 8) | (pkt[17] as u32);
    meta.addrs.v6_src.copy_from_slice(&pkt[22..38]);
    meta.addrs.v6_dst.copy_from_slice(&pkt[38..54]);

    // TCP: ports
    meta.ports.src_port = u16::from_be_bytes([pkt[54], pkt[55]]);
    meta.ports.dst_port = u16::from_be_bytes([pkt[56], pkt[57]]);

    Ok(())
}

/// Select template ID for a packet.  In production, this is the NIC
/// queue number — zero runtime cost.  Here we sniff for benchmarking.
pub fn select_template_id(pkt: &[u8]) -> Option<TemplateId> {
    if pkt.len() < 34 {
        return None;
    }
    let ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
    match ethertype {
        0x0800 => {
            if pkt[14] & 0x0F != 5 {
                return None;
            }
            match pkt[23] {
                6 => Some(TemplateId::EthIpv4Tcp),
                17 => Some(TemplateId::EthIpv4Udp),
                _ => None,
            }
        }
        0x86DD => {
            if pkt.len() < 54 {
                return None;
            }
            match pkt[20] {
                6 => Some(TemplateId::EthIpv6Tcp),
                _ => None,
            }
        }
        _ => None,
    }
}
