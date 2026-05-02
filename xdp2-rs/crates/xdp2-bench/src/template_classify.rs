//! Software classifier for template selection.
//!
//! In production this is the NIC queue number (Flow Director / ntuple).
//! For benchmarking, we sniff headers to select the matching template.

use crate::template::TemplateId;

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
enum L2Kind {
    Plain,
    Vlan,
    QinQ,
}

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
        L2Kind::Vlan => TemplateId::EthVlanArp,
        L2Kind::QinQ => TemplateId::EthQinQArp,
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
            L2Kind::Vlan => TemplateId::EthVlanIpv4Tcp,
            L2Kind::QinQ => TemplateId::EthQinQIpv4Tcp,
        }),
        17 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv4Udp,
            L2Kind::Vlan => TemplateId::EthVlanIpv4Udp,
            L2Kind::QinQ => TemplateId::EthQinQIpv4Udp,
        }),
        1 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv4Icmp,
            L2Kind::Vlan => TemplateId::EthVlanIpv4Icmp,
            L2Kind::QinQ => TemplateId::EthQinQIpv4Icmp,
        }),
        132 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv4Sctp,
            L2Kind::Vlan => TemplateId::EthVlanIpv4Sctp,
            L2Kind::QinQ => TemplateId::EthQinQIpv4Sctp,
        }),
        47 => classify_gre(pkt, l3_off + 20, kind),
        4 => classify_ipip(pkt, l3_off + 20, kind),
        _ => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv4Other,
            L2Kind::Vlan => TemplateId::EthVlanIpv4Other,
            L2Kind::QinQ => TemplateId::EthQinQIpv4Other,
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
            L2Kind::Vlan => TemplateId::EthVlanIpv6Tcp,
            L2Kind::QinQ => TemplateId::EthQinQIpv6Tcp,
        }),
        17 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv6Udp,
            L2Kind::Vlan => TemplateId::EthVlanIpv6Udp,
            L2Kind::QinQ => TemplateId::EthQinQIpv6Udp,
        }),
        58 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv6Icmpv6,
            L2Kind::Vlan => TemplateId::EthVlanIpv6Icmpv6,
            L2Kind::QinQ => TemplateId::EthQinQIpv6Icmpv6,
        }),
        132 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv6Sctp,
            L2Kind::Vlan => TemplateId::EthVlanIpv6Sctp,
            L2Kind::QinQ => TemplateId::EthQinQIpv6Sctp,
        }),
        // IPv6 extension headers (0,43,44,51,50,60,135) have variable length — fall back.
        0 | 43 | 44 | 50 | 51 | 60 | 135 => None,
        _ => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv6Other,
            L2Kind::Vlan => TemplateId::EthVlanIpv6Other,
            L2Kind::QinQ => TemplateId::EthQinQIpv6Other,
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
                    L2Kind::Vlan => TemplateId::EthVlanIpv4GreIpv4Tcp,
                    L2Kind::QinQ => TemplateId::EthQinQIpv4GreIpv4Tcp,
                }),
                17 => Some(match kind {
                    L2Kind::Plain => TemplateId::EthIpv4GreIpv4Udp,
                    L2Kind::Vlan => TemplateId::EthVlanIpv4GreIpv4Udp,
                    L2Kind::QinQ => TemplateId::EthQinQIpv4GreIpv4Udp,
                }),
                1 => Some(match kind {
                    L2Kind::Plain => TemplateId::EthIpv4GreIpv4Icmp,
                    L2Kind::Vlan => TemplateId::EthVlanIpv4GreIpv4Icmp,
                    L2Kind::QinQ => TemplateId::EthQinQIpv4GreIpv4Icmp,
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
                    L2Kind::Vlan => TemplateId::EthVlanIpv4GreIpv6Tcp,
                    L2Kind::QinQ => TemplateId::EthQinQIpv4GreIpv6Tcp,
                }),
                17 => Some(match kind {
                    L2Kind::Plain => TemplateId::EthIpv4GreIpv6Udp,
                    L2Kind::Vlan => TemplateId::EthVlanIpv4GreIpv6Udp,
                    L2Kind::QinQ => TemplateId::EthQinQIpv4GreIpv6Udp,
                }),
                58 => Some(match kind {
                    L2Kind::Plain => TemplateId::EthIpv4GreIpv6Icmpv6,
                    L2Kind::Vlan => TemplateId::EthVlanIpv4GreIpv6Icmpv6,
                    L2Kind::QinQ => TemplateId::EthQinQIpv4GreIpv6Icmpv6,
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
        6 => Some(TemplateId::EthIpv4GreIpv4GreIpv4Tcp),
        17 => Some(TemplateId::EthIpv4GreIpv4GreIpv4Udp),
        1 => Some(TemplateId::EthIpv4GreIpv4GreIpv4Icmp),
        _ => None,
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
            L2Kind::Vlan => TemplateId::EthVlanIpv4Ipv4Tcp,
            L2Kind::QinQ => TemplateId::EthQinQIpv4Ipv4Tcp,
        }),
        17 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv4Ipv4Udp,
            L2Kind::Vlan => TemplateId::EthVlanIpv4Ipv4Udp,
            L2Kind::QinQ => TemplateId::EthQinQIpv4Ipv4Udp,
        }),
        1 => Some(match kind {
            L2Kind::Plain => TemplateId::EthIpv4Ipv4Icmp,
            L2Kind::Vlan => TemplateId::EthVlanIpv4Ipv4Icmp,
            L2Kind::QinQ => TemplateId::EthQinQIpv4Ipv4Icmp,
        }),
        _ => None,
    }
}
