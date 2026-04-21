//! Chain-histogram probe — first step of the fast-path dispatch exploration
//! (see `xdp2-rs/docs/fast-path-dispatch.md`).
//!
//! Parses every packet once with the graph engine, derives a coarse
//! protocol-chain signature from the resulting `FlowMeta`, and prints a
//! top-N histogram with cumulative percentages. The purpose is to
//! characterize how skewed real traffic is, to decide whether a static
//! top-N classifier (option a) is sufficient or whether an adaptive LRU
//! (option b) is warranted.
//!
//! The signature is derived from `FlowMeta` rather than by instrumenting
//! the graph engine, which keeps the hot path untouched. It is a coarse
//! approximation — some tunneled chains collapse to the same label when
//! their tunnel-specific fields (keyid, esp_spi, …) are zero — but it is
//! good enough for a first-order distribution.
//!
//! Not a benchmark: accuracy of the signature matters, throughput does
//! not.
//!
//! Items are consumed from `main.rs`; the library target does not
//! re-export them.
#![allow(dead_code)]
//!
//! ## Usage
//!
//! ```bash
//! xdp2-bench --pcap <path> --chain-histogram            # top 20
//! xdp2-bench --pcap <path> --chain-histogram --top 50   # top 50
//! ```
//!
//! Parse failures are counted separately and reported at the end.

use std::collections::HashMap;
use std::fmt::Write;

use crate::flow_meta::FlowMeta;
use crate::graph;
use crate::pcap::StoredPacket;

/// Build a short string signature for a parsed packet's protocol chain,
/// derived from `FlowMeta`. Two packets with the same signature share the
/// same chain (to the resolution of what `FlowMeta` records).
pub(crate) fn signature(meta: &FlowMeta) -> String {
    let mut s = String::with_capacity(64);
    s.push_str("eth");

    // VLAN / QinQ stack — FlowMeta records up to 2 tags.
    for _ in 0..meta.vlan_count.min(2) {
        s.push_str("/vlan");
    }

    match meta.eth_proto {
        0x0800 => s.push_str("/ipv4"),
        0x86dd => s.push_str("/ipv6"),
        0x0806 => {
            s.push_str("/arp");
            return s;
        }
        0x8847 | 0x8848 => s.push_str("/mpls"),
        0 => return s, // Unresolved L3 (graph stopped at L2).
        other => {
            let _ = write!(s, "/eth-{:#06x}", other);
            return s;
        }
    }

    if meta.is_fragment {
        s.push_str("/frag");
    }

    // L4 / next header.
    match meta.ip_proto {
        0 => {} // no L4 recorded
        1 => s.push_str("/icmp"),
        2 => s.push_str("/igmp"),
        4 => s.push_str("/ipip"),
        6 => s.push_str("/tcp"),
        17 => s.push_str("/udp"),
        41 => s.push_str("/6in4"),
        47 => s.push_str("/gre"),
        50 => s.push_str("/esp"),
        51 => s.push_str("/ah"),
        58 => s.push_str("/icmpv6"),
        115 => s.push_str("/l2tp"),
        132 => s.push_str("/sctp"),
        n => {
            let _ = write!(s, "/ip-{}", n);
        }
    }

    // Coarse tunnel hints. These are best-effort: FlowMeta flattens nested
    // encapsulations, so "/udp+vxlan" means "UDP with a VXLAN-looking VNI",
    // not a definitive identification.
    if meta.keyid != 0 && meta.ip_proto == 17 {
        s.push_str("+vxlan?");
    }
    if meta.gre.flags != 0 || meta.gre.keyid != 0 {
        s.push_str("+gre-inner");
    }
    if meta.esp_spi != 0 {
        s.push_str("+esp-spi");
    }
    if meta.l2tp_session_id != 0 {
        s.push_str("+l2tp-sid");
    }

    s
}

/// Run the probe: parse all packets, bucket by chain signature, print the
/// top-`top_n` by count. Returns silently after printing.
pub(crate) fn run(packets: &[&StoredPacket], top_n: usize) {
    let parser = graph::make_parser();
    let mut counts: HashMap<String, u64> = HashMap::new();
    let mut parsed = 0u64;
    let mut failed = 0u64;

    for pkt in packets {
        match graph::parse_packet(&parser, &pkt.data) {
            Ok(out) => {
                *counts.entry(signature(&out.metadata)).or_insert(0) += 1;
                parsed += 1;
            }
            Err(_) => failed += 1,
        }
    }

    let mut entries: Vec<(String, u64)> = counts.into_iter().collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let total_seen = parsed + failed;
    let distinct = entries.len();
    let shown = top_n.min(distinct);

    println!(
        "Chain histogram: {} distinct chains across {} parsed packets ({} failed)",
        distinct, parsed, failed
    );
    println!(
        "{:>4}  {:>8}  {:>6}  {:>6}  chain",
        "rank", "count", "pct", "cum"
    );

    let parsed_f = parsed.max(1) as f64;
    let mut cumulative: u64 = 0;
    for (i, (sig, count)) in entries.iter().take(shown).enumerate() {
        cumulative += *count;
        let pct = 100.0 * (*count as f64) / parsed_f;
        let cum = 100.0 * (cumulative as f64) / parsed_f;
        println!(
            "{:>4}  {:>8}  {:>5.1}%  {:>5.1}%  {}",
            i + 1,
            count,
            pct,
            cum,
            sig
        );
    }

    if distinct > shown {
        let remaining: u64 = entries.iter().skip(shown).map(|(_, c)| *c).sum();
        let pct = 100.0 * (remaining as f64) / parsed_f;
        println!(
            "  ..  {:>8}  {:>5.1}%   —     ({} other chains)",
            remaining,
            pct,
            distinct - shown
        );
    }

    println!();
    let top1_pct = entries
        .first()
        .map(|(_, c)| 100.0 * (*c as f64) / parsed_f)
        .unwrap_or(0.0);
    let top5_pct = entries.iter().take(5).map(|(_, c)| *c).sum::<u64>() as f64 * 100.0 / parsed_f;
    let top10_pct = entries.iter().take(10).map(|(_, c)| *c).sum::<u64>() as f64 * 100.0 / parsed_f;
    println!(
        "Summary: top-1 = {:.1}%, top-5 = {:.1}%, top-10 = {:.1}% of {} packets ({} total, {} parse failures)",
        top1_pct, top5_pct, top10_pct, parsed, total_seen, failed
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_meta::AddrType;

    fn meta_eth_ipv4_tcp() -> FlowMeta {
        FlowMeta {
            addr_type: AddrType::Ipv4,
            eth_proto: 0x0800,
            ip_proto: 6,
            ..FlowMeta::default()
        }
    }

    #[test]
    fn signature_basic_chains() {
        let tcp4 = meta_eth_ipv4_tcp();
        assert_eq!(signature(&tcp4), "eth/ipv4/tcp");

        let udp6 = FlowMeta {
            addr_type: AddrType::Ipv6,
            eth_proto: 0x86dd,
            ip_proto: 17,
            ..FlowMeta::default()
        };
        assert_eq!(signature(&udp6), "eth/ipv6/udp");

        let arp = FlowMeta {
            eth_proto: 0x0806,
            ..FlowMeta::default()
        };
        assert_eq!(signature(&arp), "eth/arp");
    }

    #[test]
    fn signature_vlan_qinq() {
        let qinq_tcp = FlowMeta {
            vlan_count: 2,
            eth_proto: 0x0800,
            ip_proto: 6,
            ..FlowMeta::default()
        };
        assert_eq!(signature(&qinq_tcp), "eth/vlan/vlan/ipv4/tcp");
    }

    #[test]
    fn signature_fragment_and_tunnel_hints() {
        let frag = FlowMeta {
            eth_proto: 0x0800,
            ip_proto: 17,
            is_fragment: true,
            ..FlowMeta::default()
        };
        assert_eq!(signature(&frag), "eth/ipv4/frag/udp");

        let vxlan_ish = FlowMeta {
            eth_proto: 0x0800,
            ip_proto: 17,
            keyid: 42,
            ..FlowMeta::default()
        };
        assert_eq!(signature(&vxlan_ish), "eth/ipv4/udp+vxlan?");
    }
}
