//! Property-based tests for all parser modes.
//!
//! Uses proptest to generate random and structured packet inputs, testing
//! properties like no-panic, idempotency, and truncation safety.

use proptest::prelude::*;
use xdp2_bench::flow_meta::FlowMeta;
use xdp2_bench::graph;
use xdp2_bench::graph_compiled;
use xdp2_bench::graph_mono;
use xdp2_bench::template;
use xdp2_core::Parser;
use xdp2_fuzz::seed_corpus;

fn parser() -> Parser<FlowMeta> {
    graph::make_parser()
}

// ── Strategy: random bytes of various sizes ───────────────────────────

fn arb_packet() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..2000)
}

// ── Strategy: valid Ethernet frame with random payload ────────────────

fn arb_eth_frame() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<[u8; 12]>(),  // MACs
        prop::sample::select(vec![
            0x0800u16, 0x86DD, 0x0806, 0x8035, 0x8100, 0x88A8,
            0x8847, 0x88CC, 0x888E, 0x88E5, 0x88F7, 0x8864,
            0x0000, 0x05DC, 0xFFFF,
        ]),
        prop::collection::vec(any::<u8>(), 0..500),
    )
        .prop_map(|(macs, ethertype, payload)| {
            let mut pkt = Vec::with_capacity(14 + payload.len());
            pkt.extend_from_slice(&macs);
            pkt.extend_from_slice(&ethertype.to_be_bytes());
            pkt.extend_from_slice(&payload);
            pkt
        })
}

// ── Strategy: Ethernet + IPv4 with adversarial IHL ────────────────────

fn arb_eth_ipv4() -> impl Strategy<Value = Vec<u8>> {
    (
        0u8..=15u8,   // IHL (0-15, valid is 5-15)
        any::<u8>(),  // IP protocol
        prop::collection::vec(any::<u8>(), 0..200),
    )
        .prop_map(|(ihl, proto, payload)| {
            let mut pkt = vec![0u8; 14]; // Ethernet
            pkt[12] = 0x08; pkt[13] = 0x00; // ethertype = IPv4
            // IPv4 header (20 bytes minimum)
            let ver_ihl = 0x40 | (ihl & 0x0F);
            let total_len = (20 + payload.len().min(480)) as u16;
            pkt.push(ver_ihl);
            pkt.push(0x00); // TOS
            pkt.extend_from_slice(&total_len.to_be_bytes());
            pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // id, flags, frag
            pkt.push(0x40); // TTL
            pkt.push(proto);
            pkt.extend_from_slice(&[0x00, 0x00]); // checksum
            pkt.extend_from_slice(&[10, 0, 0, 1]); // src
            pkt.extend_from_slice(&[10, 0, 0, 2]); // dst
            pkt.extend_from_slice(&payload[..payload.len().min(480)]);
            pkt
        })
}

// ── Strategy: Ethernet + IPv4 + TCP with adversarial data_offset ──────

fn arb_eth_ipv4_tcp() -> impl Strategy<Value = Vec<u8>> {
    (
        0u8..=15u8,   // TCP data_offset (valid: 5-15, adversarial: 0-4)
        prop::collection::vec(any::<u8>(), 0..100),
    )
        .prop_map(|(doff, payload)| {
            let tcp_payload = &payload[..payload.len().min(100)];
            let tcp_hdr_len = 20usize; // we always write 20 bytes of TCP
            let ip_payload_len = tcp_hdr_len + tcp_payload.len();

            let mut pkt = vec![0u8; 14]; // Ethernet
            pkt[12] = 0x08; pkt[13] = 0x00;
            // IPv4
            pkt.push(0x45); // ver=4, ihl=5
            pkt.push(0x00);
            let total_len = (20 + ip_payload_len) as u16;
            pkt.extend_from_slice(&total_len.to_be_bytes());
            pkt.extend_from_slice(&[0, 1, 0, 0, 64, 6, 0, 0]); // proto=TCP
            pkt.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
            // TCP
            pkt.extend_from_slice(&[0, 80, 0x30, 0x39]); // ports 80, 12345
            pkt.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]); // seq, ack
            pkt.push((doff << 4) | 0x02); // doff + SYN flag
            pkt.push(0x00); // flags
            pkt.extend_from_slice(&[0x20, 0x00, 0x00, 0x00, 0x00, 0x00]); // window, csum, urgent
            pkt.extend_from_slice(tcp_payload);
            pkt
        })
}

// ── Property: No parser mode ever panics on any input ─────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn no_panic_random_bytes(pkt in arb_packet()) {
        let p = parser();
        let _ = graph::parse_packet(&p, &pkt);
        let mut m1 = FlowMeta::default();
        let _ = graph_mono::parse_packet_mono(&pkt, &mut m1);
        let mut m2 = FlowMeta::default();
        let _ = graph_compiled::parse_packet(&pkt, &mut m2);
    }

    #[test]
    fn no_panic_eth_frames(pkt in arb_eth_frame()) {
        let p = parser();
        let _ = graph::parse_packet(&p, &pkt);
        let mut m1 = FlowMeta::default();
        let _ = graph_mono::parse_packet_mono(&pkt, &mut m1);
        let mut m2 = FlowMeta::default();
        let _ = graph_compiled::parse_packet(&pkt, &mut m2);
    }

    #[test]
    fn no_panic_adversarial_ipv4(pkt in arb_eth_ipv4()) {
        let p = parser();
        let _ = graph::parse_packet(&p, &pkt);
        let mut m1 = FlowMeta::default();
        let _ = graph_mono::parse_packet_mono(&pkt, &mut m1);
        let mut m2 = FlowMeta::default();
        let _ = graph_compiled::parse_packet(&pkt, &mut m2);
    }

    #[test]
    fn no_panic_adversarial_tcp_doff(pkt in arb_eth_ipv4_tcp()) {
        let p = parser();
        let _ = graph::parse_packet(&p, &pkt);
        let mut m1 = FlowMeta::default();
        let _ = graph_mono::parse_packet_mono(&pkt, &mut m1);
        let mut m2 = FlowMeta::default();
        let _ = graph_compiled::parse_packet(&pkt, &mut m2);
    }

    // ── Property: Template extractors never panic ─────────────────────

    #[test]
    fn no_panic_templates(pkt in arb_eth_frame()) {
        if let Some(id) = template::select_template_id(&pkt) {
            let mut meta = FlowMeta::default();
            let _ = template::extract_by_id(&pkt, id, &mut meta);
        }
    }

    // ── Property: Parsing is idempotent ───────────────────────────────

    #[test]
    fn graph_idempotent(pkt in arb_packet()) {
        let p = parser();
        let r1 = graph::parse_packet(&p, &pkt);
        let r2 = graph::parse_packet(&p, &pkt);
        match (r1, r2) {
            (Ok(o1), Ok(o2)) => prop_assert_eq!(o1.metadata, o2.metadata),
            (Err(e1), Err(e2)) => prop_assert_eq!(e1, e2),
            (r1, r2) => prop_assert!(false, "Idempotency violation: {:?} vs {:?}", r1.is_ok(), r2.is_ok()),
        }
    }

    #[test]
    fn mono_idempotent(pkt in arb_packet()) {
        let mut m1 = FlowMeta::default();
        let r1 = graph_mono::parse_packet_mono(&pkt, &mut m1);
        let mut m2 = FlowMeta::default();
        let r2 = graph_mono::parse_packet_mono(&pkt, &mut m2);
        prop_assert_eq!(r1, r2);
        if r1.is_ok() {
            prop_assert_eq!(m1, m2);
        }
    }

    // ── Property: Truncation never panics ─────────────────────────────

    #[test]
    fn truncation_safe(pkt in arb_eth_frame()) {
        let p = parser();
        for len in 0..pkt.len() {
            let truncated = &pkt[..len];
            let _ = graph::parse_packet(&p, truncated);
            let mut m1 = FlowMeta::default();
            let _ = graph_mono::parse_packet_mono(truncated, &mut m1);
            let mut m2 = FlowMeta::default();
            let _ = graph_compiled::parse_packet(truncated, &mut m2);
        }
    }
}

// ── Non-proptest: seed corpus through all modes ───────────────────────

#[test]
fn all_seeds_no_panic() {
    let p = parser();
    for (name, pkt) in seed_corpus::generate_seeds() {
        let _ = graph::parse_packet(&p, &pkt);
        let mut m1 = FlowMeta::default();
        let _ = graph_mono::parse_packet_mono(&pkt, &mut m1);
        let mut m2 = FlowMeta::default();
        let _ = graph_compiled::parse_packet(&pkt, &mut m2);
        if let Some(id) = template::select_template_id(&pkt) {
            let mut m3 = FlowMeta::default();
            let _ = template::extract_by_id(&pkt, id, &mut m3);
        }
        let _ = name;
    }
}
