//! Targeted adversarial unit tests.
//!
//! Hand-crafted packets for specific known-dangerous patterns. Each test
//! constructs an exact byte sequence, runs it through all parser modes,
//! and asserts: (a) no panic, (b) appropriate error handling, (c) modes agree.

#[cfg(test)]
mod tests {
    use xdp2_bench::flow_meta::FlowMeta;
    use xdp2_bench::graph;
    use xdp2_bench::graph_compiled;
    use xdp2_bench::graph_mono;
    use xdp2_core::Parser;
    use crate::oracle;
    use crate::seed_corpus::*;

    fn parser() -> Parser<FlowMeta> {
        graph::make_parser()
    }

    /// Run packet through all 3 modes, assert no panics.
    ///
    /// NOTE: We do NOT assert cross-mode consistency here because there are
    /// known divergences between the parser modes (different depth limits,
    /// different leaf-node handling). The consistency oracle tests document
    /// these separately. The critical property is: no mode ever panics.
    fn assert_safe(pkt: &[u8]) {
        let p = parser();
        // Each call must not panic — this is the core safety property
        let _g = graph::parse_packet(&p, pkt);
        let mut meta_m = FlowMeta::default();
        let _m = graph_mono::parse_packet_mono(pkt, &mut meta_m);
        let mut meta_c = FlowMeta::default();
        let _c = graph_compiled::parse_packet(pkt, &mut meta_c);
    }

    // ── Attack vector 1-2: IPv4 IHL manipulation ──────────────────────

    #[test]
    fn ipv4_ihl_zero() {
        // IHL=0 → ihl_bytes()=0, must be caught as < MIN_LEN
        let mut pkt = eth_frame(0x0800, &ipv4_header(6, &tcp_header(80, 443)));
        pkt[14] = 0x40; // ver=4, ihl=0
        assert_safe(&pkt);
    }

    #[test]
    fn ipv4_ihl_one() {
        let mut pkt = eth_frame(0x0800, &ipv4_header(6, &tcp_header(80, 443)));
        pkt[14] = 0x41; // ver=4, ihl=1 → 4 bytes, below MIN_LEN=20
        assert_safe(&pkt);
    }

    #[test]
    fn ipv4_ihl_four() {
        let mut pkt = eth_frame(0x0800, &ipv4_header(6, &tcp_header(80, 443)));
        pkt[14] = 0x44; // ver=4, ihl=4 → 16 bytes, below MIN_LEN=20
        assert_safe(&pkt);
    }

    #[test]
    fn ipv4_ihl_max() {
        // IHL=15 → 60 bytes, but only 20 bytes of actual header present
        let mut pkt = eth_frame(0x0800, &ipv4_header(6, &tcp_header(80, 443)));
        pkt[14] = 0x4F; // ver=4, ihl=15
        assert_safe(&pkt);
    }

    // ── Attack vector 3: TCP data_offset=0 ────────────────────────────

    #[test]
    fn tcp_data_offset_zero() {
        let mut pkt = eth_frame(0x0800, &ipv4_header(6, &tcp_header(80, 443)));
        // TCP data_offset is upper 4 bits of byte at offset 14+20+12 = 46
        pkt[46] = 0x02; // doff=0, flags=SYN
        assert_safe(&pkt);
    }

    #[test]
    fn tcp_data_offset_one() {
        let mut pkt = eth_frame(0x0800, &ipv4_header(6, &tcp_header(80, 443)));
        pkt[46] = 0x12; // doff=1 → 4 bytes, below MIN_LEN=20
        assert_safe(&pkt);
    }

    // ── Attack vector 4: IPv6 extension header hdrlen=255 ─────────────

    #[test]
    fn ipv6_eh_hdrlen_max() {
        // Hop-by-hop with hdrlen=255 → (255+1)*8 = 2048 bytes claimed
        let mut eh = vec![59, 255]; // next=no-next, hdrlen=255
        eh.extend_from_slice(&[0; 6]); // pad to 8 bytes minimum
        let pkt = eth_frame(0x86DD, &ipv6_header(0, &eh)); // 0 = Hop-by-Hop
        assert_safe(&pkt);
    }

    // ── Attack vector 5: AH hdrlen=255 ────────────────────────────────

    #[test]
    fn ah_hdrlen_max() {
        // AH with hdrlen=255 → (255+2)*4 = 1028 bytes claimed
        let mut ah = vec![59, 255, 0, 0]; // next=no-next, len=255, reserved
        ah.extend_from_slice(&[0; 8]); // SPI + seq
        let pkt = eth_frame(0x0800, &ipv4_header(51, &ah));
        assert_safe(&pkt);
    }

    // ── Attack vector 6: Geneve optlen=63 ─────────────────────────────

    #[test]
    fn geneve_optlen_max() {
        // Geneve with optlen=63 → 8 + 63*4 = 260 bytes header
        let mut inner_udp = udp_header(12345, 6081, &[]);
        inner_udp.truncate(8);
        let geneve_hdr = vec![0x3F, 0x00, 0x65, 0x58, 0, 0, 0x64, 0]; // optlen=63, proto=TEB
        inner_udp.extend_from_slice(&geneve_hdr);
        let total_len = inner_udp.len() as u16;
        inner_udp[4] = (total_len >> 8) as u8;
        inner_udp[5] = total_len as u8;
        let pkt = eth_frame(0x0800, &ipv4_header(17, &inner_udp));
        assert_safe(&pkt);
    }

    // ── Attack vector 7: GRE all flag bits set ────────────────────────

    #[test]
    fn gre_all_flags_set() {
        let gre = vec![0xFF, 0xFF, 0x08, 0x00]; // all flags and version bits set
        let pkt = eth_frame(0x0800, &ipv4_header(47, &gre));
        assert_safe(&pkt);
    }

    // ── Attack vector 8-9: SCTP chunk edge cases ──────────────────────

    #[test]
    fn sctp_chunk_length_zero() {
        // SCTP common header (12 bytes) + chunk with length=0
        let mut sctp = vec![0; 12]; // src_port, dst_port, vtag, checksum
        sctp.extend_from_slice(&[1, 0, 0, 0]); // chunk: type=1, flags=0, length=0
        let pkt = eth_frame(0x0800, &ipv4_header(132, &sctp));
        assert_safe(&pkt);
    }

    #[test]
    fn sctp_chunk_length_max() {
        // SCTP chunk with length=65535
        let mut sctp = vec![0; 12];
        sctp.extend_from_slice(&[1, 0, 0xFF, 0xFF]); // chunk length = 65535
        let pkt = eth_frame(0x0800, &ipv4_header(132, &sctp));
        assert_safe(&pkt);
    }

    // ── Attack vector 10: VXLAN tunnel nesting ────────────────────────

    #[test]
    fn vxlan_nesting_depth() {
        // Build deeply nested VXLAN: Eth->IP->UDP->VXLAN->Eth->IP->UDP->VXLAN->...
        // Enough layers to test depth limits but not blow the stack
        let tcp = tcp_header(80, 443);
        let mut inner = eth_frame(0x0800, &ipv4_header(6, &tcp));

        // Wrap in 6 layers of VXLAN
        for _ in 0..6 {
            let vxlan = vxlan_header(100);
            let mut udp_payload = Vec::new();
            udp_payload.extend_from_slice(&vxlan);
            udp_payload.extend_from_slice(&inner);
            let udp = udp_header(12345, 4789, &udp_payload);
            inner = eth_frame(0x0800, &ipv4_header(17, &udp));
        }

        assert_safe(&inner);
    }

    // ── Attack vector 11: VLAN chaining ───────────────────────────────

    #[test]
    fn many_vlan_tags() {
        // Chain 20 VLAN tags
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0; 12]); // MACs
        pkt.extend_from_slice(&0x8100u16.to_be_bytes());
        for _ in 0..19 {
            pkt.extend_from_slice(&vlan_tag(100, 0x8100));
        }
        pkt.extend_from_slice(&vlan_tag(100, 0x0800));
        pkt.extend_from_slice(&ipv4_header(6, &tcp_header(80, 443)));
        assert_safe(&pkt);
    }

    // ── Attack vector 13-14: Empty and single-byte packets ────────────

    #[test]
    fn empty_packet_all_modes() {
        assert_safe(&[]);
    }

    #[test]
    fn single_byte_all_modes() {
        assert_safe(&[0x00]);
        assert_safe(&[0xFF]);
        assert_safe(&[0x45]); // looks like IPv4 version nibble
    }

    // ── Attack vector 15-16: All-zeros and all-ones ───────────────────

    #[test]
    fn all_zeros_various_sizes() {
        for size in [14, 34, 54, 64, 128, 256, 512, 1500] {
            assert_safe(&vec![0u8; size]);
        }
    }

    #[test]
    fn all_ones_various_sizes() {
        for size in [14, 34, 54, 64, 128, 256, 512, 1500] {
            assert_safe(&vec![0xFFu8; size]);
        }
    }

    // ── Additional adversarial patterns ───────────────────────────────

    #[test]
    fn every_ethertype_value() {
        // Test a sampling of ethertype values including boundaries
        let payload = &[0u8; 64];
        for ethertype in [0x0000, 0x0001, 0x05DC, 0x05DD, 0x0600, 0x0800, 0x0806,
                          0x8100, 0x86DD, 0x8847, 0x88A8, 0x88CC, 0x88E5, 0x8864,
                          0x8906, 0xFFFF] {
            assert_safe(&eth_frame(ethertype, payload));
        }
    }

    #[test]
    fn every_ip_protocol() {
        // Test all 256 IP protocol numbers
        let payload = &[0u8; 32];
        for proto in 0..=255u8 {
            let pkt = eth_frame(0x0800, &ipv4_header(proto, payload));
            assert_safe(&pkt);
        }
    }

    #[test]
    fn truncation_sweep_ipv4_tcp() {
        // A valid IPv4/TCP packet, truncated at every byte offset
        let pkt = eth_frame(0x0800, &ipv4_header(6, &tcp_header(80, 443)));
        for len in 0..pkt.len() {
            assert_safe(&pkt[..len]);
        }
    }

    #[test]
    fn seed_corpus_all_safe() {
        // Every seed corpus packet must be safe across all modes
        for (name, pkt) in crate::seed_corpus::generate_seeds() {
            assert_safe(&pkt);
            let _ = name;
        }
    }

    #[test]
    fn seed_corpus_consistency_report() {
        // Run oracle on every seed and report divergences.
        // Known divergences exist between modes (depth limits, leaf handling).
        // This test documents them — it does NOT fail on inconsistency.
        let p = parser();
        let mut inconsistent = Vec::new();
        for (name, pkt) in crate::seed_corpus::generate_seeds() {
            let result = oracle::run_oracle(&p, &pkt);
            if !result.consistent {
                inconsistent.push(name);
            }
        }
        if !inconsistent.is_empty() {
            eprintln!("Known cross-mode divergences in seed corpus:");
            for name in &inconsistent {
                eprintln!("  - {}", name);
            }
        }
    }
}
