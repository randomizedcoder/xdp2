//! Seed corpus generation for fuzz targets.
//!
//! Generates minimal valid packets for each protocol path through the
//! parser graph. These seeds give coverage-guided fuzzers a head start.

/// Build a minimal Ethernet frame with the given ethertype and payload.
pub fn eth_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(14 + payload.len());
    pkt.extend_from_slice(&[0x00; 6]); // dst MAC
    pkt.extend_from_slice(&[0x00; 6]); // src MAC
    pkt.extend_from_slice(&ethertype.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

/// Minimal IPv4 header (IHL=5, 20 bytes) with given protocol and payload.
pub fn ipv4_header(protocol: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = (20 + payload.len()) as u16;
    let mut hdr = vec![
        0x45, 0x00,                                     // ver=4, ihl=5, tos=0
        (total_len >> 8) as u8, total_len as u8,        // total length
        0x00, 0x01, 0x00, 0x00,                         // id, flags, frag_off
        0x40, protocol, 0x00, 0x00,                     // ttl=64, proto, checksum
        0x0A, 0x00, 0x00, 0x01,                         // src: 10.0.0.1
        0x0A, 0x00, 0x00, 0x02,                         // dst: 10.0.0.2
    ];
    hdr.extend_from_slice(payload);
    hdr
}

/// Minimal IPv6 header (40 bytes) with given next header and payload.
pub fn ipv6_header(next_header: u8, payload: &[u8]) -> Vec<u8> {
    let payload_len = payload.len() as u16;
    let mut hdr = vec![
        0x60, 0x00, 0x00, 0x00,                         // ver=6, traffic class, flow label
        (payload_len >> 8) as u8, payload_len as u8,     // payload length
        next_header, 0x40,                               // next header, hop limit=64
    ];
    hdr.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // src
    hdr.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]); // dst
    hdr.extend_from_slice(payload);
    hdr
}

/// Minimal TCP header (doff=5, 20 bytes).
pub fn tcp_header(src_port: u16, dst_port: u16) -> Vec<u8> {
    vec![
        (src_port >> 8) as u8, src_port as u8,
        (dst_port >> 8) as u8, dst_port as u8,
        0x00, 0x00, 0x00, 0x01,   // seq
        0x00, 0x00, 0x00, 0x00,   // ack
        0x50, 0x02, 0x20, 0x00,   // doff=5, SYN, window
        0x00, 0x00, 0x00, 0x00,   // checksum, urgent
    ]
}

/// Minimal UDP header (8 bytes).
pub fn udp_header(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let len = (8 + payload.len()) as u16;
    let mut hdr = vec![
        (src_port >> 8) as u8, src_port as u8,
        (dst_port >> 8) as u8, dst_port as u8,
        (len >> 8) as u8, len as u8,
        0x00, 0x00,
    ];
    hdr.extend_from_slice(payload);
    hdr
}

/// Minimal GRE v0 header (4 bytes, no optional fields) wrapping given ethertype.
pub fn gre_header(protocol: u16) -> Vec<u8> {
    vec![
        0x00, 0x00, // flags=0, version=0
        (protocol >> 8) as u8, protocol as u8,
    ]
}

/// Minimal VXLAN header (8 bytes) with VNI.
pub fn vxlan_header(vni: u32) -> Vec<u8> {
    vec![
        0x08, 0x00, 0x00, 0x00, // flags (VNI valid)
        ((vni >> 16) & 0xFF) as u8,
        ((vni >> 8) & 0xFF) as u8,
        (vni & 0xFF) as u8,
        0x00, // reserved
    ]
}

/// 802.1Q VLAN tag (4 bytes) with given VLAN ID and inner ethertype.
pub fn vlan_tag(vid: u16, ethertype: u16) -> Vec<u8> {
    vec![
        (vid >> 8) as u8, vid as u8,
        (ethertype >> 8) as u8, ethertype as u8,
    ]
}

/// Generate the full seed corpus — one minimal valid packet per major protocol path.
pub fn generate_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let tcp = tcp_header(80, 12345);
    let udp = udp_header(1234, 5678, &[]);

    vec![
        // Basic L3
        ("eth_ipv4_tcp", eth_frame(0x0800, &ipv4_header(6, &tcp))),
        ("eth_ipv4_udp", eth_frame(0x0800, &ipv4_header(17, &udp))),
        ("eth_ipv4_icmp", eth_frame(0x0800, &ipv4_header(1, &[8, 0, 0, 0, 0, 1, 0, 1]))),
        ("eth_ipv4_sctp", eth_frame(0x0800, &ipv4_header(132, &[0; 12]))),
        ("eth_ipv6_tcp", eth_frame(0x86DD, &ipv6_header(6, &tcp))),
        ("eth_ipv6_udp", eth_frame(0x86DD, &ipv6_header(17, &udp))),
        ("eth_arp", eth_frame(0x0806, &[0, 1, 0x08, 0x00, 6, 4, 0, 1,
            0, 0, 0, 0, 0, 0, 10, 0, 0, 1,
            0, 0, 0, 0, 0, 0, 10, 0, 0, 2])),
        ("eth_rarp", eth_frame(0x8035, &[0, 1, 0x08, 0x00, 6, 4, 0, 3,
            0, 0, 0, 0, 0, 0, 10, 0, 0, 1,
            0, 0, 0, 0, 0, 0, 10, 0, 0, 2])),

        // VLAN
        ("eth_vlan_ipv4_tcp", {
            let mut pkt = Vec::new();
            pkt.extend_from_slice(&[0; 12]); // MACs
            pkt.extend_from_slice(&0x8100u16.to_be_bytes());
            pkt.extend_from_slice(&vlan_tag(100, 0x0800));
            pkt.extend_from_slice(&ipv4_header(6, &tcp));
            pkt
        }),

        // QinQ
        ("eth_qinq_ipv4_tcp", {
            let mut pkt = Vec::new();
            pkt.extend_from_slice(&[0; 12]); // MACs
            pkt.extend_from_slice(&0x88A8u16.to_be_bytes());
            pkt.extend_from_slice(&vlan_tag(200, 0x8100));
            pkt.extend_from_slice(&vlan_tag(100, 0x0800));
            pkt.extend_from_slice(&ipv4_header(6, &tcp));
            pkt
        }),

        // MPLS
        ("eth_mpls", eth_frame(0x8847, &[0x00, 0x01, 0x01, 0x40])), // label=1, bos=1

        // Tunnels
        ("eth_ipv4_gre_ipv4_tcp", eth_frame(0x0800, &ipv4_header(47, &{
            let mut gre = gre_header(0x0800);
            gre.extend_from_slice(&ipv4_header(6, &tcp));
            gre
        }))),
        ("eth_ipv4_udp_vxlan_eth_ipv4_tcp", eth_frame(0x0800, &ipv4_header(17, &{
            let mut udp_vxlan = udp_header(12345, 4789, &[]);
            // Replace UDP payload with VXLAN + inner Ethernet + IPv4 + TCP
            udp_vxlan.truncate(8); // just the UDP header
            let vxlan = vxlan_header(100);
            let inner = eth_frame(0x0800, &ipv4_header(6, &tcp));
            let total_len = (8 + vxlan.len() + inner.len()) as u16;
            udp_vxlan[4] = (total_len >> 8) as u8;
            udp_vxlan[5] = total_len as u8;
            udp_vxlan.extend_from_slice(&vxlan);
            udp_vxlan.extend_from_slice(&inner);
            udp_vxlan
        }))),

        // Management leaves
        ("eth_lldp", eth_frame(0x88CC, &[0; 4])),
        ("eth_slow", eth_frame(0x8809, &[0; 2])),
        ("eth_ptp", eth_frame(0x88F7, &[0; 34])),
        ("eth_eapol", eth_frame(0x888E, &[0; 4])),
        ("eth_cfm", eth_frame(0x8902, &[0; 4])),

        // Security
        ("eth_macsec", eth_frame(0x88E5, &[0; 8])),
        ("eth_ipv4_esp", eth_frame(0x0800, &ipv4_header(50, &[0; 16]))),
        ("eth_ipv4_ah", eth_frame(0x0800, &ipv4_header(51, &{
            // AH: next_hdr=6(TCP), len=4 → (4+2)*4=24 bytes
            let mut ah = vec![6, 4, 0, 0, 0, 0, 0, 1]; // next, len, reserved, spi
            ah.extend_from_slice(&[0; 4]); // seq
            ah.extend_from_slice(&[0; 12]); // ICV (24 - 12 = 12 bytes)
            ah.extend_from_slice(&tcp);
            ah
        }))),

        // Adversarial seeds
        ("empty", vec![]),
        ("one_byte", vec![0x42]),
        ("all_zeros_64", vec![0u8; 64]),
        ("all_ones_64", vec![0xFFu8; 64]),
        ("all_zeros_1500", vec![0u8; 1500]),
        ("all_ones_1500", vec![0xFFu8; 1500]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_corpus_generates_all_seeds() {
        let seeds = generate_seeds();
        assert!(seeds.len() >= 20, "Expected at least 20 seeds, got {}", seeds.len());
        // Verify no empty names
        for (name, pkt) in &seeds {
            assert!(!name.is_empty());
            // "empty" seed is intentionally 0 bytes
            if *name != "empty" {
                assert!(!pkt.is_empty(), "Seed '{}' produced empty packet", name);
            }
        }
    }

    #[test]
    fn eth_frame_correct_length() {
        let pkt = eth_frame(0x0800, &[1, 2, 3]);
        assert_eq!(pkt.len(), 17); // 14 + 3
        assert_eq!(pkt[12], 0x08);
        assert_eq!(pkt[13], 0x00);
    }

    #[test]
    fn ipv4_header_correct_length() {
        let hdr = ipv4_header(6, &[]);
        assert_eq!(hdr.len(), 20);
        assert_eq!(hdr[0], 0x45); // ver=4, ihl=5
        assert_eq!(hdr[9], 6);    // protocol=TCP
    }
}
