use super::*;

fn make_eth_ipv4_tcp() -> Vec<u8> {
    let mut pkt = Vec::new();
    // Ethernet: dst=00:..., src=00:..., ethertype=0x0800
    pkt.extend_from_slice(&[0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst
    pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    // IPv4: IHL=5, proto=TCP(6), src=10.0.0.1, dst=10.0.0.2
    pkt.push((4 << 4) | 5);
    pkt.push(0);
    pkt.extend_from_slice(&40u16.to_be_bytes());
    pkt.extend_from_slice(&[0; 4]);
    pkt.push(64);
    pkt.push(6);
    pkt.extend_from_slice(&[0; 2]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    // TCP: src=80, dst=443
    pkt.extend_from_slice(&80u16.to_be_bytes());
    pkt.extend_from_slice(&443u16.to_be_bytes());
    pkt.extend_from_slice(&[0; 8]);
    pkt.push(5 << 4);
    pkt.push(0x02);
    pkt.extend_from_slice(&[0; 6]);
    // TCP payload (enough for TLS leaf check on port 443)
    pkt.extend_from_slice(&[0; 8]);
    pkt
}

#[test]
fn mono_parses_eth_ipv4_tcp() {
    let pkt = make_eth_ipv4_tcp();
    let mut meta = FlowMeta::default();
    parse_packet_mono(&pkt, &mut meta).unwrap();
    // Verify metadata was populated
    assert_eq!(meta.eth_proto, 0x0800);
    assert_eq!(meta.addr_type, AddrType::Ipv4);
    assert_eq!(meta.ip_proto, 6);
    assert_eq!(meta.addrs.v4_src, u32::from_be_bytes([10, 0, 0, 1]));
    assert_eq!(meta.addrs.v4_dst, u32::from_be_bytes([10, 0, 0, 2]));
    assert_eq!(meta.ports.src_port, 80);
    assert_eq!(meta.ports.dst_port, 443);
    assert_eq!(meta.eth_addrs[0], 0xAA); // dst MAC first byte
    assert_eq!(meta.eth_addrs[6], 0x11); // src MAC first byte
}

#[test]
fn mono_rejects_empty() {
    let mut meta = FlowMeta::default();
    assert!(parse_packet_mono(&[], &mut meta).is_err());
}

#[test]
fn mono_parses_lldp() {
    let mut pkt = vec![0u8; 12];
    pkt.extend_from_slice(&0x88CCu16.to_be_bytes());
    pkt.extend_from_slice(&[0x02, 0x00, 0x07, 0x04]);
    let mut meta = FlowMeta::default();
    parse_packet_mono(&pkt, &mut meta).unwrap();
    assert_eq!(meta.eth_proto, 0x88CC);
}

#[test]
fn mono_parses_vxlan_inner_tcp() {
    let mut pkt = Vec::new();
    // Outer Ethernet + IPv4 + UDP(4789) + VXLAN + inner Ethernet + IPv4 + TCP
    pkt.extend_from_slice(&[0u8; 12]);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    pkt.push((4 << 4) | 5);
    pkt.push(0);
    pkt.extend_from_slice(&100u16.to_be_bytes());
    pkt.extend_from_slice(&[0; 4]);
    pkt.push(64);
    pkt.push(17); // UDP
    pkt.extend_from_slice(&[0; 2]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    pkt.extend_from_slice(&12345u16.to_be_bytes());
    pkt.extend_from_slice(&4789u16.to_be_bytes());
    pkt.extend_from_slice(&80u16.to_be_bytes());
    pkt.extend_from_slice(&[0; 2]);
    // VXLAN (8 bytes)
    pkt.extend_from_slice(&[0x08, 0, 0, 0, 0x12, 0x34, 0x56, 0]);
    // Inner Ethernet + IPv4 + TCP
    pkt.extend_from_slice(&[0u8; 12]);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    pkt.push((4 << 4) | 5);
    pkt.push(0);
    pkt.extend_from_slice(&40u16.to_be_bytes());
    pkt.extend_from_slice(&[0; 4]);
    pkt.push(64);
    pkt.push(6);
    pkt.extend_from_slice(&[0; 2]);
    pkt.extend_from_slice(&[192, 168, 1, 1]);
    pkt.extend_from_slice(&[192, 168, 1, 2]);
    pkt.extend_from_slice(&80u16.to_be_bytes());
    pkt.extend_from_slice(&443u16.to_be_bytes());
    pkt.extend_from_slice(&[0; 8]);
    pkt.push(5 << 4);
    pkt.push(0x02);
    pkt.extend_from_slice(&[0; 6]);
    // TCP payload (enough for TLS leaf check on port 443)
    pkt.extend_from_slice(&[0; 8]);

    let mut meta = FlowMeta::default();
    parse_packet_mono(&pkt, &mut meta).unwrap();
}

#[test]
fn mono_parses_gre_v0_ipv4_tcp() {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0u8; 12]);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    pkt.push((4 << 4) | 5);
    pkt.push(0);
    pkt.extend_from_slice(&100u16.to_be_bytes());
    pkt.extend_from_slice(&[0; 4]);
    pkt.push(64);
    pkt.push(47); // GRE
    pkt.extend_from_slice(&[0; 2]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    // GRE: flags=0, proto=IPv4
    pkt.extend_from_slice(&0x0000u16.to_be_bytes());
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    // Inner IPv4 + TCP
    pkt.push((4 << 4) | 5);
    pkt.push(0);
    pkt.extend_from_slice(&40u16.to_be_bytes());
    pkt.extend_from_slice(&[0; 4]);
    pkt.push(64);
    pkt.push(6);
    pkt.extend_from_slice(&[0; 2]);
    pkt.extend_from_slice(&[192, 168, 1, 1]);
    pkt.extend_from_slice(&[192, 168, 1, 2]);
    pkt.extend_from_slice(&80u16.to_be_bytes());
    pkt.extend_from_slice(&443u16.to_be_bytes());
    pkt.extend_from_slice(&[0; 8]);
    pkt.push(5 << 4);
    pkt.push(0x02);
    pkt.extend_from_slice(&[0; 6]);
    // TCP payload (enough for TLS leaf check on port 443)
    pkt.extend_from_slice(&[0; 8]);

    let mut meta = FlowMeta::default();
    parse_packet_mono(&pkt, &mut meta).unwrap();
}

#[test]
fn mono_parses_pppoe_ipv4_tcp() {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0u8; 12]);
    pkt.extend_from_slice(&0x8864u16.to_be_bytes());
    // PPPoE header
    pkt.push(0x11); // ver=1, type=1
    pkt.push(0x00); // code=0
    pkt.extend_from_slice(&[0x00, 0x01]); // session ID
    pkt.extend_from_slice(&44u16.to_be_bytes()); // length
    pkt.extend_from_slice(&0x0021u16.to_be_bytes()); // PPP_IP
                                                     // IPv4 + TCP
    pkt.push((4 << 4) | 5);
    pkt.push(0);
    pkt.extend_from_slice(&40u16.to_be_bytes());
    pkt.extend_from_slice(&[0; 4]);
    pkt.push(64);
    pkt.push(6);
    pkt.extend_from_slice(&[0; 2]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    pkt.extend_from_slice(&80u16.to_be_bytes());
    pkt.extend_from_slice(&443u16.to_be_bytes());
    pkt.extend_from_slice(&[0; 8]);
    pkt.push(5 << 4);
    pkt.push(0x02);
    pkt.extend_from_slice(&[0; 6]);
    // TCP payload (enough for TLS leaf check on port 443)
    pkt.extend_from_slice(&[0; 8]);

    let mut meta = FlowMeta::default();
    parse_packet_mono(&pkt, &mut meta).unwrap();
}
