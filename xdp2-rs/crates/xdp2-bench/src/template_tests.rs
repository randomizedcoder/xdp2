use super::*;

/// Build a minimal Eth/IPv4/TCP packet (54 bytes).
fn make_eth_ipv4_tcp() -> Vec<u8> {
    let mut pkt = vec![0u8; 54];
    pkt[0..6].copy_from_slice(&[0xAA; 6]);
    pkt[6..12].copy_from_slice(&[0xBB; 6]);
    pkt[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    pkt[14] = 0x45; // IPv4, IHL=5
    pkt[23] = 6; // TCP
    pkt[26..30].copy_from_slice(&[10, 0, 0, 1]);
    pkt[30..34].copy_from_slice(&[10, 0, 0, 2]);
    pkt[34..36].copy_from_slice(&80u16.to_be_bytes());
    pkt[36..38].copy_from_slice(&443u16.to_be_bytes());
    pkt
}

// ── Classifier tests ─────────────────────────────────────────

#[test]
fn classify_eth_ipv4_tcp() {
    let pkt = make_eth_ipv4_tcp();
    assert!(matches!(
        select_template_id(&pkt),
        Some(TemplateId::EthIpv4Tcp)
    ));
}

#[test]
fn classify_eth_ipv4_udp() {
    let mut pkt = make_eth_ipv4_tcp();
    pkt[23] = 17;
    assert!(matches!(
        select_template_id(&pkt),
        Some(TemplateId::EthIpv4Udp)
    ));
}

#[test]
fn classify_eth_ipv4_icmp() {
    let mut pkt = make_eth_ipv4_tcp();
    pkt[23] = 1;
    assert!(matches!(
        select_template_id(&pkt),
        Some(TemplateId::EthIpv4Icmp)
    ));
}

#[test]
fn classify_eth_ipv4_sctp() {
    let mut pkt = vec![0u8; 46];
    pkt[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    pkt[14] = 0x45;
    pkt[23] = 132;
    assert!(matches!(
        select_template_id(&pkt),
        Some(TemplateId::EthIpv4Sctp)
    ));
}

#[test]
fn classify_eth_ipv6_tcp() {
    let mut pkt = vec![0u8; 74];
    pkt[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
    pkt[14] = 0x60;
    pkt[20] = 6;
    assert!(matches!(
        select_template_id(&pkt),
        Some(TemplateId::EthIpv6Tcp)
    ));
}

#[test]
fn classify_eth_arp() {
    let mut pkt = vec![0u8; 42];
    pkt[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    assert!(matches!(select_template_id(&pkt), Some(TemplateId::EthArp)));
}

#[test]
fn classify_vlan_ipv4_tcp() {
    let mut pkt = vec![0u8; 58];
    pkt[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
    pkt[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    pkt[18] = 0x45;
    pkt[27] = 6;
    assert!(matches!(
        select_template_id(&pkt),
        Some(TemplateId::EthVlanIpv4Tcp)
    ));
}

#[test]
fn classify_qinq_ipv4_tcp() {
    let mut pkt = vec![0u8; 62];
    pkt[12..14].copy_from_slice(&0x88A8u16.to_be_bytes());
    pkt[16..18].copy_from_slice(&0x8100u16.to_be_bytes());
    pkt[20..22].copy_from_slice(&0x0800u16.to_be_bytes());
    pkt[22] = 0x45;
    pkt[31] = 6;
    assert!(matches!(
        select_template_id(&pkt),
        Some(TemplateId::EthQinQIpv4Tcp)
    ));
}

#[test]
fn classify_ipv4_with_options_returns_none() {
    let mut pkt = make_eth_ipv4_tcp();
    pkt[14] = 0x46; // IHL=6
    assert!(select_template_id(&pkt).is_none());
}

#[test]
fn classify_too_short_returns_none() {
    let pkt = vec![0u8; 10];
    assert!(select_template_id(&pkt).is_none());
}

#[test]
fn classify_unknown_ethertype_returns_none() {
    let mut pkt = vec![0u8; 64];
    pkt[12..14].copy_from_slice(&0x1234u16.to_be_bytes());
    assert!(select_template_id(&pkt).is_none());
}

#[test]
fn classify_ipv6_ext_header_returns_none() {
    let mut pkt = vec![0u8; 74];
    pkt[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
    pkt[14] = 0x60;
    pkt[20] = 0; // Hop-by-Hop
    assert!(select_template_id(&pkt).is_none());
}

// ── Extractor tests ──────────────────────────────────────────

#[test]
fn extract_eth_ipv4_tcp_populates_meta() {
    let pkt = make_eth_ipv4_tcp();
    let mut meta = FlowMeta::default();
    assert!(extract_eth_ipv4_tcp(&pkt, &mut meta).is_ok());
    assert_eq!(meta.addr_type, AddrType::Ipv4);
    assert_eq!(meta.ip_proto, 6);
    assert_eq!(meta.addrs.v4_src, u32::from_be_bytes([10, 0, 0, 1]));
    assert_eq!(meta.addrs.v4_dst, u32::from_be_bytes([10, 0, 0, 2]));
    assert_eq!(meta.ports.src_port, 80);
    assert_eq!(meta.ports.dst_port, 443);
    assert_eq!(meta.eth_proto, 0x0800);
    assert_eq!(meta.l3_off, 14);
    assert_eq!(meta.l4_off, 34);
}

#[test]
fn extract_eth_ipv4_tcp_too_short() {
    let pkt = vec![0u8; 53];
    let mut meta = FlowMeta::default();
    assert!(extract_eth_ipv4_tcp(&pkt, &mut meta).is_err());
}

#[test]
fn extract_eth_ipv6_tcp_populates_meta() {
    let mut pkt = vec![0u8; 74];
    pkt[0..6].copy_from_slice(&[0xCC; 6]);
    pkt[6..12].copy_from_slice(&[0xDD; 6]);
    pkt[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
    pkt[14] = 0x60;
    pkt[15] = 0x0A;
    pkt[16] = 0xBC;
    pkt[17] = 0xDE;
    pkt[20] = 6;
    pkt[22..38].copy_from_slice(&[1; 16]);
    pkt[38..54].copy_from_slice(&[2; 16]);
    pkt[54..56].copy_from_slice(&8080u16.to_be_bytes());
    pkt[56..58].copy_from_slice(&443u16.to_be_bytes());
    let mut meta = FlowMeta::default();
    assert!(extract_eth_ipv6_tcp(&pkt, &mut meta).is_ok());
    assert_eq!(meta.addr_type, AddrType::Ipv6);
    assert_eq!(meta.flow_label, 0xABCDE);
    assert_eq!(meta.ports.src_port, 8080);
    assert_eq!(meta.ports.dst_port, 443);
}

#[test]
fn extract_vlan_ipv4_tcp_populates_vlan() {
    let mut pkt = vec![0u8; 58];
    pkt[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
    pkt[14..16].copy_from_slice(&100u16.to_be_bytes());
    pkt[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    pkt[18] = 0x45;
    pkt[27] = 6;
    pkt[30..34].copy_from_slice(&[192, 168, 1, 1]);
    pkt[34..38].copy_from_slice(&[192, 168, 1, 2]);
    pkt[38..40].copy_from_slice(&22u16.to_be_bytes());
    pkt[40..42].copy_from_slice(&12345u16.to_be_bytes());
    let mut meta = FlowMeta::default();
    assert!(extract_vlan_ipv4_tcp(&pkt, &mut meta).is_ok());
    assert_eq!(meta.vlan_count, 1);
    assert_eq!(meta.vlan[0].tci, 100);
    assert_eq!(meta.vlan[0].tpid, 0x8100);
    assert_eq!(meta.ports.src_port, 22);
    assert_eq!(meta.ports.dst_port, 12345);
}

#[test]
fn extract_by_id_dispatch_matches_direct() {
    let pkt = make_eth_ipv4_tcp();
    let mut meta1 = FlowMeta::default();
    let mut meta2 = FlowMeta::default();
    extract_eth_ipv4_tcp(&pkt, &mut meta1).unwrap();
    extract_by_id(&pkt, TemplateId::EthIpv4Tcp, &mut meta2).unwrap();
    assert_eq!(meta1.ports.src_port, meta2.ports.src_port);
    assert_eq!(meta1.ports.dst_port, meta2.ports.dst_port);
    assert_eq!(meta1.addrs.v4_src, meta2.addrs.v4_src);
}

#[test]
fn extract_eth_arp_populates_arp_meta() {
    let mut pkt = vec![0u8; 42];
    pkt[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    pkt[20..22].copy_from_slice(&1u16.to_be_bytes());
    pkt[22..28].copy_from_slice(&[0xAA; 6]);
    pkt[28..32].copy_from_slice(&[192, 168, 1, 1]);
    pkt[32..38].copy_from_slice(&[0x00; 6]);
    pkt[38..42].copy_from_slice(&[192, 168, 1, 2]);
    let mut meta = FlowMeta::default();
    assert!(extract_eth_arp(&pkt, &mut meta).is_ok());
    assert_eq!(meta.arp.op, 1);
    assert_eq!(meta.arp.sha, [0xAA; 6]);
    assert_eq!(meta.arp.spa, u32::from_be_bytes([192, 168, 1, 1]));
    assert_eq!(meta.arp.tpa, u32::from_be_bytes([192, 168, 1, 2]));
}
