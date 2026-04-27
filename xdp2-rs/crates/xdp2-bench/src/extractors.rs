// ── Metadata extractors ─────────────────────────────────────────
//
// Each function matches a C `XDP2_METADATA_TEMP_*` macro from
// parser_metadata.h. The engine calls these with `hdr` pointing
// to the current protocol header (not the full packet).

use crate::flow_meta::{AddrType, FlowMeta};
use xdp2_core::CtrlData;

/// Ethernet: extract MACs and ethertype.
/// Matches C's `XDP2_METADATA_TEMP_ether`.
pub(crate) fn extract_ether_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    meta.eth_addrs[..12].copy_from_slice(&hdr[0..12]);
    meta.eth_proto = u16::from_be_bytes([hdr[12], hdr[13]]);
}

/// IPv4: fragment info, addresses, protocol.
/// Matches C's `XDP2_METADATA_TEMP_ipv4`.
pub(crate) fn extract_ipv4_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    let frag_off = u16::from_be_bytes([hdr[6], hdr[7]]);
    const IP_MF: u16 = 0x2000;
    const IP_OFFSET: u16 = 0x1FFF;
    if (frag_off & (IP_MF | IP_OFFSET)) != 0 {
        meta.is_fragment = true;
        meta.first_frag = (frag_off & IP_OFFSET) == 0;
    }
    meta.addr_type = AddrType::Ipv4;
    meta.ip_tos = hdr[1];   // DSCP + ECN
    meta.ip_ttl = hdr[8];   // TTL
    meta.ip_proto = hdr[9];
    meta.addrs.v4_src = u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]);
    meta.addrs.v4_dst = u32::from_be_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]);
}

/// IPv6: addresses, next header, flow label.
/// Matches C's `XDP2_METADATA_TEMP_ipv6`.
pub(crate) fn extract_ipv6_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    meta.addr_type = AddrType::Ipv6;
    // IPv6 traffic class = (byte0[3:0] << 4) | (byte1[7:4])
    meta.ip_tos = ((hdr[0] & 0x0F) << 4) | (hdr[1] >> 4);
    meta.ip_ttl = hdr[7]; // Hop Limit
    meta.ip_proto = hdr[6]; // next header
    meta.flow_label = ((hdr[1] as u32 & 0x0F) << 16) | ((hdr[2] as u32) << 8) | (hdr[3] as u32);
    meta.addrs.v6_src.copy_from_slice(&hdr[8..24]);
    meta.addrs.v6_dst.copy_from_slice(&hdr[24..40]);
}

/// IPv6 extension header: update ip_proto with next header.
/// Matches C's `XDP2_METADATA_TEMP_ipv6_eh`.
pub(crate) fn extract_ipv6_eh_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    meta.ip_proto = hdr[0];
}

/// IPv6 fragment header: fragment info + next header.
/// Matches C's `XDP2_METADATA_TEMP_ipv6_frag`.
pub(crate) fn extract_ipv6_frag_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    meta.ip_proto = hdr[0];
    let frag_off = u16::from_be_bytes([hdr[2], hdr[3]]);
    const IP6_OFFSET: u16 = 0xFFF8;
    meta.is_fragment = true;
    meta.first_frag = (frag_off & IP6_OFFSET) == 0;
}

/// Transport ports (TCP, UDP, SCTP, DCCP, UDPLite).
/// Matches C's `XDP2_METADATA_TEMP_ports`.
pub(crate) fn extract_ports_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    meta.ports.src_port = u16::from_be_bytes([hdr[0], hdr[1]]);
    meta.ports.dst_port = u16::from_be_bytes([hdr[2], hdr[3]]);
}

/// TCP: ports + flags.
/// Extends ports metadata with TCP flags byte (byte 13 of TCP header).
pub(crate) fn extract_tcp_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    meta.ports.src_port = u16::from_be_bytes([hdr[0], hdr[1]]);
    meta.ports.dst_port = u16::from_be_bytes([hdr[2], hdr[3]]);
    if hdr.len() >= 14 {
        meta.tcp_flags = hdr[13]; // SYN/ACK/FIN/RST/PSH/URG
    }
}

/// ICMP (v4 and v6): type, code, echo ID.
/// Matches C's `XDP2_METADATA_TEMP_icmp`.
pub(crate) fn extract_icmp_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    meta.icmp.icmp_type = hdr[0];
    meta.icmp.code = hdr[1];
    // Echo request/reply: v4 type 0/8, v6 type 128/129
    let t = hdr[0];
    if t == 0 || t == 8 || t == 128 || t == 129 {
        meta.icmp.id = u16::from_be_bytes([hdr[4], hdr[5]]);
    }
}

/// VLAN 802.1Q tag.
/// Matches C's `XDP2_METADATA_TEMP_vlan_8021Q`.
pub(crate) fn extract_vlan_8021q_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    let idx = if meta.vlan_count < 2 {
        meta.vlan_count as usize
    } else {
        1
    };
    if meta.vlan_count < 2 {
        meta.vlan_count += 1;
    }
    meta.vlan[idx].tci = u16::from_be_bytes([hdr[0], hdr[1]]);
    meta.vlan[idx].tpid = 0x8100;
}

/// VLAN 802.1AD (QinQ) tag.
/// Matches C's `XDP2_METADATA_TEMP_vlan_8021AD`.
pub(crate) fn extract_vlan_8021ad_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    let idx = if meta.vlan_count < 2 {
        meta.vlan_count as usize
    } else {
        1
    };
    if meta.vlan_count < 2 {
        meta.vlan_count += 1;
    }
    meta.vlan[idx].tci = u16::from_be_bytes([hdr[0], hdr[1]]);
    meta.vlan[idx].tpid = 0x88A8;
}

/// ARP/RARP: opcode, sender/target HW+IP addresses.
/// Matches C's `XDP2_METADATA_TEMP_arp_rarp`.
pub(crate) fn extract_arp_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    meta.arp.op = (u16::from_be_bytes([hdr[6], hdr[7]]) & 0xFF) as u8;
    meta.arp.sha.copy_from_slice(&hdr[8..14]);
    meta.arp.spa = u32::from_be_bytes([hdr[14], hdr[15], hdr[16], hdr[17]]);
    meta.arp.tha.copy_from_slice(&hdr[18..24]);
    meta.arp.tpa = u32::from_be_bytes([hdr[24], hdr[25], hdr[26], hdr[27]]);
}

/// MPLS label: label, TC, BoS, TTL from first 4-byte label entry.
/// Matches C's `XDP2_METADATA_TEMP_mpls`.
pub(crate) fn extract_mpls_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    let w = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    meta.mpls.label = w >> 12;
    meta.mpls.tc = ((w >> 9) & 0x7) as u8;
    meta.mpls.bos = ((w >> 8) & 0x1) != 0;
    meta.mpls.ttl = (w & 0xFF) as u8;
}

/// ESP: extract SPI.
/// Matches C's `XDP2_METADATA_TEMP_esp`.
pub(crate) fn extract_esp_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    meta.esp_spi = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
}

/// AH: extract SPI (Security Parameters Index).
/// Matches C's `XDP2_METADATA_TEMP_ah`.
pub(crate) fn extract_ah_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    meta.ah_spi = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
}

/// TIPC: extract addr_type and originating node.
/// Matches C's `XDP2_METADATA_TEMP_tipc`.
pub(crate) fn extract_tipc_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    meta.addr_type = AddrType::Tipc;
    meta.addrs.tipc_key = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
}

/// L2TPv3 (over IP, proto 115): extract session ID.
/// Matches C's `XDP2_METADATA_TEMP_l2tp`.
pub(crate) fn extract_l2tp_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    meta.l2tp_session_id = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
}

/// VXLAN: extract VNI into keyid.
pub(crate) fn extract_vxlan_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    // VNI is in bytes 4-6 (24-bit), byte 7 is reserved.
    meta.keyid = ((hdr[4] as u32) << 16) | ((hdr[5] as u32) << 8) | (hdr[6] as u32);
}

/// Geneve: extract VNI into keyid.
pub(crate) fn extract_geneve_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    // VNI is in bytes 4-6 (24-bit), byte 7 is reserved.
    meta.keyid = ((hdr[4] as u32) << 16) | ((hdr[5] as u32) << 8) | (hdr[6] as u32);
}

/// Extract GRE base flags into FlowMeta.gre.flags.
/// Matches C's `XDP2_METADATA_TEMP_gre` in parser_metadata.h.
pub(crate) fn extract_gre_metadata(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    meta.gre.flags = u16::from_be_bytes([hdr[0], hdr[1]]) as u32;
}

/// Extract GRE checksum field (4-byte flag-field: checksum + reserved).
/// Matches C's `XDP2_METADATA_TEMP_gre_checksum` in parser_metadata.h.
pub(crate) fn extract_gre_checksum(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    meta.gre.csum = u16::from_ne_bytes([hdr[0], hdr[1]]);
}

/// Extract GRE key/ID field (4-byte flag-field).
/// Matches C's `XDP2_METADATA_TEMP_gre_keyid` — stores in both gre.keyid and keyid.
pub(crate) fn extract_gre_keyid(
    hdr: &[u8],
    _hdr_len: usize,
    meta: &mut FlowMeta,
    _ctrl: &CtrlData,
) {
    let v = u32::from_ne_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    meta.gre.keyid = v;
    meta.keyid = v;
}

/// Extract GRE sequence number field (4-byte flag-field).
/// Matches C's `XDP2_METADATA_TEMP_gre_seq` in parser_metadata.h.
pub(crate) fn extract_gre_seq(hdr: &[u8], _hdr_len: usize, meta: &mut FlowMeta, _ctrl: &CtrlData) {
    meta.gre.seq = u32::from_ne_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use xdp2_core::CtrlData;

    fn ctrl() -> CtrlData {
        CtrlData::default()
    }

    #[test]
    fn ether_extracts_macs_and_ethertype() {
        let mut meta = FlowMeta::default();
        // dst=AA:BB:CC:DD:EE:FF src=11:22:33:44:55:66 ethertype=0x0800 (IPv4)
        let hdr = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00,
        ];
        extract_ether_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert_eq!(&meta.eth_addrs[..12], &hdr[..12]);
        assert_eq!(meta.eth_proto, 0x0800);
    }

    #[test]
    fn ipv4_extracts_addrs_and_protocol() {
        let mut meta = FlowMeta::default();
        // Minimal IPv4-ish header: proto=6 (TCP), src=10.0.0.1, dst=10.0.0.2
        let mut hdr = [0u8; 20];
        hdr[9] = 6; // protocol = TCP
        hdr[12..16].copy_from_slice(&[10, 0, 0, 1]);
        hdr[16..20].copy_from_slice(&[10, 0, 0, 2]);
        extract_ipv4_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert_eq!(meta.addr_type, AddrType::Ipv4);
        assert_eq!(meta.ip_proto, 6);
        assert_eq!(meta.addrs.v4_src, u32::from_be_bytes([10, 0, 0, 1]));
        assert_eq!(meta.addrs.v4_dst, u32::from_be_bytes([10, 0, 0, 2]));
        assert!(!meta.is_fragment);
    }

    #[test]
    fn ipv4_detects_first_fragment() {
        let mut meta = FlowMeta::default();
        let mut hdr = [0u8; 20];
        // MF flag set, offset=0 → first fragment
        hdr[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        extract_ipv4_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert!(meta.is_fragment);
        assert!(meta.first_frag);
    }

    #[test]
    fn ipv4_detects_later_fragment() {
        let mut meta = FlowMeta::default();
        let mut hdr = [0u8; 20];
        // offset=185 (non-zero), MF=0 → last fragment
        hdr[6..8].copy_from_slice(&0x00B9u16.to_be_bytes());
        extract_ipv4_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert!(meta.is_fragment);
        assert!(!meta.first_frag);
    }

    #[test]
    fn ipv6_extracts_addrs_and_flow_label() {
        let mut meta = FlowMeta::default();
        let mut hdr = [0u8; 40];
        hdr[0] = 0x60; // version 6
        hdr[1] = 0x0A; // traffic class + flow label high nibble = 0xA
        hdr[2] = 0xBC; // flow label mid
        hdr[3] = 0xDE; // flow label low
        hdr[6] = 17; // next header = UDP
        hdr[8..24].copy_from_slice(&[1; 16]); // src
        hdr[24..40].copy_from_slice(&[2; 16]); // dst
        extract_ipv6_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert_eq!(meta.addr_type, AddrType::Ipv6);
        assert_eq!(meta.ip_proto, 17);
        assert_eq!(meta.flow_label, 0xABCDE);
        assert_eq!(meta.addrs.v6_src, [1; 16]);
        assert_eq!(meta.addrs.v6_dst, [2; 16]);
    }

    #[test]
    fn ports_extracts_src_dst() {
        let mut meta = FlowMeta::default();
        let hdr = [0x00, 0x50, 0x01, 0xBB]; // src=80, dst=443
        extract_ports_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert_eq!(meta.ports.src_port, 80);
        assert_eq!(meta.ports.dst_port, 443);
    }

    #[test]
    fn icmp_echo_request() {
        let mut meta = FlowMeta::default();
        // type=8 (echo request), code=0, csum=XX XX, id=0x1234
        let hdr = [8, 0, 0, 0, 0x12, 0x34];
        extract_icmp_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert_eq!(meta.icmp.icmp_type, 8);
        assert_eq!(meta.icmp.code, 0);
        assert_eq!(meta.icmp.id, 0x1234);
    }

    #[test]
    fn icmp_dest_unreachable_no_id() {
        let mut meta = FlowMeta::default();
        // type=3 (dest unreachable), code=1 — not echo, so id stays 0
        let hdr = [3, 1, 0, 0, 0xAB, 0xCD];
        extract_icmp_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert_eq!(meta.icmp.icmp_type, 3);
        assert_eq!(meta.icmp.code, 1);
        assert_eq!(meta.icmp.id, 0);
    }

    #[test]
    fn vlan_8021q_first_tag() {
        let mut meta = FlowMeta::default();
        let hdr = [0x00, 0x64, 0x08, 0x00]; // TCI=100, ethertype after
        extract_vlan_8021q_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert_eq!(meta.vlan_count, 1);
        assert_eq!(meta.vlan[0].tci, 100);
        assert_eq!(meta.vlan[0].tpid, 0x8100);
    }

    #[test]
    fn vlan_qinq_stacks_two_tags() {
        let mut meta = FlowMeta::default();
        // First: outer 802.1AD
        let outer = [0x00, 0xC8, 0x00, 0x00]; // TCI=200
        extract_vlan_8021ad_metadata(&outer, outer.len(), &mut meta, &ctrl());
        // Second: inner 802.1Q
        let inner = [0x00, 0x64, 0x00, 0x00]; // TCI=100
        extract_vlan_8021q_metadata(&inner, inner.len(), &mut meta, &ctrl());
        assert_eq!(meta.vlan_count, 2);
        assert_eq!(meta.vlan[0].tci, 200);
        assert_eq!(meta.vlan[0].tpid, 0x88A8);
        assert_eq!(meta.vlan[1].tci, 100);
        assert_eq!(meta.vlan[1].tpid, 0x8100);
    }

    #[test]
    fn arp_extracts_fields() {
        let mut meta = FlowMeta::default();
        let mut hdr = [0u8; 28];
        hdr[6..8].copy_from_slice(&1u16.to_be_bytes()); // op=1 (request)
        hdr[8..14].copy_from_slice(&[0xAA; 6]); // sha
        hdr[14..18].copy_from_slice(&[192, 168, 1, 1]); // spa
        hdr[18..24].copy_from_slice(&[0xBB; 6]); // tha
        hdr[24..28].copy_from_slice(&[192, 168, 1, 2]); // tpa
        extract_arp_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert_eq!(meta.arp.op, 1);
        assert_eq!(meta.arp.sha, [0xAA; 6]);
        assert_eq!(meta.arp.spa, u32::from_be_bytes([192, 168, 1, 1]));
        assert_eq!(meta.arp.tpa, u32::from_be_bytes([192, 168, 1, 2]));
    }

    #[test]
    fn mpls_extracts_label_fields() {
        let mut meta = FlowMeta::default();
        // Label=1000 (0x3E8), TC=5, BoS=1, TTL=64
        // Binary: 000000001111101000 101 1 01000000
        //         label=1000          tc=5 bos ttl=64
        let w: u32 = (1000 << 12) | (5 << 9) | (1 << 8) | 64;
        let hdr = w.to_be_bytes();
        extract_mpls_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert_eq!(meta.mpls.label, 1000);
        assert_eq!(meta.mpls.tc, 5);
        assert!(meta.mpls.bos);
        assert_eq!(meta.mpls.ttl, 64);
    }

    #[test]
    fn esp_extracts_spi() {
        let mut meta = FlowMeta::default();
        let hdr = 0xDEADBEEFu32.to_be_bytes();
        extract_esp_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert_eq!(meta.esp_spi, 0xDEADBEEF);
    }

    #[test]
    fn ah_extracts_spi() {
        let mut meta = FlowMeta::default();
        // AH: next_hdr, len, reserved(2), SPI(4)
        let mut hdr = [0u8; 8];
        hdr[4..8].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
        extract_ah_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert_eq!(meta.ah_spi, 0xCAFEBABE);
    }

    #[test]
    fn vxlan_extracts_vni() {
        let mut meta = FlowMeta::default();
        // VXLAN: flags(1) reserved(3) VNI(3) reserved(1)
        let hdr = [0x08, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00];
        extract_vxlan_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert_eq!(meta.keyid, 0x001234);
    }

    #[test]
    fn geneve_extracts_vni() {
        let mut meta = FlowMeta::default();
        let hdr = [0x00, 0x00, 0x65, 0x58, 0xAB, 0xCD, 0xEF, 0x00];
        extract_geneve_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert_eq!(meta.keyid, 0xABCDEF);
    }

    #[test]
    fn gre_base_flags() {
        let mut meta = FlowMeta::default();
        // C=1, K=1 flags: 0xA000
        let hdr = [0xA0, 0x00, 0x08, 0x00];
        extract_gre_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert_eq!(meta.gre.flags, 0xA000);
    }

    #[test]
    fn tipc_sets_addr_type() {
        let mut meta = FlowMeta::default();
        let mut hdr = [0u8; 12];
        hdr[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
        extract_tipc_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert_eq!(meta.addr_type, AddrType::Tipc);
        assert_eq!(meta.addrs.tipc_key, 0x12345678);
    }

    #[test]
    fn l2tp_extracts_session_id() {
        let mut meta = FlowMeta::default();
        let hdr = 0xFEEDFACEu32.to_be_bytes();
        extract_l2tp_metadata(&hdr, hdr.len(), &mut meta, &ctrl());
        assert_eq!(meta.l2tp_session_id, 0xFEEDFACE);
    }
}
