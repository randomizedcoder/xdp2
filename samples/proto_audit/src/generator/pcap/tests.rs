use std::collections::BTreeMap;

use crate::ir::{Endian, FieldDef, FieldType, ProtocolDef};

use super::embedded::embedded_proto;
use super::routing::{
    build_protocol_stack, is_root, load_pcap_template, stack_route_for, upper_pdu_preamble,
    PcapTemplate, StackResult, LINK_ROOTS, STACK_ROUTES,
};
use super::serialize::{
    fixup_ipv6, fixup_udp_length, generate_pcap, generate_pcap_with_discovery, hex_dump,
    ipv4_checksum, pack_field, parse_int_value, pcap_global_header, pcap_record_header,
    select_field_value, serialize_header, PcapOutput,
};

    /// Helper: build_protocol_stack with empty discovery state (for tests that
    /// only exercise curated STACK_ROUTES).
    fn build_stack_no_discovery(
        target: &str,
        all_protos: &BTreeMap<String, ProtocolDef>,
    ) -> Result<StackResult, String> {
        let ds = crate::discovery::DiscoveryState {
            tshark: None,
            scapy: None,
            kernel: None,
        };
        let dp = BTreeMap::new();
        build_protocol_stack(target, all_protos, &ds, &dp)
    }

    /// Mutex to serialize tests that modify PROTO_AUDIT_PCAP_TEMPLATES.
    /// env::set_var is process-global, so concurrent tests race without this.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Helper: temporarily redirect PROTO_AUDIT_PCAP_TEMPLATES to a
    /// non-existent directory so generate_pcap uses synthetic stack
    /// construction instead of template lookup. Holds ENV_MUTEX to
    /// prevent concurrent tests from seeing the modified env var.
    struct NoTemplatesGuard {
        prev: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl NoTemplatesGuard {
        fn new() -> Self {
            let lock = ENV_MUTEX.lock().unwrap();
            let prev = std::env::var("PROTO_AUDIT_PCAP_TEMPLATES").ok();
            std::env::set_var("PROTO_AUDIT_PCAP_TEMPLATES", "/nonexistent_pcap_templates");
            Self { prev, _lock: lock }
        }
    }
    impl Drop for NoTemplatesGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var("PROTO_AUDIT_PCAP_TEMPLATES", v),
                None => std::env::remove_var("PROTO_AUDIT_PCAP_TEMPLATES"),
            }
        }
    }

    #[test]
    fn test_pack_field_byte_aligned_u8() {
        let mut buf = [0u8; 4];
        let field = FieldDef::new("ttl", 8, 8, FieldType::Uint);
        pack_field(&mut buf, &field, 64);
        assert_eq!(buf[1], 64);
    }

    #[test]
    fn test_pack_field_byte_aligned_u16() {
        let mut buf = [0u8; 4];
        let field = FieldDef::new("ether_type", 0, 16, FieldType::Enum).with_endian(Endian::Big);
        pack_field(&mut buf, &field, 0x0800);
        assert_eq!(buf[0], 0x08);
        assert_eq!(buf[1], 0x00);
    }

    #[test]
    fn test_pack_field_bitfield_ipv4_ver_ihl() {
        // IPv4 byte 0: version=4 (4 bits), ihl=5 (4 bits) → 0x45
        let mut buf = [0u8; 1];
        let ver = FieldDef::new("version", 0, 4, FieldType::Uint);
        let ihl = FieldDef::new("ihl", 4, 4, FieldType::Uint);
        pack_field(&mut buf, &ver, 4);
        pack_field(&mut buf, &ihl, 5);
        assert_eq!(buf[0], 0x45);
    }

    #[test]
    fn test_pack_field_3bit_flags() {
        // IP flags at offset 48, 3 bits. Value 2 (DF set) → bits: 010
        let mut buf = [0u8; 8];
        let field = FieldDef::new("flags", 48, 3, FieldType::Flags);
        pack_field(&mut buf, &field, 0b010);
        // Byte 6 (offset 48): bits 7..5 = 010, rest 0 → 0x40
        assert_eq!(buf[6], 0x40);
    }

    #[test]
    fn test_pack_field_13bit_frag_offset() {
        // Fragment offset at bit 51, 13 bits. Value 0.
        let mut buf = [0u8; 8];
        let field = FieldDef::new("fragment_offset", 51, 13, FieldType::Uint);
        pack_field(&mut buf, &field, 0);
        assert_eq!(buf[6], 0x00);
        assert_eq!(buf[7], 0x00);
    }

    #[test]
    fn test_pack_field_mac_address() {
        let mut buf = [0u8; 6];
        let field = FieldDef::new("dst_mac", 0, 48, FieldType::MacAddr).with_endian(Endian::Big);
        pack_field(&mut buf, &field, 0x020000000002);
        assert_eq!(buf, [0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    }

    #[test]
    fn test_ipv4_checksum() {
        // Standard example: IPv4 header with known checksum
        let mut header = [0u8; 20];
        header[0] = 0x45; // ver=4, ihl=5
        header[8] = 64; // ttl
        header[9] = 6; // protocol=TCP
        // src = 10.0.0.1
        header[12..16].copy_from_slice(&[10, 0, 0, 1]);
        // dst = 10.0.0.2
        header[16..20].copy_from_slice(&[10, 0, 0, 2]);
        // total_length = 40 (20 header + 20 TCP)
        header[2] = 0;
        header[3] = 40;

        let cksum = ipv4_checksum(&header);
        // Verify it's valid by checking header sums to 0 with checksum included
        header[10] = (cksum >> 8) as u8;
        header[11] = (cksum & 0xFF) as u8;
        let verify = ipv4_checksum(&header);
        assert_eq!(verify, 0, "checksum verification should be 0");
    }

    #[test]
    fn test_pcap_global_header_magic() {
        let hdr = pcap_global_header(1);
        // Little-endian magic: 0xD4C3B2A1
        assert_eq!(hdr[0], 0xD4);
        assert_eq!(hdr[1], 0xC3);
        assert_eq!(hdr[2], 0xB2);
        assert_eq!(hdr[3], 0xA1);
    }

    #[test]
    fn test_pcap_record_header_length() {
        let hdr = pcap_record_header(54);
        let incl_len = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
        let orig_len = u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]);
        assert_eq!(incl_len, 54);
        assert_eq!(orig_len, 54);
    }

    #[test]
    fn test_select_field_value_override() {
        let field = FieldDef::new("protocol", 72, 8, FieldType::Enum);
        let mut overrides = BTreeMap::new();
        overrides.insert("protocol".to_string(), 6u64);
        assert_eq!(select_field_value(&field, &overrides), 6);
    }

    #[test]
    fn test_select_field_value_default() {
        let field = FieldDef::new("version", 0, 4, FieldType::Uint).with_default_value("4");
        let overrides = BTreeMap::new();
        assert_eq!(select_field_value(&field, &overrides), 4);
    }

    #[test]
    fn test_select_field_value_ipv4_src() {
        let field = FieldDef::new("src_addr", 96, 32, FieldType::Ipv4Addr);
        let overrides = BTreeMap::new();
        let val = select_field_value(&field, &overrides);
        assert_eq!(val, u64::from(u32::from_be_bytes([10, 0, 0, 1])));
    }

    #[test]
    fn test_select_field_value_mac_dst() {
        let field = FieldDef::new("dst_mac", 0, 48, FieldType::MacAddr);
        let overrides = BTreeMap::new();
        assert_eq!(select_field_value(&field, &overrides), 0x020000000002);
    }

    #[test]
    fn test_serialize_ethernet_header() {
        let eth = embedded_proto("Ethernet").unwrap();
        let mut overrides = BTreeMap::new();
        overrides.insert("ether_type".to_string(), 0x0800u64);
        let buf = serialize_header(&eth, &overrides);
        assert_eq!(buf.len(), 14);
        // dst_mac = 02:00:00:00:00:02
        assert_eq!(&buf[0..6], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        // src_mac = 02:00:00:00:00:01
        assert_eq!(&buf[6..12], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        // ether_type = 0x0800
        assert_eq!(&buf[12..14], &[0x08, 0x00]);
    }

    #[test]
    fn test_serialize_ipv4_header() {
        let ipv4 = embedded_proto("IPv4").unwrap();
        let mut overrides = BTreeMap::new();
        overrides.insert("protocol".to_string(), 6u64);
        let buf = serialize_header(&ipv4, &overrides);
        assert_eq!(buf.len(), 20);
        // Byte 0: version=4, ihl=5 → 0x45
        assert_eq!(buf[0], 0x45);
        // Byte 8: ttl=64
        assert_eq!(buf[8], 64);
        // Byte 9: protocol=6 (TCP)
        assert_eq!(buf[9], 6);
        // src = 10.0.0.1
        assert_eq!(&buf[12..16], &[10, 0, 0, 1]);
        // dst = 10.0.0.2
        assert_eq!(&buf[16..20], &[10, 0, 0, 2]);
    }

    #[test]
    fn test_build_stack_ethernet() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("Ethernet", &protos).unwrap();
        assert_eq!(result.layers.len(), 1);
        assert_eq!(result.layers[0].proto_name, "Ethernet");
        assert_eq!(result.link_type, 1);
    }

    #[test]
    fn test_build_stack_ipv4() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("IPv4", &protos).unwrap();
        assert_eq!(result.layers.len(), 2);
        assert_eq!(result.layers[0].proto_name, "Ethernet");
        assert_eq!(result.layers[1].proto_name, "IPv4");
        assert_eq!(result.layers[0].overrides.get("ether_type"), Some(&0x0800u64));
        assert_eq!(result.link_type, 1);
    }

    #[test]
    fn test_build_stack_tcp() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("TCP", &protos).unwrap();
        assert_eq!(result.layers.len(), 3);
        assert_eq!(result.layers[0].proto_name, "Ethernet");
        assert_eq!(result.layers[1].proto_name, "IPv4");
        assert_eq!(result.layers[2].proto_name, "TCP");
        assert_eq!(result.layers[1].overrides.get("protocol"), Some(&6u64));
        assert_eq!(result.link_type, 1);
    }

    #[test]
    fn test_build_stack_unknown_proto() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("UnknownProto", &protos);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_pcap_ipv4() {
        let _guard = NoTemplatesGuard::new();
        let protos = BTreeMap::new();
        let target = embedded_proto("IPv4").unwrap();
        let output = generate_pcap(&target, &protos).unwrap();

        // PCAP = 24 (global) + 16 (record) + packet
        assert_eq!(output.stack, vec!["Ethernet", "IPv4"]);
        // Packet = 14 (Ethernet) + 20 (IPv4) = 34 bytes
        assert_eq!(output.packet_bytes.len(), 34);
        assert_eq!(output.pcap_bytes.len(), 24 + 16 + 34);

        // Verify PCAP magic
        assert_eq!(&output.pcap_bytes[0..4], &[0xD4, 0xC3, 0xB2, 0xA1]);

        // Verify IPv4 version+IHL
        assert_eq!(output.packet_bytes[14], 0x45);

        // Verify IPv4 checksum is valid
        let ipv4_hdr = &output.packet_bytes[14..34];
        assert_eq!(ipv4_checksum(ipv4_hdr), 0);
    }

    #[test]
    fn test_generate_pcap_tcp() {
        let _guard = NoTemplatesGuard::new();
        let mut protos = BTreeMap::new();
        // Minimal TCP def
        protos.insert(
            "TCP".to_string(),
            ProtocolDef::new("TCP", 160).with_fields(vec![
                FieldDef::new("src_port", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("dst_port", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("seq", 32, 32, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("ack", 64, 32, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("data_offset", 96, 4, FieldType::Uint).with_default_value("5"),
                FieldDef::new("reserved", 100, 3, FieldType::Pad),
                FieldDef::new("flags", 103, 9, FieldType::Flags),
                FieldDef::new("window", 112, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("checksum", 128, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("urgent_ptr", 144, 16, FieldType::Uint).with_endian(Endian::Big),
            ]),
        );

        let target = protos.get("TCP").unwrap().clone();
        let output = generate_pcap(&target, &protos).unwrap();

        assert_eq!(output.stack, vec!["Ethernet", "IPv4", "TCP"]);
        // 14 (Eth) + 20 (IPv4) + 20 (TCP) = 54
        assert_eq!(output.packet_bytes.len(), 54);

        // IPv4 protocol field should be 6 (TCP)
        assert_eq!(output.packet_bytes[14 + 9], 6);

        // Ethernet ether_type should be 0x0800
        assert_eq!(&output.packet_bytes[12..14], &[0x08, 0x00]);
    }

    #[test]
    fn test_hex_dump_format() {
        let data = vec![0x45, 0x00, 0x00, 0x28];
        let dump = hex_dump(&data);
        assert!(dump.contains("45 00 00 28"));
    }

    #[test]
    fn test_parse_int_value() {
        assert_eq!(parse_int_value("42"), Some(42));
        assert_eq!(parse_int_value("0x0800"), Some(0x0800));
        assert_eq!(parse_int_value("0b1010"), Some(10));
        assert_eq!(parse_int_value("abc"), None);
    }

    // ── Helper: verify a route builds the expected stack ──

    fn assert_stack(
        proto: &str,
        expected_layers: &[&str],
        parent_idx: usize,
        dispatch_field: &str,
        dispatch_value: u64,
    ) {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery(proto, &protos).unwrap();
        assert_eq!(
            result.layers.len(),
            expected_layers.len(),
            "{}: expected {} layers, got {}",
            proto,
            expected_layers.len(),
            result.layers.len()
        );
        for (i, name) in expected_layers.iter().enumerate() {
            assert_eq!(result.layers[i].proto_name, *name, "{}: layer {}", proto, i);
        }
        assert_eq!(
            result.layers[parent_idx].overrides.get(dispatch_field),
            Some(&dispatch_value),
            "{}: {}={:#x} override on layer {}",
            proto,
            dispatch_field,
            dispatch_value,
            expected_layers[parent_idx],
        );
    }

    // ── Phase 1: L2 Ethernet-direct routes ──

    #[test]
    fn test_build_stack_rarp() {
        assert_stack("RARP", &["Ethernet", "RARP"], 0, "ether_type", 0x8035);
    }

    #[test]
    fn test_build_stack_mpls() {
        assert_stack("MPLS", &["Ethernet", "MPLS"], 0, "ether_type", 0x8847);
    }

    #[test]
    fn test_build_stack_pppoe() {
        assert_stack("PPPoE", &["Ethernet", "PPPoE"], 0, "ether_type", 0x8864);
    }

    #[test]
    fn test_build_stack_lldp() {
        assert_stack("LLDP", &["Ethernet", "LLDP"], 0, "ether_type", 0x88CC);
    }

    #[test]
    fn test_build_stack_ptp() {
        assert_stack("PTP", &["Ethernet", "PTP"], 0, "ether_type", 0x88F7);
    }

    #[test]
    fn test_build_stack_eapol() {
        assert_stack("EAPOL", &["Ethernet", "EAPOL"], 0, "ether_type", 0x888E);
    }

    #[test]
    fn test_build_stack_macsec() {
        assert_stack("MACsec", &["Ethernet", "MACsec"], 0, "ether_type", 0x88E5);
    }

    #[test]
    fn test_build_stack_qinq() {
        assert_stack("QinQ", &["Ethernet", "QinQ"], 0, "ether_type", 0x88A8);
    }

    #[test]
    fn test_build_stack_pbb() {
        assert_stack("PBB", &["Ethernet", "PBB"], 0, "ether_type", 0x88E7);
    }

    #[test]
    fn test_build_stack_trill() {
        assert_stack("TRILL", &["Ethernet", "TRILL"], 0, "ether_type", 0x22F3);
    }

    #[test]
    fn test_build_stack_ethercat() {
        assert_stack("EtherCAT", &["Ethernet", "EtherCAT"], 0, "ether_type", 0x88A4);
    }

    #[test]
    fn test_build_stack_profinet() {
        assert_stack("PROFINET", &["Ethernet", "PROFINET"], 0, "ether_type", 0x8892);
    }

    #[test]
    fn test_build_stack_fcoe() {
        assert_stack("FCoE", &["Ethernet", "FCoE"], 0, "ether_type", 0x8906);
    }

    #[test]
    fn test_build_stack_fip() {
        assert_stack("FIP", &["Ethernet", "FIP"], 0, "ether_type", 0x8914);
    }

    #[test]
    fn test_build_stack_slow_protocols() {
        assert_stack("Slow_Protocols", &["Ethernet", "Slow_Protocols"], 0, "ether_type", 0x8809);
    }

    #[test]
    fn test_build_stack_lacp() {
        assert_stack("LACP", &["Ethernet", "LACP"], 0, "ether_type", 0x8809);
    }

    #[test]
    fn test_build_stack_mac_control() {
        assert_stack("MAC_Control", &["Ethernet", "MAC_Control"], 0, "ether_type", 0x8808);
    }

    #[test]
    fn test_build_stack_cfm() {
        assert_stack("CFM", &["Ethernet", "CFM"], 0, "ether_type", 0x8902);
    }

    #[test]
    fn test_build_stack_hsr() {
        assert_stack("HSR", &["Ethernet", "HSR"], 0, "ether_type", 0x892F);
    }

    #[test]
    fn test_build_stack_batman() {
        assert_stack("BATMAN", &["Ethernet", "BATMAN"], 0, "ether_type", 0x4305);
    }

    #[test]
    fn test_build_stack_nsh() {
        assert_stack("NSH", &["Ethernet", "NSH"], 0, "ether_type", 0x894F);
    }

    #[test]
    fn test_build_stack_homeplug_av() {
        assert_stack("HomePlug_AV", &["Ethernet", "HomePlug_AV"], 0, "ether_type", 0x88E1);
    }

    #[test]
    fn test_build_stack_aoe() {
        assert_stack("AoE", &["Ethernet", "AoE"], 0, "ether_type", 0x88A2);
    }

    #[test]
    fn test_build_stack_mvrp() {
        assert_stack("MVRP", &["Ethernet", "MVRP"], 0, "ether_type", 0x88F5);
    }

    #[test]
    fn test_build_stack_nc_si() {
        assert_stack("NC_SI", &["Ethernet", "NC_SI"], 0, "ether_type", 0x88F8);
    }

    #[test]
    fn test_build_stack_iec_goose() {
        assert_stack("IEC_GOOSE", &["Ethernet", "IEC_GOOSE"], 0, "ether_type", 0x88B8);
    }

    #[test]
    fn test_build_stack_iec_sv() {
        assert_stack("IEC_SV", &["Ethernet", "IEC_SV"], 0, "ether_type", 0x88BA);
    }

    #[test]
    fn test_build_stack_ipx() {
        assert_stack("IPX", &["Ethernet", "IPX"], 0, "ether_type", 0x8137);
    }

    #[test]
    fn test_build_stack_appletalk() {
        assert_stack(
            "AppleTalk",
            &["Ethernet", "LLAP", "AppleTalk"],
            0,
            "ether_type",
            0x809B,
        );
    }

    #[test]
    fn test_build_stack_tipc() {
        assert_stack("TIPC", &["Ethernet", "TIPC"], 0, "ether_type", 0x88CA);
    }

    #[test]
    fn test_build_stack_pppoed() {
        assert_stack("PPPoED", &["Ethernet", "PPPoED"], 0, "ether_type", 0x8863);
    }

    // ── Phase 2: L3 IPv4/IPv6 routes ──

    #[test]
    fn test_build_stack_ospf() {
        assert_stack("OSPF", &["Ethernet", "IPv4", "OSPF"], 1, "protocol", 89);
    }

    #[test]
    fn test_build_stack_vrrp() {
        assert_stack("VRRP", &["Ethernet", "IPv4", "VRRP"], 1, "protocol", 112);
    }

    #[test]
    fn test_build_stack_pim() {
        assert_stack("PIM", &["Ethernet", "IPv4", "PIM"], 1, "protocol", 103);
    }

    #[test]
    fn test_build_stack_l2tp() {
        assert_stack("L2TP", &["Ethernet", "IPv4", "L2TP"], 1, "protocol", 115);
    }

    #[test]
    fn test_build_stack_esp() {
        assert_stack("ESP", &["Ethernet", "IPv4", "ESP"], 1, "protocol", 50);
    }

    #[test]
    fn test_build_stack_ah() {
        assert_stack("AH", &["Ethernet", "IPv4", "AH"], 1, "protocol", 51);
    }

    #[test]
    fn test_build_stack_ip_in_ip() {
        assert_stack("IP_in_IP", &["Ethernet", "IPv4", "IP_in_IP"], 1, "protocol", 4);
    }

    #[test]
    fn test_build_stack_dccp() {
        assert_stack("DCCP", &["Ethernet", "IPv4", "DCCP"], 1, "protocol", 33);
    }

    #[test]
    fn test_build_stack_udplite() {
        assert_stack("UDPLite", &["Ethernet", "IPv4", "UDPLite"], 1, "protocol", 136);
    }

    #[test]
    fn test_build_stack_eigrp() {
        assert_stack("EIGRP", &["Ethernet", "IPv4", "EIGRP"], 1, "protocol", 88);
    }

    #[test]
    fn test_build_stack_ipv6_eh() {
        assert_stack("IPv6_EH", &["Ethernet", "IPv6", "IPv6_EH"], 1, "next_header", 0);
    }

    #[test]
    fn test_build_stack_ipv6_destopts() {
        assert_stack("IPv6_DestOpts", &["Ethernet", "IPv6", "IPv6_DestOpts"], 1, "next_header", 60);
    }

    #[test]
    fn test_build_stack_ipv6_routing() {
        assert_stack("IPv6_Routing", &["Ethernet", "IPv6", "IPv6_Routing"], 1, "next_header", 43);
    }

    #[test]
    fn test_build_stack_ipv6_fragment() {
        assert_stack("IPv6_Fragment", &["Ethernet", "IPv6", "IPv6_Fragment"], 1, "next_header", 44);
    }

    #[test]
    fn test_build_stack_srv6() {
        assert_stack("SRv6", &["Ethernet", "IPv6", "SRv6"], 1, "next_header", 43);
    }

    // ── Phase 2: fixup_ipv6 ──

    #[test]
    fn test_fixup_ipv6_payload_length() {
        let protos = BTreeMap::new();
        let target = embedded_proto("IPv6").unwrap();
        let output = generate_pcap(&target, &protos).unwrap();
        // Packet: 14 (Eth) + 40 (IPv6) = 54
        assert_eq!(output.packet_bytes.len(), 54);
        // IPv6 payload_length should be 0 (no payload after IPv6 header itself)
        assert_eq!(output.packet_bytes[14 + 4], 0);
        assert_eq!(output.packet_bytes[14 + 5], 0);
    }

    #[test]
    fn test_fixup_ipv6_with_payload() {
        // ICMPv6 over IPv6: should have payload_length = icmpv6 header size
        let mut protos = BTreeMap::new();
        let icmpv6_def = ProtocolDef::new("ICMPv6", 32).with_fields(vec![
            FieldDef::new("type", 0, 8, FieldType::Uint),
            FieldDef::new("code", 8, 8, FieldType::Uint),
            FieldDef::new("checksum", 16, 16, FieldType::Uint).with_endian(Endian::Big),
        ]);
        protos.insert("ICMPv6".to_string(), icmpv6_def.clone());
        let output = generate_pcap(&icmpv6_def, &protos).unwrap();
        // Packet: 14 (Eth) + 40 (IPv6) + 4 (ICMPv6) = 58
        assert_eq!(output.packet_bytes.len(), 58);
        // IPv6 payload_length = 4 (ICMPv6 header)
        let pl = u16::from_be_bytes([output.packet_bytes[14 + 4], output.packet_bytes[14 + 5]]);
        assert_eq!(pl, 4);
    }

    // ── Phase 3: Embedded protocol serialization ──

    #[test]
    fn test_embedded_udp() {
        let udp = embedded_proto("UDP").unwrap();
        assert_eq!(udp.min_header_bits, 64);
        assert_eq!(udp.fields.len(), 4);
        assert_eq!(udp.dispatch_field, Some("dst_port".to_string()));
        let buf = serialize_header(&udp, &BTreeMap::new());
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn test_embedded_tcp() {
        let tcp = embedded_proto("TCP").unwrap();
        assert_eq!(tcp.min_header_bits, 160);
        assert_eq!(tcp.fields.len(), 10);
        assert!(tcp.is_variable_length);
        assert_eq!(tcp.dispatch_field, Some("dst_port".to_string()));
        let buf = serialize_header(&tcp, &BTreeMap::new());
        assert_eq!(buf.len(), 20);
        // data_offset=5 → byte 12 upper nibble = 0x50
        assert_eq!(buf[12] & 0xF0, 0x50);
    }

    #[test]
    fn test_embedded_gre() {
        let gre = embedded_proto("GRE").unwrap();
        assert_eq!(gre.min_header_bits, 32);
        assert_eq!(gre.fields.len(), 2);
        assert!(gre.is_variable_length);
        assert_eq!(gre.dispatch_field, Some("protocol_type".to_string()));
        let buf = serialize_header(&gre, &BTreeMap::new());
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn test_serialize_udp_with_port_override() {
        let udp = embedded_proto("UDP").unwrap();
        let mut overrides = BTreeMap::new();
        overrides.insert("dst_port".to_string(), 53u64);
        let buf = serialize_header(&udp, &overrides);
        assert_eq!(buf.len(), 8);
        // dst_port at offset 16 bits (bytes 2-3), value 53
        assert_eq!(buf[2], 0);
        assert_eq!(buf[3], 53);
    }

    #[test]
    fn test_serialize_tcp_with_port_override() {
        let tcp = embedded_proto("TCP").unwrap();
        let mut overrides = BTreeMap::new();
        overrides.insert("dst_port".to_string(), 80u64);
        let buf = serialize_header(&tcp, &overrides);
        // dst_port at bytes 2-3, value 80
        assert_eq!(buf[2], 0);
        assert_eq!(buf[3], 80);
    }

    #[test]
    fn test_serialize_gre_with_protocol_override() {
        let gre = embedded_proto("GRE").unwrap();
        let mut overrides = BTreeMap::new();
        overrides.insert("protocol_type".to_string(), 0x6558u64);
        let buf = serialize_header(&gre, &overrides);
        assert_eq!(buf[2], 0x65);
        assert_eq!(buf[3], 0x58);
    }

    // ── Phase 3: fixup_udp_length ──

    #[test]
    fn test_fixup_udp_length() {
        let _guard = NoTemplatesGuard::new();
        let mut protos = BTreeMap::new();
        // DNS over UDP: Eth → IPv4 → UDP → DNS
        let dns_def = ProtocolDef::new("DNS", 96).with_fields(vec![
            FieldDef::new("id", 0, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("flags", 16, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("qdcount", 32, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("ancount", 48, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("nscount", 64, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("arcount", 80, 16, FieldType::Uint).with_endian(Endian::Big),
        ]);
        protos.insert("DNS".to_string(), dns_def.clone());
        let output = generate_pcap(&dns_def, &protos).unwrap();
        // Stack: Eth(14) + IPv4(20) + UDP(8) + DNS(12) = 54
        assert_eq!(output.stack, vec!["Ethernet", "IPv4", "UDP", "DNS"]);
        assert_eq!(output.packet_bytes.len(), 54);
        // UDP offset = 34, UDP length = 54 - 34 = 20 (8 hdr + 12 DNS)
        let udp_len = u16::from_be_bytes([output.packet_bytes[34 + 4], output.packet_bytes[34 + 5]]);
        assert_eq!(udp_len, 20);
        // UDP dst_port should be 53 (DNS)
        let dst_port = u16::from_be_bytes([output.packet_bytes[34 + 2], output.packet_bytes[34 + 3]]);
        assert_eq!(dst_port, 53);
    }

    // ── Phase 3: UDP-routed protocol stacks ──

    #[test]
    fn test_build_stack_dns() {
        assert_stack("DNS", &["Ethernet", "IPv4", "UDP", "DNS"], 2, "dst_port", 53);
    }

    #[test]
    fn test_build_stack_mdns() {
        assert_stack("mDNS", &["Ethernet", "IPv4", "UDP", "mDNS"], 2, "dst_port", 5353);
    }

    #[test]
    fn test_build_stack_dhcp() {
        assert_stack("DHCP", &["Ethernet", "IPv4", "UDP", "DHCP"], 2, "dst_port", 67);
    }

    #[test]
    fn test_build_stack_ntp() {
        assert_stack("NTP", &["Ethernet", "IPv4", "UDP", "NTP"], 2, "dst_port", 123);
    }

    #[test]
    fn test_build_stack_snmp() {
        assert_stack("SNMP", &["Ethernet", "IPv4", "UDP", "SNMP"], 2, "dst_port", 161);
    }

    #[test]
    fn test_build_stack_vxlan() {
        assert_stack("VXLAN", &["Ethernet", "IPv4", "UDP", "VXLAN"], 2, "dst_port", 4789);
    }

    #[test]
    fn test_build_stack_geneve() {
        assert_stack("Geneve", &["Ethernet", "IPv4", "UDP", "Geneve"], 2, "dst_port", 6081);
    }

    #[test]
    fn test_build_stack_wireguard() {
        assert_stack("WireGuard", &["Ethernet", "IPv4", "UDP", "WireGuard"], 2, "dst_port", 51820);
    }

    #[test]
    fn test_build_stack_quic() {
        assert_stack("QUIC", &["Ethernet", "IPv4", "UDP", "QUIC"], 2, "dst_port", 443);
    }

    #[test]
    fn test_build_stack_gtp_u() {
        assert_stack("GTP_U", &["Ethernet", "IPv4", "UDP", "GTP_U"], 2, "dst_port", 2152);
    }

    #[test]
    fn test_build_stack_gtp_c() {
        assert_stack("GTP_C", &["Ethernet", "IPv4", "UDP", "GTP_C"], 2, "dst_port", 2123);
    }

    #[test]
    fn test_build_stack_radius() {
        assert_stack("RADIUS", &["Ethernet", "IPv4", "UDP", "RADIUS"], 2, "dst_port", 1812);
    }

    #[test]
    fn test_build_stack_sip() {
        assert_stack("SIP", &["Ethernet", "IPv4", "UDP", "SIP"], 2, "dst_port", 5060);
    }

    #[test]
    fn test_build_stack_bfd() {
        assert_stack("BFD", &["Ethernet", "IPv4", "UDP", "BFD"], 2, "dst_port", 3784);
    }

    #[test]
    fn test_build_stack_rtp() {
        assert_stack("RTP", &["Ethernet", "IPv4", "UDP", "RTP"], 2, "dst_port", 5004);
    }

    #[test]
    fn test_build_stack_rtcp() {
        assert_stack("RTCP", &["Ethernet", "IPv4", "UDP", "RTCP"], 2, "dst_port", 5005);
    }

    #[test]
    fn test_build_stack_stun() {
        assert_stack("STUN", &["Ethernet", "IPv4", "UDP", "STUN"], 2, "dst_port", 3478);
    }

    #[test]
    fn test_build_stack_rip() {
        assert_stack("RIP", &["Ethernet", "IPv4", "UDP", "RIP"], 2, "dst_port", 520);
    }

    #[test]
    fn test_build_stack_vxlan_gpe() {
        assert_stack("VXLAN_GPE", &["Ethernet", "IPv4", "UDP", "VXLAN_GPE"], 2, "dst_port", 4790);
    }

    #[test]
    fn test_build_stack_lisp() {
        assert_stack("LISP", &["Ethernet", "IPv4", "UDP", "LISP"], 2, "dst_port", 4341);
    }

    #[test]
    fn test_build_stack_coap() {
        assert_stack("CoAP", &["Ethernet", "IPv4", "UDP", "CoAP"], 2, "dst_port", 5683);
    }

    #[test]
    fn test_build_stack_tftp() {
        assert_stack("TFTP", &["Ethernet", "IPv4", "UDP", "TFTP"], 2, "dst_port", 69);
    }

    #[test]
    fn test_build_stack_dhcpv6() {
        assert_stack("DHCPv6", &["Ethernet", "IPv4", "UDP", "DHCPv6"], 2, "dst_port", 547);
    }

    #[test]
    fn test_build_stack_llmnr() {
        assert_stack("LLMNR", &["Ethernet", "IPv4", "UDP", "LLMNR"], 2, "dst_port", 5355);
    }

    #[test]
    fn test_build_stack_nbns() {
        assert_stack("NBNS", &["Ethernet", "IPv4", "UDP", "NBNS"], 2, "dst_port", 137);
    }

    #[test]
    fn test_build_stack_capwap() {
        assert_stack("CAPWAP", &["Ethernet", "IPv4", "UDP", "CAPWAP"], 2, "dst_port", 5247);
    }

    #[test]
    fn test_build_stack_syslog() {
        assert_stack("Syslog", &["Ethernet", "IPv4", "UDP", "Syslog"], 2, "dst_port", 514);
    }

    #[test]
    fn test_build_stack_netflow_v5() {
        assert_stack("NetFlow_v5", &["Ethernet", "IPv4", "UDP", "NetFlow_v5"], 2, "dst_port", 2055);
    }

    #[test]
    fn test_build_stack_ipfix() {
        assert_stack("IPFIX", &["Ethernet", "IPv4", "UDP", "IPFIX"], 2, "dst_port", 4739);
    }

    #[test]
    fn test_build_stack_ikev2() {
        assert_stack("IKEv2", &["Ethernet", "IPv4", "UDP", "IKEv2"], 2, "dst_port", 500);
    }

    #[test]
    fn test_build_stack_dtls() {
        assert_stack("DTLS", &["Ethernet", "IPv4", "UDP", "DTLS"], 2, "dst_port", 4433);
    }

    #[test]
    fn test_build_stack_mqtt() {
        assert_stack("MQTT", &["Ethernet", "IPv4", "TCP", "MQTT"], 2, "dst_port", 1883);
    }

    #[test]
    fn test_build_stack_openflow() {
        assert_stack("OpenFlow", &["Ethernet", "IPv4", "TCP", "OpenFlow"], 2, "dst_port", 6653);
    }

    #[test]
    fn test_build_stack_srt() {
        assert_stack("SRT", &["Ethernet", "IPv4", "UDP", "SRT"], 2, "dst_port", 1935);
    }

    #[test]
    fn test_build_stack_lwapp() {
        assert_stack("LWAPP", &["Ethernet", "IPv4", "UDP", "LWAPP"], 2, "dst_port", 12222);
    }

    #[test]
    fn test_build_stack_tzsp() {
        assert_stack("TZSP", &["Ethernet", "IPv4", "UDP", "TZSP"], 2, "dst_port", 37008);
    }

    // ── Phase 3: TCP-routed protocol stacks ──

    #[test]
    fn test_build_stack_http() {
        assert_stack("HTTP", &["Ethernet", "IPv4", "TCP", "HTTP"], 2, "dst_port", 80);
    }

    #[test]
    fn test_build_stack_tls() {
        assert_stack("TLS", &["Ethernet", "IPv4", "TCP", "TLS"], 2, "dst_port", 443);
    }

    #[test]
    fn test_build_stack_bgp() {
        assert_stack("BGP", &["Ethernet", "IPv4", "TCP", "BGP"], 2, "dst_port", 179);
    }

    #[test]
    fn test_build_stack_ssh() {
        assert_stack("SSH", &["Ethernet", "IPv4", "TCP", "SSH"], 2, "dst_port", 22);
    }

    #[test]
    fn test_build_stack_telnet() {
        assert_stack("Telnet", &["Ethernet", "IPv4", "TCP", "Telnet"], 2, "dst_port", 23);
    }

    #[test]
    fn test_build_stack_ftp() {
        assert_stack("FTP", &["Ethernet", "IPv4", "TCP", "FTP"], 2, "dst_port", 21);
    }

    #[test]
    fn test_build_stack_smtp() {
        assert_stack("SMTP", &["UpperPDU", "SMTP"], 0, "_always", 0);
    }

    #[test]
    fn test_build_stack_imap() {
        assert_stack("IMAP", &["Ethernet", "IPv4", "TCP", "IMAP"], 2, "dst_port", 143);
    }

    #[test]
    fn test_build_stack_smb() {
        assert_stack("SMB", &["Ethernet", "IPv4", "TCP", "SMB"], 2, "dst_port", 445);
    }

    #[test]
    fn test_build_stack_ldap() {
        assert_stack("LDAP", &["Ethernet", "IPv4", "TCP", "LDAP"], 2, "dst_port", 389);
    }

    #[test]
    fn test_build_stack_diameter() {
        assert_stack("Diameter", &["Ethernet", "IPv4", "TCP", "Diameter"], 2, "dst_port", 3868);
    }

    #[test]
    fn test_build_stack_amqp() {
        assert_stack("AMQP", &["UpperPDU", "AMQP"], 0, "_always", 0);
    }

    #[test]
    fn test_build_stack_kafka() {
        assert_stack("Kafka", &["Ethernet", "IPv4", "TCP", "Kafka"], 2, "dst_port", 9092);
    }

    #[test]
    fn test_build_stack_redis() {
        assert_stack("Redis", &["Ethernet", "IPv4", "TCP", "Redis"], 2, "dst_port", 6379);
    }

    #[test]
    fn test_build_stack_memcache() {
        assert_stack("Memcache", &["Ethernet", "IPv4", "TCP", "Memcache"], 2, "dst_port", 11211);
    }

    #[test]
    fn test_build_stack_kerberos() {
        assert_stack("Kerberos", &["Ethernet", "IPv4", "TCP", "Kerberos"], 2, "dst_port", 88);
    }

    #[test]
    fn test_build_stack_modbus_tcp() {
        assert_stack("MODBUS_TCP", &["Ethernet", "IPv4", "TCP", "MODBUS_TCP"], 2, "dst_port", 502);
    }

    #[test]
    fn test_build_stack_dnp3() {
        assert_stack("DNP3", &["Ethernet", "IPv4", "TCP", "DNP3"], 2, "dst_port", 20000);
    }

    #[test]
    fn test_build_stack_enip() {
        assert_stack("ENIP", &["Ethernet", "IPv4", "TCP", "ENIP"], 2, "dst_port", 44818);
    }

    #[test]
    fn test_build_stack_opc_ua() {
        assert_stack("OPC_UA", &["Ethernet", "IPv4", "TCP", "OPC_UA"], 2, "dst_port", 4840);
    }

    #[test]
    fn test_build_stack_rtsp() {
        assert_stack("RTSP", &["Ethernet", "IPv4", "TCP", "RTSP"], 2, "dst_port", 554);
    }

    #[test]
    fn test_build_stack_skinny() {
        assert_stack("Skinny", &["Ethernet", "IPv4", "TCP", "Skinny"], 2, "dst_port", 2000);
    }

    #[test]
    fn test_build_stack_tacacs() {
        assert_stack("TACACS", &["Ethernet", "IPv4", "TCP", "TACACS"], 2, "dst_port", 49);
    }

    // ── Phase 3: GRE tunnel routes ──

    #[test]
    fn test_build_stack_nvgre() {
        assert_stack("NVGRE", &["Ethernet", "IPv4", "GRE", "NVGRE"], 2, "protocol_type", 0x6558);
    }

    #[test]
    fn test_build_stack_erspan() {
        assert_stack("ERSPAN", &["Ethernet", "IPv4", "GRE", "ERSPAN"], 2, "protocol_type", 0x88BE);
    }

    #[test]
    fn test_build_stack_gre_pptp() {
        assert_stack("GRE_PPTP", &["Ethernet", "IPv4", "GRE", "GRE_PPTP"], 2, "protocol_type", 0x880B);
    }

    // ── Phase 3: full PCAP generation for multi-layer stacks ──

    #[test]
    fn test_generate_pcap_dns_over_udp() {
        let _guard = NoTemplatesGuard::new();
        let mut protos = BTreeMap::new();
        protos.insert(
            "DNS".to_string(),
            ProtocolDef::new("DNS", 96).with_fields(vec![
                FieldDef::new("id", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("flags", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("qdcount", 32, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("ancount", 48, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("nscount", 64, 16, FieldType::Uint).with_endian(Endian::Big),
                FieldDef::new("arcount", 80, 16, FieldType::Uint).with_endian(Endian::Big),
            ]),
        );
        let target = protos.get("DNS").unwrap().clone();
        let output = generate_pcap(&target, &protos).unwrap();

        assert_eq!(output.stack, vec!["Ethernet", "IPv4", "UDP", "DNS"]);
        // 14 + 20 + 8 + 12 = 54
        assert_eq!(output.packet_bytes.len(), 54);

        // Ethernet ether_type = 0x0800
        assert_eq!(&output.packet_bytes[12..14], &[0x08, 0x00]);
        // IPv4 protocol = 17 (UDP)
        assert_eq!(output.packet_bytes[14 + 9], 17);
        // IPv4 checksum valid
        assert_eq!(ipv4_checksum(&output.packet_bytes[14..34]), 0);
        // UDP dst_port = 53
        assert_eq!(&output.packet_bytes[36..38], &[0, 53]);
        // UDP length = 20
        let udp_len = u16::from_be_bytes([output.packet_bytes[38], output.packet_bytes[39]]);
        assert_eq!(udp_len, 20);
    }

    #[test]
    fn test_generate_pcap_http_over_tcp() {
        let _guard = NoTemplatesGuard::new();
        let mut protos = BTreeMap::new();
        protos.insert("HTTP".to_string(), ProtocolDef::new("HTTP", 0));
        let http_def = protos.get("HTTP").unwrap().clone();
        let output = generate_pcap(&http_def, &protos).unwrap();

        assert_eq!(output.stack, vec!["Ethernet", "IPv4", "TCP", "HTTP"]);
        // 14 + 20 + 20 + 0 = 54
        assert_eq!(output.packet_bytes.len(), 54);
        // IPv4 protocol = 6 (TCP)
        assert_eq!(output.packet_bytes[14 + 9], 6);
        // TCP dst_port = 80
        assert_eq!(&output.packet_bytes[36..38], &[0, 80]);
    }

    #[test]
    fn test_generate_pcap_nvgre_over_gre() {
        let _guard = NoTemplatesGuard::new();
        let protos = BTreeMap::new();
        // Use the embedded NVGRE def (64 bits = 8 bytes, includes GRE+key header)
        let nvgre_def = embedded_proto("NVGRE").unwrap();
        let output = generate_pcap(&nvgre_def, &protos).unwrap();

        assert_eq!(output.stack, vec!["Ethernet", "IPv4", "GRE", "NVGRE"]);
        // 14 (Eth) + 20 (IPv4) + 4 (GRE) + 8 (NVGRE) = 46
        assert_eq!(output.packet_bytes.len(), 46);
        // IPv4 protocol = 47 (GRE)
        assert_eq!(output.packet_bytes[14 + 9], 47);
    }

    // ── Verify all STACK_ROUTES resolve ──

    #[test]
    fn test_all_stack_routes_resolve() {
        let protos = BTreeMap::new();
        for &(child, _, _, _) in STACK_ROUTES {
            let result = build_stack_no_discovery(child, &protos);
            assert!(
                result.is_ok(),
                "STACK_ROUTE for '{}' failed to build: {:?}",
                child,
                result.err()
            );
            let sr = result.unwrap();
            assert!(
                is_root(&sr.layers[0].proto_name),
                "'{}' stack should start with a link-layer root, got '{}'",
                child,
                sr.layers[0].proto_name
            );
            assert_eq!(
                sr.layers.last().unwrap().proto_name, child,
                "'{}' stack should end with the target",
                child
            );
        }
    }

    // ── Phase 1 new routes ──

    #[test]
    fn test_build_stack_wol() {
        assert_stack("WOL", &["UpperPDU", "WOL"], 0, "_always", 0);
    }

    #[test]
    fn test_build_stack_carp() {
        assert_stack("CARP", &["Ethernet", "IPv4", "CARP"], 1, "protocol", 112);
    }

    #[test]
    fn test_build_stack_rsvp() {
        assert_stack("RSVP", &["Ethernet", "IPv4", "RSVP"], 1, "protocol", 46);
    }

    #[test]
    fn test_build_stack_bacnet() {
        assert_stack("BACnet", &["Ethernet", "IPv4", "UDP", "BACnet"], 2, "dst_port", 47808);
    }

    #[test]
    fn test_build_stack_iscsi() {
        assert_stack("iSCSI", &["Ethernet", "IPv4", "TCP", "iSCSI"], 2, "dst_port", 3260);
    }

    #[test]
    fn test_build_stack_nfs() {
        assert_stack("NFS", &["UpperPDU", "NFS"], 0, "_always", 0);
    }

    #[test]
    fn test_build_stack_nvme() {
        assert_stack("NVMe", &["Ethernet", "IPv4", "TCP", "NVMe"], 2, "dst_port", 4420);
    }

    // ── Phase 2 sub-dispatch routes ──

    #[test]
    fn test_build_stack_igmpv3_query() {
        assert_stack(
            "IGMPv3_Query",
            &["Ethernet", "IPv4", "IGMP", "IGMPv3_Query"],
            2,
            "type",
            0x11,
        );
    }

    #[test]
    fn test_build_stack_ipv6_nd() {
        assert_stack(
            "IPv6_ND",
            &["Ethernet", "IPv6", "ICMPv6", "IPv6_ND"],
            2,
            "type",
            135,
        );
    }

    #[test]
    fn test_build_stack_eap() {
        assert_stack("EAP", &["Ethernet", "EAPOL", "EAP"], 1, "_always", 0);
    }

    #[test]
    fn test_build_stack_cip() {
        assert_stack(
            "CIP",
            &["UpperPDU", "CIP"],
            0,
            "_always",
            0,
        );
    }

    // ── Phase 4 Bluetooth routes ──

    #[test]
    fn test_build_stack_hci_cmd() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("HCI_CMD", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "HCI");
        assert_eq!(result.layers[1].proto_name, "HCI_CMD");
        assert_eq!(result.link_type, 187);
    }

    #[test]
    fn test_build_stack_bt_att() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("BT_ATT", &protos).unwrap();
        assert_eq!(result.layers.len(), 4);
        assert_eq!(result.layers[0].proto_name, "HCI");
        assert_eq!(result.layers[1].proto_name, "HCI_ACL");
        assert_eq!(result.layers[2].proto_name, "L2CAP");
        assert_eq!(result.layers[3].proto_name, "BT_ATT");
        assert_eq!(result.link_type, 187);
    }

    #[test]
    fn test_build_stack_bt_rfcomm_upper_pdu() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("BT_RFCOMM", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "UpperPDU");
        assert_eq!(result.layers[1].proto_name, "BT_RFCOMM");
        assert_eq!(result.link_type, 252);
    }

    // ── Phase 5 InfiniBand routes ──

    #[test]
    fn test_build_stack_ib_deth() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("IB_DETH", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "UpperPDU");
        assert_eq!(result.layers[1].proto_name, "IB_LRH");
        assert_eq!(result.layers[2].proto_name, "IB_BTH");
        assert_eq!(result.layers[3].proto_name, "IB_DETH");
        assert_eq!(result.link_type, 252);
    }

    // ── Phase 6 standalone root tests ──

    #[test]
    fn test_build_stack_can_root() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("CAN", &protos).unwrap();
        assert_eq!(result.layers.len(), 1);
        assert_eq!(result.layers[0].proto_name, "CAN");
        assert_eq!(result.link_type, 227);
    }

    #[test]
    fn test_build_stack_zigbee_aps() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("Zigbee_APS", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "IEEE802154");
        assert_eq!(result.layers[1].proto_name, "Zigbee_NWK");
        assert_eq!(result.layers[2].proto_name, "Zigbee_APS");
        assert_eq!(result.link_type, 195);
    }

    #[test]
    fn test_build_stack_nlattr() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("NLAttr", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "Netlink");
        assert_eq!(result.layers[1].proto_name, "GenNetlink");
        assert_eq!(result.layers[2].proto_name, "NLAttr");
        assert_eq!(result.link_type, 253);
    }

    // ── Phase 7 802.2 LLC/SNAP routes ──

    #[test]
    fn test_build_stack_stp() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("STP", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "Ethernet_802_3");
        assert_eq!(result.layers[1].proto_name, "LLC");
        assert_eq!(result.layers[2].proto_name, "STP");
        assert_eq!(result.link_type, 1); // DLT_EN10MB
    }

    #[test]
    fn test_build_stack_cdp() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("CDP", &protos).unwrap();
        assert_eq!(result.layers.len(), 4);
        assert_eq!(result.layers[0].proto_name, "Ethernet_802_3");
        assert_eq!(result.layers[1].proto_name, "LLC");
        assert_eq!(result.layers[2].proto_name, "SNAP");
        assert_eq!(result.layers[3].proto_name, "CDP");
    }

    // ── Phase 8 UpperPDU routes ──

    #[test]
    fn test_build_stack_scsi_upper_pdu() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("SCSI", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "UpperPDU");
        assert_eq!(result.layers[1].proto_name, "SCSI");
        assert_eq!(result.link_type, 252);
    }

    // ── Integration tests: PCAP generation for new DLTs ──

    #[test]
    fn test_generate_pcap_bt_att() {
        let _guard = NoTemplatesGuard::new();
        let protos = BTreeMap::new();
        let target = ProtocolDef::new("BT_ATT", 8).with_fields(vec![
            FieldDef::new("opcode", 0, 8, FieldType::Uint),
        ]);
        let output = generate_pcap(&target, &protos).unwrap();
        assert_eq!(output.stack, vec!["HCI", "HCI_ACL", "L2CAP", "BT_ATT"]);
        assert_eq!(output.link_type, 187);
        // Verify DLT in PCAP header (bytes 20-23, little-endian)
        let dlt = u32::from_le_bytes([
            output.pcap_bytes[20],
            output.pcap_bytes[21],
            output.pcap_bytes[22],
            output.pcap_bytes[23],
        ]);
        assert_eq!(dlt, 187);
    }

    #[test]
    fn test_generate_pcap_stp() {
        let _guard = NoTemplatesGuard::new();
        let protos = BTreeMap::new();
        let target = ProtocolDef::new("STP", 0);
        let output = generate_pcap(&target, &protos).unwrap();
        assert_eq!(
            output.stack,
            vec!["Ethernet_802_3", "LLC", "STP"]
        );
        assert_eq!(output.link_type, 1);
        // 802.3 length field (bytes 12-13) should be payload length
        let length = u16::from_be_bytes([
            output.packet_bytes[12],
            output.packet_bytes[13],
        ]);
        let expected_payload = output.packet_bytes.len() as u16 - 14;
        assert_eq!(length, expected_payload);
    }

    #[test]
    fn test_generate_pcap_upper_pdu() {
        let protos = BTreeMap::new();
        let target = ProtocolDef::new("SCSI", 0);
        let output = generate_pcap(&target, &protos).unwrap();
        assert_eq!(output.stack, vec!["UpperPDU", "SCSI"]);
        assert_eq!(output.link_type, 252);
        // Verify TLV preamble: tag=0x000C (EXP_PDU_TAG_DISSECTOR_NAME), len=4 ("scsi"), then 4 zero bytes
        assert_eq!(output.packet_bytes[0], 0x00);
        assert_eq!(output.packet_bytes[1], 0x0C);
        assert_eq!(output.packet_bytes[2], 0x00);
        assert_eq!(output.packet_bytes[3], 0x04); // "scsi" = 4 bytes
        assert_eq!(&output.packet_bytes[4..8], b"scsi");
        assert_eq!(&output.packet_bytes[8..12], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_link_type_for_roots() {
        for &(name, expected_dlt) in LINK_ROOTS {
            let protos = BTreeMap::new();
            let result = build_stack_no_discovery(name, &protos).unwrap();
            assert_eq!(
                result.link_type, expected_dlt,
                "DLT mismatch for root '{}'",
                name
            );
        }
    }

    #[test]
    fn test_upper_pdu_preamble_format() {
        let buf = upper_pdu_preamble("scsi");
        // tag=0x000C (EXP_PDU_TAG_DISSECTOR_NAME), len=4, "scsi", end marker
        assert_eq!(&buf[0..2], &[0x00, 0x0C]);
        assert_eq!(&buf[2..4], &[0x00, 0x04]);
        assert_eq!(&buf[4..8], b"scsi");
        assert_eq!(&buf[8..12], &[0, 0, 0, 0]);
        assert_eq!(buf.len(), 12);

        // Test padding: "stt" (3 bytes) should be padded to 4
        let buf2 = upper_pdu_preamble("stt");
        assert_eq!(&buf2[0..2], &[0x00, 0x0C]);
        assert_eq!(&buf2[2..4], &[0x00, 0x03]); // actual len=3
        assert_eq!(&buf2[4..7], b"stt");
        assert_eq!(buf2[7], 0); // padding byte
        assert_eq!(&buf2[8..12], &[0, 0, 0, 0]); // end marker
        assert_eq!(buf2.len(), 12);

        // Test "btsdp" (5 bytes) → padded to 8
        let buf3 = upper_pdu_preamble("btsdp");
        assert_eq!(&buf3[2..4], &[0x00, 0x05]); // actual len=5
        assert_eq!(&buf3[4..9], b"btsdp");
        assert_eq!(&buf3[9..12], &[0, 0, 0]); // 3 padding bytes
        assert_eq!(&buf3[12..16], &[0, 0, 0, 0]); // end marker
        assert_eq!(buf3.len(), 16);
    }

    #[test]
    fn test_is_root() {
        assert!(is_root("Ethernet"));
        assert!(is_root("HCI"));
        assert!(!is_root("IB_LRH")); // now routed via UpperPDU
        assert!(is_root("UpperPDU"));
        assert!(is_root("CAN"));
        assert!(!is_root("IPv4"));
        assert!(!is_root("TCP"));
        assert!(!is_root("DNS"));
    }

    #[test]
    fn test_all_link_roots_have_embedded_defs() {
        for &(name, _) in LINK_ROOTS {
            assert!(
                embedded_proto(name).is_some(),
                "LINK_ROOT '{}' has no embedded_proto",
                name
            );
        }
    }

    // ── Falcon Transport Protocol routes ──

    #[test]
    fn test_build_stack_falcon_pull_request() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("Falcon-Pull-Request", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "Ethernet");
        assert_eq!(result.layers[1].proto_name, "IPv4");
        assert_eq!(result.layers[2].proto_name, "UDP");
        assert_eq!(result.layers[3].proto_name, "Falcon-Version-OV");
        assert_eq!(result.layers[4].proto_name, "Falcon-Packet-Type-OV");
        assert_eq!(result.layers[5].proto_name, "Falcon-Pull-Request");
        assert_eq!(result.link_type, 1);
    }

    #[test]
    fn test_build_stack_falcon_base_ack() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("Falcon-Base-ACK", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "Ethernet");
        assert_eq!(result.layers[1].proto_name, "IPv4");
        assert_eq!(result.layers[2].proto_name, "UDP");
        assert_eq!(result.layers[3].proto_name, "Falcon-Version-OV");
        assert_eq!(result.layers[4].proto_name, "Falcon-Packet-Type-OV");
        assert_eq!(result.layers[5].proto_name, "Falcon-Base-ACK");
        assert_eq!(result.link_type, 1);
    }

    #[test]
    fn test_build_stack_falcon_nack() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("Falcon-NACK", &protos).unwrap();
        assert_eq!(result.layers[3].proto_name, "Falcon-Version-OV");
        assert_eq!(result.layers[4].proto_name, "Falcon-Packet-Type-OV");
        assert_eq!(result.layers[5].proto_name, "Falcon-NACK");
    }

    // ── NVMe/TCP routes ──

    #[test]
    fn test_build_stack_nvme_tcp_r2t() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("NVMe_TCP_R2T", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "Ethernet");
        assert_eq!(result.layers[1].proto_name, "IPv4");
        assert_eq!(result.layers[2].proto_name, "TCP");
        assert_eq!(result.layers[3].proto_name, "NVMe_TCP");
        assert_eq!(result.layers[4].proto_name, "NVMe_TCP_R2T");
        assert_eq!(result.link_type, 1);
    }

    // ── RoCEv2 / CNP routes ──

    #[test]
    fn test_build_stack_rocev2() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("RoCEv2", &protos).unwrap();
        assert_eq!(result.layers[0].proto_name, "Ethernet");
        assert_eq!(result.layers[1].proto_name, "IPv4");
        assert_eq!(result.layers[2].proto_name, "UDP");
        assert_eq!(result.layers[3].proto_name, "RoCEv2");
        assert_eq!(result.link_type, 1);
    }

    #[test]
    fn test_build_stack_cnp() {
        let protos = BTreeMap::new();
        let result = build_stack_no_discovery("CNP", &protos).unwrap();
        assert_eq!(result.layers[3].proto_name, "RoCEv2");
        assert_eq!(result.layers[4].proto_name, "CNP");
    }

    #[test]
    fn test_rocev2_embedded_def() {
        let rocev2 = embedded_proto("RoCEv2").unwrap();
        assert_eq!(rocev2.min_header_bits, 96);
        assert!(rocev2.fields.iter().any(|f| f.name == "opcode"));
    }

    #[test]
    fn test_nvme_tcp_embedded_def() {
        let nvme_tcp = embedded_proto("NVMe_TCP").unwrap();
        assert_eq!(nvme_tcp.min_header_bits, 64);
        assert!(nvme_tcp.fields.iter().any(|f| f.name == "type"));
        assert!(nvme_tcp.fields.iter().any(|f| f.name == "plen"));
    }

    #[test]
    fn test_falcon_overlay_embedded_defs() {
        let version_ov = embedded_proto("Falcon-Version-OV").unwrap();
        assert_eq!(version_ov.min_header_bits, 8);
        assert!(version_ov.fields.iter().any(|f| f.name == "version"));

        let pkt_type_ov = embedded_proto("Falcon-Packet-Type-OV").unwrap();
        assert_eq!(pkt_type_ov.min_header_bits, 64);
        assert!(pkt_type_ov.fields.iter().any(|f| f.name == "packet_type"));
    }
