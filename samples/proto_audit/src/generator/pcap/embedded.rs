//! Embedded minimal protocol definitions for PCAP stack construction.

use crate::ir::{
    ElementSize, Endian, FieldDef, FieldType, ProtocolDef, RepeatGroup, RepeatTerm,
};

/// Embedded minimal protocol definitions for stack construction.
pub fn embedded_proto(name: &str) -> Option<ProtocolDef> {
    match name {
        "Ethernet" => Some(
            ProtocolDef::new("Ethernet", 112)
                .with_fields(vec![
                    FieldDef::new("dst_mac", 0, 48, FieldType::MacAddr).with_endian(Endian::Big),
                    FieldDef::new("src_mac", 48, 48, FieldType::MacAddr).with_endian(Endian::Big),
                    FieldDef::new("ether_type", 96, 16, FieldType::Enum).with_endian(Endian::Big),
                ])
                .with_dispatch_field("ether_type"),
        ),
        "IPv4" => Some(
            ProtocolDef::new("IPv4", 160)
                .with_variable_length()
                .with_fields(vec![
                    FieldDef::new("version", 0, 4, FieldType::Uint).with_default_value("4"),
                    FieldDef::new("ihl", 4, 4, FieldType::Uint)
                        .with_length(Some(4))
                        .with_default_value("5"),
                    FieldDef::new("tos", 8, 8, FieldType::Uint),
                    FieldDef::new("total_length", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("identification", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("flags", 48, 3, FieldType::Flags),
                    FieldDef::new("fragment_offset", 51, 13, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("ttl", 64, 8, FieldType::Uint).with_default_value("64"),
                    FieldDef::new("protocol", 72, 8, FieldType::Enum).with_dispatch(),
                    FieldDef::new("checksum", 80, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("src_addr", 96, 32, FieldType::Ipv4Addr)
                        .with_endian(Endian::Big),
                    FieldDef::new("dst_addr", 128, 32, FieldType::Ipv4Addr)
                        .with_endian(Endian::Big),
                ])
                .with_dispatch_field("protocol"),
        ),
        "IPv6" => Some(
            ProtocolDef::new("IPv6", 320)
                .with_fields(vec![
                    FieldDef::new("version", 0, 4, FieldType::Uint).with_default_value("6"),
                    FieldDef::new("traffic_class", 4, 8, FieldType::Uint),
                    FieldDef::new("flow_label", 12, 20, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("payload_length", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("next_header", 48, 8, FieldType::Enum).with_dispatch(),
                    FieldDef::new("hop_limit", 56, 8, FieldType::Uint).with_default_value("64"),
                    FieldDef::new("src_addr", 64, 128, FieldType::Ipv6Addr)
                        .with_endian(Endian::Big),
                    FieldDef::new("dst_addr", 192, 128, FieldType::Ipv6Addr)
                        .with_endian(Endian::Big),
                ])
                .with_dispatch_field("next_header"),
        ),
        "UDP" => Some(
            ProtocolDef::new("UDP", 64)
                .with_fields(vec![
                    FieldDef::new("src_port", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("dst_port", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("length", 32, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("checksum", 48, 16, FieldType::Uint).with_endian(Endian::Big),
                ])
                .with_dispatch_field("dst_port"),
        ),
        "TCP" => Some(
            ProtocolDef::new("TCP", 160)
                .with_variable_length()
                .with_fields(vec![
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
                ])
                .with_dispatch_field("dst_port"),
        ),
        "GRE" => Some(
            ProtocolDef::new("GRE", 32)
                .with_variable_length()
                .with_fields(vec![
                    FieldDef::new("flags_version", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("protocol_type", 16, 16, FieldType::Enum)
                        .with_endian(Endian::Big),
                ])
                .with_dispatch_field("protocol_type"),
        ),
        // ── IGMP (dispatch on type for IGMPv3 subtypes) ──
        "IGMP" => Some(
            ProtocolDef::new("IGMP", 64)
                .with_fields(vec![
                    FieldDef::new("type", 0, 8, FieldType::Enum).with_dispatch(),
                    FieldDef::new("max_resp", 8, 8, FieldType::Uint),
                    FieldDef::new("checksum", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("group_addr", 32, 32, FieldType::Ipv4Addr)
                        .with_endian(Endian::Big),
                ])
                .with_dispatch_field("type"),
        ),
        // ── ICMPv6 (dispatch on type for ND, MLD subtypes) ──
        "ICMPv6" => Some(
            ProtocolDef::new("ICMPv6", 32)
                .with_fields(vec![
                    FieldDef::new("type", 0, 8, FieldType::Enum).with_dispatch(),
                    FieldDef::new("code", 8, 8, FieldType::Uint),
                    FieldDef::new("checksum", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                ])
                .with_dispatch_field("type"),
        ),
        // ── SCTP (96 bits, child of IPv4 protocol=132) ──
        "SCTP" => Some(
            ProtocolDef::new("SCTP", 96)
                .with_fields(vec![
                    FieldDef::new("src_port", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("dst_port", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("vtag", 32, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("checksum", 64, 32, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── EAPOL (32 bits, child of Ethernet ether_type=0x888E) ──
        "EAPOL" => Some(
            ProtocolDef::new("EAPOL", 32)
                .with_fields(vec![
                    FieldDef::new("version", 0, 8, FieldType::Uint).with_default_value("2"),
                    FieldDef::new("type", 8, 8, FieldType::Uint),
                    FieldDef::new("length", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── ENIP (192 bits, child of TCP dst_port=44818) ──
        "ENIP" => Some(
            ProtocolDef::new("ENIP", 192)
                .with_fields(vec![
                    FieldDef::new("command", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("length", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("session_handle", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("status", 64, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("sender_context", 96, 64, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("options", 160, 32, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── Bluetooth: HCI H4 (8 bits, root DLT=187) ──
        "HCI" => Some(
            ProtocolDef::new("HCI", 8)
                .with_fields(vec![
                    FieldDef::new("type", 0, 8, FieldType::Enum).with_dispatch(),
                ])
                .with_dispatch_field("type"),
        ),
        // ── HCI ACL (32 bits, child of HCI type=0x02) ──
        "HCI_ACL" => Some(
            ProtocolDef::new("HCI_ACL", 32)
                .with_fields(vec![
                    FieldDef::new("handle_flags", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("dlen", 16, 16, FieldType::Uint).with_endian(Endian::Little),
                ]),
        ),
        // ── L2CAP (32 bits, child of HCI_ACL, dispatch on cid) ──
        "L2CAP" => Some(
            ProtocolDef::new("L2CAP", 32)
                .with_fields(vec![
                    FieldDef::new("len", 0, 16, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("cid", 16, 16, FieldType::Enum).with_endian(Endian::Little)
                        .with_dispatch(),
                ])
                .with_dispatch_field("cid"),
        ),
        // ── InfiniBand: LRH (64 bits, root DLT=247, dispatch on lnh) ──
        "IB_LRH" => Some(
            ProtocolDef::new("IB_LRH", 64)
                .with_fields(vec![
                    FieldDef::new("vl", 0, 4, FieldType::Uint),
                    FieldDef::new("lver", 4, 4, FieldType::Uint),
                    FieldDef::new("sl", 8, 4, FieldType::Uint),
                    FieldDef::new("reserved", 12, 2, FieldType::Pad),
                    FieldDef::new("lnh", 14, 2, FieldType::Enum).with_dispatch(),
                    FieldDef::new("dlid", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("pktlen_raw", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("slid", 48, 16, FieldType::Uint).with_endian(Endian::Big),
                ])
                .with_dispatch_field("lnh"),
        ),
        // ── InfiniBand: GRH (320 bits, similar to IPv6) ──
        "IB_GRH" => Some(
            ProtocolDef::new("IB_GRH", 320)
                .with_fields(vec![
                    FieldDef::new("ip_version", 0, 4, FieldType::Uint).with_default_value("6"),
                    FieldDef::new("traffic_class", 4, 8, FieldType::Uint),
                    FieldDef::new("flow_label", 12, 20, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("payload_length", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("next_header", 48, 8, FieldType::Uint),
                    FieldDef::new("hop_limit", 56, 8, FieldType::Uint).with_default_value("64"),
                    FieldDef::new("sgid", 64, 128, FieldType::Ipv6Addr)
                        .with_endian(Endian::Big),
                    FieldDef::new("dgid", 192, 128, FieldType::Ipv6Addr)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── InfiniBand: BTH (96 bits, dispatch on opcode) ──
        "IB_BTH" => Some(
            ProtocolDef::new("IB_BTH", 96)
                .with_fields(vec![
                    FieldDef::new("opcode", 0, 8, FieldType::Enum).with_dispatch(),
                    FieldDef::new("se_m_flags", 8, 8, FieldType::Uint),
                    FieldDef::new("pkey", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("dest_qp", 32, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("ack_psn", 64, 32, FieldType::Uint).with_endian(Endian::Big),
                ])
                .with_dispatch_field("opcode"),
        ),
        // ── CAN (128 bits, root DLT=227) ──
        "CAN" => Some(
            ProtocolDef::new("CAN", 128)
                .with_fields(vec![
                    FieldDef::new("can_id", 0, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("len", 32, 8, FieldType::Uint),
                    FieldDef::new("pad", 40, 8, FieldType::Pad),
                    FieldDef::new("res", 48, 16, FieldType::Pad),
                    FieldDef::new("data", 64, 64, FieldType::Bytes),
                ]),
        ),
        // ── CAN FD (576 bits, root DLT=227) ──
        "CAN_FD" => Some(
            ProtocolDef::new("CAN_FD", 576)
                .with_fields(vec![
                    FieldDef::new("can_id", 0, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("len", 32, 8, FieldType::Uint),
                    FieldDef::new("flags", 40, 8, FieldType::Uint),
                    FieldDef::new("res", 48, 16, FieldType::Pad),
                    FieldDef::new("data", 64, 512, FieldType::Bytes),
                ]),
        ),
        // ── CAN XL (128 bits min, root DLT=227) ──
        "CAN_XL" => Some(
            ProtocolDef::new("CAN_XL", 128)
                .with_fields(vec![
                    FieldDef::new("priority", 0, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("flags", 32, 8, FieldType::Uint),
                    FieldDef::new("sdu_type", 40, 8, FieldType::Uint),
                    FieldDef::new("len", 48, 16, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("af", 64, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("reserved", 96, 32, FieldType::Pad),
                ]),
        ),
        // ── IEEE 802.11 (192 bits, root DLT=105) ──
        "IEEE802.11" => Some(
            ProtocolDef::new("IEEE802.11", 192)
                .with_fields(vec![
                    FieldDef::new("frame_control", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("duration", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("addr1", 32, 48, FieldType::MacAddr).with_endian(Endian::Big),
                    FieldDef::new("addr2", 80, 48, FieldType::MacAddr).with_endian(Endian::Big),
                    FieldDef::new("addr3", 128, 48, FieldType::MacAddr).with_endian(Endian::Big),
                    FieldDef::new("seq_ctrl", 176, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                ]),
        ),
        // ── IEEE 802.15.4 (24 bits min, root DLT=195) ──
        "IEEE802154" => Some(
            ProtocolDef::new("IEEE802154", 24)
                .with_fields(vec![
                    FieldDef::new("frame_control", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("seq_num", 16, 8, FieldType::Uint),
                ]),
        ),
        // ── Linux SLL (128 bits, root DLT=113) ──
        "SLL" => Some(
            ProtocolDef::new("SLL", 128)
                .with_fields(vec![
                    FieldDef::new("pkttype", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("hatype", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("halen", 32, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("addr", 48, 64, FieldType::Bytes),
                    FieldDef::new("protocol", 112, 16, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── Linux SLL2 (160 bits, root DLT=276) ──
        "SLL2" => Some(
            ProtocolDef::new("SLL2", 160)
                .with_fields(vec![
                    FieldDef::new("protocol", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("reserved", 16, 16, FieldType::Pad),
                    FieldDef::new("ifindex", 32, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("hatype", 64, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("pkttype", 80, 8, FieldType::Uint),
                    FieldDef::new("halen", 88, 8, FieldType::Uint),
                    FieldDef::new("addr", 96, 64, FieldType::Bytes),
                ]),
        ),
        // ── Netlink (160 bits = 20 bytes, root DLT=253) ──
        // DLT_NETLINK requires a 4-byte pseudo-header: family(u16 LE) + pad(u16)
        // followed by the 16-byte nlmsghdr.
        // NOTE: pack_field always uses BE byte order, so LE values must be
        // pre-swapped: nlmsg_len=16 LE → bytes 10 00 00 00 → BE 0x10000000.
        "Netlink" => Some(
            ProtocolDef::new("Netlink", 160)
                .with_fields(vec![
                    // Pseudo-header: Netlink family (0 = NETLINK_ROUTE)
                    FieldDef::new("nl_family", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("nl_pad", 16, 16, FieldType::Pad),
                    // nlmsghdr starts at byte 4
                    // nlmsg_len=16 in LE = 0x10000000 in BE
                    FieldDef::new("nlmsg_len", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Little)
                        .with_default_value("268435456"),
                    // type=3 (NLMSG_DONE) in LE = 0x0300 in BE
                    FieldDef::new("type", 64, 16, FieldType::Uint)
                        .with_endian(Endian::Little)
                        .with_default_value("768"), // 3 LE = 0x0300 BE
                    FieldDef::new("flags", 80, 16, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("seq", 96, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("pid", 128, 32, FieldType::Uint).with_endian(Endian::Little),
                ]),
        ),
        // ── GenNetlink (32 bits, child of Netlink) ──
        "GenNetlink" => Some(
            ProtocolDef::new("GenNetlink", 32)
                .with_fields(vec![
                    FieldDef::new("cmd", 0, 8, FieldType::Uint),
                    FieldDef::new("version", 8, 8, FieldType::Uint).with_default_value("1"),
                    FieldDef::new("reserved", 16, 16, FieldType::Pad),
                ]),
        ),
        // ── PPP (32 bits, root DLT=9) ──
        "PPP" => Some(
            ProtocolDef::new("PPP", 32)
                .with_fields(vec![
                    FieldDef::new("address", 0, 8, FieldType::Uint).with_default_value("255"),
                    FieldDef::new("control", 8, 8, FieldType::Uint).with_default_value("3"),
                    FieldDef::new("protocol", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── ATM AAL5 (64 bits min, root DLT=11) ──
        "ATM" => Some(
            ProtocolDef::new("ATM", 64)
                .with_fields(vec![
                    FieldDef::new("llc_dsap", 0, 8, FieldType::Uint)
                        .with_default_value("170"),
                    FieldDef::new("llc_ssap", 8, 8, FieldType::Uint)
                        .with_default_value("170"),
                    FieldDef::new("llc_control", 16, 8, FieldType::Uint)
                        .with_default_value("3"),
                    FieldDef::new("snap_oui", 24, 24, FieldType::Uint),
                    FieldDef::new("snap_type", 48, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── Fibre Channel (192 bits, root DLT=224) ──
        "FC" => Some(
            ProtocolDef::new("FC", 192)
                .with_fields(vec![
                    FieldDef::new("r_ctl", 0, 8, FieldType::Uint),
                    FieldDef::new("d_id", 8, 24, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("cs_ctl", 32, 8, FieldType::Uint),
                    FieldDef::new("s_id", 40, 24, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("type", 64, 8, FieldType::Uint),
                    FieldDef::new("f_ctl", 72, 24, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("seq_id", 96, 8, FieldType::Uint),
                    FieldDef::new("df_ctl", 104, 8, FieldType::Uint),
                    FieldDef::new("seq_cnt", 112, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("ox_id", 128, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("rx_id", 144, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("parameter", 160, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── ERF (128 bits, root DLT=197) ──
        "ERF" => Some(
            ProtocolDef::new("ERF", 128)
                .with_fields(vec![
                    FieldDef::new("timestamp", 0, 64, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("type", 64, 8, FieldType::Uint),
                    FieldDef::new("flags", 72, 8, FieldType::Uint),
                    FieldDef::new("rlen", 80, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("color", 96, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("wlen", 112, 16, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── MPEG-TS (1504 bits = 188 bytes, root DLT=243) ──
        "MPEG_TS" => Some(
            ProtocolDef::new("MPEG_TS", 1504)
                .with_fields(vec![
                    FieldDef::new("sync", 0, 8, FieldType::Uint).with_default_value("71"), // 0x47
                    FieldDef::new("pid_raw", 8, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("flags_cc", 24, 8, FieldType::Uint)
                        .with_default_value("16"), // no adaptation, payload only (0x10)
                ]),
        ),
        // ── Zigbee NWK (64 bits, child of IEEE802154) ──
        "Zigbee_NWK" => Some(
            ProtocolDef::new("Zigbee_NWK", 64)
                .with_fields(vec![
                    FieldDef::new("frame_control", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("dst_addr", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("src_addr", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("radius", 48, 8, FieldType::Uint).with_default_value("1"),
                    FieldDef::new("seq_num", 56, 8, FieldType::Uint),
                ]),
        ),
        // ── Ethernet 802.3 (112 bits, same as Ethernet but with length field) ──
        "Ethernet_802_3" => Some(
            ProtocolDef::new("Ethernet_802_3", 112)
                .with_fields(vec![
                    FieldDef::new("dst_mac", 0, 48, FieldType::MacAddr).with_endian(Endian::Big),
                    FieldDef::new("src_mac", 48, 48, FieldType::MacAddr).with_endian(Endian::Big),
                    FieldDef::new("length", 96, 16, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── LLC (24 bits, child of Ethernet_802_3, dispatch on dsap) ──
        "LLC" => Some(
            ProtocolDef::new("LLC", 24)
                .with_fields(vec![
                    FieldDef::new("dsap", 0, 8, FieldType::Enum).with_dispatch(),
                    FieldDef::new("ssap", 8, 8, FieldType::Uint),
                    FieldDef::new("control", 16, 8, FieldType::Uint).with_default_value("3"),
                ])
                .with_dispatch_field("dsap"),
        ),
        // ── SNAP (40 bits, child of LLC dsap=0xAA, dispatch on protocol_id) ──
        "SNAP" => Some(
            ProtocolDef::new("SNAP", 40)
                .with_fields(vec![
                    FieldDef::new("oui", 0, 24, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("protocol_id", 24, 16, FieldType::Enum)
                        .with_endian(Endian::Big)
                        .with_dispatch(),
                ])
                .with_dispatch_field("protocol_id"),
        ),
        // ── LLDP (mandatory TLV: chassis ID type=1, length=7, subtype=4, 4-byte value) ──
        "LLDP" => Some(
            ProtocolDef::new("LLDP", 72)
                .with_fields(vec![
                    // TLV type=1 (Chassis ID), length=5
                    FieldDef::new("tlv_type_len", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("514"), // (1 << 9) | 5 = 0x0205
                    FieldDef::new("chassis_subtype", 16, 8, FieldType::Uint)
                        .with_default_value("4"), // MAC address subtype
                    FieldDef::new("chassis_id", 24, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("33554433"), // 02:00:00:01
                    // End of LLDPDU TLV (type=0, length=0)
                    FieldDef::new("end_tlv", 56, 16, FieldType::Uint),
                ]),
        ),
        // ── CFM (Connectivity Fault Management, 802.1ag) ──
        "CFM" => Some(
            ProtocolDef::new("CFM", 32)
                .with_fields(vec![
                    // MD level (3 bits) + version (5 bits)
                    FieldDef::new("md_level_version", 0, 8, FieldType::Uint)
                        .with_default_value("0"), // MD level 0, version 0
                    FieldDef::new("opcode", 8, 8, FieldType::Uint)
                        .with_default_value("1"), // CCM
                    FieldDef::new("flags", 16, 8, FieldType::Uint)
                        .with_default_value("4"), // interval=4 (1s)
                    FieldDef::new("first_tlv_offset", 24, 8, FieldType::Uint)
                        .with_default_value("70"), // standard CCM first TLV offset
                ]),
        ),
        // ── BATMAN (B.A.T.M.A.N. Advanced OGM v2, 192 bits = 24 bytes) ──
        "BATMAN" => Some(
            ProtocolDef::new("BATMAN", 192)
                .with_fields(vec![
                    FieldDef::new("packet_type", 0, 8, FieldType::Uint)
                        .with_default_value("1"), // BATADV_OGM2
                    FieldDef::new("version", 8, 8, FieldType::Uint)
                        .with_default_value("15"),
                    FieldDef::new("ttl", 16, 8, FieldType::Uint)
                        .with_default_value("50"),
                    FieldDef::new("flags", 24, 8, FieldType::Uint),
                    FieldDef::new("seqno", 32, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("orig", 64, 48, FieldType::MacAddr).with_endian(Endian::Big),
                    FieldDef::new("tvlv_len", 112, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("throughput", 128, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("reserved", 160, 32, FieldType::Pad),
                ]),
        ),
        // ── TRILL ──
        "TRILL" => Some(
            ProtocolDef::new("TRILL", 48)
                .with_fields(vec![
                    // V(2)=0, R(2)=0, M(1)=0, Op-Length(5)=0, Hop Count(6)
                    FieldDef::new("flags_hopcount", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("63"), // hop count=63
                    FieldDef::new("egress_nick", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"),
                    FieldDef::new("ingress_nick", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("2"),
                ]),
        ),
        // ── WOL (Wake-on-LAN: 6x FF sync + 16x target MAC = 102 bytes = 816 bits) ──
        // tshark "wol" dissector needs: 6 bytes 0xFF + 16 copies of same MAC.
        // With MAC=00:00:00:00:00:00, the 96 zero bytes satisfy the repeat check.
        "WOL" => Some(
            ProtocolDef::new("WOL", 816)
                .with_fields(vec![
                    FieldDef::new("sync", 0, 48, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("281474976710655"), // 0xFFFFFFFFFFFF
                ]),
        ),
        // ── PBB (Provider Backbone Bridging I-TAG, 32 bits) ──
        "PBB" => Some(
            ProtocolDef::new("PBB", 32)
                .with_fields(vec![
                    FieldDef::new("flags", 0, 8, FieldType::Uint),
                    FieldDef::new("isid", 8, 24, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"),
                ]),
        ),
        // ── MVRP (Multiple VLAN Registration Protocol, IEEE 802.1ak) ── 0x88F5
        // MRPDU: ProtocolVersion(1) + Message* + EndMark(0x0000). A Message is
        // AttributeType(1)+AttributeLength(1) + a VectorAttribute list ending in
        // an EndMark. The representative instance carries one MVRP message (VID
        // attribute) with a single VectorAttribute.
        "MVRP" => Some(
            ProtocolDef::new("MVRP", 8)
                .with_fields(vec![FieldDef::new("protocol_version", 0, 8, FieldType::Uint)])
                .with_repeat(RepeatGroup {
                    name: "message".into(),
                    start_bits: 8,
                    element: vec![
                        FieldDef::new("attribute_type", 0, 8, FieldType::Uint)
                            .with_default_value("1"), // VID
                        FieldDef::new("attribute_length", 8, 8, FieldType::Uint)
                            .with_default_value("2"), // VID = 2 bytes
                        // VectorHeader: 3b LeaveAllEvent | 13b NumberOfValues
                        FieldDef::new("vector_header", 16, 16, FieldType::Uint)
                            .with_endian(Endian::Big)
                            .with_default_value("1"), // NumberOfValues = 1
                        FieldDef::new("first_value", 32, 16, FieldType::Uint)
                            .with_endian(Endian::Big)
                            .with_default_value("100"), // starting VID
                        FieldDef::new("vector", 48, 8, FieldType::Uint), // packed events
                        // EndMark terminating the VectorAttribute list.
                        FieldDef::new("attr_end_mark", 56, 16, FieldType::Uint)
                            .with_endian(Endian::Big),
                    ],
                    element_size: ElementSize::Fixed(72),
                    terminator: RepeatTerm::EndMark {
                        size_bits: 16,
                        value: 0,
                    },
                    sample_count: 1,
                }),
        ),
        // ── MRP (Media Redundancy Protocol, IEC 62439-2) ── EtherType 0x88E3
        // tshark `pn_mrp`: MRP_Version (2B) followed by a chain of TLVs, each
        // MRP_TLVHeader{ Type(1), Length(1) } + value, ended by MRP_End
        // (Type=0, Length=0 == 0x0000). The representative instance carries one
        // MRP_Test TLV whose value fields (prio, SA, port role, ring state,
        // transition, timestamp) match pn_mrp's leaf fields.
        "MRP" => Some(
            ProtocolDef::new("MRP", 16)
                .with_fields(vec![FieldDef::new("version", 0, 16, FieldType::Uint)
                    .with_endian(Endian::Big)
                    .with_default_value("1")])
                .with_repeat(RepeatGroup {
                    name: "tlv".into(),
                    start_bits: 16,
                    element: vec![
                        FieldDef::new("type", 0, 8, FieldType::Uint)
                            .with_default_value("2"), // MRP_Test
                        FieldDef::new("length", 8, 8, FieldType::Uint)
                            .with_default_value("18"),
                        FieldDef::new("prio", 16, 16, FieldType::Uint)
                            .with_endian(Endian::Big),
                        FieldDef::new("sa", 32, 48, FieldType::MacAddr)
                            .with_endian(Endian::Big),
                        FieldDef::new("port_role", 80, 16, FieldType::Uint)
                            .with_endian(Endian::Big),
                        FieldDef::new("ring_state", 96, 16, FieldType::Uint)
                            .with_endian(Endian::Big),
                        FieldDef::new("transition", 112, 16, FieldType::Uint)
                            .with_endian(Endian::Big),
                        FieldDef::new("timestamp", 128, 32, FieldType::Uint)
                            .with_endian(Endian::Big),
                    ],
                    element_size: ElementSize::LengthField {
                        name: "length".into(),
                        multiplier: 1,
                    },
                    terminator: RepeatTerm::EndMark {
                        size_bits: 16,
                        value: 0,
                    },
                    sample_count: 1,
                }),
        ),
        // ── DHCP (BOOTP) ── RFC 2131, UDP 67/68
        // Fixed BOOTP header + magic cookie, then a DHCP options TLV list.
        // Field offsets/sizes mirror tshark's dhcp.* leaf fields; the options
        // are a repeat group ended by the End option (type 255).
        "DHCP" => Some(
            ProtocolDef::new("DHCP", 1920) // 240-byte fixed header (through cookie)
                .with_fields(vec![
                    FieldDef::new("type", 0, 8, FieldType::Uint).with_default_value("1"),
                    FieldDef::new("hw_type", 8, 8, FieldType::Uint).with_default_value("1"),
                    FieldDef::new("hw_len", 16, 8, FieldType::Uint).with_default_value("6"),
                    FieldDef::new("hops", 24, 8, FieldType::Uint),
                    FieldDef::new("id", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("305419896"), // 0x12345678
                    FieldDef::new("secs", 64, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("flags", 80, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("ip_client", 96, 32, FieldType::Ipv4Addr)
                        .with_endian(Endian::Big),
                    FieldDef::new("ip_your", 128, 32, FieldType::Ipv4Addr)
                        .with_endian(Endian::Big),
                    FieldDef::new("ip_server", 160, 32, FieldType::Ipv4Addr)
                        .with_endian(Endian::Big),
                    FieldDef::new("ip_relay", 192, 32, FieldType::Ipv4Addr)
                        .with_endian(Endian::Big),
                    FieldDef::new("mac_addr", 224, 48, FieldType::MacAddr)
                        .with_endian(Endian::Big),
                    FieldDef::new("addr_padding", 272, 80, FieldType::Pad),
                    FieldDef::new("sname", 352, 512, FieldType::Bytes), // server host name
                    FieldDef::new("file", 864, 1024, FieldType::Bytes), // boot file name
                    FieldDef::new("cookie", 1888, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1669485411"), // 0x63825363
                ])
                .with_repeat(RepeatGroup {
                    name: "option".into(),
                    start_bits: 1920,
                    element: vec![
                        FieldDef::new("option_type", 0, 8, FieldType::Uint)
                            .with_default_value("53"), // DHCP Message Type
                        FieldDef::new("option_length", 8, 8, FieldType::Uint)
                            .with_default_value("1"),
                        FieldDef::new("option_value", 16, 8, FieldType::Bytes)
                            .with_default_value("1"),
                    ],
                    element_size: ElementSize::LengthField {
                        name: "option_length".into(),
                        multiplier: 1,
                    },
                    terminator: RepeatTerm::EndMark { size_bits: 8, value: 255 },
                    sample_count: 2,
                }),
        ),
        // ── NC-SI (Network Controller Sideband Interface) ──
        "NC_SI" => Some(
            ProtocolDef::new("NC_SI", 128)
                .with_fields(vec![
                    FieldDef::new("mc_id", 0, 8, FieldType::Uint),
                    FieldDef::new("header_revision", 8, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("reserved", 16, 8, FieldType::Pad),
                    FieldDef::new("iid", 24, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("command", 32, 8, FieldType::Uint)
                        .with_default_value("1"), // Clear Initial State
                    FieldDef::new("channel_id", 40, 8, FieldType::Uint),
                    FieldDef::new("payload_length", 48, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("reserved2", 64, 32, FieldType::Pad),
                    FieldDef::new("reserved3", 96, 32, FieldType::Pad),
                ]),
        ),
        // ── LLTD (Link Layer Topology Discovery, 14 bytes min) ──
        "LLTD" => Some(
            ProtocolDef::new("LLTD", 112)
                .with_variable_length()
                .with_fields(vec![
                    FieldDef::new("version", 0, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("type_of_service", 8, 8, FieldType::Uint),
                    FieldDef::new("reserved", 16, 8, FieldType::Pad),
                    FieldDef::new("function", 24, 8, FieldType::Uint),
                    FieldDef::new("real_dst_mac", 32, 48, FieldType::MacAddr)
                        .with_endian(Endian::Big),
                    FieldDef::new("real_src_mac", 80, 48, FieldType::MacAddr)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── EDSA (Marvell EtherType DSA tag) ──
        "EDSA" => Some(
            ProtocolDef::new("EDSA", 64)
                .with_fields(vec![
                    FieldDef::new("tag_hi", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("tag_lo", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("ether_type", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("2048"), // 0x0800 = IPv4
                ]),
        ),
        // ── IEC GOOSE (minimal valid BER-encoded GOOSE PDU) ──
        "IEC_GOOSE" => Some(
            ProtocolDef::new("IEC_GOOSE", 48)
                .with_fields(vec![
                    FieldDef::new("appid", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"),
                    FieldDef::new("length", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("8"),
                    FieldDef::new("reserved1", 32, 8, FieldType::Pad),
                    FieldDef::new("reserved2", 40, 8, FieldType::Pad),
                ]),
        ),
        // ── IEC SV (Sampled Values) ──
        "IEC_SV" => Some(
            ProtocolDef::new("IEC_SV", 48)
                .with_fields(vec![
                    FieldDef::new("appid", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("16384"), // 0x4000
                    FieldDef::new("length", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("8"),
                    FieldDef::new("reserved1", 32, 8, FieldType::Pad),
                    FieldDef::new("reserved2", 40, 8, FieldType::Pad),
                ]),
        ),
        // ── CAPWAP (Control And Provisioning of Wireless APs) ──
        "CAPWAP" => Some(
            ProtocolDef::new("CAPWAP", 32)
                .with_fields(vec![
                    // Preamble: version(4)=0, type(4)=0
                    FieldDef::new("preamble", 0, 8, FieldType::Uint),
                    // HLEN(5)=2, RID(5)=0, WBID(5)=1, T(1), F(1), L(1)
                    FieldDef::new("header_flags", 8, 24, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("4194304"), // HLEN=2, WBID=1 -> 0x400000
                ]),
        ),
        // ── TZSP (TaZmen Sniffer Protocol) ──
        "TZSP" => Some(
            ProtocolDef::new("TZSP", 32)
                .with_fields(vec![
                    FieldDef::new("version", 0, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("type", 8, 8, FieldType::Uint),
                    FieldDef::new("encap", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"), // Ethernet
                ]),
        ),
        // ── SRT (Secure Reliable Transport) ──
        "SRT" => Some(
            ProtocolDef::new("SRT", 128)
                .with_fields(vec![
                    // UDT/SRT header: control bit + type + subtype
                    FieldDef::new("header", 0, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("2147483648"), // 0x80000000 = control packet
                    FieldDef::new("additional_info", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("timestamp", 64, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("dst_socket_id", 96, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── GUE (Generic UDP Encapsulation) ── RFC 8926
        "GUE" => Some(
            ProtocolDef::new("GUE", 32)
                .with_fields(vec![
                    FieldDef::new("version", 0, 2, FieldType::Uint),
                    FieldDef::new("c_bit", 2, 1, FieldType::Uint),
                    FieldDef::new("hlen", 3, 5, FieldType::Uint),
                    FieldDef::new("proto", 8, 8, FieldType::Enum)
                        .with_default_value("4"), // IPv4 inner
                    FieldDef::new("flags", 16, 16, FieldType::Flags).with_endian(Endian::Big),
                ])
                .with_dispatch_field("proto"),
        ),
        // ── STT (Stateless Transport Tunneling) ── draft-davie-stt
        "STT" => Some(
            ProtocolDef::new("STT", 144)
                .with_fields(vec![
                    FieldDef::new("version", 0, 8, FieldType::Uint),
                    FieldDef::new("flags", 8, 8, FieldType::Flags),
                    FieldDef::new("l4_offset", 16, 8, FieldType::Uint)
                        .with_default_value("14"),
                    FieldDef::new("reserved", 24, 8, FieldType::Uint),
                    FieldDef::new("max_seg_size", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("pcp_v_vlanid", 48, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("context_id", 64, 64, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("padding", 128, 16, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── BT_RFCOMM (RFCOMM frame: address + control + length + FCS) ──
        "BT_RFCOMM" => Some(
            ProtocolDef::new("BT_RFCOMM", 32)
                .with_fields(vec![
                    FieldDef::new("address", 0, 8, FieldType::Uint)
                        .with_default_value("3"), // DLCI=0, EA=1, CR=1
                    FieldDef::new("control", 8, 8, FieldType::Uint)
                        .with_default_value("63"), // SABM (0x3F)
                    FieldDef::new("length", 16, 8, FieldType::Uint)
                        .with_default_value("1"), // length=0, EA=1
                    FieldDef::new("fcs", 24, 8, FieldType::Uint)
                        .with_default_value("29"), // FCS for DLCI=0 SABM
                ]),
        ),
        // ── BT_BNEP (Bluetooth Network Encapsulation Protocol) ──
        "BT_BNEP" => Some(
            ProtocolDef::new("BT_BNEP", 16)
                .with_fields(vec![
                    // Type(7) + extension(1): type=0 (General Ethernet)
                    FieldDef::new("type_ext", 0, 8, FieldType::Uint),
                    FieldDef::new("reserved", 8, 8, FieldType::Pad),
                ]),
        ),
        // ── BT_SDP (Service Discovery Protocol) ──
        "BT_SDP" => Some(
            ProtocolDef::new("BT_SDP", 40)
                .with_fields(vec![
                    FieldDef::new("pdu_id", 0, 8, FieldType::Uint)
                        .with_default_value("1"), // SDP_ErrorResponse
                    FieldDef::new("transaction_id", 8, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("param_length", 24, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── BT_AVDTP (Audio/Video Distribution Transport Protocol) ──
        "BT_AVDTP" => Some(
            ProtocolDef::new("BT_AVDTP", 16)
                .with_fields(vec![
                    // Transaction label(4) + Packet type(2) + Message type(2)
                    FieldDef::new("header", 0, 8, FieldType::Uint)
                        .with_default_value("48"), // trans=0, single=3, command=0
                    FieldDef::new("signal_id", 8, 8, FieldType::Uint)
                        .with_default_value("1"), // AVDTP_DISCOVER
                ]),
        ),
        // ── NTLMSSP (NT LAN Manager Security Support Provider) ──
        "NTLMSSP" => Some(
            ProtocolDef::new("NTLMSSP", 96)
                .with_fields(vec![
                    // Signature: "NTLMSSP\0" = 4E544C4D53535000
                    FieldDef::new("signature_lo", 0, 32, FieldType::Uint)
                        .with_endian(Endian::Little)
                        .with_default_value("1296847950"), // "NTLM" LE = 0x4D4C544E
                    FieldDef::new("signature_hi", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Little)
                        .with_default_value("5264211"), // "SSP\0" LE = 0x00505353
                    FieldDef::new("message_type", 64, 32, FieldType::Uint)
                        .with_endian(Endian::Little)
                        .with_default_value("1"), // Negotiate
                ]),
        ),
        // ── MCTP (Management Component Transport Protocol) ──
        "MCTP" => Some(
            ProtocolDef::new("MCTP", 32)
                .with_fields(vec![
                    FieldDef::new("version", 0, 4, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("reserved", 4, 4, FieldType::Pad),
                    FieldDef::new("dest_eid", 8, 8, FieldType::Uint),
                    FieldDef::new("src_eid", 16, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("flags_seq_tag", 24, 8, FieldType::Uint)
                        .with_default_value("200"), // SOM=1, EOM=1, seq=0, TO=0, tag=8
                ]),
        ),
        // ── X25 (X.25 Packet Layer Protocol) ──
        "X25" => Some(
            ProtocolDef::new("X25", 24)
                .with_fields(vec![
                    FieldDef::new("gfi_lcg", 0, 8, FieldType::Uint)
                        .with_default_value("16"), // GFI=0001 (modulo 8), LCG=0
                    FieldDef::new("lcn", 8, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("type", 16, 8, FieldType::Uint)
                        .with_default_value("11"), // Call Request (0x0B)
                ]),
        ),
        // ── DSA (Distributed Switch Architecture tag) ──
        "DSA" => Some(
            ProtocolDef::new("DSA", 32)
                .with_fields(vec![
                    FieldDef::new("tag_hi", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("tag_lo", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── Teredo (IPv6 over UDP tunneling, RFC 4380) ──
        // Minimum: an encapsulated IPv6 header (version=6 in first nibble)
        "Teredo" => Some(
            ProtocolDef::new("Teredo", 320) // 40-byte IPv6 header
                .with_fields(vec![
                    FieldDef::new("version", 0, 4, FieldType::Uint)
                        .with_default_value("6"), // IPv6
                    FieldDef::new("traffic_class", 4, 8, FieldType::Uint),
                    FieldDef::new("flow_label", 12, 20, FieldType::Uint),
                    FieldDef::new("payload_length", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("next_header", 48, 8, FieldType::Uint)
                        .with_default_value("59"), // No Next Header
                    FieldDef::new("hop_limit", 56, 8, FieldType::Uint)
                        .with_default_value("64"),
                    // src: 2001:0000:... (Teredo prefix)
                    FieldDef::new("src_addr_hi", 64, 64, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("2306124484190404608"), // 0x20010000_00000000
                    FieldDef::new("src_addr_lo", 128, 64, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("dst_addr_hi", 192, 64, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("2306124484190404608"),
                    FieldDef::new("dst_addr_lo", 256, 64, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"),
                ]),
        ),
        // ── LWAPP (Lightweight Access Point Protocol) ──
        "LWAPP" => Some(
            ProtocolDef::new("LWAPP", 48) // 6-byte LWAPP header
                .with_fields(vec![
                    // Flags: version(2)=0, RID(3)=0, C(1)=1 (control), F(1)=0, L(1)=0
                    FieldDef::new("flags", 0, 8, FieldType::Uint)
                        .with_default_value("4"), // C bit = control message
                    FieldDef::new("fragment_id", 8, 8, FieldType::Uint),
                    FieldDef::new("length", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("status", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── MPLS_OAM (MPLS Echo / LSP Ping, RFC 4379) ──
        "MPLS_OAM" => Some(
            ProtocolDef::new("MPLS_OAM", 256) // 32-byte minimum MPLS echo
                .with_fields(vec![
                    FieldDef::new("version", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"),
                    // msg_type: 1=request, 2=reply
                    FieldDef::new("msg_type", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"), // Echo Request
                    FieldDef::new("reply_mode", 32, 8, FieldType::Uint)
                        .with_default_value("2"), // Reply via IPv4
                    FieldDef::new("return_code", 40, 8, FieldType::Uint),
                    FieldDef::new("return_subcode", 48, 8, FieldType::Uint),
                    FieldDef::new("sender_handle", 56, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("seq_number", 88, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"),
                    // Timestamps: sender (64 bits) + receiver (64 bits)
                    FieldDef::new("ts_sent_sec", 120, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("ts_sent_usec", 152, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("ts_recv_sec", 184, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("ts_recv_usec", 216, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── TPLINK_SMARTHOME (TP-Link Smart Home JSON) ──
        // tshark expects a 4-byte length prefix then XOR-encrypted JSON
        "TPLINK_SMARTHOME" => Some(
            ProtocolDef::new("TPLINK_SMARTHOME", 64) // 4-byte len + 4 bytes data
                .with_fields(vec![
                    FieldDef::new("length", 0, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("4"), // 4 bytes of encrypted data follow
                    // XOR-encrypted JSON payload (first byte XOR'd with 0xAB)
                    FieldDef::new("data", 32, 32, FieldType::Bytes),
                ]),
        ),
        // ── NFS (via ONC-RPC header, RPC program=100003) ──
        "NFS" => Some(
            ProtocolDef::new("NFS", 320) // 40-byte RPC Call header
                .with_fields(vec![
                    FieldDef::new("xid", 0, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"),
                    FieldDef::new("msg_type", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Big), // 0=Call
                    FieldDef::new("rpc_version", 64, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("2"),
                    FieldDef::new("program", 96, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("100003"), // NFS
                    FieldDef::new("program_version", 128, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("3"), // NFSv3
                    FieldDef::new("procedure", 160, 32, FieldType::Uint)
                        .with_endian(Endian::Big), // NULL procedure
                    FieldDef::new("cred_flavor", 192, 32, FieldType::Uint)
                        .with_endian(Endian::Big), // AUTH_NULL
                    FieldDef::new("cred_length", 224, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("verf_flavor", 256, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("verf_length", 288, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── AMQP (Advanced Message Queuing Protocol) ──
        // AMQP 0-9-1 protocol header: "AMQP" + 0x00 + major.minor.revision
        "AMQP" => Some(
            ProtocolDef::new("AMQP", 64)
                .with_fields(vec![
                    FieldDef::new("signature", 0, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1095586645"), // "AMQP" = 0x414D5150
                    FieldDef::new("proto_id", 32, 8, FieldType::Uint), // 0 for AMQP
                    FieldDef::new("major", 40, 8, FieldType::Uint)
                        .with_default_value("0"),
                    FieldDef::new("minor", 48, 8, FieldType::Uint)
                        .with_default_value("9"),
                    FieldDef::new("revision", 56, 8, FieldType::Uint)
                        .with_default_value("1"),
                ]),
        ),
        // ── SMTP: text protocol, needs banner line ──
        // SMTP needs "220 " server greeting to trigger dissector
        "SMTP" => Some(
            ProtocolDef::new("SMTP", 96) // "220 srv\r\n" = 12 bytes (96 bits)
                .with_fields(vec![
                    // "220 " = 0x32323020
                    FieldDef::new("greeting_code", 0, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("842014752"), // "220 "
                    // "srv\r" = 0x7372760D
                    FieldDef::new("greeting_host", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1936941837"), // "srv\r"
                    // "\nOK\n" or just pad
                    FieldDef::new("greeting_end", 64, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("178257930"), // "\nOK\n" = 0x0A4F4B0A
                ]),
        ),
        // ── OCSP (Online Certificate Status Protocol) ──
        // Minimal DER: SEQUENCE { SEQUENCE { SEQUENCE { ... } } }
        // OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest }
        // TBSRequest ::= SEQUENCE { requestList SEQUENCE OF Request }
        "OCSP" => Some(
            ProtocolDef::new("OCSP", 80) // 10 bytes minimal DER
                .with_fields(vec![
                    // SEQUENCE tag + length (outer OCSPRequest)
                    FieldDef::new("seq_tag", 0, 8, FieldType::Uint)
                        .with_default_value("48"), // 0x30 = SEQUENCE
                    FieldDef::new("seq_len", 8, 8, FieldType::Uint)
                        .with_default_value("8"),
                    // Inner SEQUENCE (TBSRequest)
                    FieldDef::new("tbs_tag", 16, 8, FieldType::Uint)
                        .with_default_value("48"), // 0x30
                    FieldDef::new("tbs_len", 24, 8, FieldType::Uint)
                        .with_default_value("6"),
                    // requestList SEQUENCE OF
                    FieldDef::new("reqlist_tag", 32, 8, FieldType::Uint)
                        .with_default_value("48"), // 0x30
                    FieldDef::new("reqlist_len", 40, 8, FieldType::Uint)
                        .with_default_value("4"),
                    // Single Request: SEQUENCE { reqCert CertID }
                    FieldDef::new("req_tag", 48, 8, FieldType::Uint)
                        .with_default_value("48"), // 0x30
                    FieldDef::new("req_len", 56, 8, FieldType::Uint)
                        .with_default_value("2"),
                    // CertID: SEQUENCE {}
                    FieldDef::new("certid_tag", 64, 8, FieldType::Uint)
                        .with_default_value("48"), // 0x30
                    FieldDef::new("certid_len", 72, 8, FieldType::Uint)
                        .with_default_value("0"),
                ]),
        ),
        // ══════════════════════════════════════════════════════════════
        // Bucket 1 — Batch 1: 15 simple RFC-based protocols
        // ══════════════════════════════════════════════════════════════

        // ── DCCP (Datagram Congestion Control Protocol) ── RFC 4340
        // 12-byte generic header (before type-specific fields)
        "DCCP" => Some(
            ProtocolDef::new("DCCP", 96)
                .with_fields(vec![
                    FieldDef::new("src_port", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("dst_port", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("data_offset", 32, 8, FieldType::Uint)
                        .with_default_value("3"), // 3 × 32-bit words = 12 bytes
                    FieldDef::new("ccval", 40, 4, FieldType::Uint),
                    FieldDef::new("cscov", 44, 4, FieldType::Uint),
                    FieldDef::new("checksum", 48, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("res", 64, 3, FieldType::Uint),
                    FieldDef::new("type", 67, 4, FieldType::Uint), // 0=Request
                    FieldDef::new("x", 71, 1, FieldType::Uint),    // extended seq
                    FieldDef::new("seq_high", 72, 8, FieldType::Uint),
                    FieldDef::new("seq_low", 80, 16, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── UDPLite ── RFC 3828
        "UDPLite" => Some(
            ProtocolDef::new("UDPLite", 64)
                .with_fields(vec![
                    FieldDef::new("src_port", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("dst_port", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("checksum_coverage", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("8"), // cover header only
                    FieldDef::new("checksum", 48, 16, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── IPComp (IP Payload Compression) ── RFC 3173
        "IPComp" => Some(
            ProtocolDef::new("IPComp", 32)
                .with_fields(vec![
                    FieldDef::new("next_header", 0, 8, FieldType::Enum),
                    FieldDef::new("flags", 8, 8, FieldType::Uint),
                    FieldDef::new("cpi", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"), // DEFLATE
                ])
                .with_dispatch_field("next_header"),
        ),
        // ── NVGRE (Network Virtualization using GRE) ── RFC 7637
        // GRE header with Key bit set, protocol_type=0x6558 (TransEther)
        "NVGRE" => Some(
            ProtocolDef::new("NVGRE", 64)
                .with_fields(vec![
                    FieldDef::new("flags", 0, 4, FieldType::Flags)
                        .with_default_value("2"), // K bit set
                    FieldDef::new("version", 4, 3, FieldType::Uint),
                    FieldDef::new("reserved0", 7, 9, FieldType::Uint),
                    FieldDef::new("protocol_type", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("25944"), // 0x6558 TransEther
                    FieldDef::new("vsid", 32, 24, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("flow_id", 56, 8, FieldType::Uint),
                ]),
        ),
        // ── EtherIP ── RFC 3378
        "EtherIP" => Some(
            ProtocolDef::new("EtherIP", 16)
                .with_fields(vec![
                    FieldDef::new("version", 0, 4, FieldType::Uint)
                        .with_default_value("3"), // version 3
                    FieldDef::new("reserved", 4, 12, FieldType::Uint),
                ]),
        ),
        // ── VXLAN_GPE (VXLAN Generic Protocol Extension) ── draft-ietf-nvo3
        "VXLAN_GPE" => Some(
            ProtocolDef::new("VXLAN_GPE", 64)
                .with_fields(vec![
                    FieldDef::new("flags", 0, 8, FieldType::Flags)
                        .with_default_value("12"), // I+P bits (0x0C)
                    FieldDef::new("reserved0", 8, 16, FieldType::Uint),
                    FieldDef::new("next_protocol", 24, 8, FieldType::Enum)
                        .with_default_value("1"), // IPv4
                    FieldDef::new("vni", 32, 24, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("reserved1", 56, 8, FieldType::Uint),
                ])
                .with_dispatch_field("next_protocol"),
        ),
        // ── OSPFv3 ── RFC 5340
        "OSPFv3" => Some(
            ProtocolDef::new("OSPFv3", 128) // 16 bytes
                .with_fields(vec![
                    FieldDef::new("version", 0, 8, FieldType::Uint)
                        .with_default_value("3"),
                    FieldDef::new("type", 8, 8, FieldType::Uint)
                        .with_default_value("1"), // Hello
                    FieldDef::new("length", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("16"),
                    FieldDef::new("router_id", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("16843009"), // 1.1.1.1
                    FieldDef::new("area_id", 64, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("checksum", 96, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("instance_id", 112, 8, FieldType::Uint),
                    FieldDef::new("reserved", 120, 8, FieldType::Uint),
                ]),
        ),
        // ── RIPng ── RFC 2080
        "RIPng" => Some(
            ProtocolDef::new("RIPng", 32) // 4-byte header
                .with_fields(vec![
                    FieldDef::new("command", 0, 8, FieldType::Uint)
                        .with_default_value("2"), // Response
                    FieldDef::new("version", 8, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("reserved", 16, 16, FieldType::Uint),
                ]),
        ),
        // ── PIM (Protocol Independent Multicast) ── RFC 4601
        "PIM" => Some(
            ProtocolDef::new("PIM", 32) // 4-byte header
                .with_fields(vec![
                    FieldDef::new("version", 0, 4, FieldType::Uint)
                        .with_default_value("2"),
                    FieldDef::new("type", 4, 4, FieldType::Uint), // 0=Hello
                    FieldDef::new("reserved", 8, 8, FieldType::Uint),
                    FieldDef::new("checksum", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── MSDP (Multicast Source Discovery Protocol) ── RFC 3618
        "MSDP" => Some(
            ProtocolDef::new("MSDP", 24) // 3-byte TLV header
                .with_fields(vec![
                    FieldDef::new("type", 0, 8, FieldType::Uint)
                        .with_default_value("4"), // KeepAlive
                    FieldDef::new("length", 8, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("3"), // 3 bytes (header only)
                ]),
        ),
        // ── CARP (Common Address Redundancy Protocol) ── RFC 5798 variant
        "CARP" => Some(
            ProtocolDef::new("CARP", 160) // 20 bytes
                .with_fields(vec![
                    FieldDef::new("version", 0, 4, FieldType::Uint)
                        .with_default_value("2"),
                    FieldDef::new("type", 4, 4, FieldType::Uint)
                        .with_default_value("1"), // Advertisement
                    FieldDef::new("vhid", 8, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("advskew", 16, 8, FieldType::Uint),
                    FieldDef::new("authlen", 24, 8, FieldType::Uint),
                    FieldDef::new("demotion", 32, 8, FieldType::Uint),
                    FieldDef::new("advbase", 40, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("checksum", 48, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("counter0", 64, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("counter1", 96, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("hmac", 128, 32, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── HSRP (Hot Standby Router Protocol) ── RFC 2281
        "HSRP" => Some(
            ProtocolDef::new("HSRP", 160) // 20 bytes
                .with_fields(vec![
                    FieldDef::new("version", 0, 8, FieldType::Uint),
                    FieldDef::new("opcode", 8, 8, FieldType::Uint), // 0=Hello
                    FieldDef::new("state", 16, 8, FieldType::Uint)
                        .with_default_value("16"), // Active
                    FieldDef::new("hellotime", 24, 8, FieldType::Uint)
                        .with_default_value("3"),
                    FieldDef::new("holdtime", 32, 8, FieldType::Uint)
                        .with_default_value("10"),
                    FieldDef::new("priority", 40, 8, FieldType::Uint)
                        .with_default_value("100"),
                    FieldDef::new("group", 48, 8, FieldType::Uint),
                    FieldDef::new("reserved", 56, 8, FieldType::Uint),
                    FieldDef::new("auth", 64, 64, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("vip", 128, 32, FieldType::Ipv4Addr).with_endian(Endian::Big),
                ]),
        ),
        // ── TWAMP (Two-Way Active Measurement Protocol) ── RFC 5357
        // Sender test packet (unauthenticated mode)
        "TWAMP" => Some(
            ProtocolDef::new("TWAMP", 112) // 14 bytes
                .with_fields(vec![
                    FieldDef::new("seq_number", 0, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("timestamp_sec", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("timestamp_frac", 64, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("error_estimate", 96, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("32769"), // S=1, scale=0, multiplier=1
                ]),
        ),

        // ══════════════════════════════════════════════════════════════
        // Bucket 1 — Batch 2: remaining simple RFC protocols
        // ══════════════════════════════════════════════════════════════

        // ── IPv6_HopByHop (Hop-by-Hop Options) ── RFC 2460
        "IPv6_HopByHop" => Some(
            ProtocolDef::new("IPv6_HopByHop", 64) // 8 bytes minimum
                .with_variable_length()
                .with_fields(vec![
                    FieldDef::new("next_header", 0, 8, FieldType::Enum),
                    FieldDef::new("hdr_ext_len", 8, 8, FieldType::Uint), // in 8-octet units, minus 1
                    FieldDef::new("opt_type", 16, 8, FieldType::Uint)
                        .with_default_value("1"), // PadN
                    FieldDef::new("opt_len", 24, 8, FieldType::Uint)
                        .with_default_value("4"),
                    FieldDef::new("opt_data", 32, 32, FieldType::Uint),
                ])
                .with_dispatch_field("next_header"),
        ),
        // ── IPv6_MobileIP (Mobility Header) ── RFC 6275
        "IPv6_MobileIP" => Some(
            ProtocolDef::new("IPv6_MobileIP", 64) // 8 bytes minimum
                .with_variable_length()
                .with_fields(vec![
                    FieldDef::new("payload_proto", 0, 8, FieldType::Enum),
                    FieldDef::new("hdr_len", 8, 8, FieldType::Uint),
                    FieldDef::new("mh_type", 16, 8, FieldType::Uint), // 0=BRR
                    FieldDef::new("reserved", 24, 8, FieldType::Uint),
                    FieldDef::new("checksum", 32, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("message_data", 48, 16, FieldType::Uint),
                ]),
        ),
        // ── SixInFour (IPv6-in-IPv4 tunneling) ── RFC 4213
        // No extra header — just IPv4(proto=41) → IPv6, minimal encap
        "SixInFour" => Some(
            ProtocolDef::new("SixInFour", 0), // zero-header tunnel (IPv4 proto 41 = IPv6)
        ),
        // ── PIM_Assert ── RFC 4601 (PIM Assert message, type=5)
        "PIM_Assert" => Some(
            ProtocolDef::new("PIM_Assert", 64) // 8 bytes PIM header + payload
                .with_fields(vec![
                    FieldDef::new("version", 0, 4, FieldType::Uint)
                        .with_default_value("2"),
                    FieldDef::new("type", 4, 4, FieldType::Uint)
                        .with_default_value("5"), // Assert
                    FieldDef::new("reserved", 8, 8, FieldType::Uint),
                    FieldDef::new("checksum", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("group_addr", 32, 32, FieldType::Ipv4Addr)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── PIM_BSR (Bootstrap Router) ── RFC 4601 (type=4)
        "PIM_BSR" => Some(
            ProtocolDef::new("PIM_BSR", 64)
                .with_fields(vec![
                    FieldDef::new("version", 0, 4, FieldType::Uint)
                        .with_default_value("2"),
                    FieldDef::new("type", 4, 4, FieldType::Uint)
                        .with_default_value("4"), // Bootstrap
                    FieldDef::new("reserved", 8, 8, FieldType::Uint),
                    FieldDef::new("checksum", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("fragment_tag", 32, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("hash_mask_len", 48, 8, FieldType::Uint),
                    FieldDef::new("bsr_priority", 56, 8, FieldType::Uint),
                ]),
        ),
        // ── PIMv6 ── RFC 3973 (PIM over IPv6, same header as PIM)
        "PIMv6" => Some(
            ProtocolDef::new("PIMv6", 32)
                .with_fields(vec![
                    FieldDef::new("version", 0, 4, FieldType::Uint)
                        .with_default_value("2"),
                    FieldDef::new("type", 4, 4, FieldType::Uint),
                    FieldDef::new("reserved", 8, 8, FieldType::Uint),
                    FieldDef::new("checksum", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── PCP (Port Control Protocol) ── RFC 6887
        "PCP" => Some(
            ProtocolDef::new("PCP", 192) // 24 bytes
                .with_fields(vec![
                    FieldDef::new("version", 0, 8, FieldType::Uint)
                        .with_default_value("2"),
                    FieldDef::new("opcode", 8, 8, FieldType::Uint)
                        .with_default_value("1"), // MAP request (R=0)
                    FieldDef::new("reserved", 16, 16, FieldType::Uint),
                    FieldDef::new("lifetime", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("3600"),
                    FieldDef::new("client_ip", 64, 128, FieldType::Ipv6Addr)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── PFCP (Packet Forwarding Control Protocol) ── 3GPP TS 29.244
        "PFCP" => Some(
            ProtocolDef::new("PFCP", 64) // 8-byte base header (no SEID)
                .with_fields(vec![
                    FieldDef::new("flags", 0, 8, FieldType::Flags)
                        .with_default_value("32"), // version=1 (0x20)
                    FieldDef::new("message_type", 8, 8, FieldType::Uint)
                        .with_default_value("1"), // Heartbeat Request
                    FieldDef::new("length", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("4"),
                    FieldDef::new("seq_number", 32, 24, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("spare", 56, 8, FieldType::Uint),
                ]),
        ),
        // ── GTPv2_C (GTP v2 Control) ── 3GPP TS 29.274
        "GTPv2_C" => Some(
            ProtocolDef::new("GTPv2_C", 96) // 12 bytes with TEID
                .with_fields(vec![
                    FieldDef::new("version", 0, 3, FieldType::Uint)
                        .with_default_value("2"),
                    FieldDef::new("p_flag", 3, 1, FieldType::Uint),
                    FieldDef::new("t_flag", 4, 1, FieldType::Uint)
                        .with_default_value("1"), // TEID present
                    FieldDef::new("spare", 5, 3, FieldType::Uint),
                    FieldDef::new("message_type", 8, 8, FieldType::Uint)
                        .with_default_value("1"), // Echo Request
                    FieldDef::new("length", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("8"),
                    FieldDef::new("teid", 32, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("seq_number", 64, 24, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("spare2", 88, 8, FieldType::Uint),
                ]),
        ),
        // ── GTP_V0 (GTP v0) ── 3GPP TS 09.60
        "GTP_V0" => Some(
            ProtocolDef::new("GTP_V0", 160) // 20 bytes
                .with_fields(vec![
                    FieldDef::new("flags", 0, 8, FieldType::Flags)
                        .with_default_value("30"), // version=0, PT=1, SNN=1, N-PDU=1 → 0x1E
                    FieldDef::new("message_type", 8, 8, FieldType::Uint)
                        .with_default_value("1"), // Echo Request
                    FieldDef::new("length", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("12"),
                    FieldDef::new("seq_number", 32, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("flow_label", 48, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("sndcp_n_pdu", 64, 8, FieldType::Uint),
                    FieldDef::new("spare", 72, 24, FieldType::Uint),
                    FieldDef::new("tid", 96, 64, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── OWAMP (One-Way Active Measurement) ── RFC 4656
        "OWAMP" => Some(
            ProtocolDef::new("OWAMP", 112) // 14 bytes sender test packet
                .with_fields(vec![
                    FieldDef::new("seq_number", 0, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("timestamp_sec", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("timestamp_frac", 64, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("error_estimate", 96, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("32769"),
                ]),
        ),
        // ── MPLS_Echo (MPLS Ping/Traceroute) ── RFC 4379
        "MPLS_Echo" => Some(
            ProtocolDef::new("MPLS_Echo", 256) // 32 bytes
                .with_fields(vec![
                    FieldDef::new("version", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"),
                    FieldDef::new("global_flags", 16, 16, FieldType::Flags)
                        .with_endian(Endian::Big),
                    FieldDef::new("msg_type", 32, 8, FieldType::Uint)
                        .with_default_value("1"), // Echo Request
                    FieldDef::new("reply_mode", 40, 8, FieldType::Uint)
                        .with_default_value("2"), // Reply via IPv4/IPv6 UDP
                    FieldDef::new("return_code", 48, 8, FieldType::Uint),
                    FieldDef::new("return_subcode", 56, 8, FieldType::Uint),
                    FieldDef::new("sender_handle", 64, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("seq_number", 96, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("ts_sent_sec", 128, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("ts_sent_frac", 160, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("ts_recv_sec", 192, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("ts_recv_frac", 224, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── DoIP (Diagnostics over IP) ── ISO 13400-2
        "DoIP" => Some(
            ProtocolDef::new("DoIP", 64) // 8 bytes
                .with_fields(vec![
                    FieldDef::new("version", 0, 8, FieldType::Uint)
                        .with_default_value("2"),
                    FieldDef::new("inv_version", 8, 8, FieldType::Uint)
                        .with_default_value("253"), // 0xFD = ~0x02
                    FieldDef::new("type", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"), // Vehicle identification request
                    FieldDef::new("length", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── DNS_TCP (DNS over TCP with 2-byte length prefix) ── RFC 1035
        "DNS_TCP" => Some(
            ProtocolDef::new("DNS_TCP", 112) // 2-byte length + 12-byte DNS header
                .with_fields(vec![
                    FieldDef::new("length", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("12"),
                    FieldDef::new("transaction_id", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("flags", 32, 16, FieldType::Flags)
                        .with_endian(Endian::Big)
                        .with_default_value("256"), // 0x0100 = standard query
                    FieldDef::new("questions", 48, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"),
                    FieldDef::new("answer_rrs", 64, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("authority_rrs", 80, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("additional_rrs", 96, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── ECHO (Echo Protocol) ── RFC 862
        "ECHO" => Some(
            ProtocolDef::new("ECHO", 32) // 4 bytes of echo data
                .with_fields(vec![
                    FieldDef::new("data", 0, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1"),
                ]),
        ),
        // ── DISCARD (Discard Protocol) ── RFC 863
        "DISCARD" => Some(
            ProtocolDef::new("DISCARD", 32)
                .with_fields(vec![
                    FieldDef::new("data", 0, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── CHARGEN (Character Generator) ── RFC 864
        "CHARGEN" => Some(
            ProtocolDef::new("CHARGEN", 32)
                .with_fields(vec![
                    FieldDef::new("data", 0, 32, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("538976288"), // " 0 " = 0x20203020
                ]),
        ),
        // ── DAYTIME (Daytime Protocol) ── RFC 867
        "DAYTIME" => Some(
            ProtocolDef::new("DAYTIME", 32)
                .with_fields(vec![
                    FieldDef::new("data", 0, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── IPX (Internetwork Packet Exchange) ── Novell
        "IPX" => Some(
            ProtocolDef::new("IPX", 240) // 30 bytes
                .with_fields(vec![
                    FieldDef::new("checksum", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("65535"), // 0xFFFF = no checksum
                    FieldDef::new("length", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("30"),
                    FieldDef::new("transport_control", 32, 8, FieldType::Uint),
                    FieldDef::new("packet_type", 40, 8, FieldType::Uint),
                    FieldDef::new("dst_network", 48, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("dst_node", 80, 48, FieldType::MacAddr)
                        .with_endian(Endian::Big),
                    FieldDef::new("dst_socket", 128, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("src_network", 144, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("src_node", 176, 48, FieldType::MacAddr)
                        .with_endian(Endian::Big),
                    FieldDef::new("src_socket", 224, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),
        // ── LLAP (LocalTalk Link Access Protocol) ── 3-byte bridging header
        // tshark inserts an LLAP layer between Ethernet (0x809B) and DDP.
        // Modelled as its own layer so the AppleTalk/DDP header aligns with
        // tshark's `ddp` PDML proto during round-trip validation.
        "LLAP" => Some(
            ProtocolDef::new("LLAP", 24)
                .with_fields(vec![
                    FieldDef::new("dst", 0, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("src", 8, 8, FieldType::Uint)
                        .with_default_value("2"),
                    FieldDef::new("type", 16, 8, FieldType::Enum)
                        .with_default_value("2"), // 2 = DDP
                ]),
        ),
        // ── AppleTalk (long-form DDP) ── carried under LLAP (EtherType 0x809B)
        // Datagram Delivery Protocol long header, 13 bytes = 104 bits. Field
        // offsets/sizes mirror tshark's ddp.* leaf fields.
        "AppleTalk" => Some(
            ProtocolDef::new("AppleTalk", 104)
                .with_fields(vec![
                    // 2b unused | 4b hop count | 10b datagram length
                    FieldDef::new("unused", 0, 2, FieldType::Pad),
                    FieldDef::new("hop_count", 2, 4, FieldType::Uint),
                    FieldDef::new("length", 6, 10, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("21"),
                    FieldDef::new("checksum", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("dst_net", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("100"),
                    FieldDef::new("src_net", 48, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("200"),
                    FieldDef::new("dst_node", 64, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("src_node", 72, 8, FieldType::Uint)
                        .with_default_value("2"),
                    FieldDef::new("dst_socket", 80, 8, FieldType::Uint)
                        .with_default_value("2"),
                    FieldDef::new("src_socket", 88, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("ddp_type", 96, 8, FieldType::Enum)
                        .with_default_value("2"), // 2 = NBP
                ]),
        ),
        // ── FCoE (Fibre Channel over Ethernet) ── FC-BB-5
        "FCoE" => Some(
            ProtocolDef::new("FCoE", 112) // 14-byte FCoE header
                .with_fields(vec![
                    FieldDef::new("version", 0, 4, FieldType::Uint),
                    FieldDef::new("reserved", 4, 100, FieldType::Uint),
                    FieldDef::new("sof", 104, 8, FieldType::Uint)
                        .with_default_value("46"), // 0x2E = SOFi3
                ]),
        ),
        // ── AVTP (Audio Video Transport Protocol) ── IEEE 1722
        "AVTP" => Some(
            ProtocolDef::new("AVTP", 96) // 12-byte common header
                .with_fields(vec![
                    FieldDef::new("subtype", 0, 8, FieldType::Uint),
                    FieldDef::new("sv_ver_mr_tv", 8, 8, FieldType::Flags),
                    FieldDef::new("sequence_num", 16, 8, FieldType::Uint),
                    FieldDef::new("reserved_tu", 24, 8, FieldType::Uint),
                    FieldDef::new("stream_id", 32, 64, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── L2TPv3 (Layer 2 Tunneling Protocol v3) ── RFC 3931
        "L2TPv3" => Some(
            ProtocolDef::new("L2TPv3", 96) // 12-byte header (IP encap)
                .with_fields(vec![
                    FieldDef::new("session_id", 0, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("cookie", 32, 64, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── Y1731 (Ethernet OAM) ── IEEE 802.1ag / ITU-T Y.1731
        "Y1731" => Some(
            ProtocolDef::new("Y1731", 32) // 4-byte common OAM header
                .with_fields(vec![
                    FieldDef::new("md_level", 0, 3, FieldType::Uint),
                    FieldDef::new("version", 3, 5, FieldType::Uint),
                    FieldDef::new("opcode", 8, 8, FieldType::Uint)
                        .with_default_value("1"), // CCM
                    FieldDef::new("flags", 16, 8, FieldType::Flags),
                    FieldDef::new("first_tlv_offset", 24, 8, FieldType::Uint)
                        .with_default_value("70"),
                ]),
        ),
        // ── GRE6 (GRE over IPv6) ── same GRE header, routed via IPv6
        "GRE6" => Some(
            ProtocolDef::new("GRE6", 32) // 4-byte minimal GRE
                .with_fields(vec![
                    FieldDef::new("flags", 0, 16, FieldType::Flags).with_endian(Endian::Big),
                    FieldDef::new("protocol_type", 16, 16, FieldType::Enum)
                        .with_endian(Endian::Big)
                        .with_default_value("2048"), // 0x0800 = IPv4
                ])
                .with_dispatch_field("protocol_type"),
        ),
        // ── DNP3 (Distributed Network Protocol 3.0) ── IEEE 1815
        "DNP3" => Some(
            ProtocolDef::new("DNP3", 80) // 10-byte data link header
                .with_fields(vec![
                    FieldDef::new("start", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Big)
                        .with_default_value("1478"), // 0x0564
                    FieldDef::new("length", 16, 8, FieldType::Uint)
                        .with_default_value("5"),
                    FieldDef::new("control", 24, 8, FieldType::Uint)
                        .with_default_value("196"), // 0xC4 = DIR=1, PRM=1, FCV=0, FC=4
                    FieldDef::new("destination", 32, 16, FieldType::Uint)
                        .with_endian(Endian::Little), // DNP3 uses little-endian!
                    FieldDef::new("source", 48, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("crc", 64, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                ]),
        ),

        // ═══════════════════════════════════════════════════════════
        //  Bucket 3: Sub-protocols inheriting parent structure
        // ═══════════════════════════════════════════════════════════

        // ── HCI_CMD (HCI Command packet, child of HCI type=0x01) ──
        "HCI_CMD" => Some(
            ProtocolDef::new("HCI_CMD", 24) // 3-byte header
                .with_fields(vec![
                    FieldDef::new("opcode", 0, 16, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("param_len", 16, 8, FieldType::Uint),
                ]),
        ),
        // ── HCI_SCO (HCI Synchronous data, child of HCI type=0x03) ──
        "HCI_SCO" => Some(
            ProtocolDef::new("HCI_SCO", 24) // 3-byte header
                .with_fields(vec![
                    FieldDef::new("handle", 0, 12, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("status", 12, 4, FieldType::Uint),
                    FieldDef::new("dlen", 16, 8, FieldType::Uint),
                ]),
        ),
        // ── HCI_Event (HCI Event packet, child of HCI type=0x04) ──
        "HCI_Event" => Some(
            ProtocolDef::new("HCI_Event", 16) // 2-byte header
                .with_fields(vec![
                    FieldDef::new("event_code", 0, 8, FieldType::Uint)
                        .with_default_value("14"), // Command Complete (0x0E)
                    FieldDef::new("param_len", 8, 8, FieldType::Uint),
                ]),
        ),
        // ── HCI_ISO (HCI ISO data, child of HCI type=0x05) ──
        "HCI_ISO" => Some(
            ProtocolDef::new("HCI_ISO", 32) // 4-byte header
                .with_fields(vec![
                    FieldDef::new("handle_flags", 0, 16, FieldType::Uint)
                        .with_endian(Endian::Little),
                    FieldDef::new("dlen", 16, 16, FieldType::Uint).with_endian(Endian::Little),
                ]),
        ),
        // ── BT_ATT (Attribute Protocol, child of L2CAP cid=0x0004) ──
        "BT_ATT" => Some(
            ProtocolDef::new("BT_ATT", 8)
                .with_fields(vec![
                    FieldDef::new("opcode", 0, 8, FieldType::Uint)
                        .with_default_value("2"), // Exchange MTU Request
                ]),
        ),
        // ── BT_SMP (Security Manager Protocol, child of L2CAP cid=0x0006) ──
        "BT_SMP" => Some(
            ProtocolDef::new("BT_SMP", 56) // 7 bytes for Pairing Request
                .with_fields(vec![
                    FieldDef::new("code", 0, 8, FieldType::Uint)
                        .with_default_value("1"), // Pairing Request
                    FieldDef::new("io_capability", 8, 8, FieldType::Uint),
                    FieldDef::new("oob_flag", 16, 8, FieldType::Uint),
                    FieldDef::new("auth_req", 24, 8, FieldType::Uint),
                    FieldDef::new("max_key_size", 32, 8, FieldType::Uint)
                        .with_default_value("16"),
                    FieldDef::new("init_key_dist", 40, 8, FieldType::Uint),
                    FieldDef::new("resp_key_dist", 48, 8, FieldType::Uint),
                ]),
        ),
        // ── LMP (Link Manager Protocol, Bluetooth) ──
        "LMP" => Some(
            ProtocolDef::new("LMP", 16)
                .with_fields(vec![
                    FieldDef::new("tid_opcode", 0, 8, FieldType::Uint)
                        .with_default_value("3"), // TID=0, opcode=3 (LMP_accepted)
                    FieldDef::new("content", 8, 8, FieldType::Uint),
                ]),
        ),
        // ── PPP_LCP (Link Control Protocol, PPP 0xC021) ──
        "PPP_LCP" => Some(
            ProtocolDef::new("PPP_LCP", 32)
                .with_fields(vec![
                    FieldDef::new("code", 0, 8, FieldType::Uint)
                        .with_default_value("1"), // Configure-Request
                    FieldDef::new("identifier", 8, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("length", 16, 16, FieldType::Uint).with_endian(Endian::Big)
                        .with_default_value("4"),
                ]),
        ),
        // ── PPP_IPCP (IP Control Protocol, PPP 0x8021) ──
        "PPP_IPCP" => Some(
            ProtocolDef::new("PPP_IPCP", 32)
                .with_fields(vec![
                    FieldDef::new("code", 0, 8, FieldType::Uint)
                        .with_default_value("1"), // Configure-Request
                    FieldDef::new("identifier", 8, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("length", 16, 16, FieldType::Uint).with_endian(Endian::Big)
                        .with_default_value("4"),
                ]),
        ),
        // ── PPP_IPv6CP (IPv6 Control Protocol, PPP 0x8057) ──
        "PPP_IPv6CP" => Some(
            ProtocolDef::new("PPP_IPv6CP", 32)
                .with_fields(vec![
                    FieldDef::new("code", 0, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("identifier", 8, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("length", 16, 16, FieldType::Uint).with_endian(Endian::Big)
                        .with_default_value("4"),
                ]),
        ),
        // ── PPP_CCP (Compression Control Protocol, PPP 0x80FD) ──
        "PPP_CCP" => Some(
            ProtocolDef::new("PPP_CCP", 32)
                .with_fields(vec![
                    FieldDef::new("code", 0, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("identifier", 8, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("length", 16, 16, FieldType::Uint).with_endian(Endian::Big)
                        .with_default_value("4"),
                ]),
        ),
        // ── PPP_CHAP (Challenge Handshake Auth, PPP 0xC223) ──
        "PPP_CHAP" => Some(
            ProtocolDef::new("PPP_CHAP", 32)
                .with_fields(vec![
                    FieldDef::new("code", 0, 8, FieldType::Uint)
                        .with_default_value("1"), // Challenge
                    FieldDef::new("identifier", 8, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("length", 16, 16, FieldType::Uint).with_endian(Endian::Big)
                        .with_default_value("4"),
                ]),
        ),
        // ── InfiniBand sub-protocols (children of IB_BTH via opcode) ──
        "IB_DETH" => Some(
            ProtocolDef::new("IB_DETH", 64) // 8 bytes
                .with_fields(vec![
                    FieldDef::new("qkey", 0, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("src_qp", 32, 32, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        "IB_RETH" => Some(
            ProtocolDef::new("IB_RETH", 128) // 16 bytes
                .with_fields(vec![
                    FieldDef::new("va", 0, 64, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("r_key", 64, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("dma_len", 96, 32, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        "IB_AETH" => Some(
            ProtocolDef::new("IB_AETH", 32) // 4 bytes
                .with_fields(vec![
                    FieldDef::new("syndrome", 0, 8, FieldType::Uint),
                    FieldDef::new("msn", 8, 24, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        "IB_RDETH" => Some(
            ProtocolDef::new("IB_RDETH", 32) // 4 bytes
                .with_fields(vec![
                    FieldDef::new("reserved", 0, 8, FieldType::Pad),
                    FieldDef::new("ee_context", 8, 24, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        "IB_AtomicETH" => Some(
            ProtocolDef::new("IB_AtomicETH", 224) // 28 bytes
                .with_fields(vec![
                    FieldDef::new("va", 0, 64, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("r_key", 64, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("swap_or_add", 96, 64, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("compare", 160, 64, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        "IB_ImmDt" => Some(
            ProtocolDef::new("IB_ImmDt", 32) // 4 bytes
                .with_fields(vec![
                    FieldDef::new("data", 0, 32, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        "IB_MAD" => Some(
            ProtocolDef::new("IB_MAD", 192) // 24-byte common MAD header
                .with_fields(vec![
                    FieldDef::new("base_version", 0, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("mgmt_class", 8, 8, FieldType::Uint)
                        .with_default_value("1"), // Subnet Management
                    FieldDef::new("class_version", 16, 8, FieldType::Uint)
                        .with_default_value("1"),
                    FieldDef::new("method", 24, 8, FieldType::Uint)
                        .with_default_value("1"), // Get
                    FieldDef::new("status", 32, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("class_specific", 48, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("transaction_id", 64, 64, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("attr_id", 128, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("reserved", 144, 16, FieldType::Pad),
                    FieldDef::new("attr_mod", 160, 32, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── CAN sub-protocols ──
        "CAN_J1939" => Some(
            ProtocolDef::new("CAN_J1939", 128) // same frame as CAN
                .with_fields(vec![
                    FieldDef::new("can_id", 0, 32, FieldType::Uint).with_endian(Endian::Little)
                        .with_default_value("2566914048"), // PGN 0xFECA (Address Claimed) with EFF
                    FieldDef::new("len", 32, 8, FieldType::Uint).with_default_value("8"),
                    FieldDef::new("pad", 40, 8, FieldType::Pad),
                    FieldDef::new("res", 48, 16, FieldType::Pad),
                    FieldDef::new("data", 64, 64, FieldType::Bytes),
                ]),
        ),
        "CAN_OBD2" => Some(
            ProtocolDef::new("CAN_OBD2", 128)
                .with_fields(vec![
                    FieldDef::new("can_id", 0, 32, FieldType::Uint).with_endian(Endian::Little)
                        .with_default_value("2024"), // 0x7E8 = OBD-II response
                    FieldDef::new("len", 32, 8, FieldType::Uint).with_default_value("8"),
                    FieldDef::new("pad", 40, 8, FieldType::Pad),
                    FieldDef::new("res", 48, 16, FieldType::Pad),
                    FieldDef::new("data", 64, 64, FieldType::Bytes),
                ]),
        ),
        "CAN_TP" => Some(
            ProtocolDef::new("CAN_TP", 128)
                .with_fields(vec![
                    FieldDef::new("can_id", 0, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("len", 32, 8, FieldType::Uint).with_default_value("8"),
                    FieldDef::new("pad", 40, 8, FieldType::Pad),
                    FieldDef::new("res", 48, 16, FieldType::Pad),
                    FieldDef::new("data", 64, 64, FieldType::Bytes),
                ]),
        ),

        // ═══════════════════════════════════════════════════════════
        //  Bucket 5: Protocols with tshark dissectors (mapping fixes)
        // ═══════════════════════════════════════════════════════════

        // ── ERSPAN (Encapsulated Remote SPAN, via GRE) ──
        "ERSPAN" => Some(
            ProtocolDef::new("ERSPAN", 64) // Type II header (8 bytes)
                .with_fields(vec![
                    FieldDef::new("ver_vlan", 0, 16, FieldType::Uint).with_endian(Endian::Big)
                        .with_default_value("4096"), // version=1, vlan=0
                    FieldDef::new("cos_en_t_session", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("reserved", 32, 12, FieldType::Pad),
                    FieldDef::new("index", 44, 20, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── VXLAN_GBP (VXLAN with Group Based Policy) ──
        "VXLAN_GBP" => Some(
            ProtocolDef::new("VXLAN_GBP", 64) // 8-byte VXLAN header with GBP flag
                .with_fields(vec![
                    FieldDef::new("flags", 0, 8, FieldType::Flags)
                        .with_default_value("136"), // 0x88: I=1, G=1 (GBP flag)
                    FieldDef::new("reserved1", 8, 8, FieldType::Pad),
                    FieldDef::new("group_policy_id", 16, 16, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("vni", 32, 24, FieldType::Uint).with_endian(Endian::Big)
                        .with_default_value("100"),
                    FieldDef::new("reserved2", 56, 8, FieldType::Pad),
                ]),
        ),
        // ── SDP (Session Description Protocol, text but has PDML fields) ──
        "SDP" => Some(
            ProtocolDef::new("SDP", 0) // text protocol, minimal stub
                .with_fields(vec![
                    FieldDef::new("version", 0, 0, FieldType::Uint),
                ]),
        ),
        // ── GVRP (GARP VLAN Registration Protocol) ── 802.1Q
        "GVRP" => Some(
            ProtocolDef::new("GVRP", 16) // GARP PDU header
                .with_fields(vec![
                    FieldDef::new("attribute_type", 0, 8, FieldType::Uint)
                        .with_default_value("1"), // VLAN attribute
                    FieldDef::new("attribute_length", 8, 8, FieldType::Uint),
                ]),
        ),
        // ── MSTP (Multiple Spanning Tree Protocol) ── 802.1s
        // ── STP variants (all share BPDU structure, differ by version/flags) ──
        "RSTP" => Some(
            ProtocolDef::new("RSTP", 280) // 35-byte BPDU
                .with_fields(vec![
                    FieldDef::new("protocol_id", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("version", 16, 8, FieldType::Uint).with_default_value("2"), // RSTP
                    FieldDef::new("type", 24, 8, FieldType::Uint).with_default_value("2"), // RST BPDU
                    FieldDef::new("flags", 32, 8, FieldType::Flags),
                    FieldDef::new("root_id", 40, 64, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("root_path_cost", 104, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("bridge_id", 136, 64, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("port_id", 200, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("message_age", 216, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("max_age", 232, 16, FieldType::Uint).with_endian(Endian::Big)
                        .with_default_value("5120"), // 20 seconds (in 1/256ths)
                    FieldDef::new("hello_time", 248, 16, FieldType::Uint).with_endian(Endian::Big)
                        .with_default_value("512"), // 2 seconds
                    FieldDef::new("forward_delay", 264, 16, FieldType::Uint).with_endian(Endian::Big)
                        .with_default_value("3840"), // 15 seconds
                ]),
        ),
        "PVST" => Some(
            ProtocolDef::new("PVST", 280) // same BPDU as STP, different encapsulation
                .with_fields(vec![
                    FieldDef::new("protocol_id", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("version", 16, 8, FieldType::Uint),
                    FieldDef::new("type", 24, 8, FieldType::Uint),
                    FieldDef::new("flags", 32, 8, FieldType::Flags),
                    FieldDef::new("root_id", 40, 64, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("root_path_cost", 104, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("bridge_id", 136, 64, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("port_id", 200, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("message_age", 216, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("max_age", 232, 16, FieldType::Uint).with_endian(Endian::Big)
                        .with_default_value("5120"),
                    FieldDef::new("hello_time", 248, 16, FieldType::Uint).with_endian(Endian::Big)
                        .with_default_value("512"),
                    FieldDef::new("forward_delay", 264, 16, FieldType::Uint).with_endian(Endian::Big)
                        .with_default_value("3840"),
                ]),
        ),
        "MSTP" => Some(
            ProtocolDef::new("MSTP", 280) // BPDU with version=3
                .with_fields(vec![
                    FieldDef::new("protocol_id", 0, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("version", 16, 8, FieldType::Uint).with_default_value("3"), // MSTP
                    FieldDef::new("type", 24, 8, FieldType::Uint).with_default_value("2"),
                    FieldDef::new("flags", 32, 8, FieldType::Flags),
                    FieldDef::new("root_id", 40, 64, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("root_path_cost", 104, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("bridge_id", 136, 64, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("port_id", 200, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("message_age", 216, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("max_age", 232, 16, FieldType::Uint).with_endian(Endian::Big)
                        .with_default_value("5120"),
                    FieldDef::new("hello_time", 248, 16, FieldType::Uint).with_endian(Endian::Big)
                        .with_default_value("512"),
                    FieldDef::new("forward_delay", 264, 16, FieldType::Uint).with_endian(Endian::Big)
                        .with_default_value("3840"),
                ]),
        ),
        // ── sFlow (sampled flow) ──
        "sFlow" => Some(
            ProtocolDef::new("sFlow", 224) // 28-byte v5 header
                .with_fields(vec![
                    FieldDef::new("version", 0, 32, FieldType::Uint).with_endian(Endian::Big)
                        .with_default_value("5"),
                    FieldDef::new("agent_address_type", 32, 32, FieldType::Uint)
                        .with_endian(Endian::Big).with_default_value("1"), // IPv4
                    FieldDef::new("agent_address", 64, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("sub_agent_id", 96, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("sequence_number", 128, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                    FieldDef::new("uptime", 160, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("num_samples", 192, 32, FieldType::Uint)
                        .with_endian(Endian::Big),
                ]),
        ),

        // ── SOCKS (SOCKSv5 handshake) ──
        "SOCKS" => Some(
            ProtocolDef::new("SOCKS", 24) // 3-byte v5 greeting
                .with_fields(vec![
                    FieldDef::new("version", 0, 8, FieldType::Uint).with_default_value("5"),
                    FieldDef::new("nmethods", 8, 8, FieldType::Uint).with_default_value("1"),
                    FieldDef::new("methods", 16, 8, FieldType::Uint), // 0x00 = no auth
                ]),
        ),
        // ── IRC (Internet Relay Chat) ──
        "IRC" => Some(
            ProtocolDef::new("IRC", 0)
                .with_fields(vec![
                    FieldDef::new("command", 0, 0, FieldType::Uint),
                ]),
        ),
        // ── TACACS (Terminal Access Controller, RFC 8907) ──
        "TACACS" => Some(
            ProtocolDef::new("TACACS", 96) // 12-byte header
                .with_fields(vec![
                    FieldDef::new("major_version", 0, 4, FieldType::Uint)
                        .with_default_value("12"), // major=0xC
                    FieldDef::new("minor_version", 4, 4, FieldType::Uint),
                    FieldDef::new("type", 8, 8, FieldType::Uint)
                        .with_default_value("1"), // Authentication
                    FieldDef::new("seq_no", 16, 8, FieldType::Uint).with_default_value("1"),
                    FieldDef::new("flags", 24, 8, FieldType::Flags)
                        .with_default_value("1"), // TAC_PLUS_UNENCRYPTED_FLAG
                    FieldDef::new("session_id", 32, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("length", 64, 32, FieldType::Uint).with_endian(Endian::Big),
                ]),
        ),
        // ── MMRP (Multiple MAC Registration Protocol, IEEE 802.1ak) ── 0x88F6
        // Same MRPDU framing as MVRP; the representative message carries a MAC
        // Address attribute (6-byte value) with one VectorAttribute.
        "MMRP" => Some(
            ProtocolDef::new("MMRP", 8)
                .with_fields(vec![FieldDef::new("protocol_version", 0, 8, FieldType::Uint)])
                .with_repeat(RepeatGroup {
                    name: "message".into(),
                    start_bits: 8,
                    element: vec![
                        FieldDef::new("attribute_type", 0, 8, FieldType::Uint)
                            .with_default_value("2"), // MAC Address
                        FieldDef::new("attribute_length", 8, 8, FieldType::Uint)
                            .with_default_value("6"), // MAC = 6 bytes
                        FieldDef::new("vector_header", 16, 16, FieldType::Uint)
                            .with_endian(Endian::Big)
                            .with_default_value("1"),
                        FieldDef::new("first_value", 32, 48, FieldType::MacAddr)
                            .with_endian(Endian::Big),
                        FieldDef::new("vector", 80, 8, FieldType::Uint),
                        FieldDef::new("attr_end_mark", 88, 16, FieldType::Uint)
                            .with_endian(Endian::Big),
                    ],
                    element_size: ElementSize::Fixed(104),
                    terminator: RepeatTerm::EndMark {
                        size_bits: 16,
                        value: 0,
                    },
                    sample_count: 1,
                }),
        ),

        // ── UpperPDU (virtual, 0 bits, root DLT=252) ──
        "UpperPDU" => Some(ProtocolDef::new("UpperPDU", 0)),

        // ── Netlink SkMemInfo (kernel SK_MEMINFO_* enum, __u32[9]) ──
        "NL_Diag_SkMemInfo" => Some(
            ProtocolDef::new("NL_Diag_SkMemInfo", 288)
                .with_fields(vec![
                    FieldDef::new("rmem_alloc", 0, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("rcv_buf", 32, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("wmem_alloc", 64, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("snd_buf", 96, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("fwd_alloc", 128, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("wmem_queued", 160, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("optmem", 192, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("backlog", 224, 32, FieldType::Uint).with_endian(Endian::Little),
                    FieldDef::new("drops", 256, 32, FieldType::Uint).with_endian(Endian::Little),
                ]),
        ),

        // ── iSCSI BHS (384 bits = 48 bytes, dispatch on opcode) ──
        "iSCSI" => Some(
            ProtocolDef::new("iSCSI", 384)
                .with_fields(vec![
                    FieldDef::new("opcode", 0, 8, FieldType::Enum).with_dispatch(),
                    FieldDef::new("flags", 8, 8, FieldType::Uint),
                    FieldDef::new("rsvd2", 16, 16, FieldType::Pad),
                    FieldDef::new("hlength", 32, 8, FieldType::Uint),
                    FieldDef::new("dlength", 40, 24, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("lun", 64, 64, FieldType::Bytes),
                    FieldDef::new("itt", 128, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("other", 160, 224, FieldType::Bytes),
                ])
                .with_dispatch_field("opcode"),
        ),
        // ── RoCEv2: BTH over UDP:4791 (96 bits, dispatch on opcode) ──
        "RoCEv2" => Some(
            ProtocolDef::new("RoCEv2", 96)
                .with_fields(vec![
                    FieldDef::new("opcode", 0, 8, FieldType::Enum).with_dispatch(),
                    FieldDef::new("se_m_flags", 8, 8, FieldType::Uint),
                    FieldDef::new("pkey", 16, 16, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("dest_qp", 32, 32, FieldType::Uint).with_endian(Endian::Big),
                    FieldDef::new("ack_psn", 64, 32, FieldType::Uint).with_endian(Endian::Big),
                ])
                .with_dispatch_field("opcode"),
        ),
        // ── NVMe/TCP common PDU header (64 bits, dispatch on type) ──
        "NVMe_TCP" => Some(
            ProtocolDef::new("NVMe_TCP", 64)
                .with_fields(vec![
                    FieldDef::new("type", 0, 8, FieldType::Enum).with_dispatch(),
                    FieldDef::new("flags", 8, 8, FieldType::Uint),
                    FieldDef::new("hlen", 16, 8, FieldType::Uint),
                    FieldDef::new("pdo", 24, 8, FieldType::Uint),
                    FieldDef::new("plen", 32, 32, FieldType::Uint).with_endian(Endian::Little),
                ])
                .with_dispatch_field("type"),
        ),
        // ── Falcon Transport Protocol overlays ──
        "Falcon-Version-OV" => Some(
            ProtocolDef::new("Falcon-Version-OV", 8)
                .with_fields(vec![
                    FieldDef::new("rsvd", 0, 4, FieldType::Pad),
                    FieldDef::new("version", 4, 4, FieldType::Enum)
                        .with_dispatch()
                        .with_default_value("1"),
                ])
                .with_dispatch_field("version"),
        ),
        "Falcon-Packet-Type-OV" => Some(
            ProtocolDef::new("Falcon-Packet-Type-OV", 64)
                .with_fields(vec![
                    FieldDef::new("rsvd1", 0, 32, FieldType::Pad),
                    FieldDef::new("rsvd2", 32, 1, FieldType::Pad),
                    FieldDef::new("packet_type", 33, 4, FieldType::Enum).with_dispatch(),
                    FieldDef::new("rsvd3", 37, 27, FieldType::Pad),
                ])
                .with_dispatch_field("packet_type"),
        ),

        _ => None,
    }
}
