//! Roundtrip tests: source → IR → reverse lookup confirms consistency.
//!
//! Each test verifies:
//! 1. Forward: extractor produces correct IR field properties
//! 2. Reverse: TOML reverse lookup confirms the original mapping is consistent

use crate::extractors::{etherparse, kernel, libpcap, omi, scapy, tshark};
use crate::ir::{Endian, FieldDef, FieldType};
use crate::test_data::*;
use crate::type_mapping;

/// Assert a field exists with the expected properties.
fn assert_field(
    fields: &[FieldDef],
    name: &str,
    offset: u32,
    size: u32,
    ft: FieldType,
    endian: Endian,
) {
    let field = fields
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("field '{}' not found", name));
    assert_eq!(field.offset_bits, offset, "{}: offset", name);
    assert_eq!(field.size_bits, size, "{}: size", name);
    assert_eq!(field.field_type, ft, "{}: field_type", name);
    assert_eq!(field.endian, endian, "{}: endian", name);
}

// ── Kernel roundtrip tests ──

#[test]
fn roundtrip_kernel_ipv4() {
    let mappings = type_mapping::load_kernel_mappings(None).unwrap();
    let ks = kernel::parse_kernel_struct(KERNEL_IPHDR, "iphdr")
        .unwrap()
        .unwrap();
    let fields = kernel::to_field_defs_with(&ks, &mappings);

    assert_eq!(fields.len(), 11);
    assert_field(&fields, "version", 0, 4, FieldType::Uint, Endian::Na);
    assert_field(&fields, "ihl", 4, 4, FieldType::Uint, Endian::Na);
    assert_field(&fields, "tos", 8, 8, FieldType::Uint, Endian::Na);
    assert_field(&fields, "tot_len", 16, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "id", 32, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "frag_off", 48, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "ttl", 64, 8, FieldType::Uint, Endian::Na);
    assert_field(&fields, "protocol", 72, 8, FieldType::Enum, Endian::Na);
    assert_field(&fields, "check", 80, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "saddr", 96, 32, FieldType::Ipv4Addr, Endian::Big);
    assert_field(&fields, "daddr", 128, 32, FieldType::Ipv4Addr, Endian::Big);

    // Reverse: protocol is in Enum overrides, __be32 matches (32, Big)
    assert!(mappings
        .field_names_for_type(&FieldType::Enum)
        .contains(&"protocol"));
    assert!(mappings.c_types_for(32, &Endian::Big).contains(&"__be32"));
}

#[test]
fn roundtrip_kernel_ethernet() {
    let mappings = type_mapping::load_kernel_mappings(None).unwrap();
    let ks = kernel::parse_kernel_struct(KERNEL_ETHHDR, "ethhdr")
        .unwrap()
        .unwrap();
    let fields = kernel::to_field_defs_with(&ks, &mappings);

    assert_eq!(fields.len(), 3);
    assert_field(&fields, "h_dest", 0, 48, FieldType::MacAddr, Endian::Big);
    assert_field(&fields, "h_source", 48, 48, FieldType::MacAddr, Endian::Big);
    assert_field(&fields, "h_proto", 96, 16, FieldType::Enum, Endian::Big);

    assert!(mappings
        .field_names_for_type(&FieldType::Enum)
        .contains(&"h_proto"));
    assert!(mappings.c_types_for(16, &Endian::Big).contains(&"__be16"));
}

#[test]
fn roundtrip_kernel_udp() {
    let mappings = type_mapping::load_kernel_mappings(None).unwrap();
    let ks = kernel::parse_kernel_struct(KERNEL_UDPHDR, "udphdr")
        .unwrap()
        .unwrap();
    let fields = kernel::to_field_defs_with(&ks, &mappings);

    assert_eq!(fields.len(), 4);
    assert_field(&fields, "source", 0, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "dest", 16, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "len", 32, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "check", 48, 16, FieldType::Uint, Endian::Big);

    // Total: 64 bits = 8 bytes
    let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
    assert_eq!(total, 64);
}

#[test]
fn roundtrip_kernel_tcp() {
    let mappings = type_mapping::load_kernel_mappings(None).unwrap();
    let ks = kernel::parse_kernel_struct(KERNEL_TCPHDR, "tcphdr")
        .unwrap()
        .unwrap();
    let fields = kernel::to_field_defs_with(&ks, &mappings);

    // source, dest, seq, ack_seq, doff, res1, cwr..fin (8 flags), window, check, urg_ptr
    assert!(fields.len() >= 13, "TCP should have ≥13 fields, got {}", fields.len());
    assert_field(&fields, "source", 0, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "dest", 16, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "seq", 32, 32, FieldType::Uint, Endian::Big);
    assert_field(&fields, "ack_seq", 64, 32, FieldType::Uint, Endian::Big);
    assert_field(&fields, "doff", 96, 4, FieldType::Uint, Endian::Na);
    assert_field(&fields, "window", 112, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "check", 128, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "urg_ptr", 144, 16, FieldType::Uint, Endian::Big);

    // Total: 160 bits = 20 bytes (TCP minimum header)
    // Bitfield region: doff:4 + res1:4 + 8 flag bits = 16 bits
    let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
    assert_eq!(total, 160);
}

#[test]
fn roundtrip_kernel_arp() {
    let mappings = type_mapping::load_kernel_mappings(None).unwrap();
    let ks = kernel::parse_kernel_struct(KERNEL_ARPHDR, "arphdr")
        .unwrap()
        .unwrap();
    let fields = kernel::to_field_defs_with(&ks, &mappings);

    assert_eq!(fields.len(), 5);
    assert_field(&fields, "ar_hrd", 0, 16, FieldType::Enum, Endian::Big);
    assert_field(&fields, "ar_pro", 16, 16, FieldType::Enum, Endian::Big);
    assert_field(&fields, "ar_hln", 32, 8, FieldType::Uint, Endian::Na);
    assert_field(&fields, "ar_pln", 40, 8, FieldType::Uint, Endian::Na);
    assert_field(&fields, "ar_op", 48, 16, FieldType::Enum, Endian::Big);

    // Reverse: all three Enum fields in overrides
    let enum_names = mappings.field_names_for_type(&FieldType::Enum);
    assert!(enum_names.contains(&"ar_hrd"));
    assert!(enum_names.contains(&"ar_pro"));
    assert!(enum_names.contains(&"ar_op"));
}

#[test]
fn roundtrip_kernel_vlan() {
    let mappings = type_mapping::load_kernel_mappings(None).unwrap();
    let ks = kernel::parse_kernel_struct(KERNEL_VLANHDR, "vlan_hdr")
        .unwrap()
        .unwrap();
    let fields = kernel::to_field_defs_with(&ks, &mappings);

    assert_eq!(fields.len(), 2);
    assert_field(&fields, "h_vlan_TCI", 0, 16, FieldType::Flags, Endian::Big);
    assert_field(
        &fields,
        "h_vlan_encapsulated_proto",
        16,
        16,
        FieldType::Enum,
        Endian::Big,
    );

    assert!(mappings
        .field_names_for_type(&FieldType::Flags)
        .contains(&"h_vlan_TCI"));
    assert!(mappings
        .field_names_for_type(&FieldType::Enum)
        .contains(&"h_vlan_encapsulated_proto"));
}

#[test]
fn roundtrip_kernel_icmp() {
    let mappings = type_mapping::load_kernel_mappings(None).unwrap();
    let ks = kernel::parse_kernel_struct(KERNEL_ICMPHDR, "icmphdr")
        .unwrap()
        .unwrap();
    let fields = kernel::to_field_defs_with(&ks, &mappings);

    assert_eq!(fields.len(), 5);
    assert_field(&fields, "type", 0, 8, FieldType::Enum, Endian::Na);
    assert_field(&fields, "code", 8, 8, FieldType::Enum, Endian::Na);
    assert_field(&fields, "checksum", 16, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "id", 32, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "sequence", 48, 16, FieldType::Uint, Endian::Big);

    let enum_names = mappings.field_names_for_type(&FieldType::Enum);
    assert!(enum_names.contains(&"type"));
    assert!(enum_names.contains(&"code"));
}

// ── Scapy roundtrip tests ──

#[test]
fn roundtrip_scapy_ipv4() {
    let mappings = type_mapping::load_scapy_mappings(None).unwrap();
    let sp = scapy::parse_scapy_json(SCAPY_IP_JSON).unwrap();
    let proto = scapy::to_protocol_def_with(&sp, &mappings);

    assert_eq!(proto.fields.len(), 12);
    assert_eq!(proto.min_header_bits, 160);
    assert_field(&proto.fields, "version", 0, 4, FieldType::Uint, Endian::Na);
    assert_field(&proto.fields, "ihl", 4, 4, FieldType::Uint, Endian::Na);
    assert_field(&proto.fields, "tos", 8, 8, FieldType::Uint, Endian::Na);
    assert_field(&proto.fields, "len", 16, 16, FieldType::Uint, Endian::Big);
    assert_field(&proto.fields, "flags", 48, 3, FieldType::Flags, Endian::Na);
    assert_field(&proto.fields, "proto", 72, 8, FieldType::Enum, Endian::Na);
    assert_field(&proto.fields, "src", 96, 32, FieldType::Ipv4Addr, Endian::Big);
    assert_field(&proto.fields, "dst", 128, 32, FieldType::Ipv4Addr, Endian::Big);

    // Reverse: ByteEnumField → Enum, SourceIPField → Ipv4Addr
    assert!(mappings
        .classes_for_type(&FieldType::Enum)
        .contains(&"ByteEnumField"));
    assert!(mappings
        .classes_for_type(&FieldType::Ipv4Addr)
        .contains(&"SourceIPField"));
}

#[test]
fn roundtrip_scapy_tcp() {
    let mappings = type_mapping::load_scapy_mappings(None).unwrap();
    let sp = scapy::parse_scapy_json(SCAPY_TCP_JSON).unwrap();
    let proto = scapy::to_protocol_def_with(&sp, &mappings);

    assert_eq!(proto.fields.len(), 10);
    assert_eq!(proto.min_header_bits, 160);
    assert_field(&proto.fields, "sport", 0, 16, FieldType::Uint, Endian::Big);
    assert_field(&proto.fields, "dport", 16, 16, FieldType::Uint, Endian::Big);
    assert_field(&proto.fields, "seq", 32, 32, FieldType::Uint, Endian::Big);
    assert_field(&proto.fields, "ack", 64, 32, FieldType::Uint, Endian::Big);
    assert_field(&proto.fields, "dataofs", 96, 4, FieldType::Uint, Endian::Na);
    assert_field(&proto.fields, "reserved", 100, 3, FieldType::Pad, Endian::Na);
    assert_field(&proto.fields, "flags", 103, 9, FieldType::Flags, Endian::Big);
    assert_field(&proto.fields, "window", 112, 16, FieldType::Uint, Endian::Big);
    assert_field(&proto.fields, "chksum", 128, 16, FieldType::Uint, Endian::Big);
    assert_field(&proto.fields, "urgptr", 144, 16, FieldType::Uint, Endian::Big);
}

#[test]
fn roundtrip_scapy_udp() {
    let mappings = type_mapping::load_scapy_mappings(None).unwrap();
    let sp = scapy::parse_scapy_json(SCAPY_UDP_JSON).unwrap();
    let proto = scapy::to_protocol_def_with(&sp, &mappings);

    assert_eq!(proto.fields.len(), 4);
    assert_eq!(proto.min_header_bits, 64);
    assert_field(&proto.fields, "sport", 0, 16, FieldType::Uint, Endian::Big);
    assert_field(&proto.fields, "dport", 16, 16, FieldType::Uint, Endian::Big);
    assert_field(&proto.fields, "len", 32, 16, FieldType::Uint, Endian::Big);
    assert_field(&proto.fields, "chksum", 48, 16, FieldType::Uint, Endian::Big);
}

#[test]
fn roundtrip_scapy_ethernet() {
    let mappings = type_mapping::load_scapy_mappings(None).unwrap();
    let sp = scapy::parse_scapy_json(SCAPY_ETHER_JSON).unwrap();
    let proto = scapy::to_protocol_def_with(&sp, &mappings);

    assert_eq!(proto.fields.len(), 3);
    assert_eq!(proto.min_header_bits, 112);
    assert_field(&proto.fields, "dst", 0, 48, FieldType::MacAddr, Endian::Big);
    assert_field(&proto.fields, "src", 48, 48, FieldType::MacAddr, Endian::Big);
    assert_field(&proto.fields, "type", 96, 16, FieldType::Enum, Endian::Big);

    assert!(mappings
        .classes_for_type(&FieldType::MacAddr)
        .contains(&"DestMACField"));
    assert!(mappings
        .classes_for_type(&FieldType::Enum)
        .contains(&"XShortEnumField"));
}

// ── tshark roundtrip tests ──

#[test]
fn roundtrip_tshark_ipv4() {
    let mappings = type_mapping::load_tshark_mappings(None).unwrap();
    let packets = tshark::parse_pdml(TSHARK_ETH_IP_PDML).unwrap();
    let ip = tshark::extract_protocol_from_pdml(&packets, "ip").unwrap();
    let proto = tshark::to_protocol_def_with(&ip, &mappings);

    assert_eq!(proto.min_header_bits, 160);
    assert_field(&proto.fields, "ip.proto", 72, 8, FieldType::Enum, Endian::Na);
    assert_field(
        &proto.fields,
        "ip.src",
        96,
        32,
        FieldType::Ipv4Addr,
        Endian::Big,
    );
    assert_field(
        &proto.fields,
        "ip.dst",
        128,
        32,
        FieldType::Ipv4Addr,
        Endian::Big,
    );
    assert_field(&proto.fields, "ip.flags", 48, 8, FieldType::Flags, Endian::Na);

    // Reverse: tshark rules can produce these types at these bit widths
    assert!(mappings.matches_for(&FieldType::Enum, 8));
    assert!(mappings.matches_for(&FieldType::Ipv4Addr, 32));
    assert!(mappings.matches_for(&FieldType::Flags, 8));
}

#[test]
fn roundtrip_tshark_ethernet() {
    let mappings = type_mapping::load_tshark_mappings(None).unwrap();
    let packets = tshark::parse_pdml(TSHARK_ETH_IP_PDML).unwrap();
    let eth = tshark::extract_protocol_from_pdml(&packets, "eth").unwrap();
    let proto = tshark::to_protocol_def_with(&eth, &mappings);

    assert_eq!(proto.min_header_bits, 112);
    assert_field(&proto.fields, "eth.dst", 0, 48, FieldType::MacAddr, Endian::Big);
    assert_field(&proto.fields, "eth.src", 48, 48, FieldType::MacAddr, Endian::Big);
    assert_field(&proto.fields, "eth.type", 96, 16, FieldType::Enum, Endian::Big);

    assert!(mappings.matches_for(&FieldType::MacAddr, 48));
    assert!(mappings.matches_for(&FieldType::Enum, 16));
}

#[test]
fn roundtrip_tshark_udp() {
    let mappings = type_mapping::load_tshark_mappings(None).unwrap();
    let packets = tshark::parse_pdml(TSHARK_UDP_PDML).unwrap();
    let udp = tshark::extract_protocol_from_pdml(&packets, "udp").unwrap();
    let proto = tshark::to_protocol_def_with(&udp, &mappings);

    assert_eq!(proto.min_header_bits, 64);
    // payload and checksum.status should be filtered out
    assert_eq!(proto.fields.len(), 4);
    assert_field(&proto.fields, "udp.srcport", 0, 16, FieldType::Uint, Endian::Big);
    assert_field(&proto.fields, "udp.dstport", 16, 16, FieldType::Uint, Endian::Big);
    assert_field(&proto.fields, "udp.length", 32, 16, FieldType::Uint, Endian::Big);
    assert_field(
        &proto.fields,
        "udp.checksum",
        48,
        16,
        FieldType::Uint,
        Endian::Big,
    );

    assert!(mappings.matches_for(&FieldType::Uint, 16));
}

// ── Etherparse roundtrip tests ──

#[test]
fn roundtrip_etherparse_ethernet() {
    let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
    let es = etherparse::parse_etherparse_struct(ETHERPARSE_ETHERNET2_HEADER, "Ethernet2Header")
        .unwrap()
        .unwrap();
    let fields = etherparse::to_field_defs_with(&es, &mappings);

    assert_eq!(fields.len(), 3);
    assert_field(&fields, "source", 0, 48, FieldType::MacAddr, Endian::Big);
    assert_field(&fields, "destination", 48, 48, FieldType::MacAddr, Endian::Big);
    assert_field(&fields, "ether_type", 96, 16, FieldType::Enum, Endian::Big);

    // Total: 112 bits = 14 bytes
    let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
    assert_eq!(total, 112);
}

#[test]
fn roundtrip_etherparse_udp() {
    let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
    let es = etherparse::parse_etherparse_struct(ETHERPARSE_UDP_HEADER, "UdpHeader")
        .unwrap()
        .unwrap();
    let fields = etherparse::to_field_defs_with(&es, &mappings);

    assert_eq!(fields.len(), 4);
    assert_field(&fields, "source_port", 0, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "destination_port", 16, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "length", 32, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "checksum", 48, 16, FieldType::Uint, Endian::Big);

    let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
    assert_eq!(total, 64);
}

#[test]
fn roundtrip_etherparse_ipv4() {
    let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
    let es = etherparse::parse_etherparse_struct(ETHERPARSE_IPV4_HEADER, "Ipv4Header")
        .unwrap()
        .unwrap();
    let fields = etherparse::to_field_defs_with(&es, &mappings);

    // dscp(6)+ecn(2)+total_len(16)+identification(16)+dont_fragment(1)+more_fragments(1)
    // +fragment_offset(13)+time_to_live(8)+protocol(8)+header_checksum(16)+source(32)+destination(32)
    // = 12 fields (options skipped)
    assert_eq!(fields.len(), 12);

    // dscp starts at offset 8 (version:4 + ihl:4 implicit)
    assert_field(&fields, "dscp", 8, 6, FieldType::Uint, Endian::Na);
    assert_field(&fields, "ecn", 14, 2, FieldType::Uint, Endian::Na);
    assert_field(&fields, "total_len", 16, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "identification", 32, 16, FieldType::Uint, Endian::Big);
    // After identification: +1 reserved bit gap
    assert_field(&fields, "dont_fragment", 49, 1, FieldType::Uint, Endian::Na);
    assert_field(&fields, "more_fragments", 50, 1, FieldType::Uint, Endian::Na);
    assert_field(&fields, "fragment_offset", 51, 13, FieldType::Uint, Endian::Big);
    assert_field(&fields, "time_to_live", 64, 8, FieldType::Uint, Endian::Na);
    assert_field(&fields, "protocol", 72, 8, FieldType::Enum, Endian::Na);
    assert_field(&fields, "header_checksum", 80, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "source", 96, 32, FieldType::Ipv4Addr, Endian::Big);
    assert_field(&fields, "destination", 128, 32, FieldType::Ipv4Addr, Endian::Big);
}

#[test]
fn roundtrip_etherparse_tcp() {
    let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
    let es = etherparse::parse_etherparse_struct(ETHERPARSE_TCP_HEADER, "TcpHeader")
        .unwrap()
        .unwrap();
    let fields = etherparse::to_field_defs_with(&es, &mappings);

    // source_port, destination_port, sequence_number, acknowledgment_number,
    // ns, fin, syn, rst, psh, ack, urg, ece, cwr, window_size, checksum, urgent_pointer
    // = 16 fields (options skipped)
    assert_eq!(fields.len(), 16);

    assert_field(&fields, "source_port", 0, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "destination_port", 16, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "sequence_number", 32, 32, FieldType::Uint, Endian::Big);
    assert_field(&fields, "acknowledgment_number", 64, 32, FieldType::Uint, Endian::Big);

    // TCP flags at explicit wire positions
    assert_field(&fields, "ns", 103, 1, FieldType::Flags, Endian::Na);
    assert_field(&fields, "cwr", 104, 1, FieldType::Flags, Endian::Na);
    assert_field(&fields, "ece", 105, 1, FieldType::Flags, Endian::Na);
    assert_field(&fields, "fin", 111, 1, FieldType::Flags, Endian::Na);

    assert_field(&fields, "window_size", 112, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "checksum", 128, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "urgent_pointer", 144, 16, FieldType::Uint, Endian::Big);

    let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
    assert_eq!(total, 160);
}

#[test]
fn roundtrip_etherparse_ipv6() {
    let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
    let es = etherparse::parse_etherparse_struct(ETHERPARSE_IPV6_HEADER, "Ipv6Header")
        .unwrap()
        .unwrap();
    let fields = etherparse::to_field_defs_with(&es, &mappings);

    // traffic_class(8)+flow_label(20)+payload_length(16)+next_header(8)+hop_limit(8)
    // +source(128)+destination(128) = 7 fields
    assert_eq!(fields.len(), 7);

    // Starts at offset 4 (version:4 implicit)
    assert_field(&fields, "traffic_class", 4, 8, FieldType::Uint, Endian::Na);
    assert_field(&fields, "flow_label", 12, 20, FieldType::Uint, Endian::Big);
    assert_field(&fields, "payload_length", 32, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "next_header", 48, 8, FieldType::Enum, Endian::Na);
    assert_field(&fields, "hop_limit", 56, 8, FieldType::Uint, Endian::Na);
    assert_field(&fields, "source", 64, 128, FieldType::Ipv6Addr, Endian::Big);
    assert_field(&fields, "destination", 192, 128, FieldType::Ipv6Addr, Endian::Big);

    let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
    assert_eq!(total, 320); // 40 bytes
}

// ── libpcap gencode roundtrip tests ──

#[test]
fn roundtrip_libpcap_ipv4_gencode() {
    let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
    let def = libpcap::extract_from_gencode("IPv4", "IPv4", &mappings)
        .unwrap()
        .unwrap();

    assert_eq!(def.fields.len(), 4);
    assert_field(&def.fields, "protocol", 72, 8, FieldType::Enum, Endian::Na);
    assert_field(&def.fields, "frag_off", 48, 16, FieldType::Uint, Endian::Big);
    assert_field(
        &def.fields,
        "src_addr",
        96,
        32,
        FieldType::Ipv4Addr,
        Endian::Big,
    );
    assert_field(
        &def.fields,
        "dst_addr",
        128,
        32,
        FieldType::Ipv4Addr,
        Endian::Big,
    );

    // Source info
    let info = def.sources.get("libpcap").unwrap();
    assert!(info.present);
    assert_eq!(info.field_count, 4);
}

#[test]
fn roundtrip_libpcap_udp_gencode() {
    let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
    let def = libpcap::extract_from_gencode("UDP", "UDP", &mappings)
        .unwrap()
        .unwrap();

    assert_eq!(def.fields.len(), 2);
    assert_field(&def.fields, "src_port", 0, 16, FieldType::Uint, Endian::Big);
    assert_field(&def.fields, "dst_port", 16, 16, FieldType::Uint, Endian::Big);

    let total = def
        .fields
        .last()
        .map(|f| f.offset_bits + f.size_bits)
        .unwrap();
    assert_eq!(total, 32);
}

#[test]
fn roundtrip_libpcap_tcp_gencode() {
    let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
    let def = libpcap::extract_from_gencode("TCP", "TCP", &mappings)
        .unwrap()
        .unwrap();

    assert_eq!(def.fields.len(), 2);
    assert_field(&def.fields, "src_port", 0, 16, FieldType::Uint, Endian::Big);
    assert_field(&def.fields, "dst_port", 16, 16, FieldType::Uint, Endian::Big);
}

#[test]
fn roundtrip_libpcap_ipv6_gencode() {
    let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
    let def = libpcap::extract_from_gencode("IPv6", "IPv6", &mappings)
        .unwrap()
        .unwrap();

    assert_eq!(def.fields.len(), 3);
    assert_field(&def.fields, "next_header", 48, 8, FieldType::Enum, Endian::Na);
    assert_field(
        &def.fields,
        "src_addr",
        64,
        128,
        FieldType::Ipv6Addr,
        Endian::Big,
    );
    assert_field(
        &def.fields,
        "dst_addr",
        192,
        128,
        FieldType::Ipv6Addr,
        Endian::Big,
    );

    let total = def
        .fields
        .last()
        .map(|f| f.offset_bits + f.size_bits)
        .unwrap();
    assert_eq!(total, 320); // 40 bytes
}

#[test]
fn roundtrip_libpcap_arp_gencode() {
    let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
    let def = libpcap::extract_from_gencode("ARP", "ARP", &mappings)
        .unwrap()
        .unwrap();

    assert_eq!(def.fields.len(), 2);
    assert_field(
        &def.fields,
        "src_addr",
        112,
        32,
        FieldType::Ipv4Addr,
        Endian::Big,
    );
    assert_field(
        &def.fields,
        "dst_addr",
        192,
        32,
        FieldType::Ipv4Addr,
        Endian::Big,
    );
}

// ── libpcap struct roundtrip tests ──

#[test]
fn roundtrip_libpcap_sll_struct() {
    let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
    let ls = libpcap::parse_libpcap_struct(LIBPCAP_SLL_HEADER, "sll_header")
        .unwrap()
        .unwrap();
    let fields = libpcap::struct_to_field_defs(&ls, &mappings);

    assert_eq!(fields.len(), 5);
    assert_field(&fields, "sll_pkttype", 0, 16, FieldType::Enum, Endian::Big);
    assert_field(&fields, "sll_hatype", 16, 16, FieldType::Enum, Endian::Big);
    assert_field(&fields, "sll_halen", 32, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "sll_addr", 48, 64, FieldType::Uint, Endian::Big);
    assert_field(
        &fields,
        "sll_protocol",
        112,
        16,
        FieldType::Enum,
        Endian::Big,
    );

    let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
    assert_eq!(total, 128); // 16 bytes
}

#[test]
fn roundtrip_libpcap_vlan_struct() {
    let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
    let ls = libpcap::parse_libpcap_struct(LIBPCAP_VLAN_TAG, "vlan_tag")
        .unwrap()
        .unwrap();
    let fields = libpcap::struct_to_field_defs(&ls, &mappings);

    assert_eq!(fields.len(), 2);
    assert_field(&fields, "vlan_tci", 0, 16, FieldType::Flags, Endian::Big);
    assert_field(&fields, "vlan_tpid", 16, 16, FieldType::Enum, Endian::Big);

    let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
    assert_eq!(total, 32); // 4 bytes
}

// ── Etherparse overlay roundtrip tests ──

#[test]
fn roundtrip_etherparse_overlay_gre() {
    let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
    let es = etherparse::parse_etherparse_struct(ETHERPARSE_GRE_HEADER, "GreHeader")
        .unwrap()
        .unwrap();
    let fields = etherparse::to_field_defs_with(&es, &mappings);

    assert_eq!(fields.len(), 7);
    assert_field(&fields, "checksum_present", 0, 1, FieldType::Uint, Endian::Na);
    assert_field(&fields, "reserved0", 1, 1, FieldType::Flags, Endian::Na);
    assert_field(&fields, "key_present", 2, 1, FieldType::Uint, Endian::Na);
    assert_field(&fields, "sequence_present", 3, 1, FieldType::Uint, Endian::Na);
    assert_field(&fields, "reserved1", 4, 9, FieldType::Flags, Endian::Big);
    assert_field(&fields, "version", 13, 3, FieldType::Uint, Endian::Na);
    assert_field(&fields, "protocol_type", 16, 16, FieldType::Enum, Endian::Big);
    let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
    assert_eq!(total, 32); // 4 bytes
}

#[test]
fn roundtrip_etherparse_overlay_sctp() {
    let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
    let es = etherparse::parse_etherparse_struct(ETHERPARSE_SCTP_HEADER, "SctpHeader")
        .unwrap()
        .unwrap();
    let fields = etherparse::to_field_defs_with(&es, &mappings);

    assert_eq!(fields.len(), 4);
    assert_field(&fields, "source_port", 0, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "destination_port", 16, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "verification_tag", 32, 32, FieldType::Uint, Endian::Big);
    assert_field(&fields, "checksum", 64, 32, FieldType::Uint, Endian::Big);
    let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
    assert_eq!(total, 96); // 12 bytes
}

#[test]
fn roundtrip_etherparse_overlay_esp() {
    let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
    let es = etherparse::parse_etherparse_struct(ETHERPARSE_ESP_HEADER, "EspHeader")
        .unwrap()
        .unwrap();
    let fields = etherparse::to_field_defs_with(&es, &mappings);

    assert_eq!(fields.len(), 2);
    assert_field(&fields, "spi", 0, 32, FieldType::Uint, Endian::Big);
    assert_field(&fields, "seq_number", 32, 32, FieldType::Uint, Endian::Big);
    let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
    assert_eq!(total, 64); // 8 bytes
}

#[test]
fn roundtrip_etherparse_overlay_ah() {
    let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
    let es = etherparse::parse_etherparse_struct(ETHERPARSE_AH_HEADER, "AhHeader")
        .unwrap()
        .unwrap();
    let fields = etherparse::to_field_defs_with(&es, &mappings);

    assert_eq!(fields.len(), 5);
    assert_field(&fields, "next_header", 0, 8, FieldType::Enum, Endian::Na);
    assert_field(&fields, "payload_len", 8, 8, FieldType::Uint, Endian::Na);
    assert_field(&fields, "reserved", 16, 16, FieldType::Flags, Endian::Big);
    assert_field(&fields, "spi", 32, 32, FieldType::Uint, Endian::Big);
    assert_field(&fields, "seq_number", 64, 32, FieldType::Uint, Endian::Big);
    let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
    assert_eq!(total, 96); // 12 bytes
}

#[test]
fn roundtrip_etherparse_overlay_dns() {
    let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
    let es = etherparse::parse_etherparse_struct(ETHERPARSE_DNS_HEADER, "DnsHeader")
        .unwrap()
        .unwrap();
    let fields = etherparse::to_field_defs_with(&es, &mappings);

    assert_eq!(fields.len(), 6);
    assert_field(&fields, "id", 0, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "flags", 16, 16, FieldType::Flags, Endian::Big);
    assert_field(&fields, "qd_count", 32, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "ar_count", 80, 16, FieldType::Uint, Endian::Big);
    let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
    assert_eq!(total, 96); // 12 bytes
}

#[test]
fn roundtrip_etherparse_overlay_vxlan() {
    let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
    let es = etherparse::parse_etherparse_struct(ETHERPARSE_VXLAN_HEADER, "VxlanHeader")
        .unwrap()
        .unwrap();
    let fields = etherparse::to_field_defs_with(&es, &mappings);

    assert_eq!(fields.len(), 6);
    assert_field(&fields, "reserved_flags0", 0, 4, FieldType::Flags, Endian::Na);
    assert_field(&fields, "vni_valid", 4, 1, FieldType::Uint, Endian::Na);
    assert_field(&fields, "reserved_flags1", 5, 3, FieldType::Flags, Endian::Na);
    assert_field(&fields, "reserved1", 8, 24, FieldType::Flags, Endian::Big);
    assert_field(&fields, "vni", 32, 24, FieldType::Uint, Endian::Big);
    assert_field(&fields, "reserved2", 56, 8, FieldType::Flags, Endian::Na);
    let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
    assert_eq!(total, 64); // 8 bytes
}

// ── libpcap overlay roundtrip tests ──

#[test]
fn roundtrip_libpcap_overlay_gre() {
    let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
    let ls = libpcap::parse_libpcap_struct(LIBPCAP_GRE_HEADER, "gre_header")
        .unwrap()
        .unwrap();
    let fields = libpcap::struct_to_field_defs(&ls, &mappings);

    assert_eq!(fields.len(), 7);
    assert_field(&fields, "gre_checksum_present", 0, 1, FieldType::Uint, Endian::Na);
    assert_field(&fields, "gre_reserved0", 1, 1, FieldType::Uint, Endian::Na);
    assert_field(&fields, "gre_key_present", 2, 1, FieldType::Uint, Endian::Na);
    assert_field(&fields, "gre_sequence_present", 3, 1, FieldType::Uint, Endian::Na);
    assert_field(&fields, "gre_reserved1", 4, 9, FieldType::Uint, Endian::Na);
    assert_field(&fields, "gre_version", 13, 3, FieldType::Uint, Endian::Na);
    assert_field(&fields, "gre_protocol_type", 16, 16, FieldType::Enum, Endian::Big);
    let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
    assert_eq!(total, 32); // 4 bytes
}

#[test]
fn roundtrip_libpcap_overlay_esp() {
    let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
    let ls = libpcap::parse_libpcap_struct(LIBPCAP_ESP_HEADER, "esp_header")
        .unwrap()
        .unwrap();
    let fields = libpcap::struct_to_field_defs(&ls, &mappings);

    assert_eq!(fields.len(), 2);
    assert_field(&fields, "esp_spi", 0, 32, FieldType::Uint, Endian::Big);
    assert_field(&fields, "esp_seq", 32, 32, FieldType::Uint, Endian::Big);
    let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
    assert_eq!(total, 64); // 8 bytes
}

#[test]
fn roundtrip_libpcap_overlay_dns() {
    let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
    let ls = libpcap::parse_libpcap_struct(LIBPCAP_DNS_HEADER, "dns_header")
        .unwrap()
        .unwrap();
    let fields = libpcap::struct_to_field_defs(&ls, &mappings);

    assert_eq!(fields.len(), 6);
    assert_field(&fields, "dns_id", 0, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "dns_flags", 16, 16, FieldType::Flags, Endian::Big);
    assert_field(&fields, "dns_qd_count", 32, 16, FieldType::Uint, Endian::Big);
    assert_field(&fields, "dns_ar_count", 80, 16, FieldType::Uint, Endian::Big);
    let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
    assert_eq!(total, 96); // 12 bytes
}

// ── PCAP generation unit tests ──
// These test the generator directly without tshark (no #[ignore]).

use crate::generator::pcap;
use std::collections::BTreeMap;
use crate::ir::ProtocolDef;

#[test]
fn pcap_generate_ipv4_valid_checksum() {
    let protos = BTreeMap::new();
    let target = ProtocolDef::new("IPv4", 160);
    let output = pcap::generate_pcap(&target, &protos).unwrap();

    // IPv4 header starts at byte 14 (after Ethernet)
    let ipv4_hdr = &output.packet_bytes[14..34];
    assert_eq!(pcap::ipv4_checksum(ipv4_hdr), 0, "IPv4 checksum should verify to 0");
}

#[test]
fn pcap_generate_tcp_stack_correct() {
    let mut protos = BTreeMap::new();
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
    let output = pcap::generate_pcap(&target, &protos).unwrap();

    // Ethernet + IPv4 + TCP = 14 + 20 + 20 = 54 bytes
    assert_eq!(output.packet_bytes.len(), 54);
    assert_eq!(output.stack, vec!["Ethernet", "IPv4", "TCP"]);

    // EtherType = 0x0800
    assert_eq!(&output.packet_bytes[12..14], &[0x08, 0x00]);
    // IPv4 protocol = 6 (TCP)
    assert_eq!(output.packet_bytes[23], 6);
}

#[test]
fn pcap_generate_udp_stack_correct() {
    let mut protos = BTreeMap::new();
    protos.insert(
        "UDP".to_string(),
        ProtocolDef::new("UDP", 64).with_fields(vec![
            FieldDef::new("src_port", 0, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("dst_port", 16, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("length", 32, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("checksum", 48, 16, FieldType::Uint).with_endian(Endian::Big),
        ]),
    );
    let target = protos.get("UDP").unwrap().clone();
    let output = pcap::generate_pcap(&target, &protos).unwrap();

    // Ethernet + IPv4 + UDP = 14 + 20 + 8 = 42 bytes
    assert_eq!(output.packet_bytes.len(), 42);
    // IPv4 protocol = 17 (UDP)
    assert_eq!(output.packet_bytes[23], 17);
}

#[test]
fn pcap_file_starts_with_magic() {
    let protos = BTreeMap::new();
    let target = ProtocolDef::new("IPv4", 160);
    let output = pcap::generate_pcap(&target, &protos).unwrap();
    // Little-endian PCAP magic: D4 C3 B2 A1
    assert_eq!(&output.pcap_bytes[0..4], &[0xD4, 0xC3, 0xB2, 0xA1]);
}

// ── PCAP round-trip tests (require tshark at runtime) ──

#[test]
#[ignore]
fn pcap_roundtrip_ipv4_tshark() {
    let protos = BTreeMap::new();
    let target = ProtocolDef::new("IPv4", 160);
    let output = pcap::generate_pcap(&target, &protos).unwrap();

    // Write PCAP to temp file
    let tmp = std::env::temp_dir().join("proto-audit-test-ipv4.pcap");
    std::fs::write(&tmp, &output.pcap_bytes).unwrap();

    // Run tshark
    let xml = tshark::run_tshark(&tmp, "tshark", 1).unwrap();
    let packets = tshark::parse_pdml(&xml).unwrap();
    let ip = tshark::extract_protocol_from_pdml(&packets, "ip");
    assert!(ip.is_some(), "tshark should find IP protocol in generated PCAP");

    let _ = std::fs::remove_file(&tmp);
}

#[test]
#[ignore]
fn pcap_roundtrip_tcp_tshark() {
    let mut protos = BTreeMap::new();
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
    let output = pcap::generate_pcap(&target, &protos).unwrap();

    let tmp = std::env::temp_dir().join("proto-audit-test-tcp.pcap");
    std::fs::write(&tmp, &output.pcap_bytes).unwrap();

    let xml = tshark::run_tshark(&tmp, "tshark", 1).unwrap();
    let packets = tshark::parse_pdml(&xml).unwrap();
    let tcp = tshark::extract_protocol_from_pdml(&packets, "tcp");
    assert!(tcp.is_some(), "tshark should find TCP protocol in generated PCAP");

    let _ = std::fs::remove_file(&tmp);
}

// ── OMI (Open Markets Initiative) roundtrip tests ──

#[test]
fn roundtrip_omi_soupbin_packet_header() {
    let mappings = type_mapping::load_omi_mappings(None).unwrap();
    let def = omi::extract_from_source(
        OMI_SOUPBIN_PACKET_HEADER,
        "SoupBinTCP_PacketHeader",
        "PacketHeaderT",
        "nasdaq/Nasdaq.Common.SoupBinTcp.Ouch.v3.0.h",
        &mappings,
    )
    .unwrap()
    .unwrap();

    assert_eq!(def.fields.len(), 2);
    assert_eq!(def.min_header_bits, 24);
    assert_field(&def.fields, "PacketLength", 0, 16, FieldType::Uint, Endian::Big);
    // char PacketType → Enum via field_type_overrides
    assert_field(&def.fields, "PacketType", 16, 8, FieldType::Enum, Endian::Na);
}

#[test]
fn roundtrip_omi_itch_non_cross_trade() {
    let mappings = type_mapping::load_omi_mappings(None).unwrap();
    let def = omi::extract_from_source(
        OMI_ITCH_NON_CROSS_TRADE,
        "ITCH_v5_NonCrossTrade",
        "NonCrossTradeMessageT",
        "nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h",
        &mappings,
    )
    .unwrap()
    .unwrap();

    assert_eq!(def.fields.len(), 9);
    // 16+16+8+64+8+32+64+32+64 = 304 bits = 38 bytes
    assert_eq!(def.min_header_bits, 304);

    assert_field(&def.fields, "StockLocate", 0, 16, FieldType::Uint, Endian::Big);
    assert_field(&def.fields, "TrackingNumber", 16, 16, FieldType::Uint, Endian::Big);
    // OMI's char Timestamp is 1 byte — a known wire/struct divergence
    // (wire format uses 6 bytes). Preserved as a cross-source finding.
    assert_field(&def.fields, "Timestamp", 32, 8, FieldType::Uint, Endian::Na);
    assert_field(&def.fields, "OrderReferenceNumber", 40, 64, FieldType::Uint, Endian::Big);
    // BuySellIndicator → Enum via field_type_overrides
    assert_field(&def.fields, "BuySellIndicator", 104, 8, FieldType::Enum, Endian::Na);
    assert_field(&def.fields, "Shares", 112, 32, FieldType::Uint, Endian::Big);
    // char[8] → 64 bits, Na endian (ASCII symbol override)
    assert_field(&def.fields, "Stock", 144, 64, FieldType::Uint, Endian::Na);
    assert_field(&def.fields, "Price", 208, 32, FieldType::Uint, Endian::Big);
    assert_field(&def.fields, "MatchNumber", 240, 64, FieldType::Uint, Endian::Big);
}

#[test]
fn roundtrip_omi_sbe_message_header() {
    let mappings = type_mapping::load_omi_mappings(None).unwrap();
    let def = omi::extract_from_source(
        OMI_SBE_MESSAGE_HEADER,
        "SBE_MDP3_MessageHeader",
        "MessageHeaderT",
        "cme/Cme.Futures.Mdp3.Sbe.v1.13.h",
        &mappings,
    )
    .unwrap()
    .unwrap();

    assert_eq!(def.fields.len(), 4);
    assert_eq!(def.min_header_bits, 64);
    // CME SBE is little-endian by spec
    assert_field(&def.fields, "BlockLength", 0, 16, FieldType::Uint, Endian::Little);
    assert_field(&def.fields, "TemplateId", 16, 16, FieldType::Uint, Endian::Little);
    assert_field(&def.fields, "SchemaId", 32, 16, FieldType::Uint, Endian::Little);
    assert_field(&def.fields, "Version", 48, 16, FieldType::Uint, Endian::Little);
}

#[test]
fn roundtrip_omi_name_mapping_lookup() {
    let p = crate::name_mapping::find_by_canonical("ITCH_v5_NonCrossTrade").unwrap();
    assert_eq!(p.omi_struct, Some("NonCrossTradeMessageT"));
    assert_eq!(
        p.omi_file,
        Some("nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h")
    );

    let p2 = crate::name_mapping::find_by_omi_struct("NonCrossTradeMessageT").unwrap();
    assert_eq!(p2.canonical, "ITCH_v5_NonCrossTrade");
}

#[test]
fn roundtrip_omi_eobi_v3_triangle_entries() {
    // Workstream 1: EOBI v3.0 entries with full c-struct + Lua + PCAP triangle.
    // Verify each entry carries omi / tshark / omi_tshark slots so the tshark
    // extractor can descend into the per-message PDML field.
    for (canonical, struct_name, pcap_path, field_name, expected_bytes) in [
        (
            "EOBI_v3_OrderAdd",
            "OrderAddT",
            "Eurex/Eobi.T7.v3.0/OrderAdd.pcap",
            "eurex.derivatives.eobi.t7.v3.0.orderadd",
            40u32,
        ),
        (
            "EOBI_v3_SnapshotOrder",
            "SnapshotOrderT",
            "Eurex/Eobi.T7.v3.0/SnapshotOrder.pcap",
            "eurex.derivatives.eobi.t7.v3.0.snapshotorder",
            24,
        ),
        (
            "EOBI_v3_Heartbeat",
            "HeartbeatT",
            "Eurex/Eobi.T7.v3.0/Heartbeat.pcap",
            "eurex.derivatives.eobi.t7.v3.0.heartbeat",
            8,
        ),
    ] {
        let p = crate::name_mapping::find_by_canonical(canonical).unwrap();
        assert_eq!(p.omi_struct, Some(struct_name));
        assert_eq!(p.omi_file, Some("eurex/Eurex.Derivatives.Eobi.T7.v3.0.h"));
        assert_eq!(p.tshark, Some("eurex.derivatives.eobi.t7.v3.0.lua"));
        assert_eq!(
            p.omi_lua,
            Some("Eurex/Eurex_Derivatives_Eobi_T7_v3_0_Dissector.lua")
        );
        assert_eq!(p.omi_pcap, Some(pcap_path));
        assert_eq!(p.omi_tshark_field, Some(field_name));
        assert_eq!(p.min_header_bytes, expected_bytes);
    }
}
