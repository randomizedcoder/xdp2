//! Roundtrip tests: source → IR → reverse lookup confirms consistency.
//!
//! Each test verifies:
//! 1. Forward: extractor produces correct IR field properties
//! 2. Reverse: TOML reverse lookup confirms the original mapping is consistent

use crate::extractors::{kernel, scapy, tshark};
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
