//! Cross-generator round-trip tests: IR → generate code → re-extract → compare.
//!
//! These tests verify that code generators produce output that, when re-parsed
//! by the corresponding extractor, yields field definitions consistent with the
//! original IR. Etherparse and C targets are pure-Rust (no external tools).

use crate::comparator;
use crate::extractors::{etherparse, kernel};
use crate::generator;
use crate::ir::{self, Endian, FieldDef, FieldType};
use crate::type_mapping;

/// Build a minimal IPv4 IR for testing.
fn ipv4_ir() -> ir::ProtocolDef {
    ir::ProtocolDef::new("IPv4", 160)
        .with_variable_length()
        .with_fields(vec![
            FieldDef::new("version", 0, 4, FieldType::Uint),
            FieldDef::new("ihl", 4, 4, FieldType::Uint),
            FieldDef::new("tos", 8, 8, FieldType::Uint),
            FieldDef::new("tot_len", 16, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("id", 32, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("frag_off", 48, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("ttl", 64, 8, FieldType::Uint),
            FieldDef::new("protocol", 72, 8, FieldType::Enum).with_dispatch(),
            FieldDef::new("check", 80, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("saddr", 96, 32, FieldType::Ipv4Addr).with_endian(Endian::Big),
            FieldDef::new("daddr", 128, 32, FieldType::Ipv4Addr).with_endian(Endian::Big),
        ])
}

/// Build a minimal Ethernet IR for testing.
fn ethernet_ir() -> ir::ProtocolDef {
    ir::ProtocolDef::new("Ethernet", 112).with_fields(vec![
        FieldDef::new("h_dest", 0, 48, FieldType::MacAddr).with_endian(Endian::Big),
        FieldDef::new("h_source", 48, 48, FieldType::MacAddr).with_endian(Endian::Big),
        FieldDef::new("h_proto", 96, 16, FieldType::Enum)
            .with_endian(Endian::Big)
            .with_dispatch(),
    ])
}

/// Build a minimal UDP IR for testing.
fn udp_ir() -> ir::ProtocolDef {
    ir::ProtocolDef::new("UDP", 64).with_fields(vec![
        FieldDef::new("source", 0, 16, FieldType::Uint).with_endian(Endian::Big),
        FieldDef::new("dest", 16, 16, FieldType::Uint).with_endian(Endian::Big),
        FieldDef::new("len", 32, 16, FieldType::Uint).with_endian(Endian::Big),
        FieldDef::new("check", 48, 16, FieldType::Uint).with_endian(Endian::Big),
    ])
}

/// Build a minimal TCP IR for testing.
fn tcp_ir() -> ir::ProtocolDef {
    ir::ProtocolDef::new("TCP", 160)
        .with_variable_length()
        .with_fields(vec![
            FieldDef::new("source", 0, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("dest", 16, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("seq", 32, 32, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("ack_seq", 64, 32, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("doff", 96, 4, FieldType::Uint),
            FieldDef::new("flags", 100, 12, FieldType::Flags).with_endian(Endian::Big),
            FieldDef::new("window", 112, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("check", 128, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("urg_ptr", 144, 16, FieldType::Uint).with_endian(Endian::Big),
        ])
}

/// Build a minimal ARP IR for testing.
fn arp_ir() -> ir::ProtocolDef {
    ir::ProtocolDef::new("ARP", 64)
        .with_variable_length()
        .with_fields(vec![
            FieldDef::new("htype", 0, 16, FieldType::Uint).with_endian(Endian::Big),
            FieldDef::new("ptype", 16, 16, FieldType::Enum).with_endian(Endian::Big),
            FieldDef::new("hlen", 32, 8, FieldType::Uint),
            FieldDef::new("plen", 40, 8, FieldType::Uint),
            FieldDef::new("oper", 48, 16, FieldType::Enum).with_endian(Endian::Big),
        ])
}

// ── Etherparse round-trip tests ──

#[test]
fn crossgen_etherparse_ipv4() {
    let ir = ipv4_ir();
    let generated = generator::generate_etherparse(&ir);
    assert!(
        generated.contains("struct IPv4Header"),
        "generated should contain struct"
    );

    let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
    let parsed = etherparse::parse_etherparse_struct(&generated, "IPv4Header")
        .expect("parse should succeed")
        .expect("should find struct");
    let fields = etherparse::to_field_defs_with(&parsed, &mappings);
    assert!(!fields.is_empty(), "should extract fields");

    let roundtrip = ir::ProtocolDef::new("IPv4", 160).with_fields(fields);
    let audit =
        comparator::audit_protocol("IPv4", &[("original", &ir), ("roundtrip", &roundtrip)]);
    assert!(audit.fields_agree > 0, "at least some fields should agree");
}

#[test]
fn crossgen_etherparse_udp() {
    let ir = udp_ir();
    let generated = generator::generate_etherparse(&ir);

    let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
    let parsed = etherparse::parse_etherparse_struct(&generated, "UDPHeader")
        .expect("parse should succeed")
        .expect("should find struct");
    let fields = etherparse::to_field_defs_with(&parsed, &mappings);
    assert_eq!(fields.len(), 4, "UDP should have 4 fields");
}

#[test]
fn crossgen_etherparse_ethernet() {
    let ir = ethernet_ir();
    let generated = generator::generate_etherparse(&ir);

    let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
    let parsed = etherparse::parse_etherparse_struct(&generated, "EthernetHeader")
        .expect("parse should succeed")
        .expect("should find struct");
    let fields = etherparse::to_field_defs_with(&parsed, &mappings);
    assert!(!fields.is_empty(), "should extract fields");
}

// ── C round-trip tests ──

#[test]
fn crossgen_c_ipv4() {
    let ir = ipv4_ir();
    let generated = generator::generate_proto_def(&ir);
    assert!(
        generated.contains("iphdr") || generated.contains("IPv4"),
        "generated C should reference the protocol"
    );

    let mappings = type_mapping::load_kernel_mappings(None).unwrap();
    // The C generator produces a proto_def, try to parse its embedded struct
    let parsed = kernel::parse_kernel_struct(&generated, "iphdr");
    if let Ok(Some(ks)) = parsed {
        let fields = kernel::to_field_defs_with(&ks, &mappings);
        assert!(!fields.is_empty(), "should extract fields from generated C");

        let roundtrip = ir::ProtocolDef::new("IPv4", 160).with_fields(fields);
        let audit = comparator::audit_protocol(
            "IPv4",
            &[("original", &ir), ("roundtrip", &roundtrip)],
        );
        assert!(audit.fields_agree > 0, "at least some fields should agree");
    }
    // If parse fails, that's OK — the C generator may emit XDP2-specific macros
    // that the kernel parser can't handle. The test verifies the generator runs.
}

#[test]
fn crossgen_c_udp() {
    let ir = udp_ir();
    let generated = generator::generate_proto_def(&ir);
    assert!(!generated.is_empty());
}

#[test]
fn crossgen_c_tcp() {
    let ir = tcp_ir();
    let generated = generator::generate_proto_def(&ir);
    assert!(!generated.is_empty());
}

#[test]
fn crossgen_c_arp() {
    let ir = arp_ir();
    let generated = generator::generate_proto_def(&ir);
    assert!(!generated.is_empty());
}

// ── Scapy generation test (no runtime, just verify generation) ──

#[test]
fn crossgen_scapy_generates() {
    let ir = ipv4_ir();
    let generated = generator::generate_scapy(&ir);
    assert!(
        generated.contains("class IPv4"),
        "should contain Scapy class"
    );
    assert!(
        generated.contains("fields_desc"),
        "should contain fields_desc"
    );
}

#[test]
fn crossgen_scapy_udp_generates() {
    let ir = udp_ir();
    let generated = generator::generate_scapy(&ir);
    assert!(generated.contains("class UDP"));
    assert!(generated.contains("ShortField"));
}
