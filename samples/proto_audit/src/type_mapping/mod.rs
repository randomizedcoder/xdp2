//! Extensible type mapping system.
//!
//! Loads TOML mapping files that define how each source's type system
//! translates to the proto-audit IR. Developers can extend these files
//! to add new source types or correct classifications without touching
//! Rust code.
//!
//! Mappings are embedded in the binary via `include_str!()` so the tool
//! works without external files. Override with `--mappings-dir` or
//! `PROTO_AUDIT_MAPPINGS_DIR`.

mod kernel;
mod scapy;
mod tshark;
mod etherparse;
mod libpcap;
mod scapy_gen;

pub use kernel::*;
pub use scapy::*;
pub use tshark::*;
pub use etherparse::*;
pub use libpcap::*;
pub use scapy_gen::*;

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::ir::{Endian, FieldType};

// ── Embedded defaults ──

const DEFAULT_KERNEL_TOML: &str = include_str!("../../mappings/kernel.toml");
const DEFAULT_SCAPY_TOML: &str = include_str!("../../mappings/scapy.toml");
const DEFAULT_TSHARK_TOML: &str = include_str!("../../mappings/tshark.toml");
const DEFAULT_ETHERPARSE_TOML: &str = include_str!("../../mappings/etherparse.toml");
const DEFAULT_ETHERPARSE_GEN_TOML: &str = include_str!("../../mappings/etherparse_gen.toml");
const DEFAULT_SCAPY_GEN_TOML: &str = include_str!("../../mappings/scapy_gen.toml");
const DEFAULT_LIBPCAP_TOML: &str = include_str!("../../mappings/libpcap.toml");

// ── Shared types ──

#[derive(Debug, Deserialize)]
pub struct FieldTypeOverride {
    #[serde(rename = "type")]
    pub field_type: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub require_bits: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct ArrayEndianOverride {
    pub endian: String,
    #[serde(default)]
    pub reason: String,
}

// ── Parsing helpers ──

/// Parse a FieldType string into the enum.
pub fn parse_field_type(s: &str) -> Option<FieldType> {
    match s {
        "Uint" => Some(FieldType::Uint),
        "Sint" => Some(FieldType::Sint),
        "Bytes" => Some(FieldType::Bytes),
        "Ipv4Addr" => Some(FieldType::Ipv4Addr),
        "Ipv6Addr" => Some(FieldType::Ipv6Addr),
        "MacAddr" => Some(FieldType::MacAddr),
        "Flags" => Some(FieldType::Flags),
        "Enum" => Some(FieldType::Enum),
        "Pad" => Some(FieldType::Pad),
        _ => None,
    }
}

/// Parse an Endian string into the enum.
pub fn parse_endian(s: &str) -> Option<Endian> {
    match s {
        "Big" => Some(Endian::Big),
        "Little" => Some(Endian::Little),
        "Na" => Some(Endian::Na),
        _ => None,
    }
}

// ── Loading ──

/// Load kernel mappings from a directory, or use embedded defaults.
pub fn load_kernel_mappings(dir: Option<&Path>) -> Result<KernelMappings> {
    load_mappings(dir, "kernel.toml", DEFAULT_KERNEL_TOML)
}

/// Load scapy mappings from a directory, or use embedded defaults.
pub fn load_scapy_mappings(dir: Option<&Path>) -> Result<ScapyMappings> {
    load_mappings(dir, "scapy.toml", DEFAULT_SCAPY_TOML)
}

/// Load tshark mappings from a directory, or use embedded defaults.
pub fn load_tshark_mappings(dir: Option<&Path>) -> Result<TsharkMappings> {
    load_mappings(dir, "tshark.toml", DEFAULT_TSHARK_TOML)
}

/// Load etherparse mappings from a directory, or use embedded defaults.
pub fn load_etherparse_mappings(dir: Option<&Path>) -> Result<EtherparseMappings> {
    load_mappings(dir, "etherparse.toml", DEFAULT_ETHERPARSE_TOML)
}

/// Load etherparse generation mappings from a directory, or use embedded defaults.
pub fn load_etherparse_gen_mappings(dir: Option<&Path>) -> Result<EtherparseGenMappings> {
    load_mappings(dir, "etherparse_gen.toml", DEFAULT_ETHERPARSE_GEN_TOML)
}

/// Load scapy generation mappings from a directory, or use embedded defaults.
pub fn load_scapy_gen_mappings(dir: Option<&Path>) -> Result<ScapyGenMappings> {
    load_mappings(dir, "scapy_gen.toml", DEFAULT_SCAPY_GEN_TOML)
}

/// Load libpcap mappings from a directory, or use embedded defaults.
pub fn load_libpcap_mappings(dir: Option<&Path>) -> Result<LibpcapMappings> {
    load_mappings(dir, "libpcap.toml", DEFAULT_LIBPCAP_TOML)
}

fn load_mappings<T: serde::de::DeserializeOwned>(
    dir: Option<&Path>,
    filename: &str,
    default_toml: &str,
) -> Result<T> {
    let content = if let Some(dir) = dir {
        let path = dir.join(filename);
        if path.exists() {
            std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?
        } else {
            default_toml.to_string()
        }
    } else {
        default_toml.to_string()
    };

    toml::from_str(&content).with_context(|| format!("parsing {}", filename))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_kernel_defaults() {
        let km = load_kernel_mappings(None).unwrap();
        assert_eq!(km.type_bits("__u8"), Some(8));
        assert_eq!(km.type_bits("__be16"), Some(16));
        assert_eq!(km.type_bits("__be32"), Some(32));
        assert_eq!(km.type_bits("unknown_type"), None);
    }

    #[test]
    fn test_kernel_endian() {
        let km = load_kernel_mappings(None).unwrap();
        assert_eq!(km.type_endian("__be16"), Endian::Big);
        assert_eq!(km.type_endian("__le32"), Endian::Little);
        assert_eq!(km.type_endian("__sum16"), Endian::Big);
        assert_eq!(km.type_endian("__u16"), Endian::Na);
    }

    #[test]
    fn test_kernel_field_overrides() {
        let km = load_kernel_mappings(None).unwrap();
        assert_eq!(km.field_type_override("protocol", 8), Some(FieldType::Enum));
        assert_eq!(km.field_type_override("h_proto", 16), Some(FieldType::Enum));
        assert_eq!(km.field_type_override("nexthdr", 8), Some(FieldType::Enum));
        assert_eq!(km.field_type_override("group", 32), Some(FieldType::Ipv4Addr));
        // require_bits mismatch
        assert_eq!(km.field_type_override("group", 16), None);
        // Unknown field
        assert_eq!(km.field_type_override("unknown_field", 8), None);

        // Iteration 4 additions
        assert_eq!(km.field_type_override("code", 8), Some(FieldType::Enum));
        assert_eq!(km.field_type_override("icmp6_code", 8), Some(FieldType::Enum));
        assert_eq!(km.field_type_override("h_vlan_encapsulated_proto", 16), Some(FieldType::Enum));
        assert_eq!(km.field_type_override("h_vlan_TCI", 16), Some(FieldType::Flags));
    }

    #[test]
    fn test_kernel_array_endian() {
        let km = load_kernel_mappings(None).unwrap();
        assert_eq!(
            km.array_endian_override("unsigned char", 6),
            Some(Endian::Big)
        );
        assert_eq!(km.array_endian_override("unsigned char", 4), None);
    }

    #[test]
    fn test_load_scapy_defaults() {
        let sm = load_scapy_mappings(None).unwrap();
        assert_eq!(sm.field_type("IPField"), Some(FieldType::Ipv4Addr));
        assert_eq!(sm.field_type("ByteEnumField"), Some(FieldType::Enum));
        assert_eq!(sm.field_type("ShortEnumField"), None); // deliberately unmapped
        assert_eq!(sm.field_type("StrField"), Some(FieldType::Bytes));

        // Iteration 4 additions
        assert_eq!(sm.field_type("EnumField"), Some(FieldType::Enum));
        assert_eq!(sm.field_type("LongEnumField"), Some(FieldType::Enum));
        assert_eq!(sm.field_type("MultiEnumField"), Some(FieldType::Enum));
        assert_eq!(sm.field_type("XShortEnumField"), Some(FieldType::Enum));
    }

    #[test]
    fn test_scapy_endian() {
        let sm = load_scapy_mappings(None).unwrap();
        assert_eq!(sm.endian("ShortField", 16), Endian::Big);
        assert_eq!(sm.endian("LEShortField", 16), Endian::Little);
        assert_eq!(sm.endian("ByteField", 8), Endian::Na);
    }

    #[test]
    fn test_scapy_name_patterns() {
        let sm = load_scapy_mappings(None).unwrap();
        assert_eq!(sm.name_pattern_type("flags"), Some(FieldType::Flags));
        assert_eq!(sm.name_pattern_type("tcp_flag_syn"), Some(FieldType::Flags));
        assert_eq!(sm.name_pattern_type("pad"), Some(FieldType::Pad));
        assert_eq!(sm.name_pattern_type("reserved"), Some(FieldType::Pad));
        assert_eq!(sm.name_pattern_type("version"), None);
    }

    #[test]
    fn test_load_tshark_defaults() {
        let tm = load_tshark_mappings(None).unwrap();
        assert_eq!(tm.infer_field_type("ip.src", 32), FieldType::Ipv4Addr);
        assert_eq!(tm.infer_field_type("ip.dst", 32), FieldType::Ipv4Addr);
        assert_eq!(tm.infer_field_type("ipv6.src", 128), FieldType::Ipv6Addr);
        assert_eq!(tm.infer_field_type("eth.src", 48), FieldType::MacAddr);
        assert_eq!(tm.infer_field_type("arp.src_hw", 48), FieldType::MacAddr);
        assert_eq!(tm.infer_field_type("ip.flags", 8), FieldType::Flags);
        assert_eq!(tm.infer_field_type("ip.proto", 8), FieldType::Enum);
        assert_eq!(tm.infer_field_type("eth.type", 16), FieldType::Enum);
        assert_eq!(tm.infer_field_type("ip.ttl", 8), FieldType::Uint);

        // Iteration 4 additions
        assert_eq!(tm.infer_field_type("icmp.code", 8), FieldType::Enum);
        assert_eq!(tm.infer_field_type("icmpv6.code", 8), FieldType::Enum);
        assert_eq!(tm.infer_field_type("ipv6.dst_host.addr", 128), FieldType::Ipv6Addr);
    }

    #[test]
    fn test_tshark_extended_blocklist() {
        let tm = load_tshark_mappings(None).unwrap();
        assert!(tm.is_blocked("tcp.stream"));
        assert!(tm.is_blocked("tcp.segment"));
        assert!(tm.is_blocked("tcp.analysis"));
        assert!(tm.is_blocked("tcp.reassembled_in"));
        assert!(tm.is_blocked("tcp.reassembled.length"));
        assert!(tm.is_blocked("udp.payload"));
        assert!(!tm.is_blocked("udp.srcport"));
    }

    #[test]
    fn test_tshark_blocklist() {
        let tm = load_tshark_mappings(None).unwrap();
        assert!(tm.is_blocked("udp.payload"));
        assert!(tm.is_blocked("eth.padding"));
        assert!(tm.is_blocked("udp.checksum.status"));
        assert!(!tm.is_blocked("udp.srcport"));
    }

    #[test]
    fn test_parse_field_type() {
        assert_eq!(parse_field_type("Uint"), Some(FieldType::Uint));
        assert_eq!(parse_field_type("Enum"), Some(FieldType::Enum));
        assert_eq!(parse_field_type("Ipv4Addr"), Some(FieldType::Ipv4Addr));
        assert_eq!(parse_field_type("Invalid"), None);
    }

    #[test]
    fn test_parse_endian() {
        assert_eq!(parse_endian("Big"), Some(Endian::Big));
        assert_eq!(parse_endian("Little"), Some(Endian::Little));
        assert_eq!(parse_endian("Na"), Some(Endian::Na));
        assert_eq!(parse_endian("Invalid"), None);
    }

    #[test]
    fn test_kernel_all_field_overrides_roundtrip() {
        let km = load_kernel_mappings(None).unwrap();
        for (name, ovr) in &km.field_type_overrides {
            let expected_ft = parse_field_type(&ovr.field_type)
                .unwrap_or_else(|| panic!("invalid type '{}' for override '{}'", ovr.field_type, name));
            let bits = ovr.require_bits.unwrap_or(8);
            assert_eq!(
                km.field_type_override(name, bits),
                Some(expected_ft.clone()),
                "forward lookup failed for '{}'",
                name
            );
            assert!(
                km.field_names_for_type(&expected_ft).contains(&name.as_str()),
                "reverse lookup for {:?} should contain '{}'",
                expected_ft,
                name
            );
        }
    }

    #[test]
    fn test_scapy_all_field_types_roundtrip() {
        let sm = load_scapy_mappings(None).unwrap();
        for (class, type_str) in &sm.field_types {
            let expected_ft = parse_field_type(type_str)
                .unwrap_or_else(|| panic!("invalid type '{}' for class '{}'", type_str, class));
            assert_eq!(
                sm.field_type(class),
                Some(expected_ft.clone()),
                "forward lookup failed for '{}'",
                class
            );
            assert!(
                sm.classes_for_type(&expected_ft).contains(&class.as_str()),
                "reverse lookup for {:?} should contain '{}'",
                expected_ft,
                class
            );
        }
    }

    #[test]
    fn test_tshark_all_patterns_exercised() {
        let tm = load_tshark_mappings(None).unwrap();
        for (suffix, type_str) in &tm.suffix_types {
            let ft = parse_field_type(type_str)
                .unwrap_or_else(|| panic!("invalid type '{}' for suffix '{}'", type_str, suffix));
            assert!(
                tm.matches_for(&ft, 48),
                "suffix '{}' → {:?} should be reachable via matches_for",
                suffix,
                ft
            );
        }
        for entry in &tm.suffix_types_by_size {
            let ft = parse_field_type(&entry.field_type)
                .unwrap_or_else(|| panic!("invalid type '{}' for suffix '{}'", entry.field_type, entry.suffix));
            assert!(
                tm.matches_for(&ft, entry.bits),
                "suffix '{}' @ {} bits → {:?} should be reachable",
                entry.suffix,
                entry.bits,
                ft
            );
        }
        for (pattern, entry) in &tm.enum_patterns {
            assert!(
                tm.matches_for(&FieldType::Enum, entry.max_bits),
                "enum pattern '{}' @ max {} bits should be reachable",
                pattern,
                entry.max_bits
            );
        }
    }

    #[test]
    fn test_load_libpcap_defaults() {
        let lm = load_libpcap_mappings(None).unwrap();
        assert_eq!(lm.type_bits("uint8_t"), Some(8));
        assert_eq!(lm.type_bits("uint16_t"), Some(16));
        assert_eq!(lm.type_bits("uint32_t"), Some(32));
        assert!(lm.gencode_protocols.contains_key("IPv4"));
        assert!(lm.gencode_protocols.contains_key("UDP"));
        assert!(lm.gencode_protocols.contains_key("TCP"));
        assert!(lm.gencode_protocols.contains_key("IPv6"));
        assert!(lm.gencode_protocols.contains_key("ARP"));
    }

    #[test]
    fn test_libpcap_gencode_ipv4_fields() {
        let lm = load_libpcap_mappings(None).unwrap();
        let ipv4 = &lm.gencode_protocols["IPv4"];
        assert_eq!(ipv4["protocol"].byte_offset, 9);
        assert_eq!(ipv4["protocol"].size_bytes, 1);
        assert_eq!(ipv4["protocol"].field_type, Some("Enum".to_string()));
        assert_eq!(ipv4["src_addr"].byte_offset, 12);
        assert_eq!(ipv4["src_addr"].size_bytes, 4);
    }

    #[test]
    fn test_libpcap_type_endian() {
        let lm = load_libpcap_mappings(None).unwrap();
        assert_eq!(lm.type_endian("uint16_t"), Endian::Big);
        assert_eq!(lm.type_endian("uint32_t"), Endian::Big);
        assert_eq!(lm.type_endian("uint8_t"), Endian::Na);
    }

    #[test]
    fn test_libpcap_field_overrides() {
        let lm = load_libpcap_mappings(None).unwrap();
        assert_eq!(lm.field_type_override("sll_protocol"), Some(FieldType::Enum));
        assert_eq!(lm.field_type_override("vlan_tci"), Some(FieldType::Flags));
        assert_eq!(lm.field_type_override("vlan_tpid"), Some(FieldType::Enum));
    }

    #[test]
    fn test_libpcap_array_endian() {
        let lm = load_libpcap_mappings(None).unwrap();
        assert_eq!(
            lm.array_endian_override("uint8_t", 8),
            Some(Endian::Big)
        );
        assert_eq!(lm.array_endian_override("uint8_t", 4), None);
    }

    #[test]
    fn test_libpcap_struct_protocols() {
        let lm = load_libpcap_mappings(None).unwrap();
        let vlan = &lm.struct_protocols["vlan_tag"];
        assert_eq!(vlan.source_file, "pcap/vlan.h");
        assert_eq!(vlan.struct_name, "vlan_tag");
    }
}
