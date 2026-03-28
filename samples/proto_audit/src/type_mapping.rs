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

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::ir::{Endian, FieldType};

// ── Embedded defaults ──

const DEFAULT_KERNEL_TOML: &str = include_str!("../mappings/kernel.toml");
const DEFAULT_SCAPY_TOML: &str = include_str!("../mappings/scapy.toml");
const DEFAULT_TSHARK_TOML: &str = include_str!("../mappings/tshark.toml");
const DEFAULT_ETHERPARSE_TOML: &str = include_str!("../mappings/etherparse.toml");
const DEFAULT_ETHERPARSE_GEN_TOML: &str = include_str!("../mappings/etherparse_gen.toml");
const DEFAULT_SCAPY_GEN_TOML: &str = include_str!("../mappings/scapy_gen.toml");
const DEFAULT_LIBPCAP_TOML: &str = include_str!("../mappings/libpcap.toml");

// ── Kernel mappings ──

#[derive(Debug, Deserialize)]
pub struct KernelMappings {
    pub type_bits: HashMap<String, u32>,
    pub type_endian: HashMap<String, String>,
    pub field_type_overrides: HashMap<String, FieldTypeOverride>,
    #[serde(default)]
    pub array_endian_overrides: HashMap<String, ArrayEndianOverride>,
    #[serde(default)]
    pub struct_sizes: HashMap<String, u32>,
}

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

impl KernelMappings {
    /// Look up bit width for a C type.
    ///
    /// Also handles `struct X` types via the `struct_sizes` table.
    pub fn type_bits(&self, c_type: &str) -> Option<u32> {
        if let Some(&bits) = self.type_bits.get(c_type) {
            return Some(bits);
        }
        // Check struct_sizes for embedded struct types (e.g., "icmp6hdr")
        self.struct_sizes.get(c_type).copied()
    }

    /// Determine endianness from C type using prefix/exact rules.
    pub fn type_endian(&self, c_type: &str) -> Endian {
        // Check exact matches first
        for (key, val) in &self.type_endian {
            if let Some(exact) = key.strip_prefix("exact:") {
                if c_type == exact {
                    return parse_endian(val).unwrap_or(Endian::Na);
                }
            }
        }
        // Then prefix matches
        for (key, val) in &self.type_endian {
            if let Some(prefix) = key.strip_prefix("prefix:") {
                if c_type.starts_with(prefix) {
                    return parse_endian(val).unwrap_or(Endian::Na);
                }
            }
        }
        Endian::Na
    }

    /// Check for field name type override.
    pub fn field_type_override(&self, name: &str, bits: u32) -> Option<FieldType> {
        if let Some(ovr) = self.field_type_overrides.get(name) {
            if let Some(req) = ovr.require_bits {
                if bits != req {
                    return None;
                }
            }
            return parse_field_type(&ovr.field_type);
        }
        None
    }

    /// Check for array endian override.
    pub fn array_endian_override(&self, c_type: &str, array_size: u32) -> Option<Endian> {
        let key = format!("{}:{}", c_type, array_size);
        if let Some(ovr) = self.array_endian_overrides.get(&key) {
            return parse_endian(&ovr.endian);
        }
        None
    }

    /// Given an IR FieldType, return field names that map to it via overrides.
    pub fn field_names_for_type(&self, ft: &FieldType) -> Vec<&str> {
        self.field_type_overrides
            .iter()
            .filter_map(|(name, ovr)| {
                if parse_field_type(&ovr.field_type).as_ref() == Some(ft) {
                    Some(name.as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Given bit width + endian, return C types that match.
    pub fn c_types_for(&self, bits: u32, endian: &Endian) -> Vec<&str> {
        self.type_bits
            .iter()
            .filter_map(|(c_type, &b)| {
                if b == bits && &self.type_endian(c_type) == endian {
                    Some(c_type.as_str())
                } else {
                    None
                }
            })
            .collect()
    }
}

// ── Scapy mappings ──

#[derive(Debug, Deserialize)]
pub struct ScapyMappings {
    pub field_types: HashMap<String, String>,
    pub endian_prefixes: HashMap<String, String>,
    pub name_patterns: HashMap<String, String>,
    pub unwrap_classes: HashMap<String, bool>,
}

impl ScapyMappings {
    /// Look up field type by Scapy class name.
    pub fn field_type(&self, class: &str) -> Option<FieldType> {
        self.field_types
            .get(class)
            .and_then(|s| parse_field_type(s))
    }

    /// Determine endianness from class name prefixes.
    pub fn endian(&self, class: &str, bits: u32) -> Endian {
        if bits <= 8 {
            return Endian::Na;
        }
        for (prefix, endian_str) in &self.endian_prefixes {
            if class.starts_with(prefix) {
                return parse_endian(endian_str).unwrap_or(Endian::Big);
            }
        }
        Endian::Big // Scapy defaults to network byte order
    }

    /// Check field name patterns for fallback type inference.
    pub fn name_pattern_type(&self, name: &str) -> Option<FieldType> {
        for (pattern, type_str) in &self.name_patterns {
            if name.contains(pattern) {
                return parse_field_type(type_str);
            }
        }
        None
    }

    /// Check if a class is an unwrap target.
    pub fn should_unwrap(&self, class: &str) -> bool {
        self.unwrap_classes.get(class).copied().unwrap_or(false)
    }

    /// Given an IR FieldType, return Scapy classes that map to it.
    pub fn classes_for_type(&self, ft: &FieldType) -> Vec<&str> {
        self.field_types
            .iter()
            .filter_map(|(class, type_str)| {
                if parse_field_type(type_str).as_ref() == Some(ft) {
                    Some(class.as_str())
                } else {
                    None
                }
            })
            .collect()
    }
}

// ── tshark mappings ──

#[derive(Debug, Deserialize)]
pub struct TsharkMappings {
    pub suffix_types: HashMap<String, String>,
    pub suffix_types_by_size: Vec<SuffixTypeBySizeEntry>,
    pub contains_types: HashMap<String, String>,
    pub enum_patterns: HashMap<String, EnumPatternEntry>,
    pub blocklist_suffixes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SuffixTypeBySizeEntry {
    pub suffix: String,
    pub bits: u32,
    #[serde(rename = "type")]
    pub field_type: String,
}

#[derive(Debug, Deserialize)]
pub struct EnumPatternEntry {
    pub max_bits: u32,
}

impl TsharkMappings {
    /// Infer field type from tshark field name and bit width.
    pub fn infer_field_type(&self, name: &str, bits: u32) -> FieldType {
        // 1. Suffix types (unconditional on size)
        for (suffix, type_str) in &self.suffix_types {
            if name.ends_with(suffix) {
                if let Some(ft) = parse_field_type(type_str) {
                    return ft;
                }
            }
        }

        // 2. Suffix types by size
        for entry in &self.suffix_types_by_size {
            if name.ends_with(&entry.suffix) && bits == entry.bits {
                if let Some(ft) = parse_field_type(&entry.field_type) {
                    return ft;
                }
            }
        }

        // 3. Contains types (flags, pad, reserved)
        for (pattern, type_str) in &self.contains_types {
            if name.contains(pattern) {
                if let Some(ft) = parse_field_type(type_str) {
                    return ft;
                }
            }
        }

        // 4. Enum patterns
        for (pattern, entry) in &self.enum_patterns {
            if name.contains(pattern) && bits <= entry.max_bits {
                return FieldType::Enum;
            }
        }

        FieldType::Uint
    }

    /// Check if a tshark field name is blocklisted.
    pub fn is_blocked(&self, name: &str) -> bool {
        self.blocklist_suffixes
            .iter()
            .any(|suffix| name.ends_with(suffix))
    }

    /// Given an IR FieldType + bits, return whether any tshark rule would produce it.
    pub fn matches_for(&self, ft: &FieldType, bits: u32) -> bool {
        // Check suffix_types (unconditional on size)
        for type_str in self.suffix_types.values() {
            if parse_field_type(type_str).as_ref() == Some(ft) {
                return true;
            }
        }
        // Check suffix_types_by_size
        for entry in &self.suffix_types_by_size {
            if entry.bits == bits && parse_field_type(&entry.field_type).as_ref() == Some(ft) {
                return true;
            }
        }
        // Check contains_types
        for type_str in self.contains_types.values() {
            if parse_field_type(type_str).as_ref() == Some(ft) {
                return true;
            }
        }
        // Check enum_patterns
        if *ft == FieldType::Enum {
            for entry in self.enum_patterns.values() {
                if bits <= entry.max_bits {
                    return true;
                }
            }
        }
        // Default inference is Uint
        *ft == FieldType::Uint
    }
}

// ── Etherparse mappings ──

#[derive(Debug, Deserialize)]
pub struct EtherparseMappings {
    pub type_bits: HashMap<String, u32>,
    #[serde(default)]
    pub type_endian: HashMap<String, String>,
    #[serde(default)]
    pub field_type_overrides: HashMap<String, FieldTypeOverride>,
    #[serde(default)]
    pub array_endian_overrides: HashMap<String, ArrayEndianOverride>,
    #[serde(default)]
    pub implicit_fields: HashMap<String, ImplicitFieldConfig>,
    #[serde(default)]
    pub flag_bit_offsets: HashMap<String, HashMap<String, u32>>,
}

#[derive(Debug, Deserialize)]
pub struct ImplicitFieldConfig {
    #[serde(default)]
    pub start_offset_bits: u32,
    #[serde(default)]
    pub gaps: Vec<GapEntry>,
}

#[derive(Debug, Deserialize)]
pub struct GapEntry {
    pub after: String,
    pub skip_bits: u32,
}

impl EtherparseMappings {
    /// Look up bit width for a Rust type.
    pub fn type_bits(&self, rust_type: &str) -> Option<u32> {
        self.type_bits.get(rust_type).copied()
    }

    /// Check for field name type override.
    pub fn field_type_override(&self, name: &str) -> Option<FieldType> {
        self.field_type_overrides
            .get(name)
            .and_then(|ovr| parse_field_type(&ovr.field_type))
    }

    /// Check for array endian override.
    pub fn array_endian_override(&self, rust_type: &str, array_size: u32) -> Option<Endian> {
        let key = format!("{}:{}", rust_type, array_size);
        self.array_endian_overrides
            .get(&key)
            .and_then(|ovr| parse_endian(&ovr.endian))
    }

    /// Get implicit field config for a struct.
    pub fn implicit_field_config(&self, struct_name: &str) -> Option<&ImplicitFieldConfig> {
        self.implicit_fields.get(struct_name)
    }

    /// Get flag bit offsets for a struct.
    pub fn flag_bit_offsets(&self, struct_name: &str) -> Option<&HashMap<String, u32>> {
        self.flag_bit_offsets.get(struct_name)
    }
}

// ── Etherparse generation mappings ──

#[derive(Debug, Deserialize)]
pub struct EtherparseGenMappings {
    pub rust_types: HashMap<String, String>,
    #[serde(default)]
    pub newtypes: HashMap<String, String>,
    #[serde(default)]
    pub derives: DerivesConfig,
    #[serde(default)]
    pub skip_fields: HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
pub struct DerivesConfig {
    #[serde(default)]
    pub default: Vec<String>,
}

impl EtherparseGenMappings {
    /// Look up Rust type for an IR field by (FieldType, size_bits).
    pub fn rust_type(&self, ft: &FieldType, bits: u32) -> Option<&str> {
        let key = format!("{:?}:{}", ft, bits);
        self.rust_types.get(&key).map(|s| s.as_str())
    }

    /// Check for a newtype override by field name.
    pub fn newtype(&self, field_name: &str) -> Option<&str> {
        self.newtypes.get(field_name).map(|s| s.as_str())
    }

    /// Check if a field should be skipped for a given struct.
    pub fn should_skip(&self, struct_name: &str, field_name: &str) -> bool {
        self.skip_fields
            .get(struct_name)
            .map(|v| v.iter().any(|f| f == field_name))
            .unwrap_or(false)
    }
}

// ── Scapy generation mappings ──

#[derive(Debug, Deserialize)]
pub struct ScapyGenMappings {
    pub field_classes: HashMap<String, String>,
    #[serde(default)]
    pub name_overrides: HashMap<String, String>,
    #[serde(default)]
    pub le_prefixes: HashMap<String, String>,
}

impl ScapyGenMappings {
    /// Look up Scapy field class for an IR field by (FieldType, size_bits).
    pub fn field_class(&self, ft: &FieldType, bits: u32) -> Option<&str> {
        let key = format!("{:?}:{}", ft, bits);
        self.field_classes.get(&key).map(|s| s.as_str())
    }

    /// Check for a field name override.
    pub fn name_override(&self, field_name: &str) -> Option<&str> {
        self.name_overrides.get(field_name).map(|s| s.as_str())
    }

    /// Get LE variant of a field class, if one exists.
    pub fn le_variant(&self, class: &str) -> Option<&str> {
        self.le_prefixes.get(class).map(|s| s.as_str())
    }
}

// ── Libpcap mappings ──

#[derive(Debug, Deserialize)]
pub struct LibpcapMappings {
    pub type_bits: HashMap<String, u32>,
    #[serde(default)]
    pub type_endian: HashMap<String, String>,
    #[serde(default)]
    pub field_type_overrides: HashMap<String, FieldTypeOverride>,
    #[serde(default)]
    pub array_endian_overrides: HashMap<String, ArrayEndianOverride>,
    #[serde(default)]
    pub gencode_protocols: HashMap<String, HashMap<String, GencodeField>>,
    #[serde(default)]
    pub struct_protocols: HashMap<String, StructProtocol>,
}

#[derive(Debug, Deserialize)]
pub struct GencodeField {
    pub byte_offset: u32,
    pub size_bytes: u32,
    #[serde(default)]
    pub field_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StructProtocol {
    pub source_file: String,
    pub struct_name: String,
}

impl LibpcapMappings {
    /// Look up bit width for a C type.
    pub fn type_bits(&self, c_type: &str) -> Option<u32> {
        self.type_bits.get(c_type).copied()
    }

    /// Determine endianness from C type using prefix/exact rules.
    pub fn type_endian(&self, c_type: &str) -> Endian {
        for (key, val) in &self.type_endian {
            if let Some(exact) = key.strip_prefix("exact:") {
                if c_type == exact {
                    return parse_endian(val).unwrap_or(Endian::Na);
                }
            }
        }
        for (key, val) in &self.type_endian {
            if let Some(prefix) = key.strip_prefix("prefix:") {
                if c_type.starts_with(prefix) {
                    return parse_endian(val).unwrap_or(Endian::Na);
                }
            }
        }
        Endian::Na
    }

    /// Check for field name type override.
    pub fn field_type_override(&self, name: &str) -> Option<FieldType> {
        self.field_type_overrides
            .get(name)
            .and_then(|ovr| parse_field_type(&ovr.field_type))
    }

    /// Check for array endian override.
    pub fn array_endian_override(&self, c_type: &str, array_size: u32) -> Option<Endian> {
        let key = format!("{}:{}", c_type, array_size);
        self.array_endian_overrides
            .get(&key)
            .and_then(|ovr| parse_endian(&ovr.endian))
    }
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
        // XShortEnumField → Enum (EtherType fields, closed registry)
        // vs ShortEnumField → None (ports, open namespace)
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
        // Existing blocklist still works
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
            // Forward: override produces expected type
            assert_eq!(
                km.field_type_override(name, bits),
                Some(expected_ft.clone()),
                "forward lookup failed for '{}'",
                name
            );
            // Reverse: field name appears in reverse lookup
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
            // Forward: class produces expected type
            assert_eq!(
                sm.field_type(class),
                Some(expected_ft.clone()),
                "forward lookup failed for '{}'",
                class
            );
            // Reverse: class appears in reverse lookup
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
        // Every suffix_type should be reachable
        for (suffix, type_str) in &tm.suffix_types {
            let ft = parse_field_type(type_str)
                .unwrap_or_else(|| panic!("invalid type '{}' for suffix '{}'", type_str, suffix));
            assert!(
                tm.matches_for(&ft, 48), // 48 is a common size for MAC suffix types
                "suffix '{}' → {:?} should be reachable via matches_for",
                suffix,
                ft
            );
        }
        // Every suffix_type_by_size should be reachable
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
        // Every enum_pattern should be reachable
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
