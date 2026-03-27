//! Intermediate Representation for protocol definitions.
//!
//! The IR captures a canonical protocol definition assembled from multiple
//! authoritative sources (XDP2, Linux kernel, Scapy, tshark). Each source
//! may define fields differently — the IR normalizes offsets, sizes, and
//! types so cross-source comparison is straightforward.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A single protocol header field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldDef {
    /// Canonical field name (consensus across sources)
    pub name: String,
    /// Bit offset from protocol header start
    pub offset_bits: u32,
    /// Field width in bits
    pub size_bits: u32,
    /// Semantic type
    pub field_type: FieldType,
    /// Byte order (Na for sub-byte or single-byte fields)
    pub endian: Endian,
    /// Human-readable description
    #[serde(default)]
    pub description: String,
    /// This field carries the "next protocol" identifier
    #[serde(default)]
    pub is_dispatch: bool,
    /// This field controls variable header length
    #[serde(default)]
    pub is_length: bool,
    /// If is_length: actual_bytes = field_value * multiplier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length_multiplier: Option<u32>,
    /// How each source names this field.
    /// Keys: "xdp2", "kernel", "scapy", "tshark"
    #[serde(default)]
    pub source_names: BTreeMap<String, String>,
    /// Default value from source (e.g., "4", "0x0800", "0")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    /// Names for individual flag bits (e.g., ["Reserved", "DF", "MF"])
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flag_names: Option<Vec<String>>,
}

/// Semantic type of a protocol field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FieldType {
    /// Unsigned integer
    Uint,
    /// Signed integer
    Sint,
    /// Raw byte sequence
    Bytes,
    /// IPv4 address (32 bits)
    Ipv4Addr,
    /// IPv6 address (128 bits)
    Ipv6Addr,
    /// MAC address (48 bits)
    MacAddr,
    /// Individual bit flags
    Flags,
    /// Enumerated value (protocol number, ethertype, etc.)
    Enum,
    /// Reserved / padding
    Pad,
}

/// Byte order of a field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Endian {
    /// Network byte order (most protocols)
    Big,
    /// Little-endian (some L2, USB, etc.)
    Little,
    /// Sub-byte or single-byte field (endianness not applicable)
    Na,
}

/// Maps a dispatch field value to a next protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DispatchEntry {
    /// Field value (e.g., 0x0800, 6, 17)
    pub value: u32,
    /// Target protocol canonical name
    pub protocol: String,
    /// Which sources define this binding
    #[serde(default)]
    pub sources: Vec<String>,
}

/// Canonical protocol definition assembled from multiple sources.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolDef {
    /// Canonical name: "IPv4", "TCP", "Ethernet"
    pub name: String,
    /// Minimum header size in bits
    pub min_header_bits: u32,
    /// Can header exceed minimum?
    #[serde(default)]
    pub is_variable_length: bool,
    /// Ordered fields (by bit offset)
    #[serde(default)]
    pub fields: Vec<FieldDef>,

    /// Which field carries next protocol identifier (None for leaf protocols)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatch_field: Option<String>,
    /// Protocol dispatch table
    #[serde(default)]
    pub dispatch_table: Vec<DispatchEntry>,

    /// How this protocol is identified from parent protocols.
    /// e.g., {"ethertype": [2048], "ip_proto": [6]}
    #[serde(default)]
    pub identifiers: BTreeMap<String, Vec<u32>>,

    /// Per-source metadata
    #[serde(default)]
    pub sources: BTreeMap<String, SourceInfo>,
}

/// What one source says about this protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceInfo {
    /// Whether this source has a definition for the protocol
    pub present: bool,
    /// Path to the source file (if applicable)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    /// Source-specific name: "xdp2_parse_ipv4" / "IP" / "iphdr" / "ip"
    #[serde(default)]
    pub source_name: String,
    /// Number of fields defined by this source
    #[serde(default)]
    pub field_count: u32,
    /// Minimum header size in bytes
    #[serde(default)]
    pub min_header_bytes: u32,
    /// Additional notes
    #[serde(default)]
    pub notes: Vec<String>,
}

/// Result of comparing a field across sources.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldComparison {
    /// Canonical field name
    pub name: String,
    /// Bit offset (consensus or first-seen)
    pub offset_bits: u32,
    /// Field width in bits
    pub size_bits: u32,
    /// Which sources fully agree (offset+size+type+endian)
    pub sources_agree: Vec<String>,
    /// Which sources structurally agree (offset+size match, type/endian may differ)
    #[serde(default)]
    pub sources_structural: Vec<String>,
    /// Which sources disagree (with details)
    pub mismatches: Vec<FieldMismatch>,
}

/// A specific mismatch between sources for a field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldMismatch {
    pub source: String,
    pub field: String,
    pub expected: String,
    pub actual: String,
}

/// Overall audit result for a protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditResult {
    pub protocol: String,
    pub sources_present: Vec<String>,
    pub sources_missing: Vec<String>,
    pub field_comparisons: Vec<FieldComparison>,
    pub total_fields: u32,
    pub fields_agree: u32,
    /// Fields where sources match on offset+size but disagree on type/endian
    #[serde(default)]
    pub fields_type_differ: u32,
    pub fields_mismatch: u32,
    pub fields_missing: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ipv4() -> ProtocolDef {
        ProtocolDef {
            name: "IPv4".to_string(),
            min_header_bits: 160,
            is_variable_length: true,
            fields: vec![
                FieldDef {
                    name: "version".to_string(),
                    offset_bits: 0,
                    size_bits: 4,
                    field_type: FieldType::Uint,
                    endian: Endian::Na,
                    description: "IP version (always 4)".to_string(),
                    is_dispatch: false,
                    is_length: false,
                    length_multiplier: None,
                    source_names: BTreeMap::from([
                        ("kernel".into(), "version".into()),
                        ("scapy".into(), "version".into()),
                        ("tshark".into(), "ip.version".into()),
                    ]),
                    default_value: None,
                    flag_names: None,
                },
                FieldDef {
                    name: "ihl".to_string(),
                    offset_bits: 4,
                    size_bits: 4,
                    field_type: FieldType::Uint,
                    endian: Endian::Na,
                    description: "Internet Header Length (in 32-bit words)".to_string(),
                    is_dispatch: false,
                    is_length: true,
                    length_multiplier: Some(4),
                    source_names: BTreeMap::from([
                        ("kernel".into(), "ihl".into()),
                        ("scapy".into(), "ihl".into()),
                        ("tshark".into(), "ip.hdr_len".into()),
                    ]),
                    default_value: None,
                    flag_names: None,
                },
                FieldDef {
                    name: "tos".to_string(),
                    offset_bits: 8,
                    size_bits: 8,
                    field_type: FieldType::Uint,
                    endian: Endian::Na,
                    description: "Type of Service / DSCP + ECN".to_string(),
                    is_dispatch: false,
                    is_length: false,
                    length_multiplier: None,
                    source_names: BTreeMap::from([
                        ("kernel".into(), "tos".into()),
                        ("scapy".into(), "tos".into()),
                        ("tshark".into(), "ip.dsfield".into()),
                    ]),
                    default_value: None,
                    flag_names: None,
                },
                FieldDef {
                    name: "total_length".to_string(),
                    offset_bits: 16,
                    size_bits: 16,
                    field_type: FieldType::Uint,
                    endian: Endian::Big,
                    description: "Total packet length in bytes".to_string(),
                    is_dispatch: false,
                    is_length: false,
                    length_multiplier: None,
                    source_names: BTreeMap::from([
                        ("kernel".into(), "tot_len".into()),
                        ("scapy".into(), "len".into()),
                        ("tshark".into(), "ip.len".into()),
                    ]),
                    default_value: None,
                    flag_names: None,
                },
                FieldDef {
                    name: "identification".to_string(),
                    offset_bits: 32,
                    size_bits: 16,
                    field_type: FieldType::Uint,
                    endian: Endian::Big,
                    description: "Fragment identification".to_string(),
                    is_dispatch: false,
                    is_length: false,
                    length_multiplier: None,
                    source_names: BTreeMap::from([
                        ("kernel".into(), "id".into()),
                        ("scapy".into(), "id".into()),
                        ("tshark".into(), "ip.id".into()),
                    ]),
                    default_value: None,
                    flag_names: None,
                },
                FieldDef {
                    name: "flags".to_string(),
                    offset_bits: 48,
                    size_bits: 3,
                    field_type: FieldType::Flags,
                    endian: Endian::Na,
                    description: "IP flags (Reserved, DF, MF)".to_string(),
                    is_dispatch: false,
                    is_length: false,
                    length_multiplier: None,
                    source_names: BTreeMap::from([
                        ("kernel".into(), "frag_off(high bits)".into()),
                        ("scapy".into(), "flags".into()),
                        ("tshark".into(), "ip.flags".into()),
                    ]),
                    default_value: None,
                    flag_names: None,
                },
                FieldDef {
                    name: "fragment_offset".to_string(),
                    offset_bits: 51,
                    size_bits: 13,
                    field_type: FieldType::Uint,
                    endian: Endian::Big,
                    description: "Fragment offset (in 8-byte units)".to_string(),
                    is_dispatch: false,
                    is_length: false,
                    length_multiplier: None,
                    source_names: BTreeMap::from([
                        ("kernel".into(), "frag_off(low bits)".into()),
                        ("scapy".into(), "frag".into()),
                        ("tshark".into(), "ip.frag_offset".into()),
                    ]),
                    default_value: None,
                    flag_names: None,
                },
                FieldDef {
                    name: "ttl".to_string(),
                    offset_bits: 64,
                    size_bits: 8,
                    field_type: FieldType::Uint,
                    endian: Endian::Na,
                    description: "Time to Live".to_string(),
                    is_dispatch: false,
                    is_length: false,
                    length_multiplier: None,
                    source_names: BTreeMap::from([
                        ("kernel".into(), "ttl".into()),
                        ("scapy".into(), "ttl".into()),
                        ("tshark".into(), "ip.ttl".into()),
                    ]),
                    default_value: None,
                    flag_names: None,
                },
                FieldDef {
                    name: "protocol".to_string(),
                    offset_bits: 72,
                    size_bits: 8,
                    field_type: FieldType::Enum,
                    endian: Endian::Na,
                    description: "Next-layer protocol number".to_string(),
                    is_dispatch: true,
                    is_length: false,
                    length_multiplier: None,
                    source_names: BTreeMap::from([
                        ("kernel".into(), "protocol".into()),
                        ("scapy".into(), "proto".into()),
                        ("tshark".into(), "ip.proto".into()),
                        ("xdp2".into(), "protocol".into()),
                    ]),
                    default_value: None,
                    flag_names: None,
                },
                FieldDef {
                    name: "checksum".to_string(),
                    offset_bits: 80,
                    size_bits: 16,
                    field_type: FieldType::Uint,
                    endian: Endian::Big,
                    description: "Header checksum".to_string(),
                    is_dispatch: false,
                    is_length: false,
                    length_multiplier: None,
                    source_names: BTreeMap::from([
                        ("kernel".into(), "check".into()),
                        ("scapy".into(), "chksum".into()),
                        ("tshark".into(), "ip.checksum".into()),
                    ]),
                    default_value: None,
                    flag_names: None,
                },
                FieldDef {
                    name: "src_addr".to_string(),
                    offset_bits: 96,
                    size_bits: 32,
                    field_type: FieldType::Ipv4Addr,
                    endian: Endian::Big,
                    description: "Source IP address".to_string(),
                    is_dispatch: false,
                    is_length: false,
                    length_multiplier: None,
                    source_names: BTreeMap::from([
                        ("kernel".into(), "saddr".into()),
                        ("scapy".into(), "src".into()),
                        ("tshark".into(), "ip.src".into()),
                        ("xdp2".into(), "saddr".into()),
                    ]),
                    default_value: None,
                    flag_names: None,
                },
                FieldDef {
                    name: "dst_addr".to_string(),
                    offset_bits: 128,
                    size_bits: 32,
                    field_type: FieldType::Ipv4Addr,
                    endian: Endian::Big,
                    description: "Destination IP address".to_string(),
                    is_dispatch: false,
                    is_length: false,
                    length_multiplier: None,
                    source_names: BTreeMap::from([
                        ("kernel".into(), "daddr".into()),
                        ("scapy".into(), "dst".into()),
                        ("tshark".into(), "ip.dst".into()),
                        ("xdp2".into(), "daddr".into()),
                    ]),
                    default_value: None,
                    flag_names: None,
                },
            ],
            dispatch_field: Some("protocol".to_string()),
            dispatch_table: vec![
                DispatchEntry {
                    value: 1,
                    protocol: "ICMP".to_string(),
                    sources: vec!["kernel".into(), "scapy".into(), "tshark".into()],
                },
                DispatchEntry {
                    value: 6,
                    protocol: "TCP".to_string(),
                    sources: vec!["kernel".into(), "scapy".into(), "tshark".into()],
                },
                DispatchEntry {
                    value: 17,
                    protocol: "UDP".to_string(),
                    sources: vec!["kernel".into(), "scapy".into(), "tshark".into()],
                },
                DispatchEntry {
                    value: 47,
                    protocol: "GRE".to_string(),
                    sources: vec!["kernel".into(), "scapy".into(), "tshark".into()],
                },
            ],
            identifiers: BTreeMap::from([("ethertype".into(), vec![2048])]),
            sources: BTreeMap::from([
                (
                    "xdp2".into(),
                    SourceInfo {
                        present: true,
                        file_path: Some("ip/proto_ipv4.h".into()),
                        source_name: "xdp2_parse_ipv4".into(),
                        field_count: 0,
                        min_header_bytes: 20,
                        notes: vec![
                            "Fields come from kernel struct iphdr, not defined in proto_def directly".into(),
                        ],
                    },
                ),
                (
                    "kernel".into(),
                    SourceInfo {
                        present: true,
                        file_path: Some("include/uapi/linux/ip.h".into()),
                        source_name: "iphdr".into(),
                        field_count: 12,
                        min_header_bytes: 20,
                        notes: vec![],
                    },
                ),
                (
                    "scapy".into(),
                    SourceInfo {
                        present: true,
                        file_path: Some("scapy/layers/inet.py".into()),
                        source_name: "IP".into(),
                        field_count: 13,
                        min_header_bytes: 20,
                        notes: vec![],
                    },
                ),
                (
                    "tshark".into(),
                    SourceInfo {
                        present: true,
                        file_path: None,
                        source_name: "ip".into(),
                        field_count: 12,
                        min_header_bytes: 20,
                        notes: vec![],
                    },
                ),
            ]),
        }
    }

    #[test]
    fn test_ir_json_roundtrip() {
        let proto = sample_ipv4();
        let json = serde_json::to_string_pretty(&proto).unwrap();
        let parsed: ProtocolDef = serde_json::from_str(&json).unwrap();
        assert_eq!(proto, parsed);
    }

    #[test]
    fn test_ir_field_count() {
        let proto = sample_ipv4();
        assert_eq!(proto.fields.len(), 12);
    }

    #[test]
    fn test_ir_dispatch_field() {
        let proto = sample_ipv4();
        assert_eq!(proto.dispatch_field, Some("protocol".to_string()));
        let dispatch = proto
            .fields
            .iter()
            .find(|f| f.is_dispatch)
            .expect("should have dispatch field");
        assert_eq!(dispatch.name, "protocol");
        assert_eq!(dispatch.offset_bits, 72);
        assert_eq!(dispatch.size_bits, 8);
    }

    #[test]
    fn test_ir_length_field() {
        let proto = sample_ipv4();
        let ihl = proto
            .fields
            .iter()
            .find(|f| f.is_length)
            .expect("should have length field");
        assert_eq!(ihl.name, "ihl");
        assert_eq!(ihl.length_multiplier, Some(4));
    }

    #[test]
    fn test_ir_total_bits() {
        let proto = sample_ipv4();
        let last = proto.fields.last().unwrap();
        let total = last.offset_bits + last.size_bits;
        assert_eq!(total, 160); // 20 bytes
        assert_eq!(proto.min_header_bits, 160);
    }

    #[test]
    fn test_ir_source_names() {
        let proto = sample_ipv4();
        let src_addr = proto.fields.iter().find(|f| f.name == "src_addr").unwrap();
        assert_eq!(src_addr.source_names.get("kernel"), Some(&"saddr".into()));
        assert_eq!(src_addr.source_names.get("scapy"), Some(&"src".into()));
        assert_eq!(src_addr.source_names.get("tshark"), Some(&"ip.src".into()));
    }

    #[test]
    fn test_ir_identifiers() {
        let proto = sample_ipv4();
        assert_eq!(proto.identifiers.get("ethertype"), Some(&vec![2048]));
    }
}
