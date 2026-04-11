//! Parser IR (JSON) types.
//!
//! The Parser IR is a JSON format that describes protocol parse graphs
//! declaratively. The C++ compiler can emit this format, and this Rust
//! compiler can consume it — decoupling graph construction from Clang AST.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `ParserIr` | `documentation/parser-ir.md` | Top-level JSON structure |
//! | `ParserDef` | `graph.h:761-799` | `parser<G>` struct |
//! | `ParseNodeDef` | `graph.h:195-323` | `vertex_property` struct |
//! | `ProtoTableDef` | `graph.h:325-330` | `edge_property` + table |
//! | `HdrLengthDef` | `graph.h:234-240` | Length extraction fields |
//! | `NextProtoDef` | `graph.h:248-260` | Next protocol extraction |
//! | `TlvParseNodeDef` | `graph.h:81-180` | `tlv_node` struct |
//! | `FlagFieldDef` | `graph.h:182-193` | `flag_fields_node` struct |

use serde::{Deserialize, Serialize};

/// Top-level Parser IR document.
///
/// Reimplements: JSON IR format from `documentation/parser-ir.md`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ParserIr {
    /// Parser configurations (typically one per IR file).
    #[serde(default)]
    pub parsers: Vec<ParserDef>,

    /// Protocol parse node definitions.
    #[serde(default)]
    pub parse_nodes: Vec<ParseNodeDef>,

    /// Protocol dispatch tables (key → next node).
    #[serde(default)]
    pub proto_tables: Vec<ProtoTableDef>,

    /// TLV tables (TLV type → TLV node).
    #[serde(default)]
    pub tlv_tables: Vec<TlvTableDef>,

    /// Flag-field tables.
    #[serde(default)]
    pub flag_fields_tables: Vec<FlagFieldsTableDef>,
}

/// Parser configuration.
///
/// Reimplements: `parser<G>` in `graph.h:761-799`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ParserDef {
    pub name: String,
    pub root_node: String,

    #[serde(default)]
    pub okay_target: Option<String>,
    #[serde(default)]
    pub fail_target: Option<String>,
    #[serde(default)]
    pub encap_target: Option<String>,

    #[serde(default = "default_max_nodes")]
    pub max_nodes: u32,
    #[serde(default = "default_max_encaps")]
    pub max_encaps: u32,
    #[serde(default = "default_max_frames")]
    pub max_frames: u32,
    #[serde(default)]
    pub frame_size: u32,
    #[serde(default)]
    pub metameta_size: u32,
    #[serde(default)]
    pub num_counters: u32,
    #[serde(default)]
    pub num_keys: u32,
}

fn default_max_nodes() -> u32 {
    255
}
fn default_max_encaps() -> u32 {
    4
}
fn default_max_frames() -> u32 {
    4
}

/// Protocol parse node definition.
///
/// Reimplements: `vertex_property` in `graph.h:195-323`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ParseNodeDef {
    pub name: String,

    #[serde(default)]
    pub min_hdr_length: usize,

    /// Variable header length extraction (if header is not fixed-size).
    #[serde(default)]
    pub hdr_length: Option<HdrLengthDef>,

    /// Next protocol extraction and dispatch table entries.
    #[serde(default)]
    pub next_proto: Option<NextProtoDef>,

    /// Protocol dispatch table name (alternative to inline entries).
    #[serde(default)]
    pub table: Option<String>,

    /// Whether this is an overlay node (consumes no bytes).
    #[serde(default)]
    pub overlay: bool,

    /// Whether this is an encapsulation boundary.
    #[serde(default)]
    pub encap: bool,

    /// Handler function name.
    #[serde(default)]
    pub handler: Option<String>,

    /// Metadata extraction function name.
    #[serde(default)]
    pub metadata: Option<String>,

    /// Post-handler function name.
    #[serde(default)]
    pub post_handler: Option<String>,

    /// TLV parsing configuration.
    #[serde(default)]
    pub tlvs_parse_node: Option<TlvsParseNodeDef>,

    /// Flag-fields parsing configuration.
    #[serde(default)]
    pub flag_fields_parse_node: Option<FlagFieldsParseNodeDef>,

    /// Array parsing configuration.
    #[serde(default)]
    pub array_parse_node: Option<ArrayParseNodeDef>,

    /// Return code for unknown protocol values.
    #[serde(default)]
    pub unknown_proto_ret: Option<i32>,

    /// Wildcard node for unmatched protocol values.
    #[serde(default)]
    pub wildcard_proto_node: Option<String>,
}

/// Header length extraction from packet bytes.
///
/// Extracts a field from the header, optionally masks and shifts it,
/// then multiplies to get the header length in bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HdrLengthDef {
    /// Byte offset of the length field within the header.
    pub field_off: usize,
    /// Size of the length field in bytes (1, 2, or 4).
    pub field_len: usize,
    /// Bitmask to apply after reading (e.g., "0xf" for IHL).
    #[serde(default)]
    pub mask: Option<String>,
    /// Right-shift amount after masking.
    #[serde(default)]
    pub shift: Option<u32>,
    /// Multiplier (e.g., 4 for IHL*4).
    #[serde(default = "default_multiplier")]
    pub multiplier: u32,
    /// Addend after multiplication (e.g., for (hdrlen+2)*4).
    #[serde(default)]
    pub add: Option<i32>,
}

fn default_multiplier() -> u32 {
    1
}

/// Next protocol extraction and dispatch entries.
///
/// Reimplements: next_proto fields in `vertex_property`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NextProtoDef {
    /// Byte offset of the protocol field.
    pub field_off: usize,
    /// Size of the protocol field in bytes (1, 2, or 4).
    pub field_len: usize,
    /// Bitmask to apply.
    #[serde(default)]
    pub mask: Option<String>,
    /// Dispatch table entries (inline).
    #[serde(default)]
    pub ents: Vec<ProtoTableEntry>,
}

/// A single dispatch table entry: key → next node name.
///
/// Reimplements: `edge_property` in `graph.h:325-330`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProtoTableEntry {
    /// Dispatch key (numeric or hex string like "0x0800").
    pub key: serde_json::Value,
    /// Destination parse node name.
    pub node: String,
}

impl ProtoTableEntry {
    /// Parse the key as an integer (handles both numeric and hex string).
    pub fn key_value(&self) -> Option<i64> {
        match &self.key {
            serde_json::Value::Number(n) => n.as_i64(),
            serde_json::Value::String(s) => {
                let s = s.trim();
                if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                    i64::from_str_radix(hex, 16).ok()
                } else {
                    s.parse().ok()
                }
            }
            _ => None,
        }
    }
}

/// Named protocol dispatch table.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProtoTableDef {
    pub name: String,
    pub entries: Vec<ProtoTableEntry>,
}

/// TLV field extraction descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TlvFieldDef {
    pub field_off: usize,
    pub field_len: usize,
    #[serde(default)]
    pub mask: Option<String>,
}

/// TLV parsing configuration for a parse node.
///
/// Reimplements: TLV fields in `vertex_property` and `ParseTlvsNode`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TlvsParseNodeDef {
    pub tlv_type: TlvFieldDef,
    pub tlv_length: TlvFieldDef,

    #[serde(default)]
    pub tlv_start_offset: Option<TlvFieldDef>,

    /// PAD1 type value (single-byte padding, no length field).
    #[serde(default)]
    pub pad1: Option<u32>,

    /// EOL (end-of-list) type value.
    #[serde(default)]
    pub eol: Option<u32>,

    /// TLV table name for type dispatch.
    #[serde(default)]
    pub table: Option<String>,

    /// Maximum number of TLVs to parse.
    #[serde(default)]
    pub max_tlvs: Option<u32>,

    /// Minimum TLV length.
    #[serde(default)]
    pub min_tlv_len: Option<usize>,
}

/// A single TLV table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TlvTableEntry {
    pub key: u32,
    pub name: String,
    #[serde(default)]
    pub min_len: Option<usize>,
    #[serde(default)]
    pub handler: Option<String>,
    #[serde(default)]
    pub metadata: Option<String>,
}

/// Named TLV table.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TlvTableDef {
    pub name: String,
    pub entries: Vec<TlvTableEntry>,
}

/// Flag-fields parsing configuration for a parse node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FlagFieldsParseNodeDef {
    /// Table name for flag field dispatch.
    pub table: String,
    /// Function/expression to get the flags value.
    #[serde(default)]
    pub get_flags: Option<String>,
    /// Offset where flag-dependent fields start.
    #[serde(default)]
    pub start_fields_offset: Option<usize>,
}

/// A single flag-field definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FlagFieldEntry {
    pub name: String,
    pub flag: u32,
    #[serde(default)]
    pub mask: Option<u32>,
    pub size: usize,
    #[serde(default)]
    pub handler: Option<String>,
    #[serde(default)]
    pub metadata: Option<String>,
}

/// Named flag-fields table.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FlagFieldsTableDef {
    pub name: String,
    pub entries: Vec<FlagFieldEntry>,
}

/// Array parsing configuration for a parse node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ArrayParseNodeDef {
    /// Table name for array element dispatch.
    pub table: String,
    /// Maximum number of array elements.
    #[serde(default)]
    pub max_els: Option<u32>,
    /// Element length in bytes.
    #[serde(default)]
    pub el_length: Option<usize>,
}

impl ParserIr {
    /// Deserialize from JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize to pretty-printed JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Find a parse node by name.
    pub fn find_node(&self, name: &str) -> Option<&ParseNodeDef> {
        self.parse_nodes.iter().find(|n| n.name == name)
    }

    /// Find a proto table by name.
    pub fn find_proto_table(&self, name: &str) -> Option<&ProtoTableDef> {
        self.proto_tables.iter().find(|t| t.name == name)
    }

    /// Find a TLV table by name.
    pub fn find_tlv_table(&self, name: &str) -> Option<&TlvTableDef> {
        self.tlv_tables.iter().find(|t| t.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_IR: &str = r#"{
        "parsers": [{
            "name": "test_parser",
            "root-node": "eth_node",
            "okay-target": "okay",
            "max-nodes": 128
        }],
        "parse-nodes": [
            {
                "name": "eth_node",
                "min-hdr-length": 14,
                "next-proto": {
                    "field-off": 12,
                    "field-len": 2,
                    "ents": [
                        {"key": "0x0800", "node": "ipv4_node"},
                        {"key": "0x86DD", "node": "ipv6_node"}
                    ]
                }
            },
            {
                "name": "ipv4_node",
                "min-hdr-length": 20,
                "hdr-length": {
                    "field-off": 0,
                    "field-len": 1,
                    "mask": "0xf",
                    "multiplier": 4
                },
                "next-proto": {
                    "field-off": 9,
                    "field-len": 1,
                    "ents": [
                        {"key": 6, "node": "tcp_node"},
                        {"key": 17, "node": "udp_node"}
                    ]
                }
            },
            {
                "name": "tcp_node",
                "min-hdr-length": 20
            },
            {
                "name": "udp_node",
                "min-hdr-length": 8
            },
            {
                "name": "ipv6_node",
                "min-hdr-length": 40
            }
        ],
        "proto-tables": []
    }"#;

    #[test]
    fn parse_sample_ir() {
        let ir = ParserIr::from_json(SAMPLE_IR).unwrap();
        assert_eq!(ir.parsers.len(), 1);
        assert_eq!(ir.parsers[0].name, "test_parser");
        assert_eq!(ir.parsers[0].root_node, "eth_node");
        assert_eq!(ir.parsers[0].max_nodes, 128);
        assert_eq!(ir.parse_nodes.len(), 5);
    }

    #[test]
    fn parse_hex_keys() {
        let ir = ParserIr::from_json(SAMPLE_IR).unwrap();
        let eth = ir.find_node("eth_node").unwrap();
        let np = eth.next_proto.as_ref().unwrap();
        assert_eq!(np.ents[0].key_value(), Some(0x0800));
        assert_eq!(np.ents[1].key_value(), Some(0x86DD));
    }

    #[test]
    fn parse_numeric_keys() {
        let ir = ParserIr::from_json(SAMPLE_IR).unwrap();
        let ipv4 = ir.find_node("ipv4_node").unwrap();
        let np = ipv4.next_proto.as_ref().unwrap();
        assert_eq!(np.ents[0].key_value(), Some(6));  // TCP
        assert_eq!(np.ents[1].key_value(), Some(17)); // UDP
    }

    #[test]
    fn hdr_length_def() {
        let ir = ParserIr::from_json(SAMPLE_IR).unwrap();
        let ipv4 = ir.find_node("ipv4_node").unwrap();
        let hl = ipv4.hdr_length.as_ref().unwrap();
        assert_eq!(hl.field_off, 0);
        assert_eq!(hl.field_len, 1);
        assert_eq!(hl.mask.as_deref(), Some("0xf"));
        assert_eq!(hl.multiplier, 4);
    }

    #[test]
    fn find_node() {
        let ir = ParserIr::from_json(SAMPLE_IR).unwrap();
        assert!(ir.find_node("tcp_node").is_some());
        assert!(ir.find_node("nonexistent").is_none());
    }

    #[test]
    fn roundtrip_json() {
        let ir = ParserIr::from_json(SAMPLE_IR).unwrap();
        let json = ir.to_json().unwrap();
        let ir2 = ParserIr::from_json(&json).unwrap();
        assert_eq!(ir2.parsers.len(), ir.parsers.len());
        assert_eq!(ir2.parse_nodes.len(), ir.parse_nodes.len());
    }

    #[test]
    fn defaults() {
        let ir: ParserIr = serde_json::from_str(r#"{
            "parsers": [{"name": "p", "root-node": "r"}]
        }"#).unwrap();
        assert_eq!(ir.parsers[0].max_nodes, 255);
        assert_eq!(ir.parsers[0].max_encaps, 4);
        assert_eq!(ir.parsers[0].max_frames, 4);
        assert!(ir.parse_nodes.is_empty());
        assert!(ir.proto_tables.is_empty());
    }
}
