//! Scapy protocol extractor.
//!
//! Scapy definitions are extracted via a Python helper script that
//! introspects `Packet.fields_desc` at runtime and dumps JSON to stdout.
//! This module parses that JSON output into IR types.
//!
//! The Python helper is at `helpers/scapy_dump.py`.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use crate::ir::{Endian, FieldDef, FieldType, ProtocolDef, SourceInfo};

/// Deserialize a number that may be float (e.g., 3.0) as u32.
fn deserialize_u32_from_float<'de, D>(deserializer: D) -> std::result::Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: f64 = Deserialize::deserialize(deserializer)?;
    Ok(v as u32)
}

/// Raw JSON output from the scapy_dump.py helper.
#[derive(Debug, Deserialize)]
pub struct ScapyProtocol {
    /// Scapy class name (e.g., "IP")
    pub name: String,
    /// Module path (e.g., "scapy.layers.inet")
    #[serde(default)]
    pub module: String,
    /// Fields in order
    pub fields: Vec<ScapyField>,
    /// Total minimum header size in bytes
    #[serde(default, deserialize_with = "deserialize_u32_from_float")]
    pub min_bytes: u32,
}

/// A field from Scapy's fields_desc.
#[derive(Debug, Deserialize)]
pub struct ScapyField {
    /// Field name
    pub name: String,
    /// Scapy field class name (e.g., "ByteField", "ShortField", "BitField")
    pub field_class: String,
    /// Size in bits
    #[serde(deserialize_with = "deserialize_u32_from_float")]
    pub size_bits: u32,
    /// Default value (as string)
    #[serde(default)]
    pub default: Option<String>,
}

/// Run the scapy_dump.py helper and parse the output.
///
/// `helper_path` is the path to scapy_dump.py.
/// `protocol` is the Scapy class name (e.g., "IP", "TCP").
/// `python_bin` is the Python interpreter (default: "python3").
pub fn run_scapy_helper(
    helper_path: &Path,
    protocol: &str,
    python_bin: &str,
) -> Result<ScapyProtocol> {
    let output = Command::new(python_bin)
        .arg(helper_path)
        .arg(protocol)
        .output()
        .with_context(|| {
            format!(
                "running scapy helper: {} {} {}",
                python_bin,
                helper_path.display(),
                protocol
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "scapy helper failed for {}: {}",
            protocol,
            stderr.trim()
        );
    }

    let stdout = String::from_utf8(output.stdout)
        .context("scapy helper output is not valid UTF-8")?;
    parse_scapy_json(&stdout)
}

/// Parse scapy JSON output (for testing without subprocess).
pub fn parse_scapy_json(json: &str) -> Result<ScapyProtocol> {
    serde_json::from_str(json).context("parsing scapy JSON output")
}

/// Map a Scapy field class name to our IR FieldType.
fn scapy_field_type(class: &str, name: &str) -> FieldType {
    match class {
        "IPField" | "SourceIPField" | "DestIPField" => FieldType::Ipv4Addr,
        "IP6Field" | "SourceIP6Field" | "DestIP6Field" => FieldType::Ipv6Addr,
        "MACField" | "SourceMACField" | "DestMACField" => FieldType::MacAddr,
        "FlagsField" | "BitField" if name.contains("flags") || name.contains("flag") => {
            FieldType::Flags
        }
        "XByteEnumField" | "ByteEnumField" | "ShortEnumField" | "IntEnumField" => FieldType::Enum,
        "StrField" | "StrFixedLenField" | "PacketField" => FieldType::Bytes,
        "SignedByteField" | "SignedShortField" | "SignedIntField" => FieldType::Sint,
        _ => {
            if name.contains("pad") || name.contains("reserved") {
                FieldType::Pad
            } else {
                FieldType::Uint
            }
        }
    }
}

/// Determine endianness from Scapy field class.
fn scapy_endian(class: &str, bits: u32) -> Endian {
    if bits <= 8 {
        return Endian::Na;
    }
    // LE* fields are little-endian
    if class.starts_with("LE") {
        Endian::Little
    } else {
        // Scapy defaults to big-endian (network byte order)
        Endian::Big
    }
}

/// Convert a ScapyProtocol into an IR ProtocolDef.
pub fn to_protocol_def(sp: &ScapyProtocol) -> ProtocolDef {
    let mut fields = Vec::new();
    let mut offset_bits: u32 = 0;

    for sf in &sp.fields {
        let field_type = scapy_field_type(&sf.field_class, &sf.name);
        let endian = scapy_endian(&sf.field_class, sf.size_bits);

        fields.push(FieldDef {
            name: sf.name.clone(),
            offset_bits,
            size_bits: sf.size_bits,
            field_type,
            endian,
            description: String::new(),
            is_dispatch: false,
            is_length: false,
            length_multiplier: None,
            source_names: BTreeMap::from([("scapy".to_string(), sf.name.clone())]),
        });

        offset_bits += sf.size_bits;
    }

    let field_count = fields.len() as u32;

    ProtocolDef {
        name: sp.name.clone(),
        min_header_bits: offset_bits,
        is_variable_length: false,
        fields,
        dispatch_field: None,
        dispatch_table: vec![],
        identifiers: BTreeMap::new(),
        sources: BTreeMap::from([(
            "scapy".to_string(),
            SourceInfo {
                present: true,
                file_path: if sp.module.is_empty() {
                    None
                } else {
                    Some(sp.module.replace('.', "/") + ".py")
                },
                source_name: sp.name.clone(),
                field_count,
                min_header_bytes: sp.min_bytes,
                notes: vec![],
            },
        )]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_IP_JSON: &str = r#"{
  "name": "IP",
  "module": "scapy.layers.inet",
  "min_bytes": 20,
  "fields": [
    {"name": "version", "field_class": "BitField", "size_bits": 4},
    {"name": "ihl", "field_class": "BitField", "size_bits": 4},
    {"name": "tos", "field_class": "XByteField", "size_bits": 8},
    {"name": "len", "field_class": "ShortField", "size_bits": 16},
    {"name": "id", "field_class": "ShortField", "size_bits": 16},
    {"name": "flags", "field_class": "FlagsField", "size_bits": 3},
    {"name": "frag", "field_class": "BitField", "size_bits": 13},
    {"name": "ttl", "field_class": "ByteField", "size_bits": 8},
    {"name": "proto", "field_class": "ByteEnumField", "size_bits": 8},
    {"name": "chksum", "field_class": "XShortField", "size_bits": 16},
    {"name": "src", "field_class": "SourceIPField", "size_bits": 32},
    {"name": "dst", "field_class": "DestIPField", "size_bits": 32}
  ]
}"#;

    #[test]
    fn test_parse_scapy_json() {
        let sp = parse_scapy_json(SAMPLE_IP_JSON).unwrap();
        assert_eq!(sp.name, "IP");
        assert_eq!(sp.module, "scapy.layers.inet");
        assert_eq!(sp.fields.len(), 12);
        assert_eq!(sp.min_bytes, 20);
    }

    #[test]
    fn test_to_protocol_def() {
        let sp = parse_scapy_json(SAMPLE_IP_JSON).unwrap();
        let proto = to_protocol_def(&sp);

        assert_eq!(proto.name, "IP");
        assert_eq!(proto.fields.len(), 12);
        assert_eq!(proto.min_header_bits, 160); // 20 bytes

        // Check field offsets
        let version = &proto.fields[0];
        assert_eq!(version.offset_bits, 0);
        assert_eq!(version.size_bits, 4);

        let ihl = &proto.fields[1];
        assert_eq!(ihl.offset_bits, 4);
        assert_eq!(ihl.size_bits, 4);

        let tos = &proto.fields[2];
        assert_eq!(tos.offset_bits, 8);
        assert_eq!(tos.size_bits, 8);

        // Check IP address type detection
        let src = proto.fields.iter().find(|f| f.name == "src").unwrap();
        assert_eq!(src.field_type, FieldType::Ipv4Addr);
        assert_eq!(src.size_bits, 32);
        assert_eq!(src.offset_bits, 96);

        let dst = proto.fields.iter().find(|f| f.name == "dst").unwrap();
        assert_eq!(dst.field_type, FieldType::Ipv4Addr);
        assert_eq!(dst.offset_bits, 128);

        // Check enum type detection
        let proto_field = proto.fields.iter().find(|f| f.name == "proto").unwrap();
        assert_eq!(proto_field.field_type, FieldType::Enum);

        // Check flags type detection
        let flags = proto.fields.iter().find(|f| f.name == "flags").unwrap();
        assert_eq!(flags.field_type, FieldType::Flags);
    }

    #[test]
    fn test_scapy_endian() {
        assert_eq!(scapy_endian("ShortField", 16), Endian::Big);
        assert_eq!(scapy_endian("LEShortField", 16), Endian::Little);
        assert_eq!(scapy_endian("ByteField", 8), Endian::Na);
        assert_eq!(scapy_endian("BitField", 4), Endian::Na);
    }

    const SAMPLE_TCP_JSON: &str = r#"{
  "name": "TCP",
  "module": "scapy.layers.inet",
  "min_bytes": 20,
  "fields": [
    {"name": "sport", "field_class": "ShortEnumField", "size_bits": 16},
    {"name": "dport", "field_class": "ShortEnumField", "size_bits": 16},
    {"name": "seq", "field_class": "IntField", "size_bits": 32},
    {"name": "ack", "field_class": "IntField", "size_bits": 32},
    {"name": "dataofs", "field_class": "BitField", "size_bits": 4},
    {"name": "reserved", "field_class": "BitField", "size_bits": 3},
    {"name": "flags", "field_class": "FlagsField", "size_bits": 9},
    {"name": "window", "field_class": "ShortField", "size_bits": 16},
    {"name": "chksum", "field_class": "XShortField", "size_bits": 16},
    {"name": "urgptr", "field_class": "ShortField", "size_bits": 16}
  ]
}"#;

    #[test]
    fn test_tcp_protocol_def() {
        let sp = parse_scapy_json(SAMPLE_TCP_JSON).unwrap();
        let proto = to_protocol_def(&sp);

        assert_eq!(proto.name, "TCP");
        assert_eq!(proto.min_header_bits, 160);

        let reserved = proto.fields.iter().find(|f| f.name == "reserved").unwrap();
        assert_eq!(reserved.field_type, FieldType::Pad);
    }
}
