//! Kaitai Struct (.ksy) extractor.
//!
//! Parses Kaitai Struct format specification YAML files and converts them
//! to the proto-audit IR. Kaitai Struct is an independent, community-maintained
//! format description library (CC0-1.0 licensed) that provides a 7th
//! independent source for cross-verification of protocol header definitions.
//!
//! Kaitai Struct types map to IR as follows:
//! - `u1`/`s1` → 8 bits, `u2`/`s2` → 16 bits, `u4`/`s4` → 32 bits, `u8`/`s8` → 64 bits
//! - `bN` → N bits (bit-level fields)
//! - `size: N` → N*8 bits raw bytes
//! - Endianness from `meta.endian` or per-field suffix (`u2be`, `u2le`)

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::ir::{Endian, FieldDef, FieldType, ProtocolDef, SourceInfo};

// ── .ksy YAML structures ──

#[derive(Debug, Deserialize)]
struct KsyFile {
    meta: KsyMeta,
    #[serde(default)]
    doc: Option<String>,
    #[serde(default)]
    seq: Vec<KsyField>,
    #[serde(default)]
    types: BTreeMap<String, KsyType>,
    #[serde(default)]
    enums: BTreeMap<String, BTreeMap<String, serde_yaml::Value>>,
}

#[derive(Debug, Deserialize)]
struct KsyMeta {
    id: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    endian: Option<String>,
    #[serde(default)]
    xref: Option<KsyXref>,
}

#[derive(Debug, Deserialize)]
struct KsyXref {
    #[serde(default)]
    rfc: Option<serde_yaml::Value>,
    #[serde(default)]
    ieee: Option<serde_yaml::Value>,
    #[serde(default)]
    wikidata: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KsyField {
    id: String,
    #[serde(default, rename = "type")]
    field_type: Option<serde_yaml::Value>,
    #[serde(default)]
    size: Option<serde_yaml::Value>,
    #[serde(default)]
    doc: Option<String>,
    #[serde(default, rename = "enum")]
    enum_ref: Option<String>,
    #[serde(default, rename = "if")]
    condition: Option<serde_yaml::Value>,
    #[serde(default)]
    repeat: Option<String>,
    #[serde(default, rename = "size-eos")]
    size_eos: Option<bool>,
    #[serde(default)]
    contents: Option<serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
struct KsyType {
    #[serde(default)]
    seq: Vec<KsyField>,
}

// ── Public API ──

/// Extract a protocol definition from a .ksy file.
pub fn extract_from_ksy(path: &Path) -> Result<Option<ProtocolDef>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    let ksy: KsyFile = serde_yaml::from_str(&content)
        .with_context(|| format!("parsing YAML from {}", path.display()))?;

    let default_endian = match ksy.meta.endian.as_deref() {
        Some("be") => Endian::Big,
        Some("le") => Endian::Little,
        _ => Endian::Big, // network protocols default to big-endian
    };

    let mut fields = Vec::new();
    let mut offset_bits: u32 = 0;

    for field in &ksy.seq {
        // Skip conditional fields — they're not always present in the header
        if field.condition.is_some() {
            continue;
        }
        // Skip repeated fields — variable length
        if field.repeat.is_some() {
            continue;
        }
        // Skip size-eos fields — consume rest of stream
        if field.size_eos == Some(true) {
            continue;
        }

        let field_type_str = field.field_type.as_ref().and_then(|v| match v {
            serde_yaml::Value::String(s) => Some(s.as_str()),
            _ => None, // switch-on/cases mapping — skip
        });

        let (size_bits, field_endian, ir_type, is_signed) = if let Some(ty) = field_type_str {
            resolve_type(ty, &default_endian, &ksy.types)
        } else if let Some(ref sz) = field.size {
            // Fixed-size byte field
            let bytes = yaml_to_u32(sz).unwrap_or(0);
            if bytes == 0 {
                continue; // expression-based size, skip
            }
            (bytes * 8, default_endian.clone(), FieldType::Bytes, false)
        } else if field.contents.is_some() {
            // Magic bytes — figure out size from contents
            let size = contents_size(&field.contents);
            if size == 0 { continue; }
            (size * 8, Endian::Na, FieldType::Bytes, false)
        } else {
            continue; // no type info, skip
        };

        if size_bits == 0 {
            continue;
        }

        // Determine semantic type
        let semantic_type = if field.enum_ref.is_some() {
            FieldType::Enum
        } else {
            match size_bits {
                48 if field.id.contains("mac") || field.id.contains("addr") || field.id.contains("hw") => {
                    FieldType::MacAddr
                }
                32 if field.id.contains("ip") && field.id.contains("addr") => FieldType::Ipv4Addr,
                128 if field.id.contains("ip") && field.id.contains("addr") => FieldType::Ipv6Addr,
                _ if is_signed => FieldType::Sint,
                _ => ir_type,
            }
        };

        // Endian for sub-byte or single-byte fields
        let endian = if size_bits <= 8 {
            Endian::Na
        } else {
            field_endian
        };

        let mut source_names = BTreeMap::new();
        source_names.insert("kaitai".to_string(), field.id.clone());

        fields.push(FieldDef {
            name: field.id.clone(),
            offset_bits,
            size_bits,
            field_type: semantic_type,
            endian,
            description: field.doc.clone().unwrap_or_default(),
            is_dispatch: false,
            is_length: field.id.contains("len") || field.id.contains("length"),
            length_multiplier: None,
            source_names,
            default_value: None,
            flag_names: None,
        });

        offset_bits += size_bits;
    }

    if fields.is_empty() {
        return Ok(None);
    }

    let name = ksy.meta.title.unwrap_or_else(|| ksy.meta.id.clone());
    let file_name = path.file_name().unwrap_or_default().to_string_lossy();

    let mut sources = BTreeMap::new();
    sources.insert(
        "kaitai".to_string(),
        SourceInfo::new(&ksy.meta.id)
            .with_file(file_name.to_string()),
    );

    Ok(Some(ProtocolDef {
        name,
        min_header_bits: offset_bits,
        is_variable_length: ksy.seq.iter().any(|f| {
            f.condition.is_some() || f.repeat.is_some() || f.size_eos == Some(true)
        }),
        fields,
        dispatch_field: None,
        dispatch_table: Vec::new(),
        identifiers: BTreeMap::new(),
        sources,
        generation_source: Some("kaitai".to_string()),
        standards: Vec::new(),
        iana_registries: BTreeMap::new(),
        layer: None,
    }))
}

/// Scan a Kaitai Struct formats directory for network protocol .ksy files.
/// Returns a list of (canonical_name, path) pairs.
pub fn scan_kaitai_dir(dir: &Path) -> Result<Vec<(String, std::path::PathBuf)>> {
    let network_dir = dir.join("network");
    let mut results = Vec::new();

    if !network_dir.is_dir() {
        return Ok(results);
    }

    for entry in std::fs::read_dir(&network_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "ksy") {
            let stem = path.file_stem().unwrap_or_default().to_string_lossy();
            // Convert kaitai id to a display name
            let name = ksy_id_to_display_name(&stem);
            results.push((name, path));
        }
    }

    results.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(results)
}

// ── Internal helpers ──

/// Resolve a Kaitai type string to (size_bits, endian, field_type, is_signed).
fn resolve_type(
    ty: &str,
    default_endian: &Endian,
    types: &BTreeMap<String, KsyType>,
) -> (u32, Endian, FieldType, bool) {
    // Bit-level fields: b1, b2, ..., b64
    if ty.starts_with('b') && ty.len() > 1 {
        if let Ok(bits) = ty[1..].parse::<u32>() {
            if bits <= 64 {
                return (bits, Endian::Na, FieldType::Uint, false);
            }
        }
    }

    // Standard integer types
    let (base, explicit_endian) = match ty {
        // Unsigned
        "u1" => return (8, Endian::Na, FieldType::Uint, false),
        "u2" => (16u32, None),
        "u2be" => (16, Some(Endian::Big)),
        "u2le" => (16, Some(Endian::Little)),
        "u4" => (32, None),
        "u4be" => (32, Some(Endian::Big)),
        "u4le" => (32, Some(Endian::Little)),
        "u8" => (64, None),
        "u8be" => (64, Some(Endian::Big)),
        "u8le" => (64, Some(Endian::Little)),
        // Signed
        "s1" => return (8, Endian::Na, FieldType::Sint, true),
        "s2" => (16, None),
        "s2be" => (16, Some(Endian::Big)),
        "s2le" => (16, Some(Endian::Little)),
        "s4" => (32, None),
        "s4be" => (32, Some(Endian::Big)),
        "s4le" => (32, Some(Endian::Little)),
        "s8" => (64, None),
        "s8be" => (64, Some(Endian::Big)),
        "s8le" => (64, Some(Endian::Little)),
        // Named type — try to resolve from `types` section
        _ => {
            if let Some(sub_type) = types.get(ty) {
                let mut total_bits = 0u32;
                for f in &sub_type.seq {
                    if let Some(ft_str) = f.field_type.as_ref().and_then(|v| v.as_str()) {
                        let (bits, _, _, _) = resolve_type(ft_str, default_endian, types);
                        total_bits += bits;
                    } else if let Some(ref sz) = f.size {
                        total_bits += yaml_to_u32(sz).unwrap_or(0) * 8;
                    }
                }
                if total_bits > 0 {
                    return (total_bits, default_endian.clone(), FieldType::Bytes, false);
                }
            }
            return (0, default_endian.clone(), FieldType::Bytes, false);
        }
    };

    let endian = explicit_endian.unwrap_or_else(|| default_endian.clone());
    let ft = if base <= 8 { FieldType::Uint } else { FieldType::Uint };
    let signed = ty.starts_with('s');
    (base, endian, if signed { FieldType::Sint } else { ft }, signed)
}

/// Try to extract a u32 from a YAML value (handles integer and string).
fn yaml_to_u32(v: &serde_yaml::Value) -> Option<u32> {
    match v {
        serde_yaml::Value::Number(n) => n.as_u64().map(|n| n as u32),
        serde_yaml::Value::String(s) => {
            if let Some(hex) = s.strip_prefix("0x") {
                u32::from_str_radix(hex, 16).ok()
            } else {
                s.parse().ok()
            }
        }
        _ => None,
    }
}

/// Compute size in bytes from a `contents` field.
fn contents_size(contents: &Option<serde_yaml::Value>) -> u32 {
    match contents {
        Some(serde_yaml::Value::Sequence(seq)) => seq.len() as u32,
        Some(serde_yaml::Value::String(s)) => s.len() as u32,
        _ => 0,
    }
}

/// Convert kaitai_struct_formats id to display name.
/// "ethernet_frame" → "Ethernet", "ipv4_packet" → "IPv4", "tcp_segment" → "TCP"
fn ksy_id_to_display_name(id: &str) -> String {
    // Strip common suffixes
    let name = id
        .trim_end_matches("_packet")
        .trim_end_matches("_frame")
        .trim_end_matches("_segment")
        .trim_end_matches("_datagram")
        .trim_end_matches("_header");

    // Known canonical name mappings
    match name {
        "ethernet" => "Ethernet".to_string(),
        "ipv4" => "IPv4".to_string(),
        "ipv6" => "IPv6".to_string(),
        "tcp" => "TCP".to_string(),
        "udp" => "UDP".to_string(),
        "icmp" => "ICMPv4".to_string(),
        "dns" => "DNS".to_string(),
        "tls_client_hello" => "TLS_ClientHello".to_string(),
        "protocol_body" => "ProtocolBody".to_string(),
        "some_ip" | "someip" => "SOME/IP".to_string(),
        "rtp" => "RTP".to_string(),
        "rtcp" => "RTCP".to_string(),
        "websocket" => "WebSocket".to_string(),
        "bitcoin" => "Bitcoin".to_string(),
        "vlan" | "ieee_802_1q" => "VLAN".to_string(),
        _ => {
            // Default: capitalize first letter of each word
            name.split('_')
                .map(|w| {
                    let mut c = w.chars();
                    match c.next() {
                        None => String::new(),
                        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                    }
                })
                .collect::<Vec<_>>()
                .join("")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ksy_id_to_display_name() {
        assert_eq!(ksy_id_to_display_name("ethernet_frame"), "Ethernet");
        assert_eq!(ksy_id_to_display_name("ipv4_packet"), "IPv4");
        assert_eq!(ksy_id_to_display_name("tcp_segment"), "TCP");
        assert_eq!(ksy_id_to_display_name("udp_datagram"), "UDP");
        assert_eq!(ksy_id_to_display_name("dns_packet"), "DNS");
        assert_eq!(ksy_id_to_display_name("some_ip"), "SOME/IP");
    }

    #[test]
    fn test_resolve_type() {
        let types = BTreeMap::new();
        let be = Endian::Big;

        assert_eq!(resolve_type("u1", &be, &types).0, 8);
        assert_eq!(resolve_type("u2", &be, &types).0, 16);
        assert_eq!(resolve_type("u4", &be, &types).0, 32);
        assert_eq!(resolve_type("u8", &be, &types).0, 64);
        assert_eq!(resolve_type("b4", &be, &types).0, 4);
        assert_eq!(resolve_type("b1", &be, &types).0, 1);
        assert_eq!(resolve_type("s2", &be, &types).3, true);
        assert_eq!(resolve_type("u2le", &be, &types).1, Endian::Little);
    }
}
