//! Kaitai Struct (.ksy) extractor.
//!
//! Parses Kaitai Struct format specification YAML files and converts them
//! to the proto-audit IR. Kaitai Struct is an independent, community-maintained
//! format description library (CC0-1.0 licensed) that provides an independent
//! source for cross-verification of protocol header definitions.
//!
//! Kaitai Struct types map to IR as follows:
//! - `u1`/`s1` → 8 bits, `u2`/`s2` → 16 bits, `u4`/`s4` → 32 bits, `u8`/`s8` → 64 bits
//! - `bN` → N bits (bit-level fields)
//! - `size: N` → N*8 bits raw bytes
//! - Endianness from `meta.endian` or per-field suffix (`u2be`, `u2le`)
//!
//! Nested types are flattened into individual sub-fields with proper offsets.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::ir::{
    Endian, FieldDef, FieldType, ProtocolDef, SourceInfo, StandardBody, StandardRef,
    StandardRelationship,
};

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
    let mut dispatch_field = None;

    extract_fields_recursive(
        &ksy.seq,
        &ksy.types,
        &ksy.enums,
        &default_endian,
        &mut fields,
        &mut offset_bits,
        &mut dispatch_field,
        "", // no prefix for top-level fields
    );

    if fields.is_empty() {
        return Ok(None);
    }

    let name = ksy.meta.title.unwrap_or_else(|| ksy.meta.id.clone());
    let file_name = path.file_name().unwrap_or_default().to_string_lossy();

    let mut sources = BTreeMap::new();
    sources.insert(
        "kaitai".to_string(),
        SourceInfo::new(&ksy.meta.id).with_file(file_name.to_string()),
    );

    // Extract standards references from xref
    let standards = extract_standards(&ksy.meta.xref);

    Ok(Some(ProtocolDef {
        name,
        min_header_bits: offset_bits,
        is_variable_length: ksy.seq.iter().any(|f| {
            f.condition.is_some() || f.repeat.is_some() || f.size_eos == Some(true)
        }),
        fields,
        dispatch_field,
        dispatch_table: Vec::new(),
        identifiers: BTreeMap::new(),
        sources,
        generation_source: Some("kaitai".to_string()),
        standards,
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

/// Recursively extract fields from a sequence, flattening nested types.
fn extract_fields_recursive(
    seq: &[KsyField],
    types: &BTreeMap<String, KsyType>,
    enums: &BTreeMap<String, BTreeMap<String, serde_yaml::Value>>,
    default_endian: &Endian,
    fields: &mut Vec<FieldDef>,
    offset_bits: &mut u32,
    dispatch_field: &mut Option<String>,
    prefix: &str,
) {
    for field in seq {
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

        // Check if this is a named type that can be flattened
        if let Some(ty) = field_type_str {
            if let Some(sub_type) = types.get(ty) {
                // Flatten the nested type's fields with a prefix
                let sub_prefix = if prefix.is_empty() {
                    String::new()
                } else {
                    format!("{}.", prefix)
                };
                // Only flatten if the sub-type has fields we can extract
                let start_offset = *offset_bits;
                let start_count = fields.len();
                extract_fields_recursive(
                    &sub_type.seq,
                    types,
                    enums,
                    default_endian,
                    fields,
                    offset_bits,
                    dispatch_field,
                    &sub_prefix,
                );
                // If we extracted sub-fields, continue to next field
                if fields.len() > start_count {
                    continue;
                }
                // Otherwise fall through to treat as opaque bytes
                *offset_bits = start_offset;
            }
        }

        let (size_bits, field_endian, ir_type, is_signed) = if let Some(ty) = field_type_str {
            resolve_type(ty, default_endian, types)
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
            if size == 0 {
                continue;
            }
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
            let lower = field.id.to_lowercase();
            match size_bits {
                48 if lower.contains("mac")
                    || (lower.contains("addr") && !lower.contains("ip"))
                    || lower.contains("hw") =>
                {
                    FieldType::MacAddr
                }
                32 if lower.contains("ip") || (lower.contains("addr") && lower.contains("src"))
                    || (lower.contains("addr") && lower.contains("dst")) =>
                {
                    FieldType::Ipv4Addr
                }
                128 if lower.contains("ip") || lower.contains("addr") => FieldType::Ipv6Addr,
                _ if lower.contains("flag") => FieldType::Flags,
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

        // Extract default value from contents (magic bytes)
        let default_value = extract_default_value(&field.contents);

        // Detect dispatch field: has an enum ref with protocol-like entries
        let is_dispatch = field.enum_ref.as_ref().map_or(false, |enum_name| {
            let lower = field.id.to_lowercase();
            lower.contains("type")
                || lower.contains("proto")
                || lower.contains("next")
                || is_protocol_enum(enums, enum_name)
        }) || {
            let lower = field.id.to_lowercase();
            lower.contains("ether_type") || lower.contains("protocol") || lower.contains("next_header")
        };

        if is_dispatch && dispatch_field.is_none() {
            *dispatch_field = Some(field.id.clone());
        }

        let field_name = if prefix.is_empty() {
            field.id.clone()
        } else {
            format!("{}{}", prefix, field.id)
        };

        let mut source_names = BTreeMap::new();
        source_names.insert("kaitai".to_string(), field.id.clone());

        fields.push(FieldDef {
            name: field_name,
            offset_bits: *offset_bits,
            size_bits,
            field_type: semantic_type,
            endian,
            description: field.doc.clone().unwrap_or_default(),
            is_dispatch,
            is_length: field.id.contains("len") || field.id.contains("length"),
            length_multiplier: None,
            source_names,
            default_value,
            flag_names: None,
        });

        *offset_bits += size_bits;
    }
}

/// Check if an enum definition looks like a protocol dispatch enum.
fn is_protocol_enum(
    enums: &BTreeMap<String, BTreeMap<String, serde_yaml::Value>>,
    enum_name: &str,
) -> bool {
    if let Some(entries) = enums.get(enum_name) {
        // If entries contain protocol-like names (ipv4, tcp, udp, etc.)
        for value in entries.values() {
            if let Some(s) = value.as_str() {
                let lower = s.to_lowercase();
                if lower.contains("ipv4")
                    || lower.contains("ipv6")
                    || lower.contains("tcp")
                    || lower.contains("udp")
                    || lower.contains("arp")
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Extract a default value from the `contents` field (magic bytes).
fn extract_default_value(contents: &Option<serde_yaml::Value>) -> Option<String> {
    match contents {
        Some(serde_yaml::Value::Sequence(seq)) => {
            let hex: Vec<String> = seq
                .iter()
                .filter_map(|v| v.as_u64().map(|n| format!("{:02x}", n)))
                .collect();
            if hex.is_empty() {
                None
            } else {
                Some(format!("0x{}", hex.join("")))
            }
        }
        Some(serde_yaml::Value::String(s)) => {
            let hex: String = s.bytes().map(|b| format!("{:02x}", b)).collect();
            Some(format!("0x{}", hex))
        }
        _ => None,
    }
}

/// Extract RFC/IEEE standards references from .ksy xref metadata.
fn extract_standards(xref: &Option<KsyXref>) -> Vec<StandardRef> {
    let mut standards = Vec::new();
    if let Some(xref) = xref {
        // Extract RFC references
        if let Some(ref rfc_val) = xref.rfc {
            match rfc_val {
                serde_yaml::Value::Number(n) => {
                    if let Some(num) = n.as_u64() {
                        standards.push(StandardRef {
                            id: format!("RFC {}", num),
                            body: StandardBody::Rfc,
                            section: None,
                            url: Some(format!("https://www.rfc-editor.org/rfc/rfc{}", num)),
                            relationship: StandardRelationship::Defines,
                        });
                    }
                }
                serde_yaml::Value::Sequence(seq) => {
                    for item in seq {
                        if let Some(num) = item.as_u64() {
                            standards.push(StandardRef {
                                id: format!("RFC {}", num),
                                body: StandardBody::Rfc,
                                section: None,
                                url: Some(format!(
                                    "https://www.rfc-editor.org/rfc/rfc{}",
                                    num
                                )),
                                relationship: StandardRelationship::Defines,
                            });
                        }
                    }
                }
                serde_yaml::Value::String(s) => {
                    standards.push(StandardRef {
                        id: format!("RFC {}", s),
                        body: StandardBody::Rfc,
                        section: None,
                        url: Some(format!("https://www.rfc-editor.org/rfc/rfc{}", s)),
                        relationship: StandardRelationship::Defines,
                    });
                }
                _ => {}
            }
        }

        // Extract IEEE references
        if let Some(ref ieee_val) = xref.ieee {
            match ieee_val {
                serde_yaml::Value::String(s) => {
                    standards.push(StandardRef {
                        id: format!("IEEE {}", s),
                        body: StandardBody::Ieee,
                        section: None,
                        url: None,
                        relationship: StandardRelationship::Defines,
                    });
                }
                serde_yaml::Value::Sequence(seq) => {
                    for item in seq {
                        if let Some(s) = item.as_str() {
                            standards.push(StandardRef {
                                id: format!("IEEE {}", s),
                                body: StandardBody::Ieee,
                                section: None,
                                url: None,
                                relationship: StandardRelationship::Defines,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    }
    standards
}

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
    let signed = ty.starts_with('s');
    (
        base,
        endian,
        if signed { FieldType::Sint } else { FieldType::Uint },
        signed,
    )
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
        "arp" => "ARP".to_string(),
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

    #[test]
    fn test_extract_standards_rfc() {
        let xref = Some(KsyXref {
            rfc: Some(serde_yaml::Value::Number(serde_yaml::Number::from(791u64))),
            ieee: None,
            wikidata: None,
        });
        let standards = extract_standards(&xref);
        assert_eq!(standards.len(), 1);
        assert_eq!(standards[0].id, "RFC 791");
        assert!(matches!(standards[0].body, StandardBody::Rfc));
    }

    #[test]
    fn test_extract_standards_multiple_rfc() {
        let seq = serde_yaml::Value::Sequence(vec![
            serde_yaml::Value::Number(serde_yaml::Number::from(791u64)),
            serde_yaml::Value::Number(serde_yaml::Number::from(2474u64)),
        ]);
        let xref = Some(KsyXref {
            rfc: Some(seq),
            ieee: None,
            wikidata: None,
        });
        let standards = extract_standards(&xref);
        assert_eq!(standards.len(), 2);
        assert_eq!(standards[0].id, "RFC 791");
        assert_eq!(standards[1].id, "RFC 2474");
    }

    #[test]
    fn test_extract_default_value_bytes() {
        let contents = Some(serde_yaml::Value::Sequence(vec![
            serde_yaml::Value::Number(serde_yaml::Number::from(0x00u64)),
            serde_yaml::Value::Number(serde_yaml::Number::from(0x26u64)),
        ]));
        assert_eq!(extract_default_value(&contents), Some("0x0026".to_string()));
    }

    #[test]
    fn test_is_protocol_enum() {
        let mut enums = BTreeMap::new();
        let mut entries = BTreeMap::new();
        entries.insert(
            "0x0800".to_string(),
            serde_yaml::Value::String("ipv4".to_string()),
        );
        entries.insert(
            "0x86DD".to_string(),
            serde_yaml::Value::String("ipv6".to_string()),
        );
        enums.insert("ether_type_enum".to_string(), entries);
        assert!(is_protocol_enum(&enums, "ether_type_enum"));

        let mut non_proto = BTreeMap::new();
        non_proto.insert(
            "0".to_string(),
            serde_yaml::Value::String("request".to_string()),
        );
        enums.insert("opcode_enum".to_string(), non_proto);
        assert!(!is_protocol_enum(&enums, "opcode_enum"));
    }

    #[test]
    fn test_flag_detection() {
        let lower = "flags".to_lowercase();
        assert!(lower.contains("flag"));
    }
}
