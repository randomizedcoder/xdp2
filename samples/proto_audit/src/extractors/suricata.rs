//! Suricata Rust parser extractor.
//!
//! Parses Suricata's app-layer Rust parser source files to extract
//! wire-level protocol header struct definitions. Suricata is an
//! independent IDS/IPS engine with ~40 protocol parsers written in Rust.
//!
//! Extraction approach:
//! 1. Scan `<suricata_dir>/<proto>/parser.rs` for `pub struct Xxx{Header,Hdr,Message,Frame,Packet}`
//! 2. Extract field names, Rust primitive types, and doc comments
//! 3. Determine per-field endianness from the corresponding `parse_xxx` function
//!    by matching `be_u*` / `le_u*` calls to field names

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use regex::Regex;

use crate::ir::{Endian, FieldDef, FieldType, ProtocolDef, SourceInfo};

/// Known protocol module → canonical name mappings.
const PROTO_MAP: &[(&str, &str)] = &[
    ("dhcp", "DHCP"),
    ("dns", "DNS"),
    ("enip", "ENIP"),
    ("ftp", "FTP"),
    ("http2", "HTTP2"),
    ("ike", "IKEv2"),
    ("krb", "Kerberos"),
    ("ldap", "LDAP"),
    ("modbus", "MODBUS_TCP"),
    ("mqtt", "MQTT"),
    ("ntp", "NTP"),
    ("pgsql", "PostgreSQL"),
    ("pop3", "POP3"),
    ("quic", "QUIC"),
    ("rdp", "RDP"),
    ("rfb", "RFB"),
    ("sdp", "SDP"),
    ("sip", "SIP"),
    ("smb", "SMB"),
    ("snmp", "SNMP"),
    ("ssh", "SSH"),
    ("telnet", "Telnet"),
    ("tftp", "TFTP"),
    ("websocket", "WebSocket"),
    ("dcerpc", "DCERPC"),
    ("bittorrent_dht", "BitTorrent_DHT"),
    ("mdns", "mDNS"),
];

/// Header struct → canonical protocol mapping.
/// Maps struct names to their canonical protocol name when the struct
/// name doesn't follow the standard `<Proto>Header` pattern.
const STRUCT_MAP: &[(&str, &str)] = &[
    ("DHCPHeader", "DHCP"),
    ("EnipHeader", "ENIP"),
    ("IsakmpHeader", "IKEv2"),
    ("FixedHeader", "MQTT"),   // MQTT uses FixedHeader
    ("HTTP2FrameHeader", "HTTP2"),
    ("QuicHeader", "QUIC"),
    ("SshRecordHeader", "SSH"),
];

/// Parsed field with doc comment.
struct ParsedField {
    name: String,
    rust_type: String,
    doc_comment: String,
}

/// Extract a protocol definition from a Suricata Rust parser file.
pub fn extract_from_file(path: &Path, module_name: &str) -> Result<Vec<(String, ProtocolDef)>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    let mut results = Vec::new();

    // Find all `pub struct Xxx{Header,Hdr,Message,Frame,Packet}` blocks
    let struct_re = Regex::new(
        r"pub struct (\w+(?:Header|Hdr|Packet|Message|Frame|Fixed\w*))\s*(?:<[^>]*>)?\s*\{"
    ).unwrap();

    for cap in struct_re.captures_iter(&content) {
        let struct_name = &cap[1];
        let struct_match = cap.get(0).unwrap();
        let struct_start = struct_match.end();

        // Find the closing brace
        let Some(struct_body) = extract_struct_body(&content[struct_start..]) else {
            continue;
        };

        // Extract doc comments above the struct definition
        let _struct_doc = extract_struct_doc(&content, struct_match.start());

        // Parse fields with doc comments
        let fields = parse_struct_fields_with_docs(struct_body);
        if fields.is_empty() {
            continue;
        }

        // Determine per-field endianness from the parser function
        let field_endians = detect_per_field_endianness(&content, struct_name, &fields);

        // Fallback whole-struct endianness
        let default_endian = detect_endianness(&content, struct_name);

        // Map to canonical name
        let canonical = STRUCT_MAP.iter()
            .find(|(s, _)| *s == struct_name)
            .map(|(_, c)| c.to_string())
            .or_else(|| {
                PROTO_MAP.iter()
                    .find(|(m, _)| *m == module_name)
                    .map(|(_, c)| c.to_string())
            })
            .unwrap_or_else(|| {
                // Strip "Header"/"Hdr" suffix for canonical name
                struct_name
                    .trim_end_matches("Header")
                    .trim_end_matches("Hdr")
                    .trim_end_matches("Packet")
                    .trim_end_matches("Message")
                    .trim_end_matches("Frame")
                    .to_string()
            });

        // Detect if variable-length (has Vec/slice fields or skipped fields)
        let has_variable = struct_body.contains("Vec<") || struct_body.contains("&[u8]");

        // Build ProtocolDef
        let mut offset_bits: u32 = 0;
        let mut ir_fields = Vec::new();
        let mut dispatch_field = None;

        for pf in &fields {
            let size_bits = rust_type_to_bits(&pf.rust_type);
            if size_bits == 0 {
                continue; // skip Vec<u8>, &[u8], etc.
            }

            // Use per-field endianness if available, else fall back to struct-level
            let field_endian = if size_bits <= 8 {
                Endian::Na
            } else {
                field_endians
                    .get(&pf.name)
                    .cloned()
                    .unwrap_or_else(|| default_endian.clone())
            };

            let field_type = infer_field_type(&pf.name, size_bits);

            let is_dispatch = pf.name.contains("type") || pf.name.contains("proto") || pf.name.contains("next");
            if is_dispatch && dispatch_field.is_none() {
                dispatch_field = Some(pf.name.clone());
            }

            let mut source_names = BTreeMap::new();
            source_names.insert("suricata".to_string(), pf.name.clone());

            ir_fields.push(FieldDef {
                name: pf.name.clone(),
                offset_bits,
                size_bits,
                field_type,
                endian: field_endian,
                description: pf.doc_comment.clone(),
                is_dispatch,
                is_length: pf.name.contains("len") || pf.name.contains("length"),
                length_multiplier: None,
                source_names,
                default_value: None,
                flag_names: None,
            });

            offset_bits += size_bits;
        }

        if ir_fields.is_empty() {
            continue;
        }

        let mut sources = BTreeMap::new();
        sources.insert(
            "suricata".to_string(),
            SourceInfo::new(struct_name)
                .with_file(path.file_name().unwrap_or_default().to_string_lossy().to_string()),
        );

        let proto = ProtocolDef {
            name: canonical.clone(),
            min_header_bits: offset_bits,
            is_variable_length: has_variable,
            fields: ir_fields,
            dispatch_field,
            dispatch_table: Vec::new(),
            identifiers: BTreeMap::new(),
            sources,
            generation_source: Some("suricata".to_string()),
            standards: Vec::new(),
            iana_registries: BTreeMap::new(),
            layer: None,
            repeats: vec![],
        };

        results.push((canonical, proto));
    }

    Ok(results)
}

/// Scan a Suricata source directory for protocol modules.
pub fn scan_suricata_dir(dir: &Path) -> Result<Vec<(String, std::path::PathBuf)>> {
    let mut results = Vec::new();

    if !dir.is_dir() {
        return Ok(results);
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let module_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        // Check for parser.rs
        let parser_path = path.join("parser.rs");
        if parser_path.exists() {
            results.push((module_name, parser_path));
        }
    }

    results.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(results)
}

// ── Internal helpers ──

/// Extract the body of a struct (everything between { and matching }).
fn extract_struct_body(content: &str) -> Option<&str> {
    let mut depth = 1;
    let mut end = 0;
    for (i, ch) in content.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            _ => {}
        }
    }
    if end > 0 {
        Some(&content[..end])
    } else {
        None
    }
}

/// Extract doc comments above a struct definition.
fn extract_struct_doc(content: &str, struct_start: usize) -> String {
    let before = &content[..struct_start];
    let mut doc_lines = Vec::new();

    // Walk backwards through lines to collect /// comments
    for line in before.lines().rev() {
        let trimmed = line.trim();
        if let Some(doc) = trimmed.strip_prefix("///") {
            doc_lines.push(doc.trim().to_string());
        } else if trimmed.is_empty() {
            // Allow blank lines between doc comments
            continue;
        } else {
            break;
        }
    }

    doc_lines.reverse();
    doc_lines.join(" ")
}

/// Parse struct fields with their doc comments.
fn parse_struct_fields_with_docs(body: &str) -> Vec<ParsedField> {
    let field_re = Regex::new(
        r"pub\s+(\w+)\s*:\s*((?:&\[u8\]|Vec<u8>|\[u8;\s*\d+\]|u8|u16|u32|u64|i8|i16|i32|i64|bool|f32|f64))"
    ).unwrap();

    let mut fields = Vec::new();

    for cap in field_re.captures_iter(body) {
        let name = cap[1].to_string();
        let ty = cap[2].to_string();

        // Skip lifetime/reference fields, Vec fields — they're variable-length
        if ty.starts_with('&') || ty.starts_with("Vec") {
            continue;
        }

        // Skip fields starting with underscore (reserved/padding)
        if name.starts_with('_') {
            continue;
        }

        // Extract doc comment immediately above this field
        let field_start = cap.get(0).unwrap().start();
        let doc = extract_field_doc(body, field_start);

        fields.push(ParsedField {
            name,
            rust_type: ty,
            doc_comment: doc,
        });
    }
    fields
}

/// Extract doc comments immediately above a field declaration.
fn extract_field_doc(body: &str, field_start: usize) -> String {
    let before = &body[..field_start];
    let mut doc_lines = Vec::new();

    for line in before.lines().rev() {
        let trimmed = line.trim();
        if let Some(doc) = trimmed.strip_prefix("///") {
            doc_lines.push(doc.trim().to_string());
        } else if let Some(doc) = trimmed.strip_prefix("//") {
            // Regular comments can serve as field documentation too
            let doc = doc.trim();
            if !doc.is_empty() && !doc.starts_with('!') {
                doc_lines.push(doc.to_string());
            } else {
                break;
            }
        } else if trimmed.is_empty() {
            if !doc_lines.is_empty() {
                break; // blank line after collecting some docs = done
            }
            continue;
        } else {
            break;
        }
    }

    doc_lines.reverse();
    doc_lines.join(" ")
}

/// Detect per-field endianness from the nom parser function.
///
/// Parses the `parse_xxx` function to match fields to their `be_u*`/`le_u*` calls
/// in order, returning a per-field endianness map.
fn detect_per_field_endianness(
    source: &str,
    struct_name: &str,
    fields: &[ParsedField],
) -> BTreeMap<String, Endian> {
    let mut result = BTreeMap::new();

    // Find the parser function
    let fn_name_lower = struct_name.to_lowercase();
    let patterns = [
        format!("parse_{}", fn_name_lower.trim_end_matches("header")),
        format!("parse_{}", fn_name_lower),
    ];

    let fn_body = patterns.iter().find_map(|pattern| {
        source.find(pattern.as_str()).map(|pos| {
            let end = std::cmp::min(pos + 3000, source.len());
            &source[pos..end]
        })
    });

    let Some(fn_body) = fn_body else {
        return result;
    };

    // Extract ordered list of nom parser calls: (field_name, endian)
    // Pattern: let (i, <field>) = <be_u*|le_u*>(i)?;
    let nom_re = Regex::new(
        r"let\s+\([^,]+,\s*(\w+)\)\s*=\s*(be_u\d+|le_u\d+|be_u8|le_u8)"
    ).unwrap();

    for cap in nom_re.captures_iter(fn_body) {
        let field_name = &cap[1];
        let parser_fn = &cap[2];

        let endian = if parser_fn.starts_with("le_") {
            Endian::Little
        } else {
            Endian::Big
        };

        // Match to our extracted fields
        for pf in fields {
            if pf.name == field_name || field_name.contains(&pf.name) || pf.name.contains(field_name) {
                result.insert(pf.name.clone(), endian.clone());
                break;
            }
        }
    }

    result
}

/// Map Rust primitive types to bit sizes.
fn rust_type_to_bits(ty: &str) -> u32 {
    match ty {
        "u8" | "i8" | "bool" => 8,
        "u16" | "i16" => 16,
        "u32" | "i32" | "f32" => 32,
        "u64" | "i64" | "f64" => 64,
        _ => {
            // [u8; N] arrays
            if ty.starts_with("[u8;") {
                let n = ty.trim_start_matches("[u8;")
                    .trim_end_matches(']')
                    .trim();
                n.parse::<u32>().unwrap_or(0) * 8
            } else {
                0
            }
        }
    }
}

/// Detect whole-struct endianness from the parser function (fallback).
fn detect_endianness(source: &str, struct_name: &str) -> Endian {
    let fn_name_lower = struct_name.to_lowercase();
    let search_pattern = format!("parse_{}", fn_name_lower.trim_end_matches("header"));

    let mut be_count = 0u32;
    let mut le_count = 0u32;

    if let Some(pos) = source.find(&search_pattern) {
        let window = &source[pos..std::cmp::min(pos + 2000, source.len())];
        for line in window.lines().take(40) {
            if line.contains("be_u8") || line.contains("be_u16") || line.contains("be_u32") || line.contains("be_u64") {
                be_count += 1;
            }
            if line.contains("le_u8") || line.contains("le_u16") || line.contains("le_u32") || line.contains("le_u64") {
                le_count += 1;
            }
        }
    }

    if le_count > be_count {
        Endian::Little
    } else {
        Endian::Big // Default to big-endian (network byte order)
    }
}

/// Infer IR field type from field name and size.
fn infer_field_type(name: &str, size_bits: u32) -> FieldType {
    let lower = name.to_lowercase();
    if lower.contains("flag") {
        return FieldType::Flags;
    }
    if (lower.contains("ip") || lower.contains("addr")) && size_bits == 32 {
        return FieldType::Ipv4Addr;
    }
    if (lower.contains("mac") || lower.contains("hw")) && size_bits == 48 {
        return FieldType::MacAddr;
    }
    if lower.contains("type") || lower.contains("code") || lower.contains("opcode") {
        return FieldType::Enum;
    }
    if lower.contains("version") || lower.contains("ver") {
        return FieldType::Uint;
    }
    FieldType::Uint
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_struct_fields() {
        let body = r#"
    pub cmd: u16,
    pub pdulen: u16,
    pub session: u32,
    pub status: u32,
    pub context: u64,
    pub options: u32,
"#;
        let fields = parse_struct_fields_with_docs(body);
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0].name, "cmd");
        assert_eq!(fields[0].rust_type, "u16");
        assert_eq!(fields[4].name, "context");
    }

    #[test]
    fn test_parse_struct_fields_skips_vec() {
        let body = r#"
    pub opcode: u8,
    pub htype: u8,
    pub clientip: Vec<u8>,
    pub txid: u32,
"#;
        let fields = parse_struct_fields_with_docs(body);
        assert_eq!(fields.len(), 3); // opcode, htype, txid — clientip skipped
    }

    #[test]
    fn test_parse_struct_fields_with_docs() {
        let body = r#"
    /// Message type (request/response)
    pub msg_type: u8,
    /// Hardware type
    pub htype: u8,
    pub hlen: u8,
"#;
        let fields = parse_struct_fields_with_docs(body);
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].doc_comment, "Message type (request/response)");
        assert_eq!(fields[1].doc_comment, "Hardware type");
        assert_eq!(fields[2].doc_comment, ""); // no doc comment
    }

    #[test]
    fn test_rust_type_to_bits() {
        assert_eq!(rust_type_to_bits("u8"), 8);
        assert_eq!(rust_type_to_bits("u16"), 16);
        assert_eq!(rust_type_to_bits("u32"), 32);
        assert_eq!(rust_type_to_bits("u64"), 64);
        assert_eq!(rust_type_to_bits("bool"), 8);
        assert_eq!(rust_type_to_bits("[u8; 4]"), 32);
        assert_eq!(rust_type_to_bits("[u8; 16]"), 128);
        assert_eq!(rust_type_to_bits("Vec<u8>"), 0);
    }

    #[test]
    fn test_detect_endianness() {
        let source = r#"
pub fn parse_enip_header(i: &[u8]) -> IResult<&[u8], EnipHeader> {
    let (i, cmd) = le_u16(i)?;
    let (i, pdulen) = le_u16(i)?;
    let (i, session) = le_u32(i)?;
    Ok((i, EnipHeader { cmd, pdulen, session, status: 0, context: 0, options: 0 }))
}
"#;
        assert_eq!(detect_endianness(source, "EnipHeader"), Endian::Little);
    }

    #[test]
    fn test_detect_endianness_big() {
        let source = r#"
pub fn parse_isakmp_header(i: &[u8]) -> IResult<&[u8], IsakmpHeader> {
    let (i, init_spi) = be_u64(i)?;
    let (i, resp_spi) = be_u64(i)?;
    let (i, next_payload) = be_u8(i)?;
    Ok((i, IsakmpHeader { init_spi, resp_spi, next_payload, maj_ver: 0, min_ver: 0, exch_type: 0, flags: 0, msg_id: 0, length: 0 }))
}
"#;
        assert_eq!(detect_endianness(source, "IsakmpHeader"), Endian::Big);
    }

    #[test]
    fn test_per_field_endianness() {
        let source = r#"
pub fn parse_mixed(i: &[u8]) -> IResult<&[u8], MixedHeader> {
    let (i, big_field) = be_u16(i)?;
    let (i, little_field) = le_u32(i)?;
    Ok((i, MixedHeader { big_field, little_field }))
}
"#;
        let fields = vec![
            ParsedField { name: "big_field".to_string(), rust_type: "u16".to_string(), doc_comment: String::new() },
            ParsedField { name: "little_field".to_string(), rust_type: "u32".to_string(), doc_comment: String::new() },
        ];
        let endians = detect_per_field_endianness(source, "MixedHeader", &fields);
        assert_eq!(endians.get("big_field"), Some(&Endian::Big));
        assert_eq!(endians.get("little_field"), Some(&Endian::Little));
    }

    #[test]
    fn test_extract_struct_body() {
        let content = "pub cmd: u16,\n    pub len: u16,\n}";
        let body = extract_struct_body(content);
        assert!(body.is_some());
        assert!(body.unwrap().contains("cmd: u16"));
    }

    #[test]
    fn test_infer_field_type() {
        assert_eq!(infer_field_type("flags", 8), FieldType::Flags);
        assert_eq!(infer_field_type("src_ip", 32), FieldType::Ipv4Addr);
        assert_eq!(infer_field_type("opcode", 8), FieldType::Enum);
        assert_eq!(infer_field_type("length", 16), FieldType::Uint);
    }

    #[test]
    fn test_extract_struct_doc() {
        let content = "/// DHCP packet header\n/// Used for DHCPv4 messages\npub struct DHCPHeader {";
        let doc = extract_struct_doc(content, content.find("pub struct").unwrap());
        assert!(doc.contains("DHCP packet header"));
        assert!(doc.contains("DHCPv4 messages"));
    }

    #[test]
    fn test_variable_length_detection() {
        let body = "pub opcode: u8, pub data: Vec<u8>, pub len: u16,";
        assert!(body.contains("Vec<"));
    }
}
