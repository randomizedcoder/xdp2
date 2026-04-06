//! Suricata Rust parser extractor.
//!
//! Parses Suricata's app-layer Rust parser source files to extract
//! wire-level protocol header struct definitions. Suricata is an
//! independent IDS/IPS engine with ~40 protocol parsers written in Rust.
//!
//! Extraction approach:
//! 1. Scan `<suricata_dir>/<proto>/parser.rs` for `pub struct XxxHeader`
//! 2. Extract field names and Rust primitive types (u8, u16, u32, u64)
//! 3. Determine endianness from the corresponding `parse_xxx_header` function
//!    by looking for `be_u*` (big-endian) or `le_u*` (little-endian) calls

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

/// Extract a protocol definition from a Suricata Rust parser file.
pub fn extract_from_file(path: &Path, module_name: &str) -> Result<Vec<(String, ProtocolDef)>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    let mut results = Vec::new();

    // Find all `pub struct XxxHeader` blocks
    let struct_re = Regex::new(
        r"pub struct (\w+(?:Header|Packet|Fixed\w*))\s*(?:<[^>]*>)?\s*\{"
    ).unwrap();

    for cap in struct_re.captures_iter(&content) {
        let struct_name = &cap[1];
        let struct_start = cap.get(0).unwrap().end();

        // Find the closing brace
        let Some(struct_body) = extract_struct_body(&content[struct_start..]) else {
            continue;
        };

        // Parse fields
        let fields = parse_struct_fields(struct_body);
        if fields.is_empty() {
            continue;
        }

        // Determine endianness from the parser function
        let endian = detect_endianness(&content, struct_name);

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
                // Strip "Header" suffix for canonical name
                struct_name.trim_end_matches("Header").to_string()
            });

        // Build ProtocolDef
        let mut offset_bits: u32 = 0;
        let mut ir_fields = Vec::new();

        for (name, rust_type) in &fields {
            let size_bits = rust_type_to_bits(rust_type);
            if size_bits == 0 {
                continue; // skip Vec<u8>, &[u8], etc.
            }

            let field_endian = if size_bits <= 8 {
                Endian::Na
            } else {
                endian.clone()
            };

            let field_type = infer_field_type(name, size_bits);

            let mut source_names = BTreeMap::new();
            source_names.insert("suricata".to_string(), name.clone());

            ir_fields.push(FieldDef {
                name: name.clone(),
                offset_bits,
                size_bits,
                field_type,
                endian: field_endian,
                description: String::new(),
                is_dispatch: name.contains("type") || name.contains("proto") || name.contains("next"),
                is_length: name.contains("len") || name.contains("length"),
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
            is_variable_length: false,
            fields: ir_fields,
            dispatch_field: None,
            dispatch_table: Vec::new(),
            identifiers: BTreeMap::new(),
            sources,
            generation_source: Some("suricata".to_string()),
            standards: Vec::new(),
            iana_registries: BTreeMap::new(),
            layer: None,
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

/// Parse struct fields from the body text.
/// Returns (field_name, rust_type) pairs.
fn parse_struct_fields(body: &str) -> Vec<(String, String)> {
    let field_re = Regex::new(
        r"pub\s+(\w+)\s*:\s*((?:&\[u8\]|Vec<u8>|\[u8;\s*\d+\]|u8|u16|u32|u64|i8|i16|i32|i64|bool|f32|f64))"
    ).unwrap();

    let mut fields = Vec::new();
    for cap in field_re.captures_iter(body) {
        let name = cap[1].to_string();
        let ty = cap[2].to_string();

        // Skip lifetime/reference fields, Vec fields, etc. — they're variable-length
        if ty.starts_with('&') || ty.starts_with("Vec") {
            continue;
        }

        // Skip fields starting with underscore (reserved/padding)
        if name.starts_with('_') {
            continue;
        }

        fields.push((name, ty));
    }
    fields
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

/// Detect endianness from the parser function that corresponds to a struct.
fn detect_endianness(source: &str, struct_name: &str) -> Endian {
    // Look for a parse function near the struct
    let fn_name_lower = struct_name.to_lowercase();
    let search_pattern = format!("parse_{}", fn_name_lower.trim_end_matches("header"));

    // Count big-endian vs little-endian nom parsers
    let mut be_count = 0u32;
    let mut le_count = 0u32;

    // Find the function and scan ~30 lines for be_*/le_* calls
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
        let fields = parse_struct_fields(body);
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0], ("cmd".to_string(), "u16".to_string()));
        assert_eq!(fields[4], ("context".to_string(), "u64".to_string()));
    }

    #[test]
    fn test_parse_struct_fields_skips_vec() {
        let body = r#"
    pub opcode: u8,
    pub htype: u8,
    pub clientip: Vec<u8>,
    pub txid: u32,
"#;
        let fields = parse_struct_fields(body);
        assert_eq!(fields.len(), 3); // opcode, htype, txid — clientip skipped
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
}
