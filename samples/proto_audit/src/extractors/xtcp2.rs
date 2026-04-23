//! xtcp2 Go struct extractor.
//!
//! Parses Go struct definitions from the xtcp2 netlink parser library
//! (`pkg/xtcpnl/*.go`) to extract wire-level protocol field definitions.
//!
//! xtcp2 Go structs follow a consistent pattern:
//!   type StructName struct {
//!       FieldName GoType // bytes:N [start:end]
//!   }
//!
//! The byte offset comments are authoritative for wire layout. When present,
//! they provide exact byte offsets. When absent, offsets are computed from
//! type sizes via the TOML mappings.
//!
//! Size constants (`const StructNameSizeCst = N`) provide total struct size.
//! Type aliases (`type TCPInfo TCPInfo6_10_3`) resolve to the latest variant.

use std::path::Path;

use anyhow::{Context, Result};
use regex::Regex;

use crate::ir::{FieldDef, FieldType, ProtocolDef, SourceInfo};
use crate::type_mapping::Xtcp2Mappings;

/// Parsed Go struct field.
struct GoField {
    name: String,
    go_type: String,
    /// Byte size from comment (e.g., `// bytes:4` or `// 4 = 8`)
    byte_size: Option<u32>,
    /// Start byte offset from comment (e.g., `[8:12]`)
    byte_start: Option<u32>,
}

/// Find all `.go` files in `pkg/xtcpnl/` (non-test, non-bench).
fn find_go_files(xtcp2_src: &Path) -> Result<Vec<std::path::PathBuf>> {
    let dir = xtcp2_src.join("pkg/xtcpnl");
    if !dir.exists() {
        anyhow::bail!("xtcp2 source dir missing: {}", dir.display());
    }
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.ends_with(".go") && !name.contains("_test.go") && !name.contains("_bench_test.go") {
                files.push(path);
            }
        }
    }
    Ok(files)
}

/// Resolve a type alias (e.g., `type TCPInfo TCPInfo6_10_3`).
/// Returns the resolved struct name.
fn resolve_alias(content: &str, struct_name: &str) -> Option<String> {
    let re = Regex::new(&format!(r"type\s+{}\s+(\w+)", regex::escape(struct_name))).ok()?;
    for cap in re.captures_iter(content) {
        let target = cap[1].to_string();
        // Only resolve if it's not "struct" (which would be the struct definition itself)
        if target != "struct" {
            return Some(target);
        }
    }
    None
}

/// Parse fields from a Go struct body.
fn parse_struct_fields(body: &str) -> Vec<GoField> {
    let mut fields = Vec::new();

    // Pattern: FieldName GoType // ... or FieldName GoType
    // Also handles array types like [16]byte
    let field_re = Regex::new(
        r"^\s*(\w+)\s+(\[?\d*\]?\w+)\s*(?://\s*(.*))?$"
    ).unwrap();

    // Byte offset pattern: bytes:N [start:end]
    let bytes_bracket_re = Regex::new(r"bytes?:\s*(\d+)\s*\[(\d+):(\d+)\]").unwrap();

    // Simple cumulative pattern: N = M (size = cumulative_end)
    let simple_cumulative_re = Regex::new(r"^(\d+)\s*=\s*(\d+)").unwrap();

    for line in body.lines() {
        let line = line.trim();
        // Skip blank lines, comments-only lines, section comments
        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        if let Some(cap) = field_re.captures(line) {
            let name = cap[1].to_string();
            let go_type = cap[2].to_string();
            let comment = cap.get(3).map(|m| m.as_str()).unwrap_or("");

            let (byte_size, byte_start) = if let Some(bc) = bytes_bracket_re.captures(comment) {
                let size: u32 = bc[1].parse().unwrap_or(0);
                let start: u32 = bc[2].parse().unwrap_or(0);
                (Some(size), Some(start))
            } else if let Some(sc) = simple_cumulative_re.captures(comment) {
                let size: u32 = sc[1].parse().unwrap_or(0);
                let end: u32 = sc[2].parse().unwrap_or(0);
                let start = end.saturating_sub(size);
                (Some(size), Some(start))
            } else {
                (None, None)
            };

            fields.push(GoField { name, go_type, byte_size, byte_start });
        }
    }

    fields
}

/// Extract struct body text between `type StructName struct {` and the closing `}`.
fn extract_struct_body(content: &str, struct_name: &str) -> Option<String> {
    let pattern = format!("type {} struct {{", struct_name);
    let start = content.find(&pattern)?;
    let after_open = start + pattern.len();

    let mut depth = 1i32;
    let mut end = after_open;
    for (i, ch) in content[after_open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = after_open + i;
                    break;
                }
            }
            _ => {}
        }
    }

    Some(content[after_open..end].to_string())
}

/// Extract size constant for a struct (e.g., `BBRInfoSizeCst = 20`).
fn extract_size_const(content: &str, struct_name: &str) -> Option<u32> {
    let pattern = format!(r"{}SizeCst\s*=\s*(\d+)", regex::escape(struct_name));
    let re = Regex::new(&pattern).ok()?;
    re.captures(content).and_then(|c| c[1].parse().ok())
}

/// Convert a Go field name to snake_case for the IR.
fn to_snake_case(name: &str) -> String {
    let mut result = String::with_capacity(name.len() + 4);
    for (i, ch) in name.chars().enumerate() {
        if ch.is_uppercase() {
            if i > 0 {
                // Don't insert underscore between consecutive uppercase (e.g., "ABECN")
                let prev = name.chars().nth(i - 1).unwrap_or('_');
                let next = name.chars().nth(i + 1);
                if prev.is_lowercase() || (prev.is_uppercase() && next.map_or(false, |n| n.is_lowercase())) {
                    result.push('_');
                }
            }
            result.push(ch.to_lowercase().next().unwrap());
        } else {
            result.push(ch);
        }
    }
    result
}

/// Infer IR FieldType from Go field name.
fn infer_field_type(name: &str, bits: u32) -> FieldType {
    let lower = name.to_lowercase();
    if (lower.contains("ip") || lower.contains("addr")) && (bits == 32 || bits == 128) {
        if bits == 32 {
            return FieldType::Ipv4Addr;
        } else if bits == 128 {
            return FieldType::Ipv6Addr;
        }
    }
    if lower.contains("flags") || lower == "options" {
        return FieldType::Flags;
    }
    if lower.contains("state") || lower.contains("protocol") || lower.contains("family") || lower == "type" {
        return FieldType::Enum;
    }
    if lower.contains("pad") || lower.contains("reserved") {
        return FieldType::Pad;
    }
    FieldType::Uint
}

/// Resolve bit size for a Go type, including array types like `[16]byte`.
fn resolve_type_bits(go_type: &str, mappings: &Xtcp2Mappings) -> Option<u32> {
    // Array type: [N]elem
    if go_type.starts_with('[') {
        let re = Regex::new(r"\[(\d+)\](\w+)").ok()?;
        if let Some(cap) = re.captures(go_type) {
            let count: u32 = cap[1].parse().ok()?;
            let elem = &cap[2];
            let elem_bits = mappings.type_bits(elem)?;
            return Some(count * elem_bits);
        }
    }
    mappings.type_bits(go_type)
}

/// Extract a protocol definition from xtcp2 Go source.
pub fn extract_protocol(
    xtcp2_src: &Path,
    _proto_name: &str,
    struct_name: &str,
    mappings: &Xtcp2Mappings,
) -> Result<Option<ProtocolDef>> {
    let go_files = find_go_files(xtcp2_src)?;

    // Concatenate all Go files to search for structs and aliases
    let mut all_content = String::new();
    let mut source_file = String::new();
    for path in &go_files {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        all_content.push_str(&content);
        all_content.push('\n');
    }

    // Resolve type alias if needed (e.g., TCPInfo → TCPInfo6_10_3)
    let resolved = resolve_alias(&all_content, struct_name)
        .unwrap_or_else(|| struct_name.to_string());

    // Find the struct body
    let body = match extract_struct_body(&all_content, &resolved) {
        Some(b) => b,
        None => return Ok(None),
    };

    // Find which file contains the struct for SourceInfo
    for path in &go_files {
        let content = std::fs::read_to_string(path)?;
        if content.contains(&format!("type {} struct", resolved)) {
            source_file = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            break;
        }
    }

    let go_fields = parse_struct_fields(&body);

    // Build IR fields
    let mut fields = Vec::new();
    let mut running_offset: u32 = 0;

    for gf in &go_fields {
        let type_bytes = resolve_type_bits(&gf.go_type, mappings).map(|b| b / 8);

        // Determine bit size: prefer Go type size, fall back to comment
        // The comment "N = M" format is ambiguous: N can be field_size or
        // cumulative_start. The Go type is authoritative for size.
        let byte_size = type_bytes
            .or(gf.byte_size);
        let bit_size = match byte_size {
            Some(bs) => bs * 8,
            None => {
                // Unknown type — skip (e.g., nested struct without TOML entry)
                continue;
            }
        };

        // Determine offset: from comment, or from running total.
        // If comment byte_size disagrees with Go type size, the comment
        // uses "cumulative_start = cumulative_end" format — derive start
        // from end - type_size instead.
        let bit_offset = match (gf.byte_start, gf.byte_size, type_bytes) {
            (Some(start), Some(comment_size), Some(tb)) if comment_size != tb => {
                // Ambiguous comment: "8 = 12" for a uint32.
                // comment_size=8 is cumulative_start, not field size.
                // Recalculate: start = end - type_bytes, where end is
                // comment_start + comment_size (the original end value).
                let end = start + comment_size;
                (end - tb) * 8
            }
            (Some(start), _, _) => start * 8,
            _ => running_offset * 8,
        };

        let endian = mappings.type_endian(&gf.go_type);
        let ir_name = to_snake_case(&gf.name);
        let field_type = infer_field_type(&gf.name, bit_size);

        fields.push(
            FieldDef::new(ir_name, bit_offset, bit_size, field_type)
                .with_endian(endian)
                .with_source_name("xtcp2", &gf.name)
        );

        let actual_start_bytes = bit_offset / 8;
        running_offset = actual_start_bytes + byte_size.unwrap_or(0);
    }

    if fields.is_empty() {
        return Ok(None);
    }

    let total_bits = fields.iter()
        .map(|f| f.offset_bits + f.size_bits)
        .max()
        .unwrap_or(0);

    let source_info = SourceInfo::new("xtcp2")
        .with_file(format!("pkg/xtcpnl/{}", source_file))
        .with_field_count(fields.len() as u32)
        .with_min_header_bytes(total_bits / 8);

    let mut def = ProtocolDef::new(struct_name, total_bits)
        .with_fields(fields)
        .with_source("xtcp2", source_info);

    def.name = struct_name.to_string();

    Ok(Some(def))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Endian;
    use crate::type_mapping::load_xtcp2_mappings;

    fn test_mappings() -> Xtcp2Mappings {
        load_xtcp2_mappings(None).unwrap()
    }

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("BwLo"), "bw_lo");
        assert_eq!(to_snake_case("MinRtt"), "min_rtt");
        assert_eq!(to_snake_case("PacingGain"), "pacing_gain");
        assert_eq!(to_snake_case("SndMss"), "snd_mss");
        assert_eq!(to_snake_case("RcvSsthresh"), "rcv_ssthresh");
        assert_eq!(to_snake_case("ABECN"), "abecn");
        assert_eq!(to_snake_case("DeliveredCe"), "delivered_ce");
        assert_eq!(to_snake_case("SrcIP"), "src_ip");
        assert_eq!(to_snake_case("DstIP"), "dst_ip");
    }

    #[test]
    fn test_parse_bbrinfo_fields() {
        let body = r#"
    BwLo       uint32 // 4 = 4
    BwHi       uint32 // 4 = 8
    MinRtt     uint32 // 4 = 12
    PacingGain uint32 // 4 = 16
    CwndGain   uint32 // 4 = 20
"#;
        let fields = parse_struct_fields(body);
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0].name, "BwLo");
        assert_eq!(fields[0].go_type, "uint32");
        assert_eq!(fields[0].byte_size, Some(4));
        assert_eq!(fields[0].byte_start, Some(0));
        assert_eq!(fields[4].name, "CwndGain");
        assert_eq!(fields[4].byte_start, Some(16));
    }

    #[test]
    fn test_parse_tcpinfo_fields() {
        let body = r#"
    State       uint8 // bytes:1 [0:1]
    CaState     uint8 // bytes:1 [1:2]
    Retransmits uint8 // bytes:1 [2:3]
    Probes      uint8 // bytes:1 [3:4]
    Backoff     uint8 // bytes:1 [4:5]
    Options     uint8 // bytes:1 [5:6]
    ScaleTemp   uint8 // bytes:1 [6:7] _snd_wscale : 4, _rcv_wscale : 4; fix me
    FlagsTemp   uint8 // bytes:1 [7:8] _delivery_rate_app_limited:1, _fastopen_client_fail:2; TODO fix me!
    Rto    uint32 // bytes:4 [8:12]
    Ato    uint32 // bytes:4 [12:16]
    SndMss uint32 // bytes:4 [16:20]
    RcvMss uint32 // bytes:4 [20:24]
"#;
        let fields = parse_struct_fields(body);
        assert_eq!(fields.len(), 12);
        assert_eq!(fields[0].name, "State");
        assert_eq!(fields[0].byte_size, Some(1));
        assert_eq!(fields[0].byte_start, Some(0));
        assert_eq!(fields[8].name, "Rto");
        assert_eq!(fields[8].byte_size, Some(4));
        assert_eq!(fields[8].byte_start, Some(8));
    }

    #[test]
    fn test_parse_meminfo_fields() {
        let body = r#"
    Rmem uint32 // 4 = 4
    Wmem uint32 // 4 = 8
    Fmem uint32 // 4 = 12
    Tmem uint32 // 4 = 16
"#;
        let fields = parse_struct_fields(body);
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0].name, "Rmem");
        assert_eq!(fields[3].name, "Tmem");
        assert_eq!(fields[3].byte_start, Some(12));
    }

    #[test]
    fn test_parse_skmeminfo_fields() {
        let body = r#"
    RmemAlloc  uint32 // 4 = 4
    RcvBuf     uint32 // 4 = 8
    WmemAlloc  uint32 // 4 = 12
    SndBuf     uint32 // 4 = 16
    FwdAlloc   uint32 // 4 = 20
    WmemQueued uint32 // 4 = 24
    Optmem     uint32 // 4 = 28
    Backlog    uint32 // 4 = 32
    Drops      uint32 // 4 = 36
"#;
        let fields = parse_struct_fields(body);
        assert_eq!(fields.len(), 9);
        assert_eq!(fields[8].name, "Drops");
        assert_eq!(fields[8].byte_start, Some(32));
    }

    #[test]
    fn test_parse_dctcpinfo_fields() {
        let body = r#"
    Enabled uint16 // 2 = 2
    CEState uint16 // 2 = 4
    Alpha   uint32 // 4 = 8
    ABECN   uint32 // 8 = 12
    ABTOT   uint32 // 12 = 16
"#;
        let fields = parse_struct_fields(body);
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0].name, "Enabled");
        assert_eq!(fields[0].go_type, "uint16");
    }

    #[test]
    fn test_parse_sockid_array_type() {
        let body = r#"
    SPort     uint16   // 2 = 2
    DPort     uint16   // 2 = 4
    SrcIP     [16]byte // 16 = 20
    DstIP     [16]byte // 16 = 36
    Interface uint32   // 4 = 40
    Cookie    uint64   // 8 = 48
"#;
        let fields = parse_struct_fields(body);
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[2].name, "SrcIP");
        assert_eq!(fields[2].go_type, "[16]byte");
        assert_eq!(fields[2].byte_size, Some(16));
    }

    #[test]
    fn test_resolve_type_bits_array() {
        let mappings = test_mappings();
        assert_eq!(resolve_type_bits("[16]byte", &mappings), Some(128));
        assert_eq!(resolve_type_bits("uint32", &mappings), Some(32));
        assert_eq!(resolve_type_bits("uint64", &mappings), Some(64));
    }

    #[test]
    fn test_extract_struct_body() {
        let content = r#"
type BBRInfo struct {
    BwLo       uint32 // 4 = 4
    BwHi       uint32 // 4 = 8
}

const (
    BBRInfoSizeCst = 8
)
"#;
        let body = extract_struct_body(content, "BBRInfo").unwrap();
        assert!(body.contains("BwLo"));
        assert!(body.contains("BwHi"));
    }

    #[test]
    fn test_extract_size_const() {
        let content = r#"
const (
    BBRInfoSizeCst = 20
    BBRInfoReadCst = BBRInfoSizeCst
)
"#;
        assert_eq!(extract_size_const(content, "BBRInfo"), Some(20));
    }

    #[test]
    fn test_resolve_alias() {
        let content = "type TCPInfo TCPInfo6_10_3\n\ntype TCPInfo6_10_3 struct {\n";
        assert_eq!(resolve_alias(content, "TCPInfo"), Some("TCPInfo6_10_3".to_string()));
    }

    #[test]
    fn test_fields_to_ir() {
        let mappings = test_mappings();
        let body = r#"
    BwLo       uint32 // 4 = 4
    BwHi       uint32 // 4 = 8
    MinRtt     uint32 // 4 = 12
    PacingGain uint32 // 4 = 16
    CwndGain   uint32 // 4 = 20
"#;
        let go_fields = parse_struct_fields(body);
        let mut fields = Vec::new();
        let mut running_offset: u32 = 0;
        for gf in &go_fields {
            let byte_size = gf.byte_size
                .or_else(|| resolve_type_bits(&gf.go_type, &mappings).map(|b| b / 8));
            let bit_size = byte_size.unwrap() * 8;
            let bit_offset = gf.byte_start
                .map(|s| s * 8)
                .unwrap_or(running_offset * 8);
            let endian = mappings.type_endian(&gf.go_type);
            fields.push(
                FieldDef::new(to_snake_case(&gf.name), bit_offset, bit_size, FieldType::Uint)
                    .with_endian(endian)
            );
            running_offset = gf.byte_start.map(|s| s + byte_size.unwrap()).unwrap_or(running_offset + byte_size.unwrap());
        }
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0].name, "bw_lo");
        assert_eq!(fields[0].offset_bits, 0);
        assert_eq!(fields[0].size_bits, 32);
        assert_eq!(fields[0].endian, Endian::Little);
        assert_eq!(fields[4].name, "cwnd_gain");
        assert_eq!(fields[4].offset_bits, 128);
    }

    #[test]
    fn test_parse_pragueinfo_fields() {
        let body = r#"
    Alpha     uint64 // 8 = 8
    FracCwnd  uint64 // 8 = 16
    RateBytes uint64 // 8 = 24
    MaxBurst  uint32 // 4 = 28
    Round     uint32 // 4 = 32
    RttTarget uint32 // 4 = 36
"#;
        let fields = parse_struct_fields(body);
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0].name, "Alpha");
        assert_eq!(fields[0].go_type, "uint64");
        assert_eq!(fields[5].name, "RttTarget");
        assert_eq!(fields[5].byte_start, Some(32));
    }

    #[test]
    fn test_parse_vegasinfo_fields() {
        let body = r#"
    Enabled uint32 // 4 = 4
    RttCnt  uint32 // 4 = 8
    Rtt     uint32 // 4 = 12
    MinRtt  uint32 // 4 = 16
"#;
        let fields = parse_struct_fields(body);
        assert_eq!(fields.len(), 4);
    }

    #[test]
    fn test_infer_field_type() {
        assert_eq!(infer_field_type("SrcIP", 128), FieldType::Ipv6Addr);
        assert_eq!(infer_field_type("State", 8), FieldType::Enum);
        assert_eq!(infer_field_type("Options", 8), FieldType::Flags);
        assert_eq!(infer_field_type("Pad", 8), FieldType::Pad);
        assert_eq!(infer_field_type("Rto", 32), FieldType::Uint);
    }
}
