//! DPDK net header extractor.
//!
//! Parses DPDK's `rte_*.h` packed struct definitions to extract protocol
//! field layouts. DPDK headers use the same C struct pattern as the Linux
//! kernel but with different type annotations (`rte_be16_t` instead of
//! `__be16`) and packing macros (`__rte_packed_begin/end`).
//!
//! We preprocess the source to normalize these differences, then reuse
//! the kernel struct parser (`parse_kernel_struct` + `to_field_defs_with`)
//! with DPDK-specific type mappings loaded from `mappings/dpdk.toml`.

use anyhow::Result;
use std::path::Path;

use crate::ir::{ProtocolDef, SourceInfo};
use crate::type_mapping::{self, KernelMappings};

use super::kernel;

/// Preprocess DPDK header content so the kernel C parser can handle it.
///
/// Normalizes:
/// - `__rte_packed_begin` / `__rte_packed_end` → stripped
/// - `__rte_aligned(N)` → stripped
/// - `__extension__` → stripped
/// - `RTE_BYTE_ORDER == RTE_BIG_ENDIAN` → `__BIG_ENDIAN_BITFIELD`
/// - `RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN` → `__LITTLE_ENDIAN_BITFIELD`
fn preprocess_dpdk(content: &str) -> String {
    let mut lines: Vec<String> = Vec::new();

    for line in content.lines() {
        let mut l = line.to_string();

        // Strip DPDK packing macros
        l = l.replace("__rte_packed_begin", "");
        l = l.replace("__rte_packed_end", "");
        l = l.replace("__extension__", "");

        // Strip __rte_aligned(N) annotations
        while let Some(start) = l.find("__rte_aligned(") {
            let end = l[start..].find(')').map(|i| start + i + 1).unwrap_or(start);
            l = format!("{}{}", &l[..start], &l[end..]);
        }

        // Normalize endian conditionals to kernel convention
        l = l.replace("RTE_BYTE_ORDER == RTE_BIG_ENDIAN", "defined(__BIG_ENDIAN_BITFIELD)");
        l = l.replace("RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN", "defined(__LITTLE_ENDIAN_BITFIELD)");

        lines.push(l);
    }

    // Second pass: strip anonymous union/struct wrappers and their closing };
    // DPDK uses these for bitfield overlays, e.g.:
    //   union { uint8_t version_ihl; struct { uint8_t ihl:4; ... }; };
    // The kernel parser skips `union` lines, so we inline the contents.
    // Within unions, drop non-bitfield members (like `version_ihl`) so only
    // the bitfield decomposition remains — avoids double-counting the same byte.
    let mut result = String::with_capacity(content.len());
    let mut anon_depth: Vec<usize> = Vec::new(); // stack of brace depths
    let mut in_union = false; // true when the outermost anonymous block is a union

    for l in &lines {
        let trimmed = l.trim();

        // Detect anonymous union/struct opener (no field name after {)
        if trimmed == "union {" || trimmed == "struct {" {
            if anon_depth.is_empty() {
                in_union = trimmed == "union {";
            }
            anon_depth.push(0);
            continue; // skip this line
        }

        // Track nested braces within anonymous blocks
        if !anon_depth.is_empty() {
            if trimmed.ends_with('{') {
                if let Some(depth) = anon_depth.last_mut() {
                    *depth += 1;
                }
            }
            if trimmed == "};" {
                if let Some(depth) = anon_depth.last_mut() {
                    if *depth == 0 {
                        anon_depth.pop(); // closing }; matches our anonymous wrapper
                        if anon_depth.is_empty() {
                            in_union = false;
                        }
                        continue;
                    }
                    *depth -= 1;
                }
            }

            // Within a union, drop non-bitfield field declarations.
            // Keep bitfields (contain ':') — they're the decomposition we want.
            // This prevents e.g. `uint8_t version_ihl;` and `uint8_t version:4;`
            // both appearing as sequential fields.
            if in_union && anon_depth.len() == 1 && anon_depth[0] == 0 {
                // Strip trailing inline comments before checking for ';'
                let stripped = if let Some(pos) = trimmed.find("/*") {
                    trimmed[..pos].trim()
                } else if let Some(pos) = trimmed.find("//") {
                    trimmed[..pos].trim()
                } else {
                    trimmed
                };
                let is_field = stripped.ends_with(';')
                    && !stripped.starts_with('#');
                let is_bitfield = stripped.contains(':');
                if is_field && !is_bitfield {
                    continue; // skip aggregate member like `uint8_t version_ihl;`
                }
            }
        }

        result.push_str(l);
        result.push('\n');
    }

    result
}

/// Load DPDK type mappings (uses KernelMappings schema with DPDK types).
pub fn load_dpdk_mappings() -> Result<KernelMappings> {
    type_mapping::load_dpdk_mappings(None)
}

/// Extract a ProtocolDef from a DPDK header file for a given struct.
pub fn extract_protocol(
    content: &str,
    struct_name: &str,
    file_path: &str,
) -> Result<Option<ProtocolDef>> {
    let preprocessed = preprocess_dpdk(content);

    let ks = match kernel::parse_kernel_struct(&preprocessed, struct_name)? {
        Some(ks) => ks,
        None => return Ok(None),
    };

    let mappings = load_dpdk_mappings()?;
    let fields = kernel::to_field_defs_with(&ks, &mappings);
    let total_bits: u32 = fields
        .iter()
        .map(|f| f.offset_bits + f.size_bits)
        .max()
        .unwrap_or(0);
    let field_count = fields.len() as u32;

    Ok(Some(
        ProtocolDef::new(struct_name, total_bits)
            .with_fields(fields)
            .with_source(
                "dpdk",
                SourceInfo::new(struct_name)
                    .with_file(file_path)
                    .with_field_count(field_count)
                    .with_min_header_bytes(total_bits / 8),
            ),
    ))
}

/// Scan a DPDK net headers directory for all protocol struct definitions.
///
/// Returns `(struct_name, header_file)` pairs for each struct found.
pub fn scan_dpdk_dir(dir: &Path) -> Result<Vec<(String, String)>> {
    let net_dir = dir.join("lib").join("net");
    if !net_dir.exists() {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();
    let struct_re = regex::Regex::new(r"struct\s+(\w*rte_\w+_hdr\w*)\s*\{")?;

    for entry in std::fs::read_dir(&net_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(true, |e| e != "h") {
            continue;
        }
        let file_name = path.file_name().unwrap().to_string_lossy().to_string();
        let content = std::fs::read_to_string(&path)?;
        let preprocessed = preprocess_dpdk(&content);

        for cap in struct_re.captures_iter(&preprocessed) {
            let struct_name = cap[1].to_string();
            results.push((struct_name, file_name.clone()));
        }
    }

    results.sort();
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DPDK_TCP: &str = r#"
struct __rte_packed_begin rte_tcp_hdr {
	rte_be16_t src_port;
	rte_be16_t dst_port;
	rte_be32_t sent_seq;
	rte_be32_t recv_ack;
	uint8_t  data_off;
	uint8_t  tcp_flags;
	rte_be16_t rx_win;
	rte_be16_t cksum;
	rte_be16_t tcp_urp;
} __rte_packed_end;
"#;

    const DPDK_IPV4: &str = r#"
struct __rte_aligned(2) __rte_packed_begin rte_ipv4_hdr {
	__extension__
	union {
		uint8_t version_ihl;
		struct {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
			uint8_t ihl:4;
			uint8_t version:4;
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
			uint8_t version:4;
			uint8_t ihl:4;
#endif
		};
	};
	uint8_t  type_of_service;
	rte_be16_t total_length;
	rte_be16_t packet_id;
	rte_be16_t fragment_offset;
	uint8_t  time_to_live;
	uint8_t  next_proto_id;
	rte_be16_t hdr_checksum;
	rte_be32_t src_addr;
	rte_be32_t dst_addr;
} __rte_packed_end;
"#;

    #[test]
    fn test_extract_dpdk_tcp() {
        let def = extract_protocol(DPDK_TCP, "rte_tcp_hdr", "rte_tcp.h")
            .unwrap()
            .unwrap();
        assert_eq!(def.fields.len(), 9);
        assert_eq!(def.min_header_bits, 160);
        assert_eq!(def.fields[0].name, "src_port");
        assert_eq!(def.fields[0].size_bits, 16);
        assert_eq!(def.fields[1].name, "dst_port");
    }

    #[test]
    fn test_extract_dpdk_ipv4() {
        let def = extract_protocol(DPDK_IPV4, "rte_ipv4_hdr", "rte_ip4.h")
            .unwrap()
            .unwrap();
        // Union aggregate member (version_ihl) should be dropped; only bitfields kept
        assert_eq!(def.fields.len(), 11, "expected 11 fields (no version_ihl), got {}", def.fields.len());
        assert_eq!(def.fields[0].name, "version");
        assert_eq!(def.fields[0].size_bits, 4);
        assert_eq!(def.fields[0].offset_bits, 0);
        assert_eq!(def.fields[1].name, "ihl");
        assert_eq!(def.fields[1].size_bits, 4);
        assert_eq!(def.min_header_bits, 160);
        // Check that src_addr and dst_addr are present
        assert!(def.fields.iter().any(|f| f.name == "src_addr"));
        assert!(def.fields.iter().any(|f| f.name == "dst_addr"));
        // version_ihl aggregate should NOT be present
        assert!(!def.fields.iter().any(|f| f.name == "version_ihl"));
    }

    #[test]
    fn test_preprocess_strips_macros() {
        let input = "struct __rte_packed_begin __rte_aligned(2) rte_foo {";
        let output = preprocess_dpdk(input);
        assert!(!output.contains("__rte_packed_begin"));
        assert!(!output.contains("__rte_aligned"));
        assert!(output.contains("struct"));
        assert!(output.contains("rte_foo"));
    }
}
