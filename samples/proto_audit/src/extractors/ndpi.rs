//! nDPI header extractor.
//!
//! Parses nDPI's packed struct definitions from `ndpi_typedefs.h` to extract
//! protocol field layouts. nDPI headers use BSD-style types (`u_int8_t`,
//! `u_int16_t`) and `PACK_ON/PACK_OFF` macros for struct packing.
//!
//! We preprocess the source to normalize these differences, then reuse
//! the kernel struct parser (`parse_kernel_struct` + `to_field_defs_with`)
//! with nDPI-specific type mappings loaded from `mappings/ndpi.toml`.

use anyhow::Result;
use std::path::Path;

use crate::ir::{ProtocolDef, SourceInfo};
use crate::type_mapping::{self, KernelMappings};

use super::kernel;

/// Preprocess nDPI header content so the kernel C parser can handle it.
///
/// Normalizes:
/// - `PACK_ON` / `PACK_OFF` → stripped
/// - `__attribute__((packed))` → stripped (PACK_OFF expands to this on GCC)
/// - `__LITTLE_ENDIAN__` → `__LITTLE_ENDIAN_BITFIELD`
/// - `__BIG_ENDIAN__` → `__BIG_ENDIAN_BITFIELD`
fn preprocess_ndpi(content: &str) -> String {
    let mut result = String::with_capacity(content.len());

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip standalone PACK_ON / PACK_OFF lines
        if trimmed == "PACK_ON" || trimmed == "PACK_OFF" {
            result.push('\n');
            continue;
        }

        let mut l = line.to_string();

        // Strip inline PACK_ON/PACK_OFF/attribute
        l = l.replace("PACK_ON", "");
        l = l.replace("PACK_OFF", "");
        l = l.replace("__attribute__((packed))", "");

        // Normalize endian conditionals to kernel convention
        // nDPI uses __LITTLE_ENDIAN__ / __BIG_ENDIAN__
        l = l.replace("__LITTLE_ENDIAN__", "__LITTLE_ENDIAN_BITFIELD");
        l = l.replace("__BIG_ENDIAN__", "__BIG_ENDIAN_BITFIELD");

        result.push_str(&l);
        result.push('\n');
    }

    result
}

/// Load nDPI type mappings (uses KernelMappings schema with nDPI types).
pub fn load_ndpi_mappings() -> Result<KernelMappings> {
    type_mapping::load_ndpi_mappings(None)
}

/// Extract a ProtocolDef from nDPI headers for a given struct.
pub fn extract_protocol(
    content: &str,
    struct_name: &str,
    file_path: &str,
) -> Result<Option<ProtocolDef>> {
    let preprocessed = preprocess_ndpi(content);

    let ks = match kernel::parse_kernel_struct(&preprocessed, struct_name)? {
        Some(ks) => ks,
        None => return Ok(None),
    };

    let mappings = load_ndpi_mappings()?;
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
                "ndpi",
                SourceInfo::new(struct_name)
                    .with_file(file_path)
                    .with_field_count(field_count)
                    .with_min_header_bytes(total_bits / 8),
            ),
    ))
}

/// Scan nDPI header directory for all packed struct definitions.
///
/// Returns `(struct_name, header_file)` pairs.
pub fn scan_ndpi_dir(dir: &Path) -> Result<Vec<(String, String)>> {
    let typedefs_path = dir.join("ndpi_typedefs.h");
    if !typedefs_path.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(&typedefs_path)?;
    let preprocessed = preprocess_ndpi(&content);

    let mut results = Vec::new();
    let struct_re = regex::Regex::new(r"struct\s+(ndpi_\w+)\s*\{")?;

    for cap in struct_re.captures_iter(&preprocessed) {
        let name = cap[1].to_string();
        // Skip internal/non-protocol structs
        if name.contains("bitmask")
            || name.contains("detection_module")
            || name.contains("flow")
            || name.contains("packet_struct")
            || name.contains("proto_defaults")
        {
            continue;
        }
        results.push((name, "ndpi_typedefs.h".to_string()));
    }

    results.sort();
    results.dedup();
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Endian;

    const NDPI_IPV4: &str = r#"
PACK_ON
struct ndpi_iphdr {
#if defined(__LITTLE_ENDIAN__)
  u_int8_t ihl:4, version:4;
#elif defined(__BIG_ENDIAN__)
  u_int8_t version:4, ihl:4;
#else
# error "Byte order must be defined"
#endif
  u_int8_t tos;
  u_int16_t tot_len;
  u_int16_t id;
  u_int16_t frag_off;
  u_int8_t ttl;
  u_int8_t protocol;
  u_int16_t check;
  u_int32_t saddr;
  u_int32_t daddr;
} PACK_OFF;
"#;

    const NDPI_TCP: &str = r#"
PACK_ON
struct ndpi_tcphdr
{
  u_int16_t source;
  u_int16_t dest;
  u_int32_t seq;
  u_int32_t ack_seq;
#if defined(__LITTLE_ENDIAN__)
  u_int16_t res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#elif defined(__BIG_ENDIAN__)
  u_int16_t doff:4, res1:4, cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#else
# error "Byte order must be defined"
#endif
  u_int16_t window;
  u_int16_t check;
  u_int16_t urg_ptr;
} PACK_OFF;
"#;

    const NDPI_UDP: &str = r#"
PACK_ON
struct ndpi_udphdr
{
  u_int16_t source;
  u_int16_t dest;
  u_int16_t len;
  u_int16_t check;
} PACK_OFF;
"#;

    #[test]
    fn test_extract_ndpi_ipv4() {
        let def = extract_protocol(NDPI_IPV4, "ndpi_iphdr", "ndpi_typedefs.h")
            .unwrap()
            .unwrap();
        assert_eq!(def.fields.len(), 11);
        assert_eq!(def.min_header_bits, 160);
        assert_eq!(def.fields[0].name, "version");
        assert_eq!(def.fields[0].size_bits, 4);
        assert_eq!(def.fields[1].name, "ihl");
        assert_eq!(def.fields[1].size_bits, 4);
        // Multi-byte fields should be big-endian (network order)
        let tot_len = def.fields.iter().find(|f| f.name == "tot_len").unwrap();
        assert_eq!(tot_len.endian, Endian::Big);
    }

    #[test]
    fn test_extract_ndpi_tcp() {
        let def = extract_protocol(NDPI_TCP, "ndpi_tcphdr", "ndpi_typedefs.h")
            .unwrap()
            .unwrap();
        // source(16) + dest(16) + seq(32) + ack_seq(32) + 16 bits of flags + window(16) + check(16) + urg_ptr(16)
        assert_eq!(def.min_header_bits, 160);
        assert_eq!(def.fields[0].name, "source");
        assert_eq!(def.fields[1].name, "dest");
        // Big-endian bitfield section should give us doff, res1, then flags
        let doff = def.fields.iter().find(|f| f.name == "doff");
        assert!(doff.is_some(), "should have doff field from big-endian section");
    }

    #[test]
    fn test_extract_ndpi_udp() {
        let def = extract_protocol(NDPI_UDP, "ndpi_udphdr", "ndpi_typedefs.h")
            .unwrap()
            .unwrap();
        assert_eq!(def.fields.len(), 4);
        assert_eq!(def.min_header_bits, 64);
    }

    #[test]
    fn test_preprocess_strips_pack_macros() {
        let input = "PACK_ON\nstruct foo {\n  u_int8_t x;\n} PACK_OFF;";
        let output = preprocess_ndpi(input);
        assert!(!output.contains("PACK_ON"));
        assert!(!output.contains("PACK_OFF"));
        assert!(output.contains("struct foo"));
    }
}
