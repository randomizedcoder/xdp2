//! Linux kernel UAPI header extractor.
//!
//! Parses kernel C struct definitions to extract field-level detail:
//! field names, types, sizes, bit widths, and byte order annotations.
//!
//! Targets the highly consistent UAPI header format:
//! ```c
//! struct iphdr {
//! #if defined(__LITTLE_ENDIAN_BITFIELD)
//!     __u8    ihl:4, version:4;
//! #elif defined(__BIG_ENDIAN_BITFIELD)
//!     __u8    version:4, ihl:4;
//! #endif
//!     __u8    tos;
//!     __be16  tot_len;
//!     ...
//! };
//! ```

use anyhow::Result;
use regex::Regex;
use std::collections::BTreeMap;

use crate::ir::{Endian, FieldDef, FieldType, ProtocolDef, SourceInfo};

/// A raw field parsed from a kernel struct.
#[derive(Debug, Clone)]
pub struct KernelField {
    /// C type (e.g., "__be16", "__u8", "struct in6_addr")
    pub c_type: String,
    /// Field name
    pub name: String,
    /// Bitfield width (None for regular fields)
    pub bitfield_width: Option<u32>,
    /// Array size (None for non-arrays)
    pub array_size: Option<u32>,
}

/// Metadata for a parsed kernel struct.
#[derive(Debug, Clone)]
pub struct KernelStruct {
    pub name: String,
    pub fields: Vec<KernelField>,
    pub file_path: String,
    /// Whether the struct uses __BIG_ENDIAN_BITFIELD ordering
    pub has_endian_bitfield: bool,
}

/// Map a kernel C type to its size in bits.
fn c_type_bits(ty: &str) -> Option<u32> {
    match ty {
        "__u8" | "__s8" | "__be8" | "u8" | "char" | "unsigned char" => Some(8),
        "__u16" | "__s16" | "__be16" | "__le16" | "__sum16" | "u16" => Some(16),
        "__u32" | "__s32" | "__be32" | "__le32" | "__wsum" | "u32" => Some(32),
        "__u64" | "__s64" | "__be64" | "__le64" | "u64" => Some(64),
        _ => None,
    }
}

/// Determine endianness from kernel type annotation.
fn c_type_endian(ty: &str) -> Endian {
    if ty.starts_with("__be") {
        Endian::Big
    } else if ty.starts_with("__le") {
        Endian::Little
    } else {
        // Native types (__u8, etc.) — for single-byte, Na; for multi-byte, assume platform
        // In network protocol context, most multi-byte fields are big-endian
        Endian::Na
    }
}

/// Determine the semantic field type from the C type and field name.
fn infer_field_type(c_type: &str, name: &str, bits: u32) -> FieldType {
    // Address types by name pattern
    if name.contains("addr") || name == "src" || name == "dst" || name == "saddr" || name == "daddr"
    {
        if bits == 32 {
            return FieldType::Ipv4Addr;
        }
        if bits == 128 {
            return FieldType::Ipv6Addr;
        }
    }
    if name.contains("h_dest") || name.contains("h_source") || name.contains("mac") {
        if bits == 48 {
            return FieldType::MacAddr;
        }
    }

    // Signed types (but not __sum16 which is a checksum, not signed)
    if c_type.starts_with("__s") && !c_type.starts_with("__sum") {
        return FieldType::Sint;
    }

    // Padding/reserved
    if name.contains("pad") || name.contains("reserved") || name.starts_with("__") {
        return FieldType::Pad;
    }

    FieldType::Uint
}

/// Parse a kernel struct definition from source text.
///
/// Handles:
/// - Regular fields: `__be16 tot_len;`
/// - Bitfields: `__u8 ihl:4, version:4;`
/// - Endian-conditional bitfields: `#if defined(__BIG_ENDIAN_BITFIELD)`
/// - Arrays: `__u8 h_dest[ETH_ALEN];`
pub fn parse_kernel_struct(content: &str, struct_name: &str) -> Result<Option<KernelStruct>> {
    // Find the struct definition (handle __attribute__ and __packed before semicolon)
    let struct_pattern = format!(
        r"(?s)struct\s+{}\s*\{{(.*?)\}}\s*[^;]*;",
        regex::escape(struct_name)
    );
    let struct_re = Regex::new(&struct_pattern)?;

    let body = match struct_re.captures(content) {
        Some(cap) => cap[1].to_string(),
        None => return Ok(None),
    };

    let has_endian_bitfield = body.contains("__BIG_ENDIAN_BITFIELD");

    // We parse the __BIG_ENDIAN_BITFIELD section if present (network byte order),
    // otherwise parse all fields
    let parse_body = if has_endian_bitfield {
        // Line-by-line state machine: include non-conditional lines and
        // only the __BIG_ENDIAN_BITFIELD section of conditional blocks
        let mut result = String::new();
        let mut in_conditional = false;
        let mut in_big_endian = false;

        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("#if") && line.contains("__LITTLE_ENDIAN_BITFIELD") {
                in_conditional = true;
                in_big_endian = false;
            } else if trimmed.starts_with("#if") && line.contains("__BIG_ENDIAN_BITFIELD") {
                in_conditional = true;
                in_big_endian = true;
            } else if in_conditional && trimmed.starts_with("#elif") {
                in_big_endian = line.contains("__BIG_ENDIAN_BITFIELD");
            } else if in_conditional && trimmed.starts_with("#else") {
                in_big_endian = false;
            } else if in_conditional && trimmed.starts_with("#endif") {
                in_conditional = false;
                in_big_endian = false;
            } else if !in_conditional || in_big_endian {
                result.push_str(line);
                result.push('\n');
            }
        }
        result
    } else {
        body.clone()
    };

    let fields = parse_struct_fields(&parse_body)?;

    Ok(Some(KernelStruct {
        name: struct_name.to_string(),
        fields,
        file_path: String::new(),
        has_endian_bitfield,
    }))
}

/// Preprocess struct body to unwrap __struct_group() macros.
///
/// `__struct_group(TAG, NAME, ATTRS, MEMBERS)` is a kernel macro that
/// creates an anonymous struct group. We strip the wrapper and inline
/// the MEMBERS so the field parser can see them normally.
fn unwrap_struct_group(body: &str) -> String {
    let mut result = body.to_string();

    while let Some(start) = result.find("__struct_group(") {
        let after_open = start + "__struct_group(".len();
        // Count parentheses to find matching close
        let mut depth = 1;
        let mut end = after_open;
        for (i, ch) in result[after_open..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = after_open + i;
                        break;
                    }
                }
                _ => {}
            }
        }

        // Inside: TAG, NAME, ATTRS, MEMBERS
        // We need the MEMBERS part (everything after the 3rd comma at depth 0)
        let inner = &result[after_open..end];
        let mut comma_count = 0;
        let mut member_start = 0;
        let mut pdepth = 0;
        for (i, ch) in inner.char_indices() {
            match ch {
                '(' => pdepth += 1,
                ')' => pdepth -= 1,
                ',' if pdepth == 0 => {
                    comma_count += 1;
                    if comma_count == 3 {
                        member_start = i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }

        let members = &inner[member_start..];
        // Also skip the trailing ");" or just ")"
        let replacement_end = if result[end..].starts_with(");") {
            end + 2
        } else {
            end + 1
        };

        result = format!("{}{}{}", &result[..start], members, &result[replacement_end..]);
    }

    result
}

/// Parse individual fields from a struct body.
fn parse_struct_fields(body: &str) -> Result<Vec<KernelField>> {
    let mut fields = Vec::new();

    // Step 0: Unwrap __struct_group() macros
    let body = unwrap_struct_group(body);

    // Step 1: Filter out preprocessor directives and comments, join continuation lines
    let mut statements = Vec::new();
    let mut current = String::new();

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || trimmed.starts_with("*")
            || trimmed.starts_with("//")
            || trimmed.is_empty()
        {
            continue;
        }

        current.push(' ');
        current.push_str(trimmed);

        // If line ends with `;`, it's a complete statement
        if trimmed.ends_with(';') {
            statements.push(current.trim().to_string());
            current.clear();
        }
        // Otherwise it's a continuation (e.g., multi-line bitfield: `__u8 version:4,`)
    }

    let bitfield_re = Regex::new(r"(\w+)\s*:\s*(\d+)")?;
    let array_re = Regex::new(r"(\w+)\s*\[\s*(\w+)\s*\]")?;

    // Known multi-word C types
    let multi_word_types = [
        "unsigned char",
        "unsigned short",
        "unsigned int",
        "unsigned long",
        "signed char",
        "signed short",
        "signed int",
        "signed long",
    ];

    for stmt in &statements {
        // Remove trailing semicolon
        let stmt = stmt.trim_end_matches(';').trim();

        // Try to split into TYPE and REST
        let (c_type, rest) = 'split: {
            // Try multi-word types first
            for mwt in &multi_word_types {
                if stmt.starts_with(mwt) {
                    let rest = stmt[mwt.len()..].trim();
                    break 'split (mwt.to_string(), rest.to_string());
                }
            }
            // Single-word type: first token
            let mut parts = stmt.splitn(2, |c: char| c.is_whitespace());
            let ty = parts.next().unwrap_or("").to_string();
            let rest = parts.next().unwrap_or("").trim().to_string();
            (ty, rest)
        };

        if c_type.is_empty() || rest.is_empty() {
            continue;
        }
        // Skip union/struct embedded types
        if c_type == "union" || c_type == "struct" {
            continue;
        }

        // Parse comma-separated field list (handles bitfields across continuations)
        for part in rest.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            if let Some(bf_cap) = bitfield_re.captures(part) {
                fields.push(KernelField {
                    c_type: c_type.clone(),
                    name: bf_cap[1].to_string(),
                    bitfield_width: Some(bf_cap[2].parse()?),
                    array_size: None,
                });
            } else if let Some(arr_cap) = array_re.captures(part) {
                let size_str = &arr_cap[2];
                let size = match size_str {
                    "ETH_ALEN" => 6,
                    _ => size_str.parse().unwrap_or(1),
                };
                fields.push(KernelField {
                    c_type: c_type.clone(),
                    name: arr_cap[1].to_string(),
                    bitfield_width: None,
                    array_size: Some(size),
                });
            } else {
                // Plain field name
                let name = part.split_whitespace().next().unwrap_or(part);
                if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    fields.push(KernelField {
                        c_type: c_type.clone(),
                        name: name.to_string(),
                        bitfield_width: None,
                        array_size: None,
                    });
                }
            }
        }
    }

    Ok(fields)
}

/// Convert a KernelStruct to field-level IR definitions.
pub fn to_field_defs(ks: &KernelStruct) -> Vec<FieldDef> {
    let mut fields = Vec::new();
    let mut offset_bits: u32 = 0;

    for kf in &ks.fields {
        let bits = if let Some(bw) = kf.bitfield_width {
            bw
        } else if let Some(arr) = kf.array_size {
            c_type_bits(&kf.c_type).unwrap_or(8) * arr
        } else {
            c_type_bits(&kf.c_type).unwrap_or(0)
        };

        if bits == 0 {
            continue; // Unknown type, skip
        }

        let endian = if kf.bitfield_width.is_some() || bits <= 8 {
            Endian::Na
        } else {
            c_type_endian(&kf.c_type)
        };

        let field_type = infer_field_type(&kf.c_type, &kf.name, bits);

        fields.push(FieldDef {
            name: kf.name.clone(),
            offset_bits,
            size_bits: bits,
            field_type,
            endian,
            description: String::new(),
            is_dispatch: false,
            is_length: false,
            length_multiplier: None,
            source_names: BTreeMap::from([("kernel".to_string(), kf.name.clone())]),
        });

        offset_bits += bits;
    }

    fields
}

/// Extract a full ProtocolDef from a kernel header for a given struct.
pub fn extract_protocol(
    content: &str,
    struct_name: &str,
    file_path: &str,
) -> Result<Option<ProtocolDef>> {
    let ks = match parse_kernel_struct(content, struct_name)? {
        Some(ks) => ks,
        None => return Ok(None),
    };

    let fields = to_field_defs(&ks);
    let total_bits: u32 = fields.iter().map(|f| f.offset_bits + f.size_bits).max().unwrap_or(0);
    let field_count = fields.len() as u32;

    Ok(Some(ProtocolDef {
        name: struct_name.to_string(),
        min_header_bits: total_bits,
        is_variable_length: false,
        fields,
        dispatch_field: None,
        dispatch_table: vec![],
        identifiers: BTreeMap::new(),
        sources: BTreeMap::from([(
            "kernel".to_string(),
            SourceInfo {
                present: true,
                file_path: Some(file_path.to_string()),
                source_name: struct_name.to_string(),
                field_count,
                min_header_bytes: total_bits / 8,
                notes: vec![],
            },
        )]),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPHDR: &str = r#"
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4,
        version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
        ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    __u8    tos;
    __be16  tot_len;
    __be16  id;
    __be16  frag_off;
    __u8    ttl;
    __u8    protocol;
    __sum16 check;
    __be32  saddr;
    __be32  daddr;
};
"#;

    #[test]
    fn test_parse_iphdr() {
        let ks = parse_kernel_struct(IPHDR, "iphdr").unwrap().unwrap();
        assert_eq!(ks.name, "iphdr");
        assert!(ks.has_endian_bitfield);

        // Should have: version:4, ihl:4, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr
        assert!(ks.fields.len() >= 10, "got {} fields", ks.fields.len());

        // Check bitfield parsing (big-endian section)
        let version = &ks.fields[0];
        assert_eq!(version.name, "version");
        assert_eq!(version.bitfield_width, Some(4));

        let ihl = &ks.fields[1];
        assert_eq!(ihl.name, "ihl");
        assert_eq!(ihl.bitfield_width, Some(4));
    }

    #[test]
    fn test_iphdr_field_defs() {
        let ks = parse_kernel_struct(IPHDR, "iphdr").unwrap().unwrap();
        let fields = to_field_defs(&ks);

        // version at offset 0, 4 bits
        let version = fields.iter().find(|f| f.name == "version").unwrap();
        assert_eq!(version.offset_bits, 0);
        assert_eq!(version.size_bits, 4);
        assert_eq!(version.endian, Endian::Na);

        // ihl at offset 4, 4 bits
        let ihl = fields.iter().find(|f| f.name == "ihl").unwrap();
        assert_eq!(ihl.offset_bits, 4);
        assert_eq!(ihl.size_bits, 4);

        // tos at offset 8, 8 bits
        let tos = fields.iter().find(|f| f.name == "tos").unwrap();
        assert_eq!(tos.offset_bits, 8);
        assert_eq!(tos.size_bits, 8);

        // tot_len at offset 16, 16 bits, big-endian
        let tot_len = fields.iter().find(|f| f.name == "tot_len").unwrap();
        assert_eq!(tot_len.offset_bits, 16);
        assert_eq!(tot_len.size_bits, 16);
        assert_eq!(tot_len.endian, Endian::Big);

        // saddr at offset 96, 32 bits, Ipv4Addr
        let saddr = fields.iter().find(|f| f.name == "saddr").unwrap();
        assert_eq!(saddr.offset_bits, 96);
        assert_eq!(saddr.size_bits, 32);
        assert_eq!(saddr.field_type, FieldType::Ipv4Addr);
    }

    const ETHHDR: &str = r#"
struct ethhdr {
    unsigned char   h_dest[ETH_ALEN];
    unsigned char   h_source[ETH_ALEN];
    __be16          h_proto;
} __attribute__((packed));
"#;

    #[test]
    fn test_parse_ethhdr() {
        let ks = parse_kernel_struct(ETHHDR, "ethhdr").unwrap().unwrap();
        assert_eq!(ks.fields.len(), 3);

        assert_eq!(ks.fields[0].name, "h_dest");
        assert_eq!(ks.fields[0].array_size, Some(6));

        assert_eq!(ks.fields[1].name, "h_source");
        assert_eq!(ks.fields[1].array_size, Some(6));

        assert_eq!(ks.fields[2].name, "h_proto");
        assert_eq!(ks.fields[2].c_type, "__be16");
    }

    #[test]
    fn test_ethhdr_field_defs() {
        let ks = parse_kernel_struct(ETHHDR, "ethhdr").unwrap().unwrap();
        let fields = to_field_defs(&ks);

        let h_dest = &fields[0];
        assert_eq!(h_dest.offset_bits, 0);
        assert_eq!(h_dest.size_bits, 48);
        assert_eq!(h_dest.field_type, FieldType::MacAddr); // h_dest → MAC address

        let h_proto = &fields[2];
        assert_eq!(h_proto.offset_bits, 96);
        assert_eq!(h_proto.size_bits, 16);
        assert_eq!(h_proto.endian, Endian::Big);
    }

    #[test]
    fn test_extract_protocol() {
        let proto = extract_protocol(IPHDR, "iphdr", "include/uapi/linux/ip.h")
            .unwrap()
            .unwrap();
        assert_eq!(proto.name, "iphdr");
        assert!(proto.fields.len() >= 10);
        let src = proto.sources.get("kernel").unwrap();
        assert!(src.present);
        assert_eq!(src.min_header_bytes, 20);
    }

    /// Test parsing iphdr with __struct_group wrapping saddr/daddr
    /// (as found in modern kernel headers like glibc 2.42+)
    const IPHDR_STRUCT_GROUP: &str = r#"
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__struct_group(/* no tag */, addrs, /* no attrs */,
		__be32	saddr;
		__be32	daddr;
	);
	/*The options start here. */
};
"#;

    #[test]
    fn test_parse_iphdr_struct_group() {
        let ks = parse_kernel_struct(IPHDR_STRUCT_GROUP, "iphdr")
            .unwrap()
            .unwrap();
        assert_eq!(ks.fields.len(), 11, "expected 11 fields, got {:?}",
            ks.fields.iter().map(|f| &f.name).collect::<Vec<_>>());

        let saddr = ks.fields.iter().find(|f| f.name == "saddr").expect("saddr missing");
        assert_eq!(saddr.c_type, "__be32");

        let daddr = ks.fields.iter().find(|f| f.name == "daddr").expect("daddr missing");
        assert_eq!(daddr.c_type, "__be32");
    }

    #[test]
    fn test_iphdr_struct_group_field_defs() {
        let ks = parse_kernel_struct(IPHDR_STRUCT_GROUP, "iphdr")
            .unwrap()
            .unwrap();
        let fields = to_field_defs(&ks);

        // saddr at offset 96, 32 bits
        let saddr = fields.iter().find(|f| f.name == "saddr").unwrap();
        assert_eq!(saddr.offset_bits, 96);
        assert_eq!(saddr.size_bits, 32);
        assert_eq!(saddr.field_type, FieldType::Ipv4Addr);

        // daddr at offset 128, 32 bits
        let daddr = fields.iter().find(|f| f.name == "daddr").unwrap();
        assert_eq!(daddr.offset_bits, 128);
        assert_eq!(daddr.size_bits, 32);
        assert_eq!(daddr.field_type, FieldType::Ipv4Addr);

        // Total: 160 bits = 20 bytes
        let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap_or(0);
        assert_eq!(total, 160);
    }
}
