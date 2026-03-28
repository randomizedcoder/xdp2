//! libpcap BPF compiler + header struct extractor.
//!
//! Dual-path extractor for libpcap protocol knowledge:
//! - **Gencode offsets**: Protocol field offsets from gencode.c's BPF compiler,
//!   captured declaratively in TOML and verified against source.
//! - **C struct parsing**: For protocols defined as structs in pcap/*.h headers
//!   (SLL, VLAN).

use anyhow::Result;
use regex::Regex;
use std::path::Path;

use crate::ir::{Endian, FieldDef, FieldType, ProtocolDef, SourceInfo};
use crate::type_mapping::{self, LibpcapMappings};

// ── Gencode extraction (TOML-declared offsets) ──

/// Extract a protocol from libpcap sources.
///
/// Dispatches between gencode (TOML-declared offsets) and struct parsing
/// based on the `libpcap_file` hint from the name mapping table.
pub fn extract_protocol(
    libpcap_src: Option<&Path>,
    proto: &str,
    libpcap_name: &str,
    libpcap_file: &str,
    mappings: &LibpcapMappings,
) -> Result<Option<ProtocolDef>> {
    if libpcap_file == "gencode.c" {
        return extract_from_gencode(proto, libpcap_name, mappings);
    }

    // Struct parsing for pcap/*.h headers
    let src_dir = match libpcap_src {
        Some(dir) => dir,
        None => return Ok(None),
    };

    let struct_config = match mappings.struct_protocols.get(libpcap_name) {
        Some(config) => config,
        None => return Ok(None),
    };

    let file_path = src_dir.join(&struct_config.source_file);
    let content = match std::fs::read_to_string(&file_path) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };

    extract_from_struct(
        &content,
        proto,
        &struct_config.struct_name,
        &struct_config.source_file,
        mappings,
    )
}

/// Extract protocol fields from gencode TOML declarations.
///
/// The TOML `gencode_protocols` table captures byte offsets from gencode.c's
/// `#define` constants. This function converts them to IR FieldDefs.
pub fn extract_from_gencode(
    proto: &str,
    libpcap_name: &str,
    mappings: &LibpcapMappings,
) -> Result<Option<ProtocolDef>> {
    let gencode_fields = match mappings.gencode_protocols.get(libpcap_name) {
        Some(fields) => fields,
        None => return Ok(None),
    };

    let mut fields: Vec<FieldDef> = Vec::new();
    for (name, gf) in gencode_fields {
        let offset_bits = gf.byte_offset * 8;
        let size_bits = gf.size_bytes * 8;
        let endian = if size_bits <= 8 {
            Endian::Na
        } else {
            Endian::Big
        };
        let field_type = gf
            .field_type
            .as_ref()
            .and_then(|ft| type_mapping::parse_field_type(ft))
            .unwrap_or(FieldType::Uint);

        fields.push(
            FieldDef::new(name.clone(), offset_bits, size_bits, field_type)
                .with_endian(endian),
        );
    }

    // Sort by offset for consistent output
    fields.sort_by_key(|f| f.offset_bits);

    let total_bits = fields
        .last()
        .map(|f| f.offset_bits + f.size_bits)
        .unwrap_or(0);

    let field_count = fields.len() as u32;

    Ok(Some(ProtocolDef::new(proto, total_bits)
        .with_fields(fields)
        .with_source("libpcap", SourceInfo::new(libpcap_name)
            .with_file("gencode.c")
            .with_field_count(field_count)
            .with_min_header_bytes(total_bits / 8)
            .with_note("Offsets from BPF compiler #define constants"))))
}

// ── C struct parsing (for pcap/*.h headers) ──

/// A raw field parsed from a libpcap C struct.
#[derive(Debug, Clone)]
pub struct LibpcapField {
    pub c_type: String,
    pub name: String,
    pub array_size: Option<u32>,
}

/// Metadata for a parsed libpcap struct.
#[derive(Debug, Clone)]
pub struct LibpcapStruct {
    pub name: String,
    pub fields: Vec<LibpcapField>,
}

/// Known `#define` constants used as array sizes in libpcap headers.
const KNOWN_CONSTANTS: &[(&str, u32)] = &[("SLL_ADDRLEN", 8), ("SLL2_ADDRLEN", 8)];

/// Parse a C struct definition from libpcap header content.
///
/// Handles simple C structs with `uint*_t` types and fixed-size arrays.
pub fn parse_libpcap_struct(content: &str, struct_name: &str) -> Result<Option<LibpcapStruct>> {
    let pattern = format!(
        r"struct\s+{}\s*\{{([^}}]*)\}}",
        regex::escape(struct_name)
    );
    let re = Regex::new(&pattern)?;

    let caps = match re.captures(content) {
        Some(c) => c,
        None => return Ok(None),
    };

    let body = &caps[1];
    let mut fields = Vec::new();

    let field_re = Regex::new(r"(\w+)\s+(\w+)(?:\[(\w+)\])?\s*;")?;

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with("/*") || line.starts_with("*") {
            continue;
        }

        if let Some(caps) = field_re.captures(line) {
            let c_type = caps[1].to_string();
            let name = caps[2].to_string();
            let array_size = caps.get(3).and_then(|m| {
                let s = m.as_str();
                s.parse::<u32>().ok().or_else(|| {
                    KNOWN_CONSTANTS
                        .iter()
                        .find(|(k, _)| *k == s)
                        .map(|(_, v)| *v)
                })
            });

            fields.push(LibpcapField {
                c_type,
                name,
                array_size,
            });
        }
    }

    Ok(Some(LibpcapStruct {
        name: struct_name.to_string(),
        fields,
    }))
}

/// Convert parsed struct fields to IR FieldDefs using TOML mappings.
pub fn struct_to_field_defs(ls: &LibpcapStruct, mappings: &LibpcapMappings) -> Vec<FieldDef> {
    let mut fields = Vec::new();
    let mut offset: u32 = 0;

    for lf in &ls.fields {
        let base_bits = match mappings.type_bits(&lf.c_type) {
            Some(bits) => bits,
            None => continue,
        };

        let total_bits = if let Some(arr_size) = lf.array_size {
            base_bits * arr_size
        } else {
            base_bits
        };

        let endian = if total_bits <= 8 {
            Endian::Na
        } else if let Some(arr_size) = lf.array_size {
            mappings
                .array_endian_override(&lf.c_type, arr_size)
                .unwrap_or(Endian::Big)
        } else {
            mappings.type_endian(&lf.c_type)
        };

        let field_type = if let Some(ft) = mappings.field_type_override(&lf.name) {
            ft
        } else {
            FieldType::Uint
        };

        fields.push(
            FieldDef::new(lf.name.clone(), offset, total_bits, field_type)
                .with_endian(endian),
        );

        offset += total_bits;
    }

    fields
}

fn extract_from_struct(
    content: &str,
    proto: &str,
    struct_name: &str,
    source_file: &str,
    mappings: &LibpcapMappings,
) -> Result<Option<ProtocolDef>> {
    let ls = match parse_libpcap_struct(content, struct_name)? {
        Some(s) => s,
        None => return Ok(None),
    };

    let fields = struct_to_field_defs(&ls, mappings);
    let total_bits = fields
        .last()
        .map(|f| f.offset_bits + f.size_bits)
        .unwrap_or(0);

    let field_count = fields.len() as u32;

    Ok(Some(ProtocolDef::new(proto, total_bits)
        .with_fields(fields)
        .with_source("libpcap", SourceInfo::new(struct_name)
            .with_file(source_file)
            .with_field_count(field_count)
            .with_min_header_bytes(total_bits / 8)
            .with_note(format!("C struct from {}", source_file)))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Endian, FieldType};

    #[test]
    fn test_extract_gencode_ipv4() {
        let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
        let def = extract_from_gencode("IPv4", "IPv4", &mappings)
            .unwrap()
            .unwrap();

        assert_eq!(def.fields.len(), 4);
        assert_eq!(def.name, "IPv4");

        let protocol = def.fields.iter().find(|f| f.name == "protocol").unwrap();
        assert_eq!(protocol.offset_bits, 72);
        assert_eq!(protocol.size_bits, 8);
        assert_eq!(protocol.field_type, FieldType::Enum);
        assert_eq!(protocol.endian, Endian::Na);

        let src = def.fields.iter().find(|f| f.name == "src_addr").unwrap();
        assert_eq!(src.offset_bits, 96);
        assert_eq!(src.size_bits, 32);
        assert_eq!(src.field_type, FieldType::Ipv4Addr);
        assert_eq!(src.endian, Endian::Big);

        let dst = def.fields.iter().find(|f| f.name == "dst_addr").unwrap();
        assert_eq!(dst.offset_bits, 128);
        assert_eq!(dst.size_bits, 32);
        assert_eq!(dst.field_type, FieldType::Ipv4Addr);
    }

    #[test]
    fn test_extract_gencode_udp() {
        let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
        let def = extract_from_gencode("UDP", "UDP", &mappings)
            .unwrap()
            .unwrap();

        assert_eq!(def.fields.len(), 2);
        assert_eq!(def.fields[0].name, "src_port");
        assert_eq!(def.fields[0].offset_bits, 0);
        assert_eq!(def.fields[0].size_bits, 16);
        assert_eq!(def.fields[0].endian, Endian::Big);
        assert_eq!(def.fields[1].name, "dst_port");
        assert_eq!(def.fields[1].offset_bits, 16);
    }

    #[test]
    fn test_extract_gencode_tcp() {
        let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
        let def = extract_from_gencode("TCP", "TCP", &mappings)
            .unwrap()
            .unwrap();

        assert_eq!(def.fields.len(), 2);
        assert_eq!(def.fields[0].name, "src_port");
        assert_eq!(def.fields[1].name, "dst_port");
    }

    #[test]
    fn test_extract_gencode_ipv6() {
        let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
        let def = extract_from_gencode("IPv6", "IPv6", &mappings)
            .unwrap()
            .unwrap();

        assert_eq!(def.fields.len(), 3);

        let nh = def.fields.iter().find(|f| f.name == "next_header").unwrap();
        assert_eq!(nh.offset_bits, 48);
        assert_eq!(nh.size_bits, 8);
        assert_eq!(nh.field_type, FieldType::Enum);

        let src = def.fields.iter().find(|f| f.name == "src_addr").unwrap();
        assert_eq!(src.offset_bits, 64);
        assert_eq!(src.size_bits, 128);
        assert_eq!(src.field_type, FieldType::Ipv6Addr);

        let dst = def.fields.iter().find(|f| f.name == "dst_addr").unwrap();
        assert_eq!(dst.offset_bits, 192);
        assert_eq!(dst.size_bits, 128);
    }

    #[test]
    fn test_extract_gencode_unknown() {
        let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
        let result = extract_from_gencode("Unknown", "Unknown", &mappings).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_gencode_source_info() {
        let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
        let def = extract_from_gencode("IPv4", "IPv4", &mappings)
            .unwrap()
            .unwrap();

        let info = def.sources.get("libpcap").unwrap();
        assert!(info.present);
        assert_eq!(info.file_path, Some("gencode.c".to_string()));
        assert_eq!(info.source_name, "IPv4");
        assert_eq!(info.field_count, 4);
    }

    #[test]
    fn test_parse_sll_struct() {
        let content = r#"
#define SLL_ADDRLEN 8

struct sll_header {
    uint16_t sll_pkttype;
    uint16_t sll_hatype;
    uint16_t sll_halen;
    uint8_t  sll_addr[SLL_ADDRLEN];
    uint16_t sll_protocol;
};
"#;
        let ls = parse_libpcap_struct(content, "sll_header")
            .unwrap()
            .unwrap();
        assert_eq!(ls.fields.len(), 5);
        assert_eq!(ls.fields[0].name, "sll_pkttype");
        assert_eq!(ls.fields[0].c_type, "uint16_t");
        assert_eq!(ls.fields[3].name, "sll_addr");
        assert_eq!(ls.fields[3].array_size, Some(8));
        assert_eq!(ls.fields[4].name, "sll_protocol");
    }

    #[test]
    fn test_parse_vlan_struct() {
        let content = r#"
struct vlan_tag {
    uint16_t vlan_tci;
    uint16_t vlan_tpid;
};
"#;
        let ls = parse_libpcap_struct(content, "vlan_tag")
            .unwrap()
            .unwrap();
        assert_eq!(ls.fields.len(), 2);
        assert_eq!(ls.fields[0].name, "vlan_tci");
        assert_eq!(ls.fields[1].name, "vlan_tpid");
    }

    #[test]
    fn test_struct_to_field_defs_sll() {
        let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
        let content = r#"
#define SLL_ADDRLEN 8

struct sll_header {
    uint16_t sll_pkttype;
    uint16_t sll_hatype;
    uint16_t sll_halen;
    uint8_t  sll_addr[SLL_ADDRLEN];
    uint16_t sll_protocol;
};
"#;
        let ls = parse_libpcap_struct(content, "sll_header")
            .unwrap()
            .unwrap();
        let fields = struct_to_field_defs(&ls, &mappings);

        assert_eq!(fields.len(), 5);
        // sll_pkttype: offset 0, 16 bits, Enum (from field_type_overrides)
        assert_eq!(fields[0].name, "sll_pkttype");
        assert_eq!(fields[0].offset_bits, 0);
        assert_eq!(fields[0].size_bits, 16);
        assert_eq!(fields[0].field_type, FieldType::Enum);
        assert_eq!(fields[0].endian, Endian::Big);

        // sll_addr: offset 48, 64 bits (8 bytes), Big endian (array override)
        assert_eq!(fields[3].name, "sll_addr");
        assert_eq!(fields[3].offset_bits, 48);
        assert_eq!(fields[3].size_bits, 64);
        assert_eq!(fields[3].endian, Endian::Big);

        // sll_protocol: offset 112, 16 bits, Enum
        assert_eq!(fields[4].name, "sll_protocol");
        assert_eq!(fields[4].offset_bits, 112);
        assert_eq!(fields[4].size_bits, 16);
        assert_eq!(fields[4].field_type, FieldType::Enum);

        // Total: 128 bits = 16 bytes
        let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
        assert_eq!(total, 128);
    }

    #[test]
    fn test_struct_to_field_defs_vlan() {
        let mappings = type_mapping::load_libpcap_mappings(None).unwrap();
        let content = r#"
struct vlan_tag {
    uint16_t vlan_tci;
    uint16_t vlan_tpid;
};
"#;
        let ls = parse_libpcap_struct(content, "vlan_tag")
            .unwrap()
            .unwrap();
        let fields = struct_to_field_defs(&ls, &mappings);

        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "vlan_tci");
        assert_eq!(fields[0].offset_bits, 0);
        assert_eq!(fields[0].size_bits, 16);
        assert_eq!(fields[0].field_type, FieldType::Flags);
        assert_eq!(fields[1].name, "vlan_tpid");
        assert_eq!(fields[1].offset_bits, 16);
        assert_eq!(fields[1].field_type, FieldType::Enum);

        let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
        assert_eq!(total, 32);
    }
}
