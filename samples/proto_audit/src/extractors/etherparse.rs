//! Etherparse Rust struct extractor.
//!
//! Parses Rust `pub struct` definitions from etherparse source files and
//! converts them to the proto-audit IR, using TOML-based type mappings for
//! wire-accurate bit widths, implicit field handling, and TCP flag ordering.

use anyhow::Result;
use regex::Regex;
use crate::ir::{Endian, FieldDef, FieldType, ProtocolDef, SourceInfo};
use crate::type_mapping::{self, EtherparseMappings};

/// A raw field parsed from an etherparse Rust struct.
#[derive(Debug, Clone)]
pub struct EtherparseField {
    /// Rust type (e.g., "u16", "EtherType", "IpDscp")
    pub rust_type: String,
    /// Field name
    pub name: String,
    /// Array size (e.g., 6 for `[u8; 6]`)
    pub array_size: Option<u32>,
}

/// Metadata for a parsed etherparse struct.
#[derive(Debug, Clone)]
pub struct EtherparseStruct {
    pub name: String,
    pub fields: Vec<EtherparseField>,
    pub file_path: String,
}

/// Parse a Rust struct definition from source text.
///
/// Looks for `pub struct <name> { ... }` and extracts public fields.
pub fn parse_etherparse_struct(
    content: &str,
    struct_name: &str,
) -> Result<Option<EtherparseStruct>> {
    // Find "pub struct StructName {" and capture the body
    let pattern = format!(
        r"pub struct {}\s*\{{([^}}]*)\}}",
        regex::escape(struct_name)
    );
    let re = Regex::new(&pattern)?;

    let caps = match re.captures(content) {
        Some(c) => c,
        None => return Ok(None),
    };

    let body = &caps[1];
    let fields = parse_struct_fields(body);

    Ok(Some(EtherparseStruct {
        name: struct_name.to_string(),
        fields,
        file_path: String::new(),
    }))
}

/// Parse fields from a Rust struct body.
fn parse_struct_fields(body: &str) -> Vec<EtherparseField> {
    let mut fields = Vec::new();

    // Match: pub name: Type, or pub name: [Type; N],
    let field_re =
        Regex::new(r"pub\s+(\w+)\s*:\s*(\[(\w+)\s*;\s*(\d+)\]|(\w+))\s*,")
            .expect("static regex pattern is valid");

    for line in body.lines() {
        let line = line.trim();
        // Skip doc comments
        if line.starts_with("///") || line.starts_with("//") || line.is_empty() {
            continue;
        }
        // Skip non-pub fields
        if !line.contains("pub ") {
            continue;
        }

        if let Some(caps) = field_re.captures(line) {
            let name = caps[1].to_string();

            if caps.get(3).is_some() {
                // Array field: [Type; N]
                let elem_type = caps[3].to_string();
                let array_size: u32 = caps[4].parse().unwrap_or(0);
                fields.push(EtherparseField {
                    rust_type: elem_type,
                    name,
                    array_size: Some(array_size),
                });
            } else {
                // Simple field
                let rust_type = caps[5].to_string();
                fields.push(EtherparseField {
                    rust_type,
                    name,
                    array_size: None,
                });
            }
        }
    }

    fields
}

/// Convert an EtherparseStruct to IR field definitions using loaded mappings.
pub fn to_field_defs_with(
    es: &EtherparseStruct,
    mappings: &EtherparseMappings,
) -> Vec<FieldDef> {
    let mut fields = Vec::new();

    // Get implicit field config for this struct
    let implicit = mappings.implicit_field_config(&es.name);
    let flag_offsets = mappings.flag_bit_offsets(&es.name);

    // Start offset: skip implicit leading fields (e.g., IPv4 version+ihl)
    let mut offset = implicit.map_or(0, |c| c.start_offset_bits);

    // Track the end of the flag region so we can resume offset after flags
    let mut flag_region_end: u32 = 0;
    let mut in_flag_region = false;

    for ef in &es.fields {
        // Look up bit width
        let base_bits = match mappings.type_bits(&ef.rust_type) {
            Some(bits) => bits,
            None => continue, // Unknown type, skip
        };

        // Skip zero-bit types (TcpOptions, Ipv4Options)
        if base_bits == 0 {
            continue;
        }

        // Check if this is a flag field with explicit bit offset
        if let Some(flag_map) = flag_offsets {
            if let Some(&bit_pos) = flag_map.get(&ef.name) {
                // Flag field: use explicit wire bit position
                let ft = mappings
                    .field_type_override(&ef.name)
                    .unwrap_or(FieldType::Flags);
                fields.push(
                    FieldDef::new(ef.name.clone(), bit_pos, base_bits, ft),
                );
                // Track the end of the flag region
                let end = bit_pos + base_bits;
                if end > flag_region_end {
                    flag_region_end = end;
                }
                in_flag_region = true;
                continue;
            }
        }

        // If we just exited a flag region, advance offset past it
        if in_flag_region {
            offset = flag_region_end;
            in_flag_region = false;
        }

        // Compute field size
        let total_bits = if let Some(arr_size) = ef.array_size {
            base_bits * arr_size
        } else {
            base_bits
        };

        // Determine endianness
        let endian = if total_bits <= 8 {
            Endian::Na
        } else if let Some(arr_size) = ef.array_size {
            mappings
                .array_endian_override(&ef.rust_type, arr_size)
                .unwrap_or(Endian::Big)
        } else {
            Endian::Big
        };

        // Determine field type
        let field_type = if let Some(ft) = mappings.field_type_override(&ef.name) {
            ft
        } else {
            infer_field_type(&ef.name, &ef.rust_type, total_bits, ef.array_size)
        };

        fields.push(
            FieldDef::new(ef.name.clone(), offset, total_bits, field_type)
                .with_endian(endian),
        );

        offset += total_bits;

        // Check for gaps after this field (implicit mid-header fields)
        if let Some(cfg) = implicit {
            for gap in &cfg.gaps {
                if gap.after == ef.name {
                    offset += gap.skip_bits;
                }
            }
        }
    }

    fields
}

/// Infer semantic field type from name and Rust type.
fn infer_field_type(
    name: &str,
    _rust_type: &str,
    total_bits: u32,
    array_size: Option<u32>,
) -> FieldType {
    // Address patterns
    if let Some(arr) = array_size {
        if arr == 6 && total_bits == 48 {
            return FieldType::MacAddr;
        }
        if arr == 4 && total_bits == 32
            && (name.contains("source") || name.contains("destination") || name.contains("addr"))
        {
            return FieldType::Ipv4Addr;
        }
        if arr == 16 && total_bits == 128
            && (name.contains("source") || name.contains("destination") || name.contains("addr"))
        {
            return FieldType::Ipv6Addr;
        }
    }

    // Name patterns
    if name.contains("flags") || name.contains("reserved") || name.contains("pad") {
        return FieldType::Flags;
    }

    FieldType::Uint
}

/// Extract a full ProtocolDef from etherparse source (convenience wrapper).
///
/// Uses default (embedded) mappings.
pub fn extract_protocol(
    content: &str,
    struct_name: &str,
    file_path: &str,
) -> Result<Option<ProtocolDef>> {
    extract_protocol_with(
        content,
        struct_name,
        file_path,
        &type_mapping::load_etherparse_mappings(None)?,
    )
}

/// Extract a full ProtocolDef using explicit mappings.
pub fn extract_protocol_with(
    content: &str,
    struct_name: &str,
    file_path: &str,
    mappings: &EtherparseMappings,
) -> Result<Option<ProtocolDef>> {
    let mut es = match parse_etherparse_struct(content, struct_name)? {
        Some(s) => s,
        None => return Ok(None),
    };
    es.file_path = file_path.to_string();

    let fields = to_field_defs_with(&es, mappings);
    let total_bits = fields
        .last()
        .map(|f| f.offset_bits + f.size_bits)
        .unwrap_or(0);

    let field_count = fields.len() as u32;

    Ok(Some(ProtocolDef::new(struct_name, total_bits)
        .with_fields(fields)
        .with_source("etherparse", SourceInfo::new(struct_name)
            .with_file(file_path)
            .with_field_count(field_count)
            .with_min_header_bytes(total_bits / 8))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Endian, FieldType};

    #[test]
    fn test_parse_simple_struct() {
        let src = r#"
#[derive(Clone, Debug)]
pub struct UdpHeader {
    /// Source port.
    pub source_port: u16,
    /// Destination port.
    pub destination_port: u16,
    /// Length.
    pub length: u16,
    /// Checksum.
    pub checksum: u16,
}
"#;
        let es = parse_etherparse_struct(src, "UdpHeader")
            .unwrap()
            .unwrap();
        assert_eq!(es.fields.len(), 4);
        assert_eq!(es.fields[0].name, "source_port");
        assert_eq!(es.fields[0].rust_type, "u16");
    }

    #[test]
    fn test_parse_array_fields() {
        let src = r#"
pub struct Ethernet2Header {
    pub source: [u8; 6],
    pub destination: [u8; 6],
    pub ether_type: EtherType,
}
"#;
        let es = parse_etherparse_struct(src, "Ethernet2Header")
            .unwrap()
            .unwrap();
        assert_eq!(es.fields.len(), 3);
        assert_eq!(es.fields[0].array_size, Some(6));
        assert_eq!(es.fields[0].rust_type, "u8");
        assert_eq!(es.fields[2].rust_type, "EtherType");
    }

    #[test]
    fn test_skips_non_pub_fields() {
        let src = r#"
pub struct ArpPacket {
    pub hw_addr_type: ArpHardwareId,
    pub proto_addr_type: EtherType,
    hw_addr_size: u8,
    proto_addr_size: u8,
    pub operation: ArpOperation,
}
"#;
        let es = parse_etherparse_struct(src, "ArpPacket")
            .unwrap()
            .unwrap();
        assert_eq!(es.fields.len(), 3);
        assert_eq!(es.fields[0].name, "hw_addr_type");
        assert_eq!(es.fields[1].name, "proto_addr_type");
        assert_eq!(es.fields[2].name, "operation");
    }

    #[test]
    fn test_to_field_defs_udp() {
        let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
        let src = r#"
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}
"#;
        let es = parse_etherparse_struct(src, "UdpHeader")
            .unwrap()
            .unwrap();
        let fields = to_field_defs_with(&es, &mappings);
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0].offset_bits, 0);
        assert_eq!(fields[0].size_bits, 16);
        assert_eq!(fields[0].endian, Endian::Big);
        assert_eq!(fields[1].offset_bits, 16);
        assert_eq!(fields[3].offset_bits, 48);
    }

    #[test]
    fn test_to_field_defs_ethernet_mac() {
        let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
        let src = r#"
pub struct Ethernet2Header {
    pub source: [u8; 6],
    pub destination: [u8; 6],
    pub ether_type: EtherType,
}
"#;
        let es = parse_etherparse_struct(src, "Ethernet2Header")
            .unwrap()
            .unwrap();
        let fields = to_field_defs_with(&es, &mappings);
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].size_bits, 48);
        assert_eq!(fields[0].field_type, FieldType::MacAddr);
        assert_eq!(fields[0].endian, Endian::Big);
        assert_eq!(fields[2].field_type, FieldType::Enum);
    }

    #[test]
    fn test_to_field_defs_ipv4_implicit_offset() {
        let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
        let src = r#"
pub struct Ipv4Header {
    pub dscp: IpDscp,
    pub ecn: IpEcn,
    pub total_len: u16,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragment_offset: IpFragOffset,
    pub time_to_live: u8,
    pub protocol: IpNumber,
    pub header_checksum: u16,
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub options: Ipv4Options,
}
"#;
        let es = parse_etherparse_struct(src, "Ipv4Header")
            .unwrap()
            .unwrap();
        let fields = to_field_defs_with(&es, &mappings);
        // dscp starts at offset 8 (version:4 + ihl:4 implicit)
        let dscp = fields.iter().find(|f| f.name == "dscp").unwrap();
        assert_eq!(dscp.offset_bits, 8);
        assert_eq!(dscp.size_bits, 6);
        // protocol at offset 72
        let proto = fields.iter().find(|f| f.name == "protocol").unwrap();
        assert_eq!(proto.offset_bits, 72);
        assert_eq!(proto.field_type, FieldType::Enum);
        // source addr
        let src_f = fields.iter().find(|f| f.name == "source").unwrap();
        assert_eq!(src_f.offset_bits, 96);
        assert_eq!(src_f.size_bits, 32);
        assert_eq!(src_f.field_type, FieldType::Ipv4Addr);
        // options should be skipped (0 bits)
        assert!(fields.iter().all(|f| f.name != "options"));
    }

    #[test]
    fn test_to_field_defs_tcp_flags() {
        let mappings = type_mapping::load_etherparse_mappings(None).unwrap();
        let src = r#"
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub ns: bool,
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: TcpOptions,
}
"#;
        let es = parse_etherparse_struct(src, "TcpHeader")
            .unwrap()
            .unwrap();
        let fields = to_field_defs_with(&es, &mappings);

        // source_port at offset 0
        let sp = fields.iter().find(|f| f.name == "source_port").unwrap();
        assert_eq!(sp.offset_bits, 0);

        // ack_number at offset 64
        let ack = fields
            .iter()
            .find(|f| f.name == "acknowledgment_number")
            .unwrap();
        assert_eq!(ack.offset_bits, 64);

        // ns flag at wire bit 103 (after data_offset:4 + reserved:3 = 7 implicit bits)
        let ns = fields.iter().find(|f| f.name == "ns").unwrap();
        assert_eq!(ns.offset_bits, 103);
        assert_eq!(ns.size_bits, 1);
        assert_eq!(ns.field_type, FieldType::Flags);

        // fin at 111
        let fin = fields.iter().find(|f| f.name == "fin").unwrap();
        assert_eq!(fin.offset_bits, 111);

        // window_size after flags region: offset 112
        let win = fields.iter().find(|f| f.name == "window_size").unwrap();
        assert_eq!(win.offset_bits, 112);

        // urgent_pointer at 144
        let urg_ptr = fields.iter().find(|f| f.name == "urgent_pointer").unwrap();
        assert_eq!(urg_ptr.offset_bits, 144);

        // Total: 160 bits
        let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap();
        assert_eq!(total, 160);
    }
}
