//! OMI (Open Markets Initiative) c-structs extractor.
//!
//! Parses `typedef struct { ... } NameT;` blocks from the OMI c-structs
//! repo. These headers are auto-generated, always packed
//! (`#pragma pack(push, 1)`), and use a very small type vocabulary
//! (`uint*_t`, `int*_t`, `char`, `char[N]`).
//!
//! Endianness is per-protocol-family, not per-type: ITCH/OUCH/PITCH/EOBI
//! are big-endian on the wire, CME SBE / iLink3 / MEMX / MIAX are little-
//! endian. Resolved from the source filename stem via
//! [`OmiMappings::protocol_endian_for_file`].

use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

use crate::ir::{Endian, FieldDef, FieldType, ProtocolDef, SourceInfo};
use crate::type_mapping::OmiMappings;

/// A raw field parsed from an OMI typedef struct.
#[derive(Debug, Clone)]
pub struct OmiField {
    pub c_type: String,
    pub name: String,
    pub array_size: Option<u32>,
}

/// A parsed OMI typedef struct.
#[derive(Debug, Clone)]
pub struct OmiStruct {
    pub name: String,
    pub fields: Vec<OmiField>,
}

/// Extract a protocol from an OMI c-structs header file.
///
/// * `omi_src` — root of the pinned OMI c-structs tree (or `None` to skip)
/// * `proto` — canonical proto-audit name
/// * `omi_struct` — typedef name including the trailing `T`
///   (e.g. `NonCrossTradeMessageT`)
/// * `omi_file` — relative path inside the c-structs tree
///   (e.g. `nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h`)
pub fn extract_protocol(
    omi_src: Option<&Path>,
    proto: &str,
    omi_struct: &str,
    omi_file: &str,
    mappings: &OmiMappings,
) -> Result<Option<ProtocolDef>> {
    let src_dir = match omi_src {
        Some(d) => d,
        None => return Ok(None),
    };
    let file_path = src_dir.join(omi_file);
    let content = match std::fs::read_to_string(&file_path) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    extract_from_source(&content, proto, omi_struct, omi_file, mappings)
}

/// Extract an OMI struct directly from header-file content (used by tests
/// and the embedded-blob extractor path).
pub fn extract_from_source(
    content: &str,
    proto: &str,
    omi_struct: &str,
    omi_file: &str,
    mappings: &OmiMappings,
) -> Result<Option<ProtocolDef>> {
    // Pre-scan all typedefs so nested `FooT foo;` fields resolve via size.
    let struct_sizes = build_struct_size_map(content, mappings);

    let os = match parse_omi_struct(content, omi_struct)? {
        Some(s) => s,
        None => return Ok(None),
    };

    // Filename stem drives protocol-family endian resolution.
    let stem = Path::new(omi_file)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let proto_endian = mappings.protocol_endian_for_file(stem);

    let fields = struct_to_field_defs(&os, mappings, &struct_sizes, proto_endian);
    let total_bits = fields
        .last()
        .map(|f| f.offset_bits + f.size_bits)
        .unwrap_or(0);
    let field_count = fields.len() as u32;

    Ok(Some(
        ProtocolDef::new(proto, total_bits)
            .with_fields(fields)
            .with_source(
                "omi",
                SourceInfo::new(omi_struct)
                    .with_file(omi_file)
                    .with_field_count(field_count)
                    .with_min_header_bytes(total_bits / 8)
                    .with_note(format!("OMI c-struct from {}", omi_file)),
            ),
    ))
}

/// Parse a single `typedef struct { ... } NameT;` from OMI header content.
pub fn parse_omi_struct(content: &str, struct_name: &str) -> Result<Option<OmiStruct>> {
    // OMI typedefs look like:
    //     typedef struct {
    //         uint16_t StockLocate;
    //         char Stock[8];
    //     } NonCrossTradeMessageT;
    let pattern = format!(
        r"typedef\s+struct\s*\{{([^}}]*)\}}\s*{}\s*;",
        regex::escape(struct_name)
    );
    let re = Regex::new(&pattern)?;

    let caps = match re.captures(content) {
        Some(c) => c,
        None => return Ok(None),
    };

    Ok(Some(OmiStruct {
        name: struct_name.to_string(),
        fields: parse_field_block(&caps[1]),
    }))
}

/// Parse all `typedef struct { ... } NameT;` blocks in a file, returning
/// a name → total-bit-size map. Needed so nested struct fields
/// (`MessageHeaderT Header;`) resolve to the right wire width.
fn build_struct_size_map(content: &str, mappings: &OmiMappings) -> HashMap<String, u32> {
    let re = Regex::new(r"typedef\s+struct\s*\{([^}]*)\}\s*(\w+)\s*;")
        .expect("static regex");
    let mut map = HashMap::new();
    for caps in re.captures_iter(content) {
        let body = &caps[1];
        let name = caps[2].to_string();
        let fields = parse_field_block(body);
        let size_bits: u32 = fields
            .iter()
            .map(|f| {
                let base = mappings.type_bits(&f.c_type).unwrap_or(0);
                base * f.array_size.unwrap_or(1)
            })
            .sum();
        map.insert(name, size_bits);
    }
    map
}

/// Parse field declarations from a struct body.
fn parse_field_block(body: &str) -> Vec<OmiField> {
    let field_re = Regex::new(r"^\s*(\w+)\s+(\w+)(?:\[(\d+)\])?\s*;")
        .expect("static regex");
    let mut fields = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with("//")
            || line.starts_with("/*")
            || line.starts_with("*")
        {
            continue;
        }
        if let Some(caps) = field_re.captures(line) {
            let c_type = caps[1].to_string();
            // Skip C keywords that regex may match as "type name"
            if matches!(c_type.as_str(), "typedef" | "struct" | "return" | "const") {
                continue;
            }
            let name = caps[2].to_string();
            let array_size = caps.get(3).and_then(|m| m.as_str().parse::<u32>().ok());
            fields.push(OmiField {
                c_type,
                name,
                array_size,
            });
        }
    }
    fields
}

/// Convert parsed OMI fields to IR FieldDefs.
pub fn struct_to_field_defs(
    os: &OmiStruct,
    mappings: &OmiMappings,
    struct_sizes: &HashMap<String, u32>,
    proto_endian: Endian,
) -> Vec<FieldDef> {
    let mut fields = Vec::new();
    let mut offset: u32 = 0;

    for of in &os.fields {
        // Resolve field size: (1) primitive type_bits, (2) nested struct lookup.
        let base_bits = match mappings.type_bits(&of.c_type) {
            Some(b) => b,
            None => match struct_sizes.get(&of.c_type) {
                Some(s) => *s,
                None => continue, // unknown type — skip with no offset advance
            },
        };

        let total_bits = if let Some(arr) = of.array_size {
            base_bits * arr
        } else {
            base_bits
        };

        // Endian: (1) array override, (2) Na if sub-byte, (3) per-protocol endian.
        let endian = if let Some(arr) = of.array_size {
            mappings
                .array_endian_override(&of.c_type, arr)
                .unwrap_or_else(|| proto_endian.clone())
        } else if total_bits <= 8 {
            Endian::Na
        } else {
            proto_endian.clone()
        };

        let field_type = mappings
            .field_type_override(&of.name)
            .unwrap_or(FieldType::Uint);

        fields.push(
            FieldDef::new(of.name.clone(), offset, total_bits, field_type)
                .with_endian(endian),
        );

        offset += total_bits;
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_mapping;

    const ITCH_NON_CROSS_TRADE: &str = r#"
#pragma pack(push, 1)
typedef struct {
    uint16_t StockLocate;
    uint16_t TrackingNumber;
    char Timestamp;
    uint64_t OrderReferenceNumber;
    char BuySellIndicator;
    uint32_t Shares;
    char Stock[8];
    uint32_t Price;
    uint64_t MatchNumber;
} NonCrossTradeMessageT;
#pragma pack(pop)
"#;

    #[test]
    fn test_parse_non_cross_trade() {
        let s = parse_omi_struct(ITCH_NON_CROSS_TRADE, "NonCrossTradeMessageT")
            .unwrap()
            .unwrap();
        assert_eq!(s.fields.len(), 9);
        assert_eq!(s.fields[0].c_type, "uint16_t");
        assert_eq!(s.fields[0].name, "StockLocate");
        assert_eq!(s.fields[6].c_type, "char");
        assert_eq!(s.fields[6].array_size, Some(8));
    }

    #[test]
    fn test_extract_non_cross_trade() {
        let mappings = type_mapping::load_omi_mappings(None).unwrap();
        let def = extract_from_source(
            ITCH_NON_CROSS_TRADE,
            "ITCH v5 NonCrossTrade",
            "NonCrossTradeMessageT",
            "nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h",
            &mappings,
        )
        .unwrap()
        .unwrap();

        assert_eq!(def.fields.len(), 9);
        // Total bits = 16+16+8+64+8+32+64+32+64 = 304 bits = 38 bytes
        assert_eq!(def.min_header_bits, 304);

        // Nasdaq → Big endian on multi-byte fields
        let stock_locate = &def.fields[0];
        assert_eq!(stock_locate.name, "StockLocate");
        assert_eq!(stock_locate.size_bits, 16);
        assert_eq!(stock_locate.endian, Endian::Big);

        // char → Na endian, Enum via field_type_overrides for BuySellIndicator
        let buy_sell = &def.fields[4];
        assert_eq!(buy_sell.name, "BuySellIndicator");
        assert_eq!(buy_sell.size_bits, 8);
        assert_eq!(buy_sell.endian, Endian::Na);
        assert_eq!(buy_sell.field_type, FieldType::Enum);

        // char[8] → 64 bits, Na endian (ASCII text identifier override)
        let stock = &def.fields[6];
        assert_eq!(stock.name, "Stock");
        assert_eq!(stock.size_bits, 64);
        assert_eq!(stock.endian, Endian::Na);
    }

    const SBE_HEADER: &str = r#"
typedef struct {
    uint16_t BlockLength;
    uint16_t TemplateId;
    uint16_t SchemaId;
    uint16_t Version;
} MessageHeaderT;
"#;

    #[test]
    fn test_sbe_little_endian() {
        let mappings = type_mapping::load_omi_mappings(None).unwrap();
        let def = extract_from_source(
            SBE_HEADER,
            "SBE_MDP3_MessageHeader",
            "MessageHeaderT",
            "cme/Cme.MDP3.Sbe.v1.h",
            &mappings,
        )
        .unwrap()
        .unwrap();

        assert_eq!(def.fields.len(), 4);
        // CME → Little
        for f in &def.fields {
            assert_eq!(f.endian, Endian::Little, "field {} should be Little", f.name);
        }
    }

    const NESTED: &str = r#"
typedef struct {
    uint16_t Length;
    uint8_t Type;
} HeaderT;

typedef struct {
    HeaderT Header;
    uint32_t Value;
} MessageT;
"#;

    #[test]
    fn test_nested_struct() {
        let mappings = type_mapping::load_omi_mappings(None).unwrap();
        let def = extract_from_source(
            NESTED,
            "Nested",
            "MessageT",
            "nasdaq/Test.h",
            &mappings,
        )
        .unwrap()
        .unwrap();
        // HeaderT = 16+8 = 24 bits; Value = 32 bits → 56 total
        assert_eq!(def.fields.len(), 2);
        assert_eq!(def.fields[0].size_bits, 24);
        assert_eq!(def.fields[1].offset_bits, 24);
        assert_eq!(def.fields[1].size_bits, 32);
    }
}
