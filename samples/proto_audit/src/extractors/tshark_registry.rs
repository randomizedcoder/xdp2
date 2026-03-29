//! Convert tshark registry field metadata (from `tshark -G fields`) to IR.
//!
//! This extractor builds `ProtocolDef` from the `TsharkFieldEntry` data
//! captured by `tshark_registry.py`, without needing a PCAP file. Offsets
//! are cumulative approximations (no byte positions in `-G fields` output).

use crate::discovery::tshark_registry::TsharkProtocolEntry;
use crate::ir::{Endian, FieldDef, FieldType, ProtocolDef};

/// Map an FT_* type string to (FieldType, size_bits).
/// Returns None for types we skip (FT_NONE, FT_PROTOCOL, etc.).
fn ft_type_to_ir(ft_type: &str, bitmask: &str) -> Option<(FieldType, u32)> {
    match ft_type {
        "FT_UINT8" | "FT_INT8" | "FT_CHAR" => Some((
            if ft_type == "FT_INT8" {
                FieldType::Sint
            } else {
                FieldType::Uint
            },
            8,
        )),
        "FT_UINT16" | "FT_INT16" => Some((
            if ft_type == "FT_INT16" {
                FieldType::Sint
            } else {
                FieldType::Uint
            },
            16,
        )),
        "FT_UINT24" | "FT_INT24" => Some((
            if ft_type == "FT_INT24" {
                FieldType::Sint
            } else {
                FieldType::Uint
            },
            24,
        )),
        "FT_UINT32" | "FT_INT32" => Some((
            if ft_type == "FT_INT32" {
                FieldType::Sint
            } else {
                FieldType::Uint
            },
            32,
        )),
        "FT_UINT64" | "FT_INT64" => Some((
            if ft_type == "FT_INT64" {
                FieldType::Sint
            } else {
                FieldType::Uint
            },
            64,
        )),
        "FT_BOOLEAN" => {
            let bits = bitmask_bit_count(bitmask).unwrap_or(1);
            Some((FieldType::Uint, bits))
        }
        "FT_IPv4" => Some((FieldType::Ipv4Addr, 32)),
        "FT_IPv6" => Some((FieldType::Ipv6Addr, 128)),
        "FT_ETHER" => Some((FieldType::MacAddr, 48)),
        "FT_BYTES" | "FT_UINT_BYTES" => None, // variable length, skip
        "FT_STRING" | "FT_STRINGZ" | "FT_UINT_STRING" | "FT_STRINGZPAD"
        | "FT_STRINGZTRUNC" => None, // variable length strings
        "FT_NONE" | "FT_PROTOCOL" => None, // meta-types
        _ => None,
    }
}

/// Count the number of set bits in a bitmask string (hex or decimal).
fn bitmask_bit_count(bitmask: &str) -> Option<u32> {
    let trimmed = bitmask.trim();
    if trimmed == "0" || trimmed.is_empty() {
        return None;
    }
    let val = if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        trimmed.parse::<u64>().ok()?
    };
    Some(val.count_ones())
}

/// Convert a single tshark registry protocol entry to IR.
pub fn registry_entry_to_ir(entry: &TsharkProtocolEntry) -> Option<ProtocolDef> {
    if entry.fields.is_empty() {
        return None;
    }

    let mut fields = Vec::new();
    let mut offset_bits: u32 = 0;

    for field in &entry.fields {
        if let Some((field_type, size_bits)) = ft_type_to_ir(&field.ft_type, &field.bitmask) {
            // For bitmask fields within the same parent size, don't advance offset
            let is_bitmask = field.bitmask != "0" && !field.bitmask.is_empty();
            let actual_size = if is_bitmask {
                bitmask_bit_count(&field.bitmask).unwrap_or(size_bits)
            } else {
                size_bits
            };

            let field_name = field
                .filter_name
                .strip_prefix(&format!("{}.", entry.filter_name))
                .unwrap_or(&field.filter_name)
                .to_string();

            if field_name.is_empty() {
                continue;
            }

            let endian = if actual_size > 8 && !is_bitmask {
                Endian::Big // network byte order default
            } else {
                Endian::Na
            };

            let mut fd = FieldDef::new(&field_name, offset_bits, actual_size, field_type)
                .with_endian(endian)
                .with_description(&field.description)
                .with_source_name("tshark", &field.filter_name);

            // Mark bitmask fields as Flags if they have multiple bits
            if is_bitmask && actual_size > 1 {
                fd.field_type = FieldType::Flags;
            }

            fields.push(fd);

            if !is_bitmask {
                offset_bits += size_bits;
            }
        }
    }

    if fields.is_empty() {
        return None;
    }

    let min_header_bits = offset_bits;

    let mut def = ProtocolDef::new(&entry.long_name, min_header_bits)
        .with_fields(fields);
    def.generation_source = Some("tshark-registry".to_string());
    Some(def)
}

/// Convert all protocols from a tshark registry into IR.
pub fn registry_to_ir_map(
    registry: &crate::discovery::tshark_registry::TsharkRegistry,
) -> std::collections::HashMap<String, ProtocolDef> {
    let mut result = std::collections::HashMap::new();
    for (filter_name, entry) in &registry.protocols {
        if let Some(def) = registry_entry_to_ir(entry) {
            result.insert(filter_name.clone(), def);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::tshark_registry::TsharkFieldEntry;

    fn sample_entry() -> TsharkProtocolEntry {
        TsharkProtocolEntry {
            short_name: "DNS".to_string(),
            long_name: "Domain Name Service".to_string(),
            filter_name: "dns".to_string(),
            field_count: 3,
            fields: vec![
                TsharkFieldEntry {
                    description: "Transaction ID".to_string(),
                    filter_name: "dns.id".to_string(),
                    ft_type: "FT_UINT16".to_string(),
                    parent_proto: "dns".to_string(),
                    base: "BASE_HEX".to_string(),
                    bitmask: "0".to_string(),
                },
                TsharkFieldEntry {
                    description: "Flags".to_string(),
                    filter_name: "dns.flags".to_string(),
                    ft_type: "FT_UINT16".to_string(),
                    parent_proto: "dns".to_string(),
                    base: "BASE_HEX".to_string(),
                    bitmask: "0".to_string(),
                },
                TsharkFieldEntry {
                    description: "Source Address".to_string(),
                    filter_name: "dns.src".to_string(),
                    ft_type: "FT_IPv4".to_string(),
                    parent_proto: "dns".to_string(),
                    base: "BASE_NONE".to_string(),
                    bitmask: "0".to_string(),
                },
            ],
        }
    }

    #[test]
    fn test_registry_entry_to_ir() {
        let entry = sample_entry();
        let def = registry_entry_to_ir(&entry).unwrap();
        assert_eq!(def.name, "Domain Name Service");
        assert_eq!(def.fields.len(), 3);
        assert_eq!(def.fields[0].name, "id");
        assert_eq!(def.fields[0].size_bits, 16);
        assert_eq!(def.fields[0].field_type, FieldType::Uint);
        assert_eq!(def.fields[2].field_type, FieldType::Ipv4Addr);
        assert_eq!(def.fields[2].size_bits, 32);
        assert_eq!(def.generation_source, Some("tshark-registry".to_string()));
    }

    #[test]
    fn test_empty_entry_returns_none() {
        let entry = TsharkProtocolEntry {
            short_name: "X".to_string(),
            long_name: "X Proto".to_string(),
            filter_name: "x".to_string(),
            field_count: 0,
            fields: vec![],
        };
        assert!(registry_entry_to_ir(&entry).is_none());
    }

    #[test]
    fn test_ft_type_mapping() {
        assert_eq!(
            ft_type_to_ir("FT_UINT8", "0"),
            Some((FieldType::Uint, 8))
        );
        assert_eq!(
            ft_type_to_ir("FT_INT16", "0"),
            Some((FieldType::Sint, 16))
        );
        assert_eq!(
            ft_type_to_ir("FT_IPv4", "0"),
            Some((FieldType::Ipv4Addr, 32))
        );
        assert_eq!(
            ft_type_to_ir("FT_IPv6", "0"),
            Some((FieldType::Ipv6Addr, 128))
        );
        assert_eq!(
            ft_type_to_ir("FT_ETHER", "0"),
            Some((FieldType::MacAddr, 48))
        );
        assert!(ft_type_to_ir("FT_BYTES", "0").is_none());
        assert!(ft_type_to_ir("FT_NONE", "0").is_none());
    }

    #[test]
    fn test_bitmask_bit_count() {
        assert_eq!(bitmask_bit_count("0"), None);
        assert_eq!(bitmask_bit_count(""), None);
        assert_eq!(bitmask_bit_count("0x00f0"), Some(4));
        assert_eq!(bitmask_bit_count("0xff"), Some(8));
        assert_eq!(bitmask_bit_count("0x01"), Some(1));
    }
}
