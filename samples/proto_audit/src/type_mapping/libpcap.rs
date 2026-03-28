use std::collections::HashMap;
use serde::Deserialize;

use super::{parse_endian, parse_field_type, ArrayEndianOverride, FieldTypeOverride};
use crate::ir::{Endian, FieldType};

#[derive(Debug, Deserialize)]
pub struct LibpcapMappings {
    pub type_bits: HashMap<String, u32>,
    #[serde(default)]
    pub type_endian: HashMap<String, String>,
    #[serde(default)]
    pub field_type_overrides: HashMap<String, FieldTypeOverride>,
    #[serde(default)]
    pub array_endian_overrides: HashMap<String, ArrayEndianOverride>,
    #[serde(default)]
    pub gencode_protocols: HashMap<String, HashMap<String, GencodeField>>,
    #[serde(default)]
    pub struct_protocols: HashMap<String, StructProtocol>,
}

#[derive(Debug, Deserialize)]
pub struct GencodeField {
    pub byte_offset: u32,
    pub size_bytes: u32,
    #[serde(default)]
    pub field_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StructProtocol {
    pub source_file: String,
    pub struct_name: String,
}

impl LibpcapMappings {
    /// Look up bit width for a C type.
    pub fn type_bits(&self, c_type: &str) -> Option<u32> {
        self.type_bits.get(c_type).copied()
    }

    /// Determine endianness from C type using prefix/exact rules.
    pub fn type_endian(&self, c_type: &str) -> Endian {
        for (key, val) in &self.type_endian {
            if let Some(exact) = key.strip_prefix("exact:") {
                if c_type == exact {
                    return parse_endian(val).unwrap_or(Endian::Na);
                }
            }
        }
        for (key, val) in &self.type_endian {
            if let Some(prefix) = key.strip_prefix("prefix:") {
                if c_type.starts_with(prefix) {
                    return parse_endian(val).unwrap_or(Endian::Na);
                }
            }
        }
        Endian::Na
    }

    /// Check for field name type override.
    pub fn field_type_override(&self, name: &str) -> Option<FieldType> {
        self.field_type_overrides
            .get(name)
            .and_then(|ovr| parse_field_type(&ovr.field_type))
    }

    /// Check for array endian override.
    pub fn array_endian_override(&self, c_type: &str, array_size: u32) -> Option<Endian> {
        let key = format!("{}:{}", c_type, array_size);
        self.array_endian_overrides
            .get(&key)
            .and_then(|ovr| parse_endian(&ovr.endian))
    }
}
