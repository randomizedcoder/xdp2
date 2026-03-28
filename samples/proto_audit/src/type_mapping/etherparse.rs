use std::collections::HashMap;
use serde::Deserialize;

use super::{parse_endian, parse_field_type, FieldTypeOverride, ArrayEndianOverride};
use crate::ir::{Endian, FieldType};

#[derive(Debug, Deserialize)]
pub struct EtherparseMappings {
    pub type_bits: HashMap<String, u32>,
    #[serde(default)]
    pub type_endian: HashMap<String, String>,
    #[serde(default)]
    pub field_type_overrides: HashMap<String, FieldTypeOverride>,
    #[serde(default)]
    pub array_endian_overrides: HashMap<String, ArrayEndianOverride>,
    #[serde(default)]
    pub implicit_fields: HashMap<String, ImplicitFieldConfig>,
    #[serde(default)]
    pub flag_bit_offsets: HashMap<String, HashMap<String, u32>>,
}

#[derive(Debug, Deserialize)]
pub struct ImplicitFieldConfig {
    #[serde(default)]
    pub start_offset_bits: u32,
    #[serde(default)]
    pub gaps: Vec<GapEntry>,
}

#[derive(Debug, Deserialize)]
pub struct GapEntry {
    pub after: String,
    pub skip_bits: u32,
}

impl EtherparseMappings {
    /// Look up bit width for a Rust type.
    pub fn type_bits(&self, rust_type: &str) -> Option<u32> {
        self.type_bits.get(rust_type).copied()
    }

    /// Check for field name type override.
    pub fn field_type_override(&self, name: &str) -> Option<FieldType> {
        self.field_type_overrides
            .get(name)
            .and_then(|ovr| parse_field_type(&ovr.field_type))
    }

    /// Check for array endian override.
    pub fn array_endian_override(&self, rust_type: &str, array_size: u32) -> Option<Endian> {
        let key = format!("{}:{}", rust_type, array_size);
        self.array_endian_overrides
            .get(&key)
            .and_then(|ovr| parse_endian(&ovr.endian))
    }

    /// Get implicit field config for a struct.
    pub fn implicit_field_config(&self, struct_name: &str) -> Option<&ImplicitFieldConfig> {
        self.implicit_fields.get(struct_name)
    }

    /// Get flag bit offsets for a struct.
    pub fn flag_bit_offsets(&self, struct_name: &str) -> Option<&HashMap<String, u32>> {
        self.flag_bit_offsets.get(struct_name)
    }
}

// ── Etherparse generation mappings ──

#[derive(Debug, Deserialize)]
pub struct EtherparseGenMappings {
    pub rust_types: HashMap<String, String>,
    #[serde(default)]
    pub newtypes: HashMap<String, String>,
    #[serde(default)]
    pub derives: DerivesConfig,
    #[serde(default)]
    pub skip_fields: HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
pub struct DerivesConfig {
    #[serde(default)]
    pub default: Vec<String>,
}

impl EtherparseGenMappings {
    /// Look up Rust type for an IR field by (FieldType, size_bits).
    pub fn rust_type(&self, ft: &FieldType, bits: u32) -> Option<&str> {
        let key = format!("{:?}:{}", ft, bits);
        self.rust_types.get(&key).map(|s| s.as_str())
    }

    /// Check for a newtype override by field name.
    pub fn newtype(&self, field_name: &str) -> Option<&str> {
        self.newtypes.get(field_name).map(|s| s.as_str())
    }

    /// Check if a field should be skipped for a given struct.
    pub fn should_skip(&self, struct_name: &str, field_name: &str) -> bool {
        self.skip_fields
            .get(struct_name)
            .map(|v| v.iter().any(|f| f == field_name))
            .unwrap_or(false)
    }
}
