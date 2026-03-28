use std::collections::HashMap;
use serde::Deserialize;

use super::parse_field_type;
use crate::ir::FieldType;

#[derive(Debug, Deserialize)]
pub struct TsharkMappings {
    pub suffix_types: HashMap<String, String>,
    pub suffix_types_by_size: Vec<SuffixTypeBySizeEntry>,
    pub contains_types: HashMap<String, String>,
    pub enum_patterns: HashMap<String, EnumPatternEntry>,
    pub blocklist_suffixes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SuffixTypeBySizeEntry {
    pub suffix: String,
    pub bits: u32,
    #[serde(rename = "type")]
    pub field_type: String,
}

#[derive(Debug, Deserialize)]
pub struct EnumPatternEntry {
    pub max_bits: u32,
}

impl TsharkMappings {
    /// Infer field type from tshark field name and bit width.
    pub fn infer_field_type(&self, name: &str, bits: u32) -> FieldType {
        // 1. Suffix types (unconditional on size)
        for (suffix, type_str) in &self.suffix_types {
            if name.ends_with(suffix) {
                if let Some(ft) = parse_field_type(type_str) {
                    return ft;
                }
            }
        }

        // 2. Suffix types by size
        for entry in &self.suffix_types_by_size {
            if name.ends_with(&entry.suffix) && bits == entry.bits {
                if let Some(ft) = parse_field_type(&entry.field_type) {
                    return ft;
                }
            }
        }

        // 3. Contains types (flags, pad, reserved)
        for (pattern, type_str) in &self.contains_types {
            if name.contains(pattern) {
                if let Some(ft) = parse_field_type(type_str) {
                    return ft;
                }
            }
        }

        // 4. Enum patterns
        for (pattern, entry) in &self.enum_patterns {
            if name.contains(pattern) && bits <= entry.max_bits {
                return FieldType::Enum;
            }
        }

        FieldType::Uint
    }

    /// Check if a tshark field name is blocklisted.
    pub fn is_blocked(&self, name: &str) -> bool {
        self.blocklist_suffixes
            .iter()
            .any(|suffix| name.ends_with(suffix))
    }

    /// Given an IR FieldType + bits, return whether any tshark rule would produce it.
    pub fn matches_for(&self, ft: &FieldType, bits: u32) -> bool {
        // Check suffix_types (unconditional on size)
        for type_str in self.suffix_types.values() {
            if parse_field_type(type_str).as_ref() == Some(ft) {
                return true;
            }
        }
        // Check suffix_types_by_size
        for entry in &self.suffix_types_by_size {
            if entry.bits == bits && parse_field_type(&entry.field_type).as_ref() == Some(ft) {
                return true;
            }
        }
        // Check contains_types
        for type_str in self.contains_types.values() {
            if parse_field_type(type_str).as_ref() == Some(ft) {
                return true;
            }
        }
        // Check enum_patterns
        if *ft == FieldType::Enum {
            for entry in self.enum_patterns.values() {
                if bits <= entry.max_bits {
                    return true;
                }
            }
        }
        // Default inference is Uint
        *ft == FieldType::Uint
    }
}
