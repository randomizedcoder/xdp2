use std::collections::HashMap;
use serde::Deserialize;

use super::parse_field_type;
use crate::ir::{Endian, FieldType};

#[derive(Debug, Deserialize)]
pub struct ScapyMappings {
    pub field_types: HashMap<String, String>,
    pub endian_prefixes: HashMap<String, String>,
    pub name_patterns: HashMap<String, String>,
    pub unwrap_classes: HashMap<String, bool>,
}

impl ScapyMappings {
    /// Look up field type by Scapy class name.
    pub fn field_type(&self, class: &str) -> Option<FieldType> {
        self.field_types
            .get(class)
            .and_then(|s| parse_field_type(s))
    }

    /// Determine endianness from class name prefixes.
    pub fn endian(&self, class: &str, bits: u32) -> Endian {
        if bits <= 8 {
            return Endian::Na;
        }
        for (prefix, endian_str) in &self.endian_prefixes {
            if class.starts_with(prefix) {
                return super::parse_endian(endian_str).unwrap_or(Endian::Big);
            }
        }
        Endian::Big // Scapy defaults to network byte order
    }

    /// Check field name patterns for fallback type inference.
    pub fn name_pattern_type(&self, name: &str) -> Option<FieldType> {
        for (pattern, type_str) in &self.name_patterns {
            if name.contains(pattern) {
                return parse_field_type(type_str);
            }
        }
        None
    }

    /// Check if a class is an unwrap target.
    pub fn should_unwrap(&self, class: &str) -> bool {
        self.unwrap_classes.get(class).copied().unwrap_or(false)
    }

    /// Given an IR FieldType, return Scapy classes that map to it.
    pub fn classes_for_type(&self, ft: &FieldType) -> Vec<&str> {
        self.field_types
            .iter()
            .filter_map(|(class, type_str)| {
                if parse_field_type(type_str).as_ref() == Some(ft) {
                    Some(class.as_str())
                } else {
                    None
                }
            })
            .collect()
    }
}
