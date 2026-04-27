use std::collections::HashMap;
use serde::Deserialize;

use super::{parse_endian, parse_field_type, ArrayEndianOverride, FieldTypeOverride};
use crate::ir::{Endian, FieldType};

#[derive(Debug, Deserialize)]
pub struct KernelMappings {
    pub type_bits: HashMap<String, u32>,
    pub type_endian: HashMap<String, String>,
    pub field_type_overrides: HashMap<String, FieldTypeOverride>,
    #[serde(default)]
    pub array_endian_overrides: HashMap<String, ArrayEndianOverride>,
    #[serde(default)]
    pub struct_sizes: HashMap<String, u32>,
    #[serde(default)]
    pub union_sizes: HashMap<String, u32>,
}

impl KernelMappings {
    /// Look up bit width for a C type.
    ///
    /// Also handles `struct X` types via the `struct_sizes` table.
    pub fn type_bits(&self, c_type: &str) -> Option<u32> {
        if let Some(&bits) = self.type_bits.get(c_type) {
            return Some(bits);
        }
        // Check struct_sizes for embedded struct types (e.g., "icmp6hdr")
        if let Some(&bits) = self.struct_sizes.get(c_type) {
            return Some(bits);
        }
        // Check union_sizes for embedded union types (e.g., "ib_gid")
        self.union_sizes.get(c_type).copied()
    }

    /// Determine endianness from C type using prefix/exact rules.
    pub fn type_endian(&self, c_type: &str) -> Endian {
        // Check exact matches first
        for (key, val) in &self.type_endian {
            if let Some(exact) = key.strip_prefix("exact:") {
                if c_type == exact {
                    return parse_endian(val).unwrap_or(Endian::Na);
                }
            }
        }
        // Then prefix matches
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
    pub fn field_type_override(&self, name: &str, bits: u32) -> Option<FieldType> {
        if let Some(ovr) = self.field_type_overrides.get(name) {
            if let Some(req) = ovr.require_bits {
                if bits != req {
                    return None;
                }
            }
            return parse_field_type(&ovr.field_type);
        }
        None
    }

    /// Check for array endian override.
    pub fn array_endian_override(&self, c_type: &str, array_size: u32) -> Option<Endian> {
        let key = format!("{}:{}", c_type, array_size);
        if let Some(ovr) = self.array_endian_overrides.get(&key) {
            return parse_endian(&ovr.endian);
        }
        None
    }

    /// Given an IR FieldType, return field names that map to it via overrides.
    pub fn field_names_for_type(&self, ft: &FieldType) -> Vec<&str> {
        self.field_type_overrides
            .iter()
            .filter_map(|(name, ovr)| {
                if parse_field_type(&ovr.field_type).as_ref() == Some(ft) {
                    Some(name.as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Given bit width + endian, return C types that match.
    pub fn c_types_for(&self, bits: u32, endian: &Endian) -> Vec<&str> {
        self.type_bits
            .iter()
            .filter_map(|(c_type, &b)| {
                if b == bits && &self.type_endian(c_type) == endian {
                    Some(c_type.as_str())
                } else {
                    None
                }
            })
            .collect()
    }
}
