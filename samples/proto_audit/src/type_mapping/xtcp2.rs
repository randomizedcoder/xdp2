use std::collections::HashMap;
use serde::Deserialize;

use super::parse_endian;
use crate::ir::Endian;

#[derive(Debug, Deserialize)]
pub struct Xtcp2Mappings {
    pub type_bits: HashMap<String, u32>,
    #[serde(default)]
    pub type_endian: HashMap<String, String>,
    #[serde(default)]
    pub struct_sizes: HashMap<String, u32>,
}

impl Xtcp2Mappings {
    /// Look up bit width for a Go type (e.g., "uint32" → 32).
    pub fn type_bits(&self, go_type: &str) -> Option<u32> {
        if let Some(&bits) = self.type_bits.get(go_type) {
            return Some(bits);
        }
        // Check struct_sizes for embedded struct types
        self.struct_sizes.get(go_type).copied()
    }

    /// Determine endianness from Go type.
    pub fn type_endian(&self, go_type: &str) -> Endian {
        self.type_endian
            .get(go_type)
            .and_then(|v| parse_endian(v))
            .unwrap_or(Endian::Na)
    }
}
