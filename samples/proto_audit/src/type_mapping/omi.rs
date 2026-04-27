use std::collections::HashMap;
use serde::Deserialize;

use super::{parse_endian, parse_field_type, ArrayEndianOverride, FieldTypeOverride};
use crate::ir::{Endian, FieldType};

/// Mappings for OMI (Open Markets Initiative) auto-generated packed C headers.
///
/// OMI headers use a very small type vocabulary (fixed-width `uint*_t`, `char`,
/// `char[N]`), but endianness is per-protocol-family rather than per-type.
/// Resolution happens at extract time via [`protocol_endian_for_file`] keyed
/// by the source filename stem.
#[derive(Debug, Deserialize)]
pub struct OmiMappings {
    pub type_bits: HashMap<String, u32>,
    #[serde(default)]
    pub type_endian: HashMap<String, String>,
    /// Per-protocol-family endian, keyed by filename-stem prefix
    /// (e.g. `"Nasdaq"` → `Big`). Longest matching prefix wins.
    #[serde(default)]
    pub protocol_endian: HashMap<String, String>,
    #[serde(default)]
    pub field_type_overrides: HashMap<String, FieldTypeOverride>,
    #[serde(default)]
    pub array_endian_overrides: HashMap<String, ArrayEndianOverride>,
}

impl OmiMappings {
    /// Look up bit width for a C type.
    pub fn type_bits(&self, c_type: &str) -> Option<u32> {
        self.type_bits.get(c_type).copied()
    }

    /// Default endian for a C type (per-type rules only).
    ///
    /// OMI's endian is almost always resolved per-protocol via
    /// [`protocol_endian_for_file`] — this is only used for types flagged
    /// `Na` (uint8_t, char, int8_t).
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

    /// Resolve per-protocol-family endian from a source filename stem.
    ///
    /// Uses longest-prefix-wins matching. Returns `Endian::Big` as a safe
    /// default (network byte order) if no prefix matches.
    pub fn protocol_endian_for_file(&self, filename_stem: &str) -> Endian {
        let mut best: Option<(&str, &str)> = None;
        for (prefix, endian) in &self.protocol_endian {
            if filename_stem.starts_with(prefix.as_str()) {
                match best {
                    Some((best_prefix, _)) if best_prefix.len() >= prefix.len() => {}
                    _ => best = Some((prefix.as_str(), endian.as_str())),
                }
            }
        }
        best.and_then(|(_, v)| parse_endian(v))
            .unwrap_or(Endian::Big)
    }

    /// Check for field name type override.
    pub fn field_type_override(&self, name: &str) -> Option<FieldType> {
        self.field_type_overrides
            .get(name)
            .and_then(|ovr| parse_field_type(&ovr.field_type))
    }

    /// Check for array endian override (e.g. `char:8` → `Na`).
    pub fn array_endian_override(&self, c_type: &str, array_size: u32) -> Option<Endian> {
        let key = format!("{}:{}", c_type, array_size);
        self.array_endian_overrides
            .get(&key)
            .and_then(|ovr| parse_endian(&ovr.endian))
    }
}
