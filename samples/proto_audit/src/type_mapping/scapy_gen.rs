use std::collections::HashMap;
use serde::Deserialize;

use crate::ir::FieldType;

#[derive(Debug, Deserialize)]
pub struct ScapyGenMappings {
    pub field_classes: HashMap<String, String>,
    #[serde(default)]
    pub name_overrides: HashMap<String, String>,
    #[serde(default)]
    pub le_prefixes: HashMap<String, String>,
}

impl ScapyGenMappings {
    /// Look up Scapy field class for an IR field by (FieldType, size_bits).
    pub fn field_class(&self, ft: &FieldType, bits: u32) -> Option<&str> {
        let key = format!("{:?}:{}", ft, bits);
        self.field_classes.get(&key).map(|s| s.as_str())
    }

    /// Check for a field name override.
    pub fn name_override(&self, field_name: &str) -> Option<&str> {
        self.name_overrides.get(field_name).map(|s| s.as_str())
    }

    /// Get LE variant of a field class, if one exists.
    pub fn le_variant(&self, class: &str) -> Option<&str> {
        self.le_prefixes.get(class).map(|s| s.as_str())
    }
}
