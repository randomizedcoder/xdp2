//! Load and query the tshark protocol registry (generated at Nix build time).
//!
//! The registry JSON is produced by `helpers/tshark_registry.py` and contains:
//! - `protocols`: map of filter_name → {short_name, long_name, filter_name, field_count}
//! - `decode_tables`: map of table_name → [{value, protocol}]

use std::collections::HashMap;

/// A single field entry from `tshark -G fields`.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TsharkFieldEntry {
    /// Human-readable description
    #[serde(default)]
    pub description: String,
    /// tshark filter name (e.g., "dns.id")
    #[serde(default)]
    pub filter_name: String,
    /// FT_* type string (e.g., "FT_UINT16")
    #[serde(default)]
    pub ft_type: String,
    /// Parent protocol filter name
    #[serde(default)]
    pub parent_proto: String,
    /// Display base (e.g., "BASE_DEC", "BASE_HEX")
    #[serde(default)]
    pub base: String,
    /// Bitmask as string (e.g., "0x00f0", "0")
    #[serde(default)]
    pub bitmask: String,
}

/// A single protocol entry from the tshark registry.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TsharkProtocolEntry {
    pub short_name: String,
    pub long_name: String,
    pub filter_name: String,
    pub field_count: u32,
    /// Full field metadata from `tshark -G fields`
    #[serde(default)]
    pub fields: Vec<TsharkFieldEntry>,
}

/// A single decode table entry (parent→child dispatch).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DecodeEntry {
    pub value: String,
    pub protocol: String,
}

/// The complete tshark registry.
#[derive(Debug, Clone)]
pub struct TsharkRegistry {
    pub protocols: HashMap<String, TsharkProtocolEntry>,
    pub decode_tables: HashMap<String, Vec<DecodeEntry>>,
}

impl TsharkRegistry {
    /// Load the registry from a JSON file path.
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let raw: serde_json::Value = serde_json::from_str(&content)?;

        let protocols: HashMap<String, TsharkProtocolEntry> =
            serde_json::from_value(raw["protocols"].clone()).unwrap_or_default();
        let decode_tables: HashMap<String, Vec<DecodeEntry>> =
            serde_json::from_value(raw["decode_tables"].clone()).unwrap_or_default();

        Ok(TsharkRegistry {
            protocols,
            decode_tables,
        })
    }

    /// Look up a protocol by its filter name.
    pub fn get_protocol(&self, filter_name: &str) -> Option<&TsharkProtocolEntry> {
        self.protocols.get(filter_name)
    }

    /// Find which decode table routes to a given protocol filter name.
    /// Returns (table_name, dispatch_value).
    pub fn find_route_to(&self, filter_name: &str) -> Option<(String, String)> {
        for (table_name, entries) in &self.decode_tables {
            for entry in entries {
                if entry.protocol == filter_name {
                    return Some((table_name.clone(), entry.value.clone()));
                }
            }
        }
        None
    }

    /// Get all protocols in a decode table.
    pub fn get_decode_table(&self, table_name: &str) -> Option<&Vec<DecodeEntry>> {
        self.decode_tables.get(table_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_registry() -> TsharkRegistry {
        let json = r#"{
            "protocols": {
                "dns": {
                    "short_name": "DNS",
                    "long_name": "Domain Name Service",
                    "filter_name": "dns",
                    "field_count": 42
                },
                "tcp": {
                    "short_name": "TCP",
                    "long_name": "Transmission Control Protocol",
                    "filter_name": "tcp",
                    "field_count": 30
                }
            },
            "decode_tables": {
                "udp.port": [
                    {"value": "53", "protocol": "dns"}
                ],
                "ip.proto": [
                    {"value": "6", "protocol": "tcp"}
                ]
            }
        }"#;

        let raw: serde_json::Value = serde_json::from_str(json).unwrap();
        TsharkRegistry {
            protocols: serde_json::from_value(raw["protocols"].clone()).unwrap(),
            decode_tables: serde_json::from_value(raw["decode_tables"].clone()).unwrap(),
        }
    }

    #[test]
    fn test_get_protocol() {
        let reg = sample_registry();
        let dns = reg.get_protocol("dns").unwrap();
        assert_eq!(dns.long_name, "Domain Name Service");
        assert_eq!(dns.field_count, 42);
    }

    #[test]
    fn test_find_route_to() {
        let reg = sample_registry();
        let (table, value) = reg.find_route_to("dns").unwrap();
        assert_eq!(table, "udp.port");
        assert_eq!(value, "53");
    }
}
