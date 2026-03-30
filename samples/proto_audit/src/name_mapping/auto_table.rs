//! Data-driven protocol name mappings loaded from JSON.
//!
//! Supplements the hand-curated `table.rs` with auto-matched or
//! externally-generated protocol entries. Loaded at compile time via
//! `include_str!()` to avoid runtime file I/O.

use serde::{Deserialize, Serialize};

/// A single auto-mapped protocol entry from JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoMapping {
    /// Canonical protocol name
    pub canonical: String,
    /// tshark dissector/filter name
    #[serde(default)]
    pub tshark: Option<String>,
    /// Scapy class name
    #[serde(default)]
    pub scapy: Option<String>,
    /// Linux kernel struct name
    #[serde(default)]
    pub kernel_struct: Option<String>,
    /// Linux kernel header file
    #[serde(default)]
    pub kernel_header: Option<String>,
    /// Minimum header size in bytes
    #[serde(default)]
    pub min_header_bytes: u32,
    /// Whether header length is variable
    #[serde(default)]
    pub variable: bool,
    /// Matching confidence (0.0–1.0)
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    /// How the match was made (e.g., "exact_normalized", "decode_table")
    #[serde(default)]
    pub match_method: Option<String>,
}

fn default_confidence() -> f32 {
    0.0
}

/// Root structure of auto_mappings.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoMappings {
    pub protocols: Vec<AutoMapping>,
}

const AUTO_MAPPINGS_JSON: &str = include_str!("../../data/auto_mappings.json");

/// Load auto-mappings from the embedded JSON data.
pub fn load_auto_mappings() -> AutoMappings {
    serde_json::from_str(AUTO_MAPPINGS_JSON).unwrap_or_else(|e| {
        eprintln!("warning: failed to parse auto_mappings.json: {}", e);
        AutoMappings {
            protocols: vec![],
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_auto_mappings_count() {
        let mappings = load_auto_mappings();
        assert!(
            mappings.protocols.len() >= 1100,
            "Expected 1100+ auto-mapped protocols, got {}",
            mappings.protocols.len()
        );
    }

    #[test]
    fn test_auto_mappings_all_have_tshark() {
        let mappings = load_auto_mappings();
        for p in &mappings.protocols {
            assert!(
                p.tshark.is_some(),
                "Protocol '{}' missing tshark filter",
                p.canonical
            );
        }
    }

    #[test]
    fn test_auto_mappings_no_empty_canonicals() {
        let mappings = load_auto_mappings();
        for p in &mappings.protocols {
            assert!(!p.canonical.is_empty(), "Found empty canonical name");
        }
    }

    #[test]
    fn test_auto_mappings_no_duplicates() {
        let mappings = load_auto_mappings();
        let mut seen = std::collections::HashSet::new();
        for p in &mappings.protocols {
            assert!(
                seen.insert(&p.canonical),
                "Duplicate canonical name: {}",
                p.canonical
            );
        }
    }

    #[test]
    fn test_auto_mappings_confidence_range() {
        let mappings = load_auto_mappings();
        for p in &mappings.protocols {
            assert!(
                (0.0..=1.0).contains(&p.confidence),
                "Protocol '{}' has out-of-range confidence: {}",
                p.canonical,
                p.confidence
            );
        }
    }

    #[test]
    fn test_auto_mapping_deserialize() {
        let json = r#"{
            "protocols": [{
                "canonical": "TestProto",
                "tshark": "test",
                "scapy": "Test",
                "min_header_bytes": 4,
                "variable": true,
                "confidence": 0.95,
                "match_method": "exact_normalized"
            }]
        }"#;
        let mappings: AutoMappings = serde_json::from_str(json).unwrap();
        assert_eq!(mappings.protocols.len(), 1);
        assert_eq!(mappings.protocols[0].canonical, "TestProto");
        assert_eq!(mappings.protocols[0].confidence, 0.95);
        assert!(mappings.protocols[0].variable);
    }
}
