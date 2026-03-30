//! Load and query the Scapy protocol registry (generated at Nix build time).
//!
//! The registry JSON maps Scapy class names to their module paths:
//! `{"IP": "scapy.layers.inet", "DNS": "scapy.layers.dns", ...}`

use std::collections::HashMap;

use super::normalize_name;

/// Rich metadata for a Scapy class (from --discover-all-rich).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ScapyClassEntry {
    pub module: String,
    #[serde(default)]
    pub field_names: Vec<String>,
    #[serde(default)]
    pub field_count: u32,
    #[serde(default)]
    pub docstring: Option<String>,
    #[serde(default)]
    pub bind_layers: Option<Vec<ScapyBindLayer>>,
}

/// A bind_layers relationship from Scapy.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ScapyBindLayer {
    pub parent: String,
    #[serde(default)]
    pub bindings: HashMap<String, String>,
}

/// The Scapy protocol registry.
#[derive(Debug, Clone)]
pub struct ScapyRegistry {
    /// Map from Scapy class name → module path (simple format)
    pub classes: HashMap<String, String>,
    /// Rich metadata per class (from --discover-all-rich, if available)
    pub rich: HashMap<String, ScapyClassEntry>,
    /// Normalized name → class name (for fuzzy matching)
    normalized_index: HashMap<String, String>,
}

impl ScapyRegistry {
    /// Load the registry from a JSON file path.
    ///
    /// Supports both simple format (class → module string) and rich format
    /// (class → {module, field_names, ...}).
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;

        // Try rich format first
        if let Ok(rich) = serde_json::from_str::<HashMap<String, ScapyClassEntry>>(&content) {
            let classes: HashMap<String, String> = rich
                .iter()
                .map(|(name, entry)| (name.clone(), entry.module.clone()))
                .collect();
            let normalized_index = classes
                .keys()
                .map(|name| (normalize_name(name), name.clone()))
                .collect();
            return Ok(ScapyRegistry {
                classes,
                rich,
                normalized_index,
            });
        }

        // Fall back to simple format
        let classes: HashMap<String, String> = serde_json::from_str(&content)?;
        let normalized_index = classes
            .keys()
            .map(|name| (normalize_name(name), name.clone()))
            .collect();

        Ok(ScapyRegistry {
            classes,
            rich: HashMap::new(),
            normalized_index,
        })
    }

    /// Look up a Scapy class name by exact match.
    pub fn get_class(&self, name: &str) -> Option<&String> {
        self.classes.get(name)
    }

    /// Fuzzy-match a tshark filter name to a Scapy class name.
    ///
    /// Normalizes both names (lowercase, strip punctuation) and checks:
    /// 1. Exact normalized match
    /// 2. Containment (tshark name contains Scapy name or vice versa)
    pub fn fuzzy_match(&self, tshark_filter: &str) -> Option<String> {
        let normalized = normalize_name(tshark_filter);

        // Exact normalized match
        if let Some(class_name) = self.normalized_index.get(&normalized) {
            return Some(class_name.clone());
        }

        // Containment match (prefer shorter names to avoid false positives)
        let mut best_match: Option<(usize, &str)> = None;
        for (norm_scapy, class_name) in &self.normalized_index {
            if norm_scapy.len() < 2 {
                continue; // Skip very short names to avoid false matches
            }
            if normalized.contains(norm_scapy.as_str()) || norm_scapy.contains(normalized.as_str())
            {
                let distance = if normalized.len() > norm_scapy.len() {
                    normalized.len() - norm_scapy.len()
                } else {
                    norm_scapy.len() - normalized.len()
                };
                if best_match.is_none() || distance < best_match.unwrap().0 {
                    best_match = Some((distance, class_name));
                }
            }
        }

        best_match.map(|(_, name)| name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_registry() -> ScapyRegistry {
        let mut classes = HashMap::new();
        classes.insert("IP".to_string(), "scapy.layers.inet".to_string());
        classes.insert("TCP".to_string(), "scapy.layers.inet".to_string());
        classes.insert("DNS".to_string(), "scapy.layers.dns".to_string());
        classes.insert("MQTT".to_string(), "scapy.contrib.mqtt".to_string());

        let normalized_index = classes
            .keys()
            .map(|name| (normalize_name(name), name.clone()))
            .collect();

        ScapyRegistry {
            classes,
            rich: HashMap::new(),
            normalized_index,
        }
    }

    #[test]
    fn test_exact_match() {
        let reg = sample_registry();
        assert_eq!(reg.fuzzy_match("ip"), Some("IP".to_string()));
        assert_eq!(reg.fuzzy_match("tcp"), Some("TCP".to_string()));
        assert_eq!(reg.fuzzy_match("dns"), Some("DNS".to_string()));
    }

    #[test]
    fn test_fuzzy_match() {
        let reg = sample_registry();
        assert_eq!(reg.fuzzy_match("mqtt"), Some("MQTT".to_string()));
    }
}
