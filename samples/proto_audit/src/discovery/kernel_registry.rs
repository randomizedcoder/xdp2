//! Load and query the kernel UAPI struct registry (generated at Nix build time).
//!
//! The registry JSON maps struct names to their header files and field counts:
//! `{"iphdr": {"struct_name": "iphdr", "header": "linux/ip.h", "field_count": 12}, ...}`

use std::collections::HashMap;

use super::normalize_name;

/// A single kernel struct entry from the registry.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct KernelStructEntry {
    pub struct_name: String,
    pub header: String,
    pub field_count: u32,
}

/// The kernel UAPI struct registry.
#[derive(Debug, Clone)]
pub struct KernelRegistry {
    pub structs: HashMap<String, KernelStructEntry>,
    /// Normalized name → struct name (for fuzzy matching)
    normalized_index: HashMap<String, String>,
}

impl KernelRegistry {
    /// Load the registry from a JSON file path.
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let structs: HashMap<String, KernelStructEntry> = serde_json::from_str(&content)?;

        let normalized_index = structs
            .keys()
            .map(|name| (normalize_name(name), name.clone()))
            .collect();

        Ok(KernelRegistry {
            structs,
            normalized_index,
        })
    }

    /// Look up a kernel struct by exact name.
    pub fn get_struct(&self, name: &str) -> Option<&KernelStructEntry> {
        self.structs.get(name)
    }

    /// Fuzzy-match a tshark filter name to a kernel struct.
    ///
    /// Tries common naming patterns:
    /// - filter "dns" → struct "dnshdr" or "dns_header"
    /// - filter "tcp" → struct "tcphdr"
    /// - filter "ip" → struct "iphdr"
    pub fn fuzzy_match(&self, tshark_filter: &str) -> Option<&KernelStructEntry> {
        let normalized = normalize_name(tshark_filter);

        // Try common suffixes: hdr, _hdr, _header
        for suffix in &["hdr", "_hdr", "_header"] {
            let candidate = format!("{}{}", normalized, suffix);
            if let Some(struct_name) = self.normalized_index.get(&candidate) {
                return self.structs.get(struct_name);
            }
        }

        // Try exact normalized match
        if let Some(struct_name) = self.normalized_index.get(&normalized) {
            return self.structs.get(struct_name);
        }

        // Try containment: find structs whose normalized name contains the filter name
        for (norm_struct, struct_name) in &self.normalized_index {
            if norm_struct.len() < 3 {
                continue;
            }
            if norm_struct.contains(normalized.as_str()) && norm_struct.len() <= normalized.len() + 4
            {
                return self.structs.get(struct_name);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_registry() -> KernelRegistry {
        let mut structs = HashMap::new();
        structs.insert(
            "iphdr".to_string(),
            KernelStructEntry {
                struct_name: "iphdr".to_string(),
                header: "linux/ip.h".to_string(),
                field_count: 12,
            },
        );
        structs.insert(
            "tcphdr".to_string(),
            KernelStructEntry {
                struct_name: "tcphdr".to_string(),
                header: "linux/tcp.h".to_string(),
                field_count: 15,
            },
        );

        let normalized_index = structs
            .keys()
            .map(|name| (normalize_name(name), name.clone()))
            .collect();

        KernelRegistry {
            structs,
            normalized_index,
        }
    }

    #[test]
    fn test_fuzzy_match_suffix() {
        let reg = sample_registry();
        let m = reg.fuzzy_match("ip").unwrap();
        assert_eq!(m.struct_name, "iphdr");

        let m = reg.fuzzy_match("tcp").unwrap();
        assert_eq!(m.struct_name, "tcphdr");
    }
}
