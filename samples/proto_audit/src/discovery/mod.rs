//! Protocol auto-discovery: two-tier model.
//!
//! Tier 1 (curated): 207 protocols from `name_mapping::protocol_table()`
//! Tier 2 (discovered): auto-discovered from tshark/Scapy/kernel registries
//!
//! Both tiers produce `DiscoveredProtocol` records that feed into the same
//! audit/matrix/extract pipeline.

pub mod kernel_registry;
pub mod routes;
pub mod scapy_registry;
pub mod tshark_registry;

use std::collections::BTreeMap;

use crate::name_mapping;

/// Which tier a protocol belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Tier {
    /// Hand-curated in name_mapping::table.rs
    Curated,
    /// Auto-discovered from external registries
    Discovered,
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tier::Curated => write!(f, "C"),
            Tier::Discovered => write!(f, "D"),
        }
    }
}

/// A protocol known to proto-audit (either curated or discovered).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiscoveredProtocol {
    /// Canonical name (tshark long_name for Tier 2, or the curated name for Tier 1)
    pub canonical: String,
    /// tshark dissector/filter name (used for extraction)
    pub tshark_filter: Option<String>,
    /// Scapy class name (if matched)
    pub scapy_class: Option<String>,
    /// Kernel struct name (if matched)
    pub kernel_struct: Option<String>,
    /// Kernel header file (if matched)
    pub kernel_header: Option<String>,
    /// Which tier
    pub tier: Tier,
    /// Estimated field count (from tshark -G fields)
    pub estimated_field_count: u32,
    /// Minimum header bytes (from curated table or estimated)
    pub min_header_bytes: u32,
    /// Cross-source matching confidence (0.0–1.0, 1.0 = exact curated match)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_confidence: Option<f32>,
    /// How the cross-source match was made (e.g., "exact_normalized", "decode_table", "fuzzy")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_method: Option<String>,
}

/// The tier filter from CLI --tier flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierFilter {
    Curated,
    Discovered,
    All,
}

impl TierFilter {
    pub fn from_str(s: &str) -> Self {
        match s {
            "discovered" => TierFilter::Discovered,
            "all" => TierFilter::All,
            _ => TierFilter::Curated,
        }
    }

    pub fn matches(&self, tier: Tier) -> bool {
        match self {
            TierFilter::Curated => tier == Tier::Curated,
            TierFilter::Discovered => tier == Tier::Discovered,
            TierFilter::All => true,
        }
    }
}

/// Aggregate discovery state loaded from all registries.
pub struct DiscoveryState {
    pub tshark: Option<tshark_registry::TsharkRegistry>,
    pub scapy: Option<scapy_registry::ScapyRegistry>,
    pub kernel: Option<kernel_registry::KernelRegistry>,
}

impl DiscoveryState {
    /// Load all available registries from environment variables.
    /// Prints warnings to stderr when a registry path is set but loading fails.
    pub fn load_from_env() -> Self {
        let tshark = std::env::var("PROTO_AUDIT_TSHARK_REGISTRY")
            .ok()
            .and_then(|p| {
                match tshark_registry::TsharkRegistry::load(&p) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        eprintln!("warning: failed to load tshark registry from {}: {}", p, e);
                        None
                    }
                }
            });
        let scapy = std::env::var("PROTO_AUDIT_SCAPY_REGISTRY")
            .ok()
            .and_then(|p| {
                match scapy_registry::ScapyRegistry::load(&p) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        eprintln!("warning: failed to load scapy registry from {}: {}", p, e);
                        None
                    }
                }
            });
        let kernel = std::env::var("PROTO_AUDIT_KERNEL_REGISTRY")
            .ok()
            .and_then(|p| {
                match kernel_registry::KernelRegistry::load(&p) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        eprintln!("warning: failed to load kernel registry from {}: {}", p, e);
                        None
                    }
                }
            });
        DiscoveryState {
            tshark,
            scapy,
            kernel,
        }
    }

    /// Check if any registries are loaded.
    pub fn has_registries(&self) -> bool {
        self.tshark.is_some() || self.scapy.is_some() || self.kernel.is_some()
    }
}

/// Merge Tier 1 (curated) and Tier 2 (discovered) protocols.
///
/// Curated protocols always win in case of conflicts (same tshark filter name).
/// Returns a map from canonical name → DiscoveredProtocol.
pub fn all_protocols(state: &DiscoveryState) -> BTreeMap<String, DiscoveredProtocol> {
    let mut result = BTreeMap::new();

    // Step 1: Load all curated protocols as Tier 1
    let curated_table = name_mapping::protocol_table();
    let mut curated_tshark_filters: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    for p in &curated_table {
        if let Some(filter) = p.tshark {
            curated_tshark_filters.insert(filter.to_lowercase());
        }

        let dp = DiscoveredProtocol {
            canonical: p.canonical.to_string(),
            tshark_filter: p.tshark.map(|s| s.to_string()),
            scapy_class: p.scapy.map(|s| s.to_string()),
            kernel_struct: p.kernel_struct.map(|s| s.to_string()),
            kernel_header: p.kernel_header.map(|s| s.to_string()),
            tier: Tier::Curated,
            estimated_field_count: 0,
            min_header_bytes: p.min_header_bytes,
            match_confidence: Some(1.0),
            match_method: Some("curated".to_string()),
        };
        result.insert(p.canonical.to_string(), dp);
    }

    // Step 2: Add discovered protocols from tshark registry (Tier 2)
    if let Some(ref tshark_reg) = state.tshark {
        for (filter_name, proto) in &tshark_reg.protocols {
            // Skip if already curated
            if curated_tshark_filters.contains(&filter_name.to_lowercase()) {
                continue;
            }

            // Use the long_name as canonical for discovered protocols
            let canonical = sanitize_canonical(&proto.long_name);

            // Skip if we already have this canonical name
            if result.contains_key(&canonical) {
                continue;
            }

            // Try to find a Scapy match
            let scapy_class = state
                .scapy
                .as_ref()
                .and_then(|sr| sr.fuzzy_match(filter_name));

            // Try to find a kernel match
            let (kernel_struct, kernel_header) = state
                .kernel
                .as_ref()
                .and_then(|kr| kr.fuzzy_match(filter_name))
                .map(|ks| (Some(ks.struct_name.clone()), Some(ks.header.clone())))
                .unwrap_or((None, None));

            let dp = DiscoveredProtocol {
                canonical: canonical.clone(),
                tshark_filter: Some(filter_name.clone()),
                scapy_class,
                kernel_struct,
                kernel_header,
                tier: Tier::Discovered,
                estimated_field_count: proto.field_count,
                min_header_bytes: 0, // Unknown for discovered
                match_confidence: None,
                match_method: None,
            };
            result.insert(canonical, dp);
        }
    }

    // Step 3: Add Scapy-only protocols not already matched
    if let Some(ref scapy_reg) = state.scapy {
        for (class_name, _module) in &scapy_reg.classes {
            let normalized = normalize_name(class_name);
            let already_exists = result.values().any(|dp| {
                dp.scapy_class
                    .as_ref()
                    .map(|s| normalize_name(s) == normalized)
                    .unwrap_or(false)
            });
            if already_exists {
                continue;
            }

            let canonical = class_name.clone();
            if result.contains_key(&canonical) {
                continue;
            }

            let dp = DiscoveredProtocol {
                canonical: canonical.clone(),
                tshark_filter: None,
                scapy_class: Some(class_name.clone()),
                kernel_struct: None,
                kernel_header: None,
                tier: Tier::Discovered,
                estimated_field_count: 0,
                min_header_bytes: 0,
                match_confidence: None,
                match_method: None,
            };
            result.insert(canonical, dp);
        }
    }

    result
}

/// Normalize a protocol name for fuzzy comparison.
pub fn normalize_name(name: &str) -> String {
    name.to_lowercase()
        .replace(['-', '_', '.', ' ', '/', '(', ')'], "")
}

/// Clean up a tshark long_name into a usable canonical name.
fn sanitize_canonical(long_name: &str) -> String {
    // Truncate at common filler words for brevity
    let name = long_name
        .split(" over ")
        .next()
        .unwrap_or(long_name)
        .trim();

    // If it's very long, just take the first few words
    if name.len() > 40 {
        let words: Vec<&str> = name.split_whitespace().take(4).collect();
        return words.join(" ");
    }

    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_name() {
        assert_eq!(normalize_name("TCP"), "tcp");
        assert_eq!(normalize_name("ieee802.11"), "ieee80211");
        assert_eq!(normalize_name("CAN-FD"), "canfd");
        assert_eq!(normalize_name("some_proto"), "someproto");
    }

    #[test]
    fn test_tier_filter() {
        assert!(TierFilter::All.matches(Tier::Curated));
        assert!(TierFilter::All.matches(Tier::Discovered));
        assert!(TierFilter::Curated.matches(Tier::Curated));
        assert!(!TierFilter::Curated.matches(Tier::Discovered));
        assert!(!TierFilter::Discovered.matches(Tier::Curated));
        assert!(TierFilter::Discovered.matches(Tier::Discovered));
    }

    #[test]
    fn test_sanitize_canonical() {
        assert_eq!(sanitize_canonical("Domain Name Service"), "Domain Name Service");
        assert_eq!(
            sanitize_canonical("Something over TCP"),
            "Something"
        );
    }

    #[test]
    fn test_curated_protocols_present() {
        let state = DiscoveryState {
            tshark: None,
            scapy: None,
            kernel: None,
        };
        let protos = all_protocols(&state);
        // Should have all curated protocols even with no registries
        assert!(protos.contains_key("IPv4"));
        assert!(protos.contains_key("TCP"));
        assert!(protos.contains_key("Ethernet"));
        for dp in protos.values() {
            assert_eq!(dp.tier, Tier::Curated);
        }
    }
}
