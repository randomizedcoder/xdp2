//! Automated cross-source protocol matching engine.
//!
//! Matches protocols across tshark, Scapy, and kernel registries using
//! tiered confidence scoring. Higher tiers are more reliable.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::discovery::{
    normalize_name,
    kernel_registry::KernelRegistry,
    scapy_registry::ScapyRegistry,
    tshark_registry::TsharkRegistry,
};
use super::auto_table::AutoMapping;

/// A candidate match between sources for a single protocol.
#[derive(Debug, Clone)]
pub struct MatchCandidate {
    /// Proposed canonical name
    pub canonical: String,
    /// tshark filter name (if matched)
    pub tshark: Option<String>,
    /// tshark long_name (for display)
    pub tshark_long_name: Option<String>,
    /// Scapy class name (if matched)
    pub scapy: Option<String>,
    /// Kernel struct name (if matched)
    pub kernel_struct: Option<String>,
    /// Kernel header file (if matched)
    pub kernel_header: Option<String>,
    /// Minimum header bytes (estimated)
    pub min_header_bytes: u32,
    /// Whether header is variable length
    pub variable: bool,
    /// Match confidence (0.0–1.0)
    pub confidence: f32,
    /// How the match was made
    pub match_method: String,
    /// Number of sources matched
    pub source_count: u32,
}

/// Result of running the auto-matcher.
#[derive(Debug)]
pub struct MatchResult {
    /// New protocol matches not in the curated table
    pub new_matches: Vec<MatchCandidate>,
    /// Stats about the matching run
    pub stats: MatchStats,
}

#[derive(Debug, Default)]
pub struct MatchStats {
    pub tshark_total: usize,
    pub scapy_total: usize,
    pub kernel_total: usize,
    pub already_curated: usize,
    pub new_exact: usize,
    pub new_decode_table: usize,
    pub new_long_name: usize,
    pub new_abbreviation: usize,
    pub new_containment: usize,
    pub below_threshold: usize,
}

/// Run the auto-matching engine across all available registries.
///
/// Returns matches at or above `min_confidence`.
pub fn auto_match(
    tshark: Option<&TsharkRegistry>,
    scapy: Option<&ScapyRegistry>,
    kernel: Option<&KernelRegistry>,
    min_confidence: f32,
    curated_tshark_filters: &HashSet<String>,
    curated_canonicals: &HashSet<String>,
) -> MatchResult {
    let mut stats = MatchStats::default();
    let mut matches: BTreeMap<String, MatchCandidate> = BTreeMap::new();

    if let Some(tshark_reg) = tshark {
        stats.tshark_total = tshark_reg.protocols.len();
    }
    if let Some(scapy_reg) = scapy {
        stats.scapy_total = scapy_reg.classes.len();
    }
    if let Some(kernel_reg) = kernel {
        stats.kernel_total = kernel_reg.structs.len();
    }

    // Build reverse indexes for matching
    let scapy_normalized: HashMap<String, String> = scapy
        .map(|s| {
            s.classes
                .keys()
                .map(|name| (normalize_name(name), name.clone()))
                .collect()
        })
        .unwrap_or_default();

    let kernel_normalized: HashMap<String, String> = kernel
        .map(|k| {
            k.structs
                .keys()
                .map(|name| (normalize_name(name), name.clone()))
                .collect()
        })
        .unwrap_or_default();

    // Phase 1: Match tshark protocols against Scapy and kernel
    if let Some(tshark_reg) = tshark {
        for (filter_name, proto) in &tshark_reg.protocols {
            // Skip already-curated
            if curated_tshark_filters.contains(&filter_name.to_lowercase()) {
                stats.already_curated += 1;
                continue;
            }

            let normalized_filter = normalize_name(filter_name);
            let _normalized_long = normalize_name(&proto.long_name);

            // Try matching tiers in order of confidence

            // Tier 1: Exact normalized match against Scapy
            let scapy_match = scapy_normalized.get(&normalized_filter).cloned();

            // Tier 2: Decode table match — both tshark and Scapy register
            // to the same dispatch slot
            let decode_match = if scapy_match.is_none() {
                try_decode_table_match(filter_name, tshark_reg, scapy, &scapy_normalized)
            } else {
                None
            };

            // Tier 3: Long name / description match
            let long_name_match = if scapy_match.is_none() && decode_match.is_none() {
                try_long_name_match(&proto.long_name, &scapy_normalized)
            } else {
                None
            };

            // Tier 4: Abbreviation expansion match
            let abbrev_match =
                if scapy_match.is_none() && decode_match.is_none() && long_name_match.is_none() {
                    try_abbreviation_match(&proto.short_name, &proto.long_name, &scapy_normalized)
                } else {
                    None
                };

            // Tier 5: Containment with guard
            let containment_match = if scapy_match.is_none()
                && decode_match.is_none()
                && long_name_match.is_none()
                && abbrev_match.is_none()
            {
                try_containment_match(&normalized_filter, &scapy_normalized)
            } else {
                None
            };

            // Determine best match
            let (matched_scapy, confidence, method) = if let Some(s) = scapy_match {
                stats.new_exact += 1;
                (Some(s), 1.0, "exact_normalized")
            } else if let Some(s) = decode_match {
                stats.new_decode_table += 1;
                (Some(s), 0.9, "decode_table")
            } else if let Some(s) = long_name_match {
                stats.new_long_name += 1;
                (Some(s), 0.7, "long_name")
            } else if let Some(s) = abbrev_match {
                stats.new_abbreviation += 1;
                (Some(s), 0.6, "abbreviation")
            } else if let Some(s) = containment_match {
                stats.new_containment += 1;
                (Some(s), 0.5, "containment")
            } else {
                (None, 0.4, "tshark_only")
            };

            if confidence < min_confidence {
                stats.below_threshold += 1;
                continue;
            }

            // Try kernel match
            let (kernel_struct, kernel_header) =
                try_kernel_match(&normalized_filter, kernel, &kernel_normalized);

            // Compute source count
            let mut source_count = 1u32; // tshark always present
            if matched_scapy.is_some() {
                source_count += 1;
            }
            if kernel_struct.is_some() {
                source_count += 1;
            }

            // Use tshark long_name as canonical, sanitized
            let canonical = sanitize_canonical(&proto.long_name);

            // Skip if canonical clashes with curated
            if curated_canonicals.contains(&canonical.to_lowercase()) {
                stats.already_curated += 1;
                continue;
            }

            // Deduplicate: keep higher confidence
            if let Some(existing) = matches.get(&canonical) {
                if existing.confidence >= confidence {
                    continue;
                }
            }

            matches.insert(
                canonical.clone(),
                MatchCandidate {
                    canonical,
                    tshark: Some(filter_name.clone()),
                    tshark_long_name: Some(proto.long_name.clone()),
                    scapy: matched_scapy,
                    kernel_struct,
                    kernel_header,
                    min_header_bytes: 0,
                    variable: true, // conservative default
                    confidence,
                    match_method: method.to_string(),
                    source_count,
                },
            );
        }
    }

    // Phase 2: Add Scapy-only protocols not yet matched
    if let Some(scapy_reg) = scapy {
        for (class_name, _module) in &scapy_reg.classes {
            let normalized = normalize_name(class_name);

            // Skip if already matched via tshark
            let already_matched = matches.values().any(|m| {
                m.scapy
                    .as_ref()
                    .map(|s| normalize_name(s) == normalized)
                    .unwrap_or(false)
            });
            if already_matched {
                continue;
            }

            // Skip if curated
            if curated_canonicals.contains(&class_name.to_lowercase()) {
                continue;
            }

            let (kernel_struct, kernel_header) =
                try_kernel_match(&normalized, kernel, &kernel_normalized);

            let source_count = 1 + if kernel_struct.is_some() { 1 } else { 0 };
            let confidence = if kernel_struct.is_some() {
                0.7
            } else {
                0.4
            };

            if confidence < min_confidence {
                stats.below_threshold += 1;
                continue;
            }

            let canonical = class_name.clone();
            if matches.contains_key(&canonical) {
                continue;
            }

            matches.insert(
                canonical.clone(),
                MatchCandidate {
                    canonical,
                    tshark: None,
                    tshark_long_name: None,
                    scapy: Some(class_name.clone()),
                    kernel_struct,
                    kernel_header,
                    min_header_bytes: 0,
                    variable: true,
                    confidence,
                    match_method: "scapy_only".to_string(),
                    source_count,
                },
            );
        }
    }

    MatchResult {
        new_matches: matches.into_values().collect(),
        stats,
    }
}

/// Convert MatchCandidates to AutoMapping entries for serialization.
pub fn candidates_to_auto_mappings(candidates: &[MatchCandidate]) -> Vec<AutoMapping> {
    candidates
        .iter()
        .map(|c| AutoMapping {
            canonical: c.canonical.clone(),
            tshark: c.tshark.clone(),
            scapy: c.scapy.clone(),
            kernel_struct: c.kernel_struct.clone(),
            kernel_header: c.kernel_header.clone(),
            min_header_bytes: c.min_header_bytes,
            variable: c.variable,
            confidence: c.confidence,
            match_method: Some(c.match_method.clone()),
        })
        .collect()
}

// ── Matching tiers ──

/// Try matching via decode tables: find tshark protocols that share a decode
/// table slot with a known Scapy class.
fn try_decode_table_match(
    filter_name: &str,
    tshark_reg: &TsharkRegistry,
    scapy: Option<&ScapyRegistry>,
    scapy_normalized: &HashMap<String, String>,
) -> Option<String> {
    let scapy_reg = scapy?;

    // Find which decode table routes to this protocol
    let (table_name, _value) = tshark_reg.find_route_to(filter_name)?;

    // Check other protocols in the same decode table to see if any map to Scapy
    // classes. If the table has Scapy-mapped siblings, the protocol is likely real.
    let table_entries = tshark_reg.get_decode_table(&table_name)?;
    for entry in table_entries {
        if entry.protocol == filter_name {
            continue;
        }
        let norm_sibling = normalize_name(&entry.protocol);
        if scapy_normalized.contains_key(&norm_sibling) {
            // The decode table has Scapy-confirmed siblings — try direct Scapy match
            return scapy_reg.fuzzy_match(filter_name);
        }
    }
    None
}

/// Try matching via long_name words against Scapy class names.
fn try_long_name_match(
    long_name: &str,
    scapy_normalized: &HashMap<String, String>,
) -> Option<String> {
    // Extract significant words from long_name
    let words: Vec<String> = long_name
        .split_whitespace()
        .filter(|w| w.len() > 1)
        .map(|w| normalize_name(w))
        .collect();

    // Try initials (e.g., "Domain Name Service" → "dns")
    let initials: String = long_name
        .split_whitespace()
        .filter_map(|w| w.chars().next())
        .collect::<String>()
        .to_lowercase();
    if initials.len() >= 2 {
        if let Some(class_name) = scapy_normalized.get(&initials) {
            return Some(class_name.clone());
        }
    }

    // Try the full long_name normalized (e.g., "User Datagram Protocol" → "userdatagramprotocol")
    let full_normalized = normalize_name(long_name);
    if let Some(class_name) = scapy_normalized.get(&full_normalized) {
        return Some(class_name.clone());
    }

    // Try concatenating significant words in windows
    for window_size in [3, 2, 1] {
        if words.len() < window_size {
            continue;
        }
        for window in words.windows(window_size) {
            let combined: String = window.join("");
            if let Some(class_name) = scapy_normalized.get(&combined) {
                return Some(class_name.clone());
            }
        }
    }
    None
}

/// Try matching via abbreviation expansion.
/// Uses tshark's own short_name → long_name to build abbreviation triples.
fn try_abbreviation_match(
    short_name: &str,
    long_name: &str,
    scapy_normalized: &HashMap<String, String>,
) -> Option<String> {
    // Build abbreviation from initials of long_name words
    let initials: String = long_name
        .split_whitespace()
        .filter_map(|w| w.chars().next())
        .collect::<String>()
        .to_lowercase();

    let norm_short = normalize_name(short_name);

    // Check if the Scapy normalized index has the initials or short_name
    if let Some(class_name) = scapy_normalized.get(&initials) {
        return Some(class_name.clone());
    }
    if norm_short != initials {
        if let Some(class_name) = scapy_normalized.get(&norm_short) {
            return Some(class_name.clone());
        }
    }
    None
}

/// Try containment match with length guard to avoid false positives.
fn try_containment_match(
    normalized_filter: &str,
    scapy_normalized: &HashMap<String, String>,
) -> Option<String> {
    if normalized_filter.len() < 3 {
        return None;
    }

    let mut best: Option<(usize, String)> = None;

    for (norm_scapy, class_name) in scapy_normalized {
        if norm_scapy.len() < 3 {
            continue;
        }

        let matches = normalized_filter.contains(norm_scapy.as_str())
            || norm_scapy.contains(normalized_filter);

        if !matches {
            continue;
        }

        let distance = normalized_filter
            .len()
            .abs_diff(norm_scapy.len());

        // Guard: names must be within 4 chars of each other
        if distance > 4 {
            continue;
        }

        if best.is_none() || distance < best.as_ref().unwrap().0 {
            best = Some((distance, class_name.clone()));
        }
    }

    best.map(|(_, name)| name)
}

/// Try matching a protocol against kernel structs.
fn try_kernel_match(
    normalized_filter: &str,
    kernel: Option<&KernelRegistry>,
    kernel_normalized: &HashMap<String, String>,
) -> (Option<String>, Option<String>) {
    let kernel_reg = match kernel {
        Some(k) => k,
        None => return (None, None),
    };

    // Try common suffixes: hdr, _hdr, _header
    for suffix in ["hdr", "header"] {
        let candidate = format!("{}{}", normalized_filter, suffix);
        if let Some(struct_name) = kernel_normalized.get(&candidate) {
            if let Some(entry) = kernel_reg.structs.get(struct_name) {
                return (Some(entry.struct_name.clone()), Some(entry.header.clone()));
            }
        }
    }

    // Try exact match
    if let Some(struct_name) = kernel_normalized.get(normalized_filter) {
        if let Some(entry) = kernel_reg.structs.get(struct_name) {
            return (Some(entry.struct_name.clone()), Some(entry.header.clone()));
        }
    }

    (None, None)
}

/// Clean up a tshark long_name into a usable canonical name.
fn sanitize_canonical(long_name: &str) -> String {
    let name = long_name
        .split(" over ")
        .next()
        .unwrap_or(long_name)
        .trim();

    if name.len() > 40 {
        let words: Vec<&str> = name.split_whitespace().take(4).collect();
        return words.join(" ");
    }

    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scapy_normalized() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("ip".to_string(), "IP".to_string());
        m.insert("tcp".to_string(), "TCP".to_string());
        m.insert("dns".to_string(), "DNS".to_string());
        m.insert("mqtt".to_string(), "MQTT".to_string());
        m.insert("coap".to_string(), "CoAP".to_string());
        m
    }

    #[test]
    fn test_long_name_match() {
        let scapy = make_scapy_normalized();
        assert_eq!(
            try_long_name_match("Domain Name Service", &scapy),
            Some("DNS".to_string())
        );
    }

    #[test]
    fn test_containment_match() {
        let scapy = make_scapy_normalized();
        assert_eq!(
            try_containment_match("mqtt", &scapy),
            Some("MQTT".to_string())
        );
    }

    #[test]
    fn test_containment_guard_rejects_distant() {
        let scapy = make_scapy_normalized();
        // "ip" is too short (< 3 chars), should be rejected
        assert_eq!(try_containment_match("ip", &scapy), None);
    }

    #[test]
    fn test_sanitize_canonical() {
        assert_eq!(sanitize_canonical("Domain Name Service"), "Domain Name Service");
        assert_eq!(sanitize_canonical("Something over TCP"), "Something");
        assert_eq!(
            sanitize_canonical("Very Long Protocol Name That Goes On And On And Never Stops"),
            "Very Long Protocol Name"
        );
    }

    #[test]
    fn test_auto_match_empty_registries() {
        let result = auto_match(
            None,
            None,
            None,
            0.5,
            &HashSet::new(),
            &HashSet::new(),
        );
        assert!(result.new_matches.is_empty());
    }

    #[test]
    fn test_candidates_to_auto_mappings() {
        let candidates = vec![MatchCandidate {
            canonical: "Test".to_string(),
            tshark: Some("test".to_string()),
            tshark_long_name: Some("Test Protocol".to_string()),
            scapy: Some("Test".to_string()),
            kernel_struct: None,
            kernel_header: None,
            min_header_bytes: 4,
            variable: false,
            confidence: 0.9,
            match_method: "exact_normalized".to_string(),
            source_count: 2,
        }];
        let mappings = candidates_to_auto_mappings(&candidates);
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].canonical, "Test");
        assert_eq!(mappings[0].confidence, 0.9);
    }
}
