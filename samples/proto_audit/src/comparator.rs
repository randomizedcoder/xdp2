//! Cross-source field matching and comparison engine.
//!
//! Compares protocol definitions from different sources by matching
//! fields based on bit offset + size, then checking for mismatches
//! in type, endianness, and naming.
//!
//! Distinguishes between:
//! - **Structural agreement**: same offset + size (the layout matches)
//! - **Semantic agreement**: same offset + size + type + endian (full match)

use std::collections::{BTreeMap, HashSet};

use crate::ir::*;

// ── Shared helpers ──

/// Find fields in `fields` that overlap the bit range [offset, offset+size).
fn find_overlapping_fields<'a>(
    offset: u32,
    size: u32,
    fields: &'a [FieldDef],
) -> Vec<&'a FieldDef> {
    let start = offset;
    let end = offset + size;
    fields
        .iter()
        .filter(|f| {
            let f_start = f.offset_bits;
            let f_end = f_start + f.size_bits;
            f_start < end && start < f_end
        })
        .collect()
}

/// Build a unified field map: (offset, size) → Vec<(source_name, &FieldDef)>.
fn build_field_map<'a>(
    field_sources: &[(&'a str, &'a ProtocolDef)],
) -> BTreeMap<(u32, u32), Vec<(&'a str, &'a FieldDef)>> {
    let mut map: BTreeMap<(u32, u32), Vec<(&str, &FieldDef)>> = BTreeMap::new();
    for (src_name, proto) in field_sources {
        for field in &proto.fields {
            map.entry((field.offset_bits, field.size_bits))
                .or_default()
                .push((src_name, field));
        }
    }
    map
}

/// Compare a single field-map slot against all sources, producing a FieldComparison.
fn compare_slot(
    offset: u32,
    size: u32,
    slot_sources: &[(&str, &FieldDef)],
    field_sources: &[(&str, &ProtocolDef)],
) -> FieldComparison {
    let name = slot_sources[0].1.name.clone();
    let slot_source_names: Vec<String> =
        slot_sources.iter().map(|(s, _)| s.to_string()).collect();

    // Check for overlaps from sources that don't have this exact slot
    let mut overlap_mismatches = Vec::new();
    for (src_name, proto) in field_sources {
        if slot_source_names.contains(&src_name.to_string()) {
            continue;
        }
        let overlaps = find_overlapping_fields(offset, size, &proto.fields);
        if !overlaps.is_empty() {
            let overlap_names: Vec<_> = overlaps.iter().map(|f| f.name.clone()).collect();
            overlap_mismatches.push(FieldMismatch {
                source: src_name.to_string(),
                field: "split".to_string(),
                expected: format!("{}[{}:{}]", name, offset, offset + size),
                actual: format!("overlaps with: {}", overlap_names.join(", ")),
            });
        }
    }

    // Compare type+endian within the slot (all pairs)
    let mut type_mismatches = Vec::new();
    if slot_sources.len() >= 2 {
        for i in 0..slot_sources.len() {
            for j in (i + 1)..slot_sources.len() {
                let (_name_i, field_i) = &slot_sources[i];
                let (name_j, field_j) = &slot_sources[j];

                if field_i.field_type != field_j.field_type {
                    type_mismatches.push(FieldMismatch {
                        source: name_j.to_string(),
                        field: "field_type".to_string(),
                        expected: format!("{:?}", field_i.field_type),
                        actual: format!("{:?}", field_j.field_type),
                    });
                }
                if field_i.endian != field_j.endian
                    && field_i.endian != Endian::Na
                    && field_j.endian != Endian::Na
                {
                    type_mismatches.push(FieldMismatch {
                        source: name_j.to_string(),
                        field: "endian".to_string(),
                        expected: format!("{:?}", field_i.endian),
                        actual: format!("{:?}", field_j.endian),
                    });
                }
            }
        }
    }

    let sources_structural = slot_source_names.clone();

    let mismatched_sources: HashSet<&str> = type_mismatches
        .iter()
        .map(|m| m.source.as_str())
        .collect();
    let sources_agree: Vec<String> = slot_source_names
        .iter()
        .filter(|s| !mismatched_sources.contains(s.as_str()))
        .cloned()
        .collect();

    // Check which sources are missing this field entirely (no overlap either)
    let mut presence_mismatches = Vec::new();
    for (src_name, _proto) in field_sources {
        if slot_source_names.contains(&src_name.to_string()) {
            continue;
        }
        if overlap_mismatches.iter().any(|m| m.source == *src_name) {
            continue;
        }
        presence_mismatches.push(FieldMismatch {
            source: src_name.to_string(),
            field: "presence".to_string(),
            expected: "present".to_string(),
            actual: "missing".to_string(),
        });
    }

    let mut all_mismatches = Vec::new();
    all_mismatches.extend(type_mismatches);
    all_mismatches.extend(overlap_mismatches);
    all_mismatches.extend(presence_mismatches);

    FieldComparison {
        name,
        offset_bits: offset,
        size_bits: size,
        sources_agree,
        sources_structural,
        mismatches: all_mismatches,
    }
}

/// Compute aggregate statistics from a list of field comparisons.
/// Returns (total, agree, type_differ, mismatch, missing, structural_agree).
/// `structural_agree` counts fields where 2+ sources agree on offset+size,
/// even if presence or type mismatches exist from other sources.
fn compute_statistics(comparisons: &[FieldComparison]) -> (u32, u32, u32, u32, u32, u32) {
    let total = comparisons.len() as u32;

    let agree = comparisons
        .iter()
        .filter(|c| c.mismatches.is_empty())
        .count() as u32;

    let type_differ = comparisons
        .iter()
        .filter(|c| {
            !c.mismatches.is_empty()
                && c.sources_structural.len() >= 2
                && c.mismatches
                    .iter()
                    .all(|m| m.field == "field_type" || m.field == "endian")
        })
        .count() as u32;

    let mismatch = comparisons
        .iter()
        .filter(|c| c.mismatches.iter().any(|m| m.field == "split"))
        .count() as u32;

    let missing = comparisons
        .iter()
        .filter(|c| {
            c.mismatches.iter().any(|m| m.field == "presence")
                && !c.mismatches.iter().any(|m| m.field == "split")
        })
        .count() as u32;

    // Fields where 2+ sources structurally agree on offset+size
    let structural_agree = comparisons
        .iter()
        .filter(|c| c.sources_structural.len() >= 2)
        .count() as u32;

    (total, agree, type_differ, mismatch, missing, structural_agree)
}

/// Match fields across two protocol definitions by offset+size.
///
/// Returns a list of field comparisons showing agreement and mismatches.
pub fn compare_fields(
    source_a: &str,
    proto_a: &ProtocolDef,
    source_b: &str,
    proto_b: &ProtocolDef,
) -> Vec<FieldComparison> {
    let mut comparisons = Vec::new();

    // Index fields by (offset, size) for quick lookup
    let b_by_pos: BTreeMap<(u32, u32), &FieldDef> = proto_b
        .fields
        .iter()
        .map(|f| ((f.offset_bits, f.size_bits), f))
        .collect();

    let mut matched_b: std::collections::HashSet<(u32, u32)> = std::collections::HashSet::new();

    // Match each field in A against B
    for field_a in &proto_a.fields {
        let key = (field_a.offset_bits, field_a.size_bits);

        if let Some(field_b) = b_by_pos.get(&key) {
            matched_b.insert(key);

            let mut mismatches = Vec::new();

            // Check type
            if field_a.field_type != field_b.field_type {
                mismatches.push(FieldMismatch {
                    source: source_b.to_string(),
                    field: "field_type".to_string(),
                    expected: format!("{:?}", field_a.field_type),
                    actual: format!("{:?}", field_b.field_type),
                });
            }

            // Check endianness
            if field_a.endian != field_b.endian
                && field_a.endian != Endian::Na
                && field_b.endian != Endian::Na
            {
                mismatches.push(FieldMismatch {
                    source: source_b.to_string(),
                    field: "endian".to_string(),
                    expected: format!("{:?}", field_a.endian),
                    actual: format!("{:?}", field_b.endian),
                });
            }

            // Structural agreement: always both (offset+size matched)
            let sources_structural = vec![source_a.to_string(), source_b.to_string()];

            // Semantic agreement: only if type+endian also match
            let mut sources_agree = vec![source_a.to_string()];
            if mismatches.is_empty() {
                sources_agree.push(source_b.to_string());
            }

            comparisons.push(FieldComparison {
                name: field_a.name.clone(),
                offset_bits: field_a.offset_bits,
                size_bits: field_a.size_bits,
                sources_agree,
                sources_structural,
                mismatches,
            });
        } else {
            // Field in A but not B — try overlap matching
            let overlaps = find_overlapping_fields(
                field_a.offset_bits, field_a.size_bits, &proto_b.fields,
            );

            if overlaps.is_empty() {
                // Only in source A
                comparisons.push(FieldComparison {
                    name: field_a.name.clone(),
                    offset_bits: field_a.offset_bits,
                    size_bits: field_a.size_bits,
                    sources_agree: vec![source_a.to_string()],
                    sources_structural: vec![source_a.to_string()],
                    mismatches: vec![FieldMismatch {
                        source: source_b.to_string(),
                        field: "presence".to_string(),
                        expected: "present".to_string(),
                        actual: "missing".to_string(),
                    }],
                });
            } else {
                // Overlap — different field splitting
                let overlap_names: Vec<_> =
                    overlaps.iter().map(|f| f.name.clone()).collect();
                comparisons.push(FieldComparison {
                    name: field_a.name.clone(),
                    offset_bits: field_a.offset_bits,
                    size_bits: field_a.size_bits,
                    sources_agree: vec![source_a.to_string()],
                    sources_structural: vec![source_a.to_string()],
                    mismatches: vec![FieldMismatch {
                        source: source_b.to_string(),
                        field: "split".to_string(),
                        expected: format!(
                            "{}[{}:{}]",
                            field_a.name,
                            field_a.offset_bits,
                            field_a.offset_bits + field_a.size_bits
                        ),
                        actual: format!("overlaps with: {}", overlap_names.join(", ")),
                    }],
                });
                for o in &overlaps {
                    matched_b.insert((o.offset_bits, o.size_bits));
                }
            }
        }
    }

    // Fields in B but not A
    for field_b in &proto_b.fields {
        let key = (field_b.offset_bits, field_b.size_bits);
        if !matched_b.contains(&key) {
            comparisons.push(FieldComparison {
                name: field_b.name.clone(),
                offset_bits: field_b.offset_bits,
                size_bits: field_b.size_bits,
                sources_agree: vec![source_b.to_string()],
                sources_structural: vec![source_b.to_string()],
                mismatches: vec![FieldMismatch {
                    source: source_a.to_string(),
                    field: "presence".to_string(),
                    expected: "present".to_string(),
                    actual: "missing".to_string(),
                }],
            });
        }
    }

    // Sort by offset
    comparisons.sort_by_key(|c| (c.offset_bits, c.size_bits));
    comparisons
}

/// Build an AuditResult from multiple source definitions of the same protocol.
///
/// Uses a unified field map approach: all sources' fields are indexed by
/// (offset, size), then compared against each other — not just against a
/// single reference source. This ensures B-vs-C comparisons happen even
/// when A doesn't have a particular field.
pub fn audit_protocol(canonical_name: &str, sources: &[(&str, &ProtocolDef)]) -> AuditResult {
    let all_source_names: Vec<&str> = vec!["xdp2", "kernel", "scapy", "tshark"];
    let present: Vec<String> = sources.iter().map(|(name, _)| name.to_string()).collect();
    let missing: Vec<String> = all_source_names
        .iter()
        .filter(|s| !present.contains(&s.to_string()))
        .map(|s| s.to_string())
        .collect();

    // Filter out zero-field sources from field-level comparison.
    // These sources (e.g., XDP2) reference protocols but don't define fields,
    // so including them would cause every field to show presence:missing.
    // They're still listed in sources_present for coverage tracking.
    let field_sources: Vec<(&str, &ProtocolDef)> = sources
        .iter()
        .filter(|(_, def)| !def.fields.is_empty())
        .copied()
        .collect();

    let mut all_comparisons = Vec::new();

    if field_sources.len() >= 2 {
        let field_map = build_field_map(&field_sources);

        for (&(offset, size), slot_sources) in &field_map {
            all_comparisons.push(compare_slot(offset, size, slot_sources, &field_sources));
        }
    } else if field_sources.len() == 1 {
        // Single source — all fields agree trivially
        let (name, proto) = &field_sources[0];
        for field in &proto.fields {
            all_comparisons.push(FieldComparison {
                name: field.name.clone(),
                offset_bits: field.offset_bits,
                size_bits: field.size_bits,
                sources_agree: vec![name.to_string()],
                sources_structural: vec![name.to_string()],
                mismatches: vec![],
            });
        }
    }

    all_comparisons.sort_by_key(|c| (c.offset_bits, c.size_bits));

    let (total, agree, type_differ, mismatch, field_missing, structural_agree) =
        compute_statistics(&all_comparisons);

    // Compute validation tier from audit statistics.
    // Use structural_agree (2+ sources at same offset+size) for Silver,
    // which is more lenient than strict agree (no mismatches at all).
    let validation_tier = {
        let sources_with_fields = field_sources.len();
        let is_roundtrip = false; // Set by cmd_validate, not here
        Some(crate::discovery::compute_validation_tier(
            sources_with_fields,
            structural_agree,
            total,
            is_roundtrip,
        ))
    };

    AuditResult {
        protocol: canonical_name.to_string(),
        sources_present: present,
        sources_missing: missing,
        field_comparisons: all_comparisons,
        total_fields: total,
        fields_agree: agree,
        fields_type_differ: type_differ,
        fields_mismatch: mismatch,
        fields_missing: field_missing,
        validation_tier,
    }
}

/// Count split mismatches that are "covered" — where both sources' fields
/// cover the same bit range, just with different internal boundaries.
///
/// This is critical for round-trip validation: tshark PDML is byte-aligned and
/// often merges or splits fields differently from the IR (e.g., IPv4
/// version(4b)+IHL(4b) → single 8-bit field, or tshark's single SPI+SI field
/// vs IR's separate SPI and SI fields).
///
/// A split is covered when:
/// 1. **Exact tile**: one source's sub-fields tile the other's merged field
///    with no gaps (strict, e.g., version+IHL tiling ip.version)
/// 2. **Mutual overlap**: both sources have fields covering the same bit range,
///    just with different internal boundaries. Neither source leaves uncovered
///    bits within the overlap region.
///
/// Returns the number of split mismatches that are covered.
pub fn count_covered_splits(
    result: &AuditResult,
    source_a: &ProtocolDef,
    source_b: &ProtocolDef,
) -> u32 {
    // Phase 1: Find exact-tile covered ranges (strict, original logic)
    let mut covered_ranges: Vec<(u32, u32)> = Vec::new();

    for fc in &result.field_comparisons {
        let has_split = fc.mismatches.iter().any(|m| m.field == "split");
        if !has_split {
            continue;
        }

        let start = fc.offset_bits;
        let end = start + fc.size_bits;

        if is_exact_tile(start, end, &source_a.fields)
            || is_exact_tile(start, end, &source_b.fields)
        {
            covered_ranges.push((start, end));
        }
    }

    // Phase 2: Find mutual-overlap covered ranges.
    // Group contiguous split fields into regions and check if both sources
    // fully cover each region (possibly with different internal boundaries).
    let mut split_fields: Vec<(u32, u32)> = result
        .field_comparisons
        .iter()
        .filter(|fc| fc.mismatches.iter().any(|m| m.field == "split"))
        .map(|fc| (fc.offset_bits, fc.offset_bits + fc.size_bits))
        .collect();
    split_fields.sort();
    split_fields.dedup();

    // Merge overlapping/adjacent split field ranges into contiguous regions
    let regions = merge_ranges(&split_fields);

    for (region_start, region_end) in &regions {
        // Already covered by exact tile?
        if covered_ranges.iter().any(|&(rs, re)| rs <= *region_start && re >= *region_end) {
            continue;
        }
        // Check if both sources have fields that collectively cover the region
        if covers_range(*region_start, *region_end, &source_a.fields)
            && covers_range(*region_start, *region_end, &source_b.fields)
        {
            covered_ranges.push((*region_start, *region_end));
        }
    }

    // Merge covered_ranges so containment checks work across merged regions
    covered_ranges.sort();
    let merged_covered = merge_ranges(&covered_ranges);

    // Count split-mismatch fields that fall within any covered range
    let mut covered = 0u32;
    for fc in &result.field_comparisons {
        let has_split = fc.mismatches.iter().any(|m| m.field == "split");
        if !has_split {
            continue;
        }
        let f_start = fc.offset_bits;
        let f_end = f_start + fc.size_bits;

        if merged_covered.iter().any(|&(rs, re)| f_start >= rs && f_end <= re) {
            covered += 1;
        }
    }

    covered
}

/// Merge overlapping or adjacent ranges into non-overlapping contiguous ranges.
fn merge_ranges(ranges: &[(u32, u32)]) -> Vec<(u32, u32)> {
    if ranges.is_empty() {
        return vec![];
    }
    let mut sorted = ranges.to_vec();
    sorted.sort();
    let mut merged = vec![sorted[0]];
    for &(s, e) in &sorted[1..] {
        let last = merged.last_mut().unwrap();
        if s <= last.1 {
            last.1 = last.1.max(e);
        } else {
            merged.push((s, e));
        }
    }
    merged
}

/// Check whether `fields` contains sub-fields that exactly tile [start, end)
/// with no gaps and no overlaps, and the sub-fields are strictly smaller than
/// the range (i.e., it's actually a split, not the same field).
fn is_exact_tile(start: u32, end: u32, fields: &[FieldDef]) -> bool {
    let mut subs: Vec<(u32, u32)> = fields
        .iter()
        .filter(|f| {
            let f_start = f.offset_bits;
            let f_end = f_start + f.size_bits;
            f_start >= start && f_end <= end && f.size_bits < (end - start)
        })
        .map(|f| (f.offset_bits, f.offset_bits + f.size_bits))
        .collect();

    if subs.is_empty() {
        return false;
    }

    subs.sort();
    let mut cursor = start;
    for (s, e) in &subs {
        if *s != cursor {
            return false;
        }
        cursor = *e;
    }
    cursor == end
}

/// Check whether `fields` collectively cover [start, end) — fields may overlap
/// or extend beyond the range, but every bit in [start, end) must be covered
/// by at least one field.
fn covers_range(start: u32, end: u32, fields: &[FieldDef]) -> bool {
    // Collect all fields that overlap [start, end)
    let mut overlapping: Vec<(u32, u32)> = fields
        .iter()
        .filter(|f| {
            let f_start = f.offset_bits;
            let f_end = f_start + f.size_bits;
            f_start < end && f_end > start
        })
        .map(|f| {
            let f_start = f.offset_bits.max(start);
            let f_end = (f.offset_bits + f.size_bits).min(end);
            (f_start, f_end)
        })
        .collect();

    if overlapping.is_empty() {
        return false;
    }

    overlapping.sort();
    let mut cursor = start;
    for (s, e) in &overlapping {
        if *s > cursor {
            return false; // gap
        }
        cursor = cursor.max(*e);
    }
    cursor >= end
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_field(name: &str, offset: u32, size: u32, ft: FieldType) -> FieldDef {
        FieldDef::new(name, offset, size, ft)
    }

    fn make_proto(name: &str, fields: Vec<FieldDef>) -> ProtocolDef {
        let total = fields.last().map(|f| f.offset_bits + f.size_bits).unwrap_or(0);
        ProtocolDef::new(name, total).with_fields(fields)
    }

    #[test]
    fn test_exact_match() {
        let a = make_proto(
            "test",
            vec![
                make_field("version", 0, 4, FieldType::Uint),
                make_field("ihl", 4, 4, FieldType::Uint),
            ],
        );
        let b = make_proto(
            "test",
            vec![
                make_field("version", 0, 4, FieldType::Uint),
                make_field("ihl", 4, 4, FieldType::Uint),
            ],
        );

        let comps = compare_fields("kernel", &a, "scapy", &b);
        assert_eq!(comps.len(), 2);
        assert!(comps[0].mismatches.is_empty());
        assert!(comps[1].mismatches.is_empty());
        assert!(comps[0].sources_agree.contains(&"kernel".to_string()));
        assert!(comps[0].sources_agree.contains(&"scapy".to_string()));
        // Structural should also include both
        assert!(comps[0].sources_structural.contains(&"kernel".to_string()));
        assert!(comps[0].sources_structural.contains(&"scapy".to_string()));
    }

    #[test]
    fn test_type_mismatch() {
        let a = make_proto(
            "test",
            vec![make_field("proto", 72, 8, FieldType::Enum)],
        );
        let b = make_proto(
            "test",
            vec![make_field("proto", 72, 8, FieldType::Uint)],
        );

        let comps = compare_fields("kernel", &a, "scapy", &b);
        assert_eq!(comps.len(), 1);
        assert_eq!(comps[0].mismatches.len(), 1);
        assert_eq!(comps[0].mismatches[0].field, "field_type");
        // Structural should still include both (offset+size match)
        assert_eq!(comps[0].sources_structural.len(), 2);
        // Semantic agree should only include reference
        assert_eq!(comps[0].sources_agree, vec!["kernel".to_string()]);
    }

    #[test]
    fn test_type_mismatch_structural_agree() {
        // Same offset+size, different types → sources_structural includes both,
        // sources_agree only includes reference
        let a = make_proto(
            "test",
            vec![make_field("sport", 0, 16, FieldType::Uint)],
        );
        let b = make_proto(
            "test",
            vec![make_field("sport", 0, 16, FieldType::Enum)],
        );

        let comps = compare_fields("kernel", &a, "scapy", &b);
        assert_eq!(comps.len(), 1);
        assert_eq!(
            comps[0].sources_structural,
            vec!["kernel".to_string(), "scapy".to_string()]
        );
        assert_eq!(comps[0].sources_agree, vec!["kernel".to_string()]);
        assert_eq!(comps[0].mismatches.len(), 1);
        assert_eq!(comps[0].mismatches[0].field, "field_type");
    }

    #[test]
    fn test_missing_field() {
        let a = make_proto(
            "test",
            vec![
                make_field("version", 0, 4, FieldType::Uint),
                make_field("extra", 160, 8, FieldType::Uint),
            ],
        );
        let b = make_proto(
            "test",
            vec![make_field("version", 0, 4, FieldType::Uint)],
        );

        let comps = compare_fields("kernel", &a, "scapy", &b);
        assert_eq!(comps.len(), 2);
        // "extra" should have a presence mismatch
        let extra = comps.iter().find(|c| c.name == "extra").unwrap();
        assert_eq!(extra.mismatches[0].field, "presence");
        // Structural should only include kernel for the missing field
        assert_eq!(extra.sources_structural, vec!["kernel".to_string()]);
    }

    #[test]
    fn test_overlap_detection() {
        // Kernel has frag_off as 16 bits, scapy splits into flags(3) + frag(13)
        let a = make_proto(
            "test",
            vec![make_field("frag_off", 48, 16, FieldType::Uint)],
        );
        let b = make_proto(
            "test",
            vec![
                make_field("flags", 48, 3, FieldType::Flags),
                make_field("frag", 51, 13, FieldType::Uint),
            ],
        );

        let comps = compare_fields("kernel", &a, "scapy", &b);
        // Should detect overlap
        let frag = comps.iter().find(|c| c.name == "frag_off").unwrap();
        assert!(!frag.mismatches.is_empty());
        assert_eq!(frag.mismatches[0].field, "split");
    }

    #[test]
    fn test_audit_protocol() {
        let a = make_proto(
            "IPv4",
            vec![
                make_field("version", 0, 4, FieldType::Uint),
                make_field("ihl", 4, 4, FieldType::Uint),
            ],
        );
        let b = make_proto(
            "IPv4",
            vec![
                make_field("version", 0, 4, FieldType::Uint),
                make_field("ihl", 4, 4, FieldType::Uint),
            ],
        );

        let result = audit_protocol("IPv4", &[("kernel", &a), ("scapy", &b)]);
        assert_eq!(result.protocol, "IPv4");
        assert_eq!(result.sources_present.len(), 2);
        assert_eq!(result.fields_agree, 2);
        assert_eq!(result.fields_type_differ, 0);
        assert_eq!(result.fields_mismatch, 0);
    }

    #[test]
    fn test_audit_type_differ_counted() {
        let a = make_proto(
            "UDP",
            vec![
                make_field("sport", 0, 16, FieldType::Uint),
                make_field("dport", 16, 16, FieldType::Uint),
            ],
        );
        let b = make_proto(
            "UDP",
            vec![
                make_field("sport", 0, 16, FieldType::Enum),
                make_field("dport", 16, 16, FieldType::Uint),
            ],
        );

        let result = audit_protocol("UDP", &[("kernel", &a), ("scapy", &b)]);
        assert_eq!(result.fields_agree, 1); // dport fully agrees
        assert_eq!(result.fields_type_differ, 1); // sport structurally matches but type differs
        assert_eq!(result.fields_mismatch, 0);
    }

    #[test]
    fn test_audit_three_sources_no_bias() {
        // A has {f1, f2}, B has {f1, f3}, C has {f2, f3}
        // f3 should show B+C agreeing, not two separate "missing from A" entries
        let a = make_proto(
            "test",
            vec![
                make_field("f1", 0, 8, FieldType::Uint),
                make_field("f2", 8, 8, FieldType::Uint),
            ],
        );
        let b = make_proto(
            "test",
            vec![
                make_field("f1", 0, 8, FieldType::Uint),
                make_field("f3", 16, 8, FieldType::Uint),
            ],
        );
        let c = make_proto(
            "test",
            vec![
                make_field("f2", 8, 8, FieldType::Uint),
                make_field("f3", 16, 8, FieldType::Uint),
            ],
        );

        let result = audit_protocol("test", &[("A", &a), ("B", &b), ("C", &c)]);

        // f1: A+B have it, C missing → presence mismatch
        let f1 = result
            .field_comparisons
            .iter()
            .find(|c| c.name == "f1")
            .unwrap();
        assert!(f1.sources_structural.contains(&"A".to_string()));
        assert!(f1.sources_structural.contains(&"B".to_string()));

        // f2: A+C have it, B missing
        let f2 = result
            .field_comparisons
            .iter()
            .find(|c| c.name == "f2")
            .unwrap();
        assert!(f2.sources_structural.contains(&"A".to_string()));
        assert!(f2.sources_structural.contains(&"C".to_string()));

        // f3: B+C have it, A missing — B and C should agree with each other
        let f3 = result
            .field_comparisons
            .iter()
            .find(|c| c.name == "f3")
            .unwrap();
        assert!(f3.sources_structural.contains(&"B".to_string()));
        assert!(f3.sources_structural.contains(&"C".to_string()));
        // f3 should be a single entry, not duplicated
        let f3_count = result
            .field_comparisons
            .iter()
            .filter(|c| c.offset_bits == 16 && c.size_bits == 8)
            .count();
        assert_eq!(f3_count, 1, "f3 should appear exactly once in comparisons");
    }

    /// Cross-source test: kernel iphdr + scapy IP should agree on
    /// field types after TOML mapping (protocol→Enum, saddr→Ipv4Addr).
    #[test]
    fn test_cross_source_ipv4_kernel_scapy() {
        use crate::extractors::kernel;
        use crate::extractors::scapy;

        // Kernel iphdr
        let iphdr_c = r#"
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4, version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8    version:4, ihl:4;
#endif
    __u8    tos;
    __be16  tot_len;
    __be16  id;
    __be16  frag_off;
    __u8    ttl;
    __u8    protocol;
    __sum16 check;
    __be32  saddr;
    __be32  daddr;
};
"#;
        let ks = kernel::parse_kernel_struct(iphdr_c, "iphdr").unwrap().unwrap();
        let k_fields = kernel::to_field_defs(&ks);
        let k_proto = make_proto("iphdr", k_fields);

        // Scapy IP
        let ip_json = r#"{
  "name": "IP", "module": "scapy.layers.inet", "min_bytes": 20,
  "fields": [
    {"name": "version", "field_class": "BitField", "size_bits": 4},
    {"name": "ihl", "field_class": "BitField", "size_bits": 4},
    {"name": "tos", "field_class": "XByteField", "size_bits": 8},
    {"name": "len", "field_class": "ShortField", "size_bits": 16},
    {"name": "id", "field_class": "ShortField", "size_bits": 16},
    {"name": "flags", "field_class": "FlagsField", "size_bits": 3},
    {"name": "frag", "field_class": "BitField", "size_bits": 13},
    {"name": "ttl", "field_class": "ByteField", "size_bits": 8},
    {"name": "proto", "field_class": "ByteEnumField", "size_bits": 8},
    {"name": "chksum", "field_class": "XShortField", "size_bits": 16},
    {"name": "src", "field_class": "SourceIPField", "size_bits": 32},
    {"name": "dst", "field_class": "DestIPField", "size_bits": 32}
  ]
}"#;
        let sp = scapy::parse_scapy_json(ip_json).unwrap();
        let s_proto = scapy::to_protocol_def(&sp);

        let result = audit_protocol("IPv4", &[("kernel", &k_proto), ("scapy", &s_proto)]);

        // Both protocol fields should be Enum (kernel: protocol override, scapy: ByteEnumField)
        let proto_field = result.field_comparisons.iter()
            .find(|c| c.offset_bits == 72 && c.size_bits == 8)
            .expect("protocol/proto field at offset 72");
        assert!(proto_field.mismatches.iter().all(|m| m.field != "field_type"),
            "protocol field should agree on type (both Enum)");

        // Both src addresses should be Ipv4Addr
        let src_field = result.field_comparisons.iter()
            .find(|c| c.offset_bits == 96 && c.size_bits == 32)
            .expect("saddr/src field at offset 96");
        assert!(src_field.mismatches.iter().all(|m| m.field != "field_type"),
            "source address should agree on type (both Ipv4Addr)");

        // Scapy splits frag_off into flags(3)+frag(13), so we expect a split there
        // but version, ihl, tos, tot_len/len, id, ttl should all agree structurally
        assert!(result.fields_agree >= 5,
            "at least version, ihl, tos, ttl, id should fully agree, got {} agree",
            result.fields_agree);
    }

    /// Cross-source test: kernel ethhdr + scapy Ether should agree
    /// on h_proto→Enum and MAC address types.
    #[test]
    fn test_cross_source_ethernet_kernel_scapy() {
        use crate::extractors::kernel;
        use crate::extractors::scapy;

        let ethhdr_c = r#"
struct ethhdr {
    unsigned char   h_dest[ETH_ALEN];
    unsigned char   h_source[ETH_ALEN];
    __be16          h_proto;
} __attribute__((packed));
"#;
        let ks = kernel::parse_kernel_struct(ethhdr_c, "ethhdr").unwrap().unwrap();
        let k_fields = kernel::to_field_defs(&ks);
        let k_proto = make_proto("ethhdr", k_fields);

        let ether_json = r#"{
  "name": "Ether", "module": "scapy.layers.l2", "min_bytes": 14,
  "fields": [
    {"name": "dst", "field_class": "DestMACField", "size_bits": 48},
    {"name": "src", "field_class": "SourceMACField", "size_bits": 48},
    {"name": "type", "field_class": "XShortEnumField", "size_bits": 16}
  ]
}"#;
        let sp = scapy::parse_scapy_json(ether_json).unwrap();
        let s_proto = scapy::to_protocol_def(&sp);

        let result = audit_protocol("Ethernet", &[("kernel", &k_proto), ("scapy", &s_proto)]);

        // All 3 fields should structurally match (same offsets + sizes)
        assert_eq!(result.total_fields, 3);
        for comp in &result.field_comparisons {
            assert_eq!(comp.sources_structural.len(), 2,
                "field '{}' should be structurally present in both sources", comp.name);
        }

        // MAC fields: both should be MacAddr
        let dst_field = result.field_comparisons.iter()
            .find(|c| c.offset_bits == 0 && c.size_bits == 48)
            .unwrap();
        assert!(dst_field.mismatches.iter().all(|m| m.field != "field_type"),
            "dst MAC should agree on type (both MacAddr)");

        // h_proto: kernel=Enum (override), scapy=Enum (XShortEnumField→Enum)
        let h_proto = result.field_comparisons.iter()
            .find(|c| c.offset_bits == 96 && c.size_bits == 16)
            .unwrap();
        assert_eq!(h_proto.sources_structural.len(), 2);
        assert!(h_proto.mismatches.iter().all(|m| m.field != "field_type"),
            "h_proto/type should agree on type (both Enum)");
    }

    /// Cross-source test: kernel udphdr + scapy UDP should agree
    /// after ShortEnumField→Uint fix.
    #[test]
    fn test_cross_source_udp_kernel_scapy() {
        use crate::extractors::kernel;
        use crate::extractors::scapy;

        let udphdr_c = r#"
struct udphdr {
    __be16  source;
    __be16  dest;
    __be16  len;
    __sum16 check;
};
"#;
        let ks = kernel::parse_kernel_struct(udphdr_c, "udphdr").unwrap().unwrap();
        let k_fields = kernel::to_field_defs(&ks);
        let k_proto = make_proto("udphdr", k_fields);

        let udp_json = r#"{
  "name": "UDP", "module": "scapy.layers.inet", "min_bytes": 8,
  "fields": [
    {"name": "sport", "field_class": "ShortEnumField", "size_bits": 16},
    {"name": "dport", "field_class": "ShortEnumField", "size_bits": 16},
    {"name": "len", "field_class": "ShortField", "size_bits": 16},
    {"name": "chksum", "field_class": "XShortField", "size_bits": 16}
  ]
}"#;
        let sp = scapy::parse_scapy_json(udp_json).unwrap();
        let s_proto = scapy::to_protocol_def(&sp);

        let result = audit_protocol("UDP", &[("kernel", &k_proto), ("scapy", &s_proto)]);

        // All 4 fields should structurally match
        assert_eq!(result.total_fields, 4);
        // All 4 should be Uint (kernel: __be16→Uint, scapy: ShortEnumField→Uint)
        assert_eq!(result.fields_agree, 4,
            "all 4 UDP fields should fully agree (ShortEnumField→Uint fix), got {} agree, {} type_differ",
            result.fields_agree, result.fields_type_differ);
        assert_eq!(result.fields_type_differ, 0);
    }

    /// Cross-source test: kernel iphdr + scapy IP + tshark ip (three-way)
    #[test]
    fn test_cross_source_ipv4_three_way() {
        use crate::extractors::{kernel, scapy, tshark};
        use crate::test_data::*;

        let ks = kernel::parse_kernel_struct(KERNEL_IPHDR, "iphdr").unwrap().unwrap();
        let k_proto = make_proto("iphdr", kernel::to_field_defs(&ks));

        let sp = scapy::parse_scapy_json(SCAPY_IP_JSON).unwrap();
        let s_proto = scapy::to_protocol_def(&sp);

        let packets = tshark::parse_pdml(TSHARK_ETH_IP_PDML).unwrap();
        let ip = tshark::extract_protocol_from_pdml(&packets, "ip").unwrap();
        let t_proto = tshark::to_protocol_def(&ip);

        let result = audit_protocol(
            "IPv4",
            &[("kernel", &k_proto), ("scapy", &s_proto), ("tshark", &t_proto)],
        );

        assert_eq!(result.sources_present.len(), 3);

        // protocol/proto field: all 3 should agree on Enum
        let proto_field = result.field_comparisons.iter()
            .find(|c| c.offset_bits == 72 && c.size_bits == 8)
            .expect("protocol field at offset 72");
        assert!(proto_field.mismatches.iter().all(|m| m.field != "field_type"),
            "protocol field should agree on type across all 3 sources");

        // src address: all 3 should agree on Ipv4Addr at offset 96
        let src_field = result.field_comparisons.iter()
            .find(|c| c.offset_bits == 96 && c.size_bits == 32)
            .expect("src field at offset 96");
        assert!(src_field.mismatches.iter().all(|m| m.field != "field_type"),
            "source address should agree on Ipv4Addr across all 3 sources");

        // At least 7 fields should fully agree across all 3 sources
        // (version, ihl, tos, tot_len/len, id, ttl, protocol, check, saddr, daddr
        //  minus frag_off split = plenty of agreement)
        assert!(result.fields_agree >= 7,
            "at least 7 fields should fully agree, got {} agree",
            result.fields_agree);
    }

    /// Cross-source test: kernel ethhdr + scapy Ether + tshark eth (three-way)
    #[test]
    fn test_cross_source_ethernet_three_way() {
        use crate::extractors::{kernel, scapy, tshark};
        use crate::test_data::*;

        let ks = kernel::parse_kernel_struct(KERNEL_ETHHDR, "ethhdr").unwrap().unwrap();
        let k_proto = make_proto("ethhdr", kernel::to_field_defs(&ks));

        let sp = scapy::parse_scapy_json(SCAPY_ETHER_JSON).unwrap();
        let s_proto = scapy::to_protocol_def(&sp);

        let packets = tshark::parse_pdml(TSHARK_ETH_IP_PDML).unwrap();
        let eth = tshark::extract_protocol_from_pdml(&packets, "eth").unwrap();
        let t_proto = tshark::to_protocol_def(&eth);

        let result = audit_protocol(
            "Ethernet",
            &[("kernel", &k_proto), ("scapy", &s_proto), ("tshark", &t_proto)],
        );

        assert_eq!(result.sources_present.len(), 3);
        assert_eq!(result.total_fields, 3);

        // All 3 fields should structurally match across all 3 sources
        for comp in &result.field_comparisons {
            assert_eq!(comp.sources_structural.len(), 3,
                "field '{}' should be structurally present in all 3 sources", comp.name);
        }

        // MAC fields and h_proto should agree on type
        assert!(result.fields_agree >= 3,
            "all 3 Ethernet fields should agree, got {}", result.fields_agree);
    }

    /// Cross-source test: kernel udphdr + scapy UDP + tshark udp (three-way)
    #[test]
    fn test_cross_source_udp_three_way() {
        use crate::extractors::{kernel, scapy, tshark};
        use crate::test_data::*;

        let ks = kernel::parse_kernel_struct(KERNEL_UDPHDR, "udphdr").unwrap().unwrap();
        let k_proto = make_proto("udphdr", kernel::to_field_defs(&ks));

        let sp = scapy::parse_scapy_json(SCAPY_UDP_JSON).unwrap();
        let s_proto = scapy::to_protocol_def(&sp);

        let packets = tshark::parse_pdml(TSHARK_UDP_PDML).unwrap();
        let udp = tshark::extract_protocol_from_pdml(&packets, "udp").unwrap();
        let t_proto = tshark::to_protocol_def(&udp);

        let result = audit_protocol(
            "UDP",
            &[("kernel", &k_proto), ("scapy", &s_proto), ("tshark", &t_proto)],
        );

        assert_eq!(result.sources_present.len(), 3);
        assert_eq!(result.total_fields, 4);
        // All 4 should be Uint across all 3 sources
        assert_eq!(result.fields_agree, 4,
            "all 4 UDP fields should fully agree, got {} agree, {} type_differ",
            result.fields_agree, result.fields_type_differ);
    }

    /// Cross-source test: kernel arphdr + scapy ARP
    #[test]
    fn test_cross_source_arp_kernel_scapy() {
        use crate::extractors::{kernel, scapy};
        use crate::test_data::*;

        let ks = kernel::parse_kernel_struct(KERNEL_ARPHDR, "arphdr").unwrap().unwrap();
        let k_proto = make_proto("arphdr", kernel::to_field_defs(&ks));

        let sp = scapy::parse_scapy_json(SCAPY_ARP_JSON).unwrap();
        let s_proto = scapy::to_protocol_def(&sp);

        let result = audit_protocol("ARP", &[("kernel", &k_proto), ("scapy", &s_proto)]);

        // Kernel has 5 fields (fixed header), scapy has 9 (includes variable part)
        // 5 fields should structurally match at the same offsets
        let matched_fields: Vec<_> = result.field_comparisons.iter()
            .filter(|c| c.sources_structural.len() == 2)
            .collect();
        assert!(matched_fields.len() >= 5,
            "at least 5 fields should structurally match, got {}", matched_fields.len());

        // ar_hrd/hwtype and ar_pro/ptype should agree (both Enum via XShortEnumField)
        // ar_hln/hwlen and ar_pln/plen should agree (both Uint)
        assert!(result.fields_agree >= 4,
            "at least 4 fields should fully agree (ar_hrd, ar_pro, ar_hln, ar_pln), got {}",
            result.fields_agree);
    }

    /// Cross-source test: kernel tcphdr + scapy TCP
    #[test]
    fn test_cross_source_tcp_kernel_scapy() {
        use crate::extractors::{kernel, scapy};
        use crate::test_data::*;

        let ks = kernel::parse_kernel_struct(KERNEL_TCPHDR, "tcphdr").unwrap().unwrap();
        let k_proto = make_proto("tcphdr", kernel::to_field_defs(&ks));

        let sp = scapy::parse_scapy_json(SCAPY_TCP_JSON).unwrap();
        let s_proto = scapy::to_protocol_def(&sp);

        let result = audit_protocol("TCP", &[("kernel", &k_proto), ("scapy", &s_proto)]);

        // Ports: both Uint (kernel __be16, scapy ShortEnumField→Uint)
        let sport = result.field_comparisons.iter()
            .find(|c| c.offset_bits == 0 && c.size_bits == 16)
            .expect("sport at offset 0");
        assert!(sport.mismatches.iter().all(|m| m.field != "field_type"),
            "sport should agree on type (both Uint)");

        // seq + ack: both Uint
        let seq = result.field_comparisons.iter()
            .find(|c| c.offset_bits == 32 && c.size_bits == 32)
            .expect("seq at offset 32");
        assert!(seq.mismatches.is_empty(), "seq should fully agree");

        // At least 7 fields should agree (sport, dport, seq, ack, dataofs, window, check, urg_ptr)
        // minus any bitfield splitting differences
        assert!(result.fields_agree >= 7,
            "at least 7 TCP fields should agree, got {}", result.fields_agree);
    }

    #[test]
    fn test_audit_skip_zero_field_source() {
        // XDP2-like source: present but has 0 fields (references kernel struct)
        let xdp2 = make_proto("IPv4", vec![]);
        let kernel = make_proto(
            "IPv4",
            vec![
                make_field("version", 0, 4, FieldType::Uint),
                make_field("ihl", 4, 4, FieldType::Uint),
            ],
        );
        let scapy = make_proto(
            "IPv4",
            vec![
                make_field("version", 0, 4, FieldType::Uint),
                make_field("ihl", 4, 4, FieldType::Uint),
            ],
        );

        let result = audit_protocol(
            "IPv4",
            &[("xdp2", &xdp2), ("kernel", &kernel), ("scapy", &scapy)],
        );

        // XDP2 should still be listed as present
        assert!(result.sources_present.contains(&"xdp2".to_string()));

        // But zero-field source should NOT cause presence:missing on every field
        assert_eq!(result.fields_agree, 2, "both fields should fully agree");
        assert_eq!(result.fields_missing, 0, "no fields should be missing");

        // Verify no comparison references xdp2 as a missing source
        for comp in &result.field_comparisons {
            for m in &comp.mismatches {
                assert_ne!(
                    m.source, "xdp2",
                    "xdp2 (zero-field) should not appear in mismatches"
                );
            }
        }
    }

    /// Cross-source test: kernel ethhdr + scapy Ether + tshark eth + etherparse Ethernet2Header (four-way)
    #[test]
    fn test_cross_source_ethernet_four_way() {
        use crate::extractors::{etherparse, kernel, scapy, tshark};
        use crate::test_data::*;

        let ks = kernel::parse_kernel_struct(KERNEL_ETHHDR, "ethhdr").unwrap().unwrap();
        let k_proto = make_proto("ethhdr", kernel::to_field_defs(&ks));

        let sp = scapy::parse_scapy_json(SCAPY_ETHER_JSON).unwrap();
        let s_proto = scapy::to_protocol_def(&sp);

        let packets = tshark::parse_pdml(TSHARK_ETH_IP_PDML).unwrap();
        let eth = tshark::extract_protocol_from_pdml(&packets, "eth").unwrap();
        let t_proto = tshark::to_protocol_def(&eth);

        let e_proto = etherparse::extract_protocol(
            ETHERPARSE_ETHERNET2_HEADER, "Ethernet2Header", "test",
        )
        .unwrap()
        .unwrap();

        let result = audit_protocol(
            "Ethernet",
            &[
                ("kernel", &k_proto),
                ("scapy", &s_proto),
                ("tshark", &t_proto),
                ("etherparse", &e_proto),
            ],
        );

        assert_eq!(result.sources_present.len(), 4);
        assert_eq!(result.total_fields, 3);

        // All 3 fields should structurally match across all 4 sources
        for comp in &result.field_comparisons {
            assert_eq!(
                comp.sources_structural.len(),
                4,
                "field '{}' should be structurally present in all 4 sources",
                comp.name
            );
        }

        // MAC fields and ether_type should agree on type
        assert!(
            result.fields_agree >= 3,
            "all 3 Ethernet fields should agree, got {}",
            result.fields_agree
        );
    }

    /// Cross-source test: kernel ipv6_opt_hdr + scapy IPv6ExtHdrHopByHop
    #[test]
    fn test_cross_source_ipv6_eh_kernel_scapy() {
        use crate::extractors::{kernel, scapy};

        let ipv6_opt_hdr_c = r#"
struct ipv6_opt_hdr {
    __u8    nexthdr;
    __u8    hdrlen;
};
"#;
        let ks = kernel::parse_kernel_struct(ipv6_opt_hdr_c, "ipv6_opt_hdr")
            .unwrap()
            .unwrap();
        let k_proto = make_proto("ipv6_opt_hdr", kernel::to_field_defs(&ks));

        let hop_json = r#"{
  "name": "IPv6ExtHdrHopByHop", "module": "scapy.layers.inet6", "min_bytes": 2,
  "fields": [
    {"name": "nh", "field_class": "ByteEnumField", "size_bits": 8},
    {"name": "len", "field_class": "ByteField", "size_bits": 8}
  ]
}"#;
        let sp = scapy::parse_scapy_json(hop_json).unwrap();
        let s_proto = scapy::to_protocol_def(&sp);

        let result = audit_protocol("IPv6_EH", &[("kernel", &k_proto), ("scapy", &s_proto)]);

        assert_eq!(result.sources_present.len(), 2);
        assert_eq!(result.total_fields, 2);
        // Both fields should structurally match
        for comp in &result.field_comparisons {
            assert_eq!(
                comp.sources_structural.len(),
                2,
                "field '{}' should be structurally present in both sources",
                comp.name
            );
        }
        // nexthdr/nh: kernel override → Enum, scapy ByteEnumField → Enum
        let nh = result
            .field_comparisons
            .iter()
            .find(|c| c.offset_bits == 0 && c.size_bits == 8)
            .expect("nexthdr/nh field at offset 0");
        assert!(
            nh.mismatches.iter().all(|m| m.field != "field_type"),
            "nexthdr/nh should agree on type (both Enum)"
        );
    }

    /// Cross-source test: kernel ieee802154_hdr_fc + scapy Dot15d4
    #[test]
    fn test_cross_source_ieee802154_kernel_scapy() {
        use crate::extractors::{kernel, scapy};

        // IEEE 802.15.4 frame control is a 16-bit bitfield in the kernel
        let ieee802154_c = r#"
struct ieee802154_hdr_fc {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16   type:3,
            security:1,
            pending:1,
            ack_request:1,
            intra_pan:1,
            reserved:3,
            dest_addr_mode:2,
            version:2,
            source_addr_mode:2;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16   reserved:1,
            intra_pan:1,
            ack_request:1,
            pending:1,
            security:1,
            type:3,
            source_addr_mode:2,
            version:2,
            dest_addr_mode:2,
            reserved2:3;
#endif
};
"#;
        let ks = kernel::parse_kernel_struct(ieee802154_c, "ieee802154_hdr_fc")
            .unwrap()
            .unwrap();
        let k_fields = kernel::to_field_defs(&ks);
        let k_proto = make_proto("ieee802154_hdr_fc", k_fields);

        // Scapy Dot15d4 minimal representation (frame control fields)
        let dot15d4_json = r#"{
  "name": "Dot15d4", "module": "scapy.contrib.dot15d4", "min_bytes": 3,
  "fields": [
    {"name": "fcf_frametype", "field_class": "BitField", "size_bits": 3},
    {"name": "fcf_security", "field_class": "BitField", "size_bits": 1},
    {"name": "fcf_pending", "field_class": "BitField", "size_bits": 1},
    {"name": "fcf_ackreq", "field_class": "BitField", "size_bits": 1},
    {"name": "fcf_intrapan", "field_class": "BitField", "size_bits": 1},
    {"name": "fcf_reserved", "field_class": "BitField", "size_bits": 3},
    {"name": "fcf_destaddrmode", "field_class": "BitField", "size_bits": 2},
    {"name": "fcf_framever", "field_class": "BitField", "size_bits": 2},
    {"name": "fcf_srcaddrmode", "field_class": "BitField", "size_bits": 2},
    {"name": "seqnum", "field_class": "ByteField", "size_bits": 8}
  ]
}"#;
        let sp = scapy::parse_scapy_json(dot15d4_json).unwrap();
        let s_proto = scapy::to_protocol_def(&sp);

        let result =
            audit_protocol("IEEE802154", &[("kernel", &k_proto), ("scapy", &s_proto)]);

        assert_eq!(result.sources_present.len(), 2);

        // Both sources should have sub-byte bitfields that match at the same offsets
        // At minimum type(3), security(1), pending(1), ack_request(1), intra_pan(1) should match
        let matched: Vec<_> = result
            .field_comparisons
            .iter()
            .filter(|c| c.sources_structural.len() == 2)
            .collect();
        assert!(
            matched.len() >= 4,
            "at least 4 bitfields should structurally match, got {}",
            matched.len()
        );
    }

    /// Cross-source test: kernel udphdr + scapy UDP + tshark udp + etherparse UdpHeader (four-way)
    #[test]
    fn test_cross_source_udp_four_way() {
        use crate::extractors::{etherparse, kernel, scapy, tshark};
        use crate::test_data::*;

        let ks = kernel::parse_kernel_struct(KERNEL_UDPHDR, "udphdr").unwrap().unwrap();
        let k_proto = make_proto("udphdr", kernel::to_field_defs(&ks));

        let sp = scapy::parse_scapy_json(SCAPY_UDP_JSON).unwrap();
        let s_proto = scapy::to_protocol_def(&sp);

        let packets = tshark::parse_pdml(TSHARK_UDP_PDML).unwrap();
        let udp = tshark::extract_protocol_from_pdml(&packets, "udp").unwrap();
        let t_proto = tshark::to_protocol_def(&udp);

        let e_proto = etherparse::extract_protocol(
            ETHERPARSE_UDP_HEADER, "UdpHeader", "test",
        )
        .unwrap()
        .unwrap();

        let result = audit_protocol(
            "UDP",
            &[
                ("kernel", &k_proto),
                ("scapy", &s_proto),
                ("tshark", &t_proto),
                ("etherparse", &e_proto),
            ],
        );

        assert_eq!(result.sources_present.len(), 4);
        assert_eq!(result.total_fields, 4);
        // All 4 should be Uint across all 4 sources
        assert_eq!(
            result.fields_agree, 4,
            "all 4 UDP fields should fully agree, got {} agree, {} type_differ",
            result.fields_agree, result.fields_type_differ
        );
    }

    #[test]
    fn test_validation_tier_silver_two_sources() {
        use crate::discovery::ValidationTier;
        let a = make_proto("test", vec![make_field("f", 0, 8, FieldType::Uint)]);
        let b = make_proto("test", vec![make_field("f", 0, 8, FieldType::Uint)]);
        let result = audit_protocol("test", &[("kernel", &a), ("scapy", &b)]);
        assert_eq!(result.validation_tier, Some(ValidationTier::Silver));
    }

    #[test]
    fn test_validation_tier_bronze_single_source() {
        use crate::discovery::ValidationTier;
        let a = make_proto("test", vec![make_field("f", 0, 8, FieldType::Uint)]);
        let result = audit_protocol("test", &[("kernel", &a)]);
        assert_eq!(result.validation_tier, Some(ValidationTier::Bronze));
    }

    #[test]
    fn test_validation_tier_unvalidated_no_fields() {
        use crate::discovery::ValidationTier;
        let a = make_proto("test", vec![]);
        let result = audit_protocol("test", &[("kernel", &a)]);
        assert_eq!(result.validation_tier, Some(ValidationTier::Unvalidated));
    }

    #[test]
    fn test_is_exact_tile_basic() {
        // version(4b) + ihl(4b) exactly tile [0, 8)
        let fields = vec![
            make_field("version", 0, 4, FieldType::Uint),
            make_field("ihl", 4, 4, FieldType::Uint),
        ];
        assert!(is_exact_tile(0, 8, &fields));
    }

    #[test]
    fn test_is_exact_tile_gap() {
        // version(4b) at offset 0 does NOT tile [0, 8) — gap at [4, 8)
        let fields = vec![make_field("version", 0, 4, FieldType::Uint)];
        assert!(!is_exact_tile(0, 8, &fields));
    }

    #[test]
    fn test_is_exact_tile_no_subfields() {
        // No sub-fields in range
        let fields = vec![make_field("other", 16, 8, FieldType::Uint)];
        assert!(!is_exact_tile(0, 8, &fields));
    }

    #[test]
    fn test_is_exact_tile_three_subfields() {
        // flags(3b) + frag(13b) do NOT tile [48, 64) exactly because
        // they ARE exactly the range — but let's test 3+5+8=16
        let fields = vec![
            make_field("a", 0, 3, FieldType::Flags),
            make_field("b", 3, 5, FieldType::Uint),
            make_field("c", 8, 8, FieldType::Uint),
        ];
        assert!(is_exact_tile(0, 16, &fields));
    }

    #[test]
    fn test_covered_splits_ipv4_like() {
        // Simulate IPv4 round-trip: IR has version(4b)+ihl(4b),
        // tshark merges into ver_ihl(8b)
        let ir = make_proto(
            "IPv4",
            vec![
                make_field("version", 0, 4, FieldType::Uint),
                make_field("ihl", 4, 4, FieldType::Uint),
                make_field("tos", 8, 8, FieldType::Uint),
            ],
        );
        let tshark = make_proto(
            "IPv4",
            vec![
                make_field("ver_ihl", 0, 8, FieldType::Uint),
                make_field("tos", 8, 8, FieldType::Uint),
            ],
        );

        let refs: Vec<(&str, &ProtocolDef)> = vec![("ir", &ir), ("tshark", &tshark)];
        let result = audit_protocol("IPv4", &refs);

        // Should have split mismatches for the sub-byte fields
        assert!(result.fields_mismatch > 0);

        // But covered splits should account for all of them
        let covered = count_covered_splits(&result, &ir, &tshark);
        assert!(covered > 0);
        assert_eq!(
            result.fields_mismatch - covered,
            0,
            "all split mismatches should be covered"
        );
    }

    #[test]
    fn test_compare_field_values() {
        let mut a = BTreeMap::new();
        a.insert("version".to_string(), "4".to_string());
        a.insert("ttl".to_string(), "64".to_string());
        a.insert("protocol".to_string(), "0x06".to_string());
        a.insert("src_only".to_string(), "x".to_string());

        let mut b = BTreeMap::new();
        b.insert("version".to_string(), "4".to_string());
        b.insert("ttl".to_string(), "128".to_string());
        b.insert("protocol".to_string(), "6".to_string()); // 0x06 == 6
        b.insert("dst_only".to_string(), "y".to_string());

        let results = compare_field_values(&a, &b);
        assert_eq!(results.len(), 5); // version, ttl, protocol, src_only, dst_only

        let version = results.iter().find(|r| r.field_name == "version").unwrap();
        assert!(version.agree);

        let ttl = results.iter().find(|r| r.field_name == "ttl").unwrap();
        assert!(!ttl.agree);

        // 0x06 and 6 should agree after normalization
        let proto = results.iter().find(|r| r.field_name == "protocol").unwrap();
        assert!(proto.agree);

        // Fields present in only one source should not agree
        let src_only = results.iter().find(|r| r.field_name == "src_only").unwrap();
        assert!(!src_only.agree);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Value-level comparison (Phase 4: corpus cross-source parsing)
// ═══════════════════════════════════════════════════════════════════════════

/// A parsed field value from a single source.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FieldValue {
    pub name: String,
    pub value: String,
}

/// Result of comparing field values from two sources on the same packet layer.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ValueComparison {
    pub field_name: String,
    pub source_a_value: Option<String>,
    pub source_b_value: Option<String>,
    pub agree: bool,
}

/// Compare field values from two sources for the same protocol layer.
///
/// `fields_a` and `fields_b` are field name → value maps from two different
/// dissectors (e.g., tshark and Scapy) on the same packet.
pub fn compare_field_values(
    fields_a: &BTreeMap<String, String>,
    fields_b: &BTreeMap<String, String>,
) -> Vec<ValueComparison> {
    let all_keys: HashSet<&String> = fields_a.keys().chain(fields_b.keys()).collect();
    let mut results = Vec::new();
    for key in all_keys {
        let va = fields_a.get(key);
        let vb = fields_b.get(key);
        let agree = match (va, vb) {
            (Some(a), Some(b)) => normalize_value(a) == normalize_value(b),
            _ => false,
        };
        results.push(ValueComparison {
            field_name: key.to_string(),
            source_a_value: va.cloned(),
            source_b_value: vb.cloned(),
            agree,
        });
    }
    results.sort_by(|a, b| a.field_name.cmp(&b.field_name));
    results
}

/// Normalize a field value for comparison (strip whitespace, lowercase hex).
fn normalize_value(v: &str) -> String {
    let v = v.trim();
    // Try to normalize hex representations (0x prefix, leading zeros)
    if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        if let Ok(n) = u64::from_str_radix(hex, 16) {
            return format!("{}", n);
        }
    }
    // Try to parse as integer for consistent representation
    if let Ok(n) = v.parse::<u64>() {
        return format!("{}", n);
    }
    v.to_lowercase()
}

// ═══════════════════════════════════════════════════════════════════════════
// PCAP-level comparison (Phase 5: end-to-end pipeline verification)
// ═══════════════════════════════════════════════════════════════════════════

use crate::extractors::tshark::{PdmlField, PdmlProtocol};

/// A single field-level difference between two PCAPs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PcapFieldDiff {
    /// tshark field name (e.g., "ip.version")
    pub field_name: String,
    /// Raw hex value from the input PCAP
    pub input_hex: String,
    /// Raw hex value from the output PCAP
    pub output_hex: String,
    /// Byte position in packet
    pub pos: u32,
    /// Size in bytes
    pub size: u32,
}

/// Result of comparing two PCAPs for a given protocol layer.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PcapCompareResult {
    /// Protocol being compared
    pub protocol: String,
    /// Total fields compared
    pub fields_total: usize,
    /// Fields with matching hex values
    pub fields_match: usize,
    /// Fields with differing hex values
    pub fields_differ: Vec<PcapFieldDiff>,
    /// True if all fields match (fields_match == fields_total)
    pub pass: bool,
}

/// Result of the full pipeline with both PCAP and IR diagnostics.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PipelineDiagnostics {
    /// PCAP-level comparison (the acid test)
    pub pcap_result: PcapCompareResult,
    /// IR comparison: baseline vs after crossgen (did the generator lose fields?)
    pub ir_stage1: Option<AuditResult>,
    /// IR comparison: after crossgen vs from output PCAP (did serialization lose fields?)
    pub ir_stage2: Option<AuditResult>,
    /// IR comparison: baseline vs from output PCAP (end-to-end drift)
    pub ir_stage3: Option<AuditResult>,
}

/// Compare two PDML protocol layers field-by-field using raw hex values.
///
/// This is the PCAP-level acid test: if every field's raw hex value matches
/// between the input and output PCAPs, the pipeline preserved wire bytes.
pub fn compare_pdml_protocols(
    input: &PdmlProtocol,
    output: &PdmlProtocol,
    protocol: &str,
) -> PcapCompareResult {
    // Build a map of (pos, size) → PdmlField for the output PCAP
    let output_map: BTreeMap<(u32, u32), &PdmlField> = output
        .fields
        .iter()
        .filter(|f| f.size > 0 && !f.value.is_empty())
        .map(|f| ((f.pos, f.size), f))
        .collect();

    let mut fields_match = 0usize;
    let mut fields_differ = Vec::new();
    let mut fields_total = 0usize;

    for input_field in &input.fields {
        if input_field.size == 0 || input_field.value.is_empty() {
            continue; // Skip metadata fields
        }
        fields_total += 1;

        if let Some(output_field) = output_map.get(&(input_field.pos, input_field.size)) {
            let in_hex = normalize_hex(&input_field.value);
            let out_hex = normalize_hex(&output_field.value);
            if in_hex == out_hex {
                fields_match += 1;
            } else {
                fields_differ.push(PcapFieldDiff {
                    field_name: input_field.name.clone(),
                    input_hex: input_field.value.clone(),
                    output_hex: output_field.value.clone(),
                    pos: input_field.pos,
                    size: input_field.size,
                });
            }
        } else {
            // Field exists in input but not output — count as mismatch
            fields_differ.push(PcapFieldDiff {
                field_name: input_field.name.clone(),
                input_hex: input_field.value.clone(),
                output_hex: String::new(),
                pos: input_field.pos,
                size: input_field.size,
            });
        }
    }

    PcapCompareResult {
        protocol: protocol.to_string(),
        fields_total,
        fields_match,
        pass: fields_differ.is_empty() && fields_total > 0,
        fields_differ,
    }
}

/// Build full pipeline diagnostics: PCAP comparison + IR-level diagnostics
/// at each stage when the PCAP comparison fails.
pub fn pipeline_diagnostics(
    pcap_result: PcapCompareResult,
    ir_baseline: &ProtocolDef,
    ir_after_crossgen: Option<&ProtocolDef>,
    ir_from_output_pcap: Option<&ProtocolDef>,
) -> PipelineDiagnostics {
    // Only compute IR diagnostics if the PCAP comparison failed
    let (ir_stage1, ir_stage2, ir_stage3) = if !pcap_result.pass {
        let stage1 = ir_after_crossgen.map(|cg| {
            audit_protocol("crossgen-check", &[("baseline", ir_baseline), ("after-crossgen", cg)])
        });
        let stage2 = match (ir_after_crossgen, ir_from_output_pcap) {
            (Some(cg), Some(out)) => Some(audit_protocol(
                "serialization-check",
                &[("after-crossgen", cg), ("from-output-pcap", out)],
            )),
            _ => None,
        };
        let stage3 = ir_from_output_pcap.map(|out| {
            audit_protocol("e2e-check", &[("baseline", ir_baseline), ("from-output-pcap", out)])
        });
        (stage1, stage2, stage3)
    } else {
        (None, None, None)
    };

    PipelineDiagnostics {
        pcap_result,
        ir_stage1,
        ir_stage2,
        ir_stage3,
    }
}

/// Normalize hex strings for comparison: lowercase, strip whitespace, strip colons.
fn normalize_hex(hex: &str) -> String {
    hex.trim()
        .to_lowercase()
        .replace(':', "")
        .replace(' ', "")
}