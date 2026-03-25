//! Cross-source field matching and comparison engine.
//!
//! Compares protocol definitions from different sources by matching
//! fields based on bit offset + size, then checking for mismatches
//! in type, endianness, and naming.

use std::collections::BTreeMap;

use crate::ir::*;

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

            let mut sources_agree = vec![source_a.to_string()];
            if mismatches.is_empty() {
                sources_agree.push(source_b.to_string());
            }

            comparisons.push(FieldComparison {
                name: field_a.name.clone(),
                offset_bits: field_a.offset_bits,
                size_bits: field_a.size_bits,
                sources_agree,
                mismatches,
            });
        } else {
            // Field in A but not B — try overlap matching
            let overlaps: Vec<_> = proto_b
                .fields
                .iter()
                .filter(|fb| {
                    let a_start = field_a.offset_bits;
                    let a_end = a_start + field_a.size_bits;
                    let b_start = fb.offset_bits;
                    let b_end = b_start + fb.size_bits;
                    a_start < b_end && b_start < a_end
                })
                .collect();

            if overlaps.is_empty() {
                // Only in source A
                comparisons.push(FieldComparison {
                    name: field_a.name.clone(),
                    offset_bits: field_a.offset_bits,
                    size_bits: field_a.size_bits,
                    sources_agree: vec![source_a.to_string()],
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
pub fn audit_protocol(canonical_name: &str, sources: &[(&str, &ProtocolDef)]) -> AuditResult {
    let all_source_names: Vec<&str> = vec!["xdp2", "kernel", "scapy", "tshark"];
    let present: Vec<String> = sources.iter().map(|(name, _)| name.to_string()).collect();
    let missing: Vec<String> = all_source_names
        .iter()
        .filter(|s| !present.contains(&s.to_string()))
        .map(|s| s.to_string())
        .collect();

    let mut all_comparisons = Vec::new();

    // Compare all pairs
    if sources.len() >= 2 {
        // Use first source as reference, compare all others
        let (ref_name, ref_proto) = &sources[0];
        for (other_name, other_proto) in &sources[1..] {
            let comps = compare_fields(ref_name, ref_proto, other_name, other_proto);
            // Merge into all_comparisons
            for comp in comps {
                if let Some(existing) = all_comparisons
                    .iter_mut()
                    .find(|c: &&mut FieldComparison| {
                        c.offset_bits == comp.offset_bits && c.size_bits == comp.size_bits
                    })
                {
                    // Merge sources_agree and mismatches
                    for s in &comp.sources_agree {
                        if !existing.sources_agree.contains(s) {
                            existing.sources_agree.push(s.clone());
                        }
                    }
                    existing.mismatches.extend(comp.mismatches);
                } else {
                    all_comparisons.push(comp);
                }
            }
        }
    } else if sources.len() == 1 {
        // Single source — all fields agree trivially
        let (name, proto) = &sources[0];
        for field in &proto.fields {
            all_comparisons.push(FieldComparison {
                name: field.name.clone(),
                offset_bits: field.offset_bits,
                size_bits: field.size_bits,
                sources_agree: vec![name.to_string()],
                mismatches: vec![],
            });
        }
    }

    all_comparisons.sort_by_key(|c| (c.offset_bits, c.size_bits));

    let total = all_comparisons.len() as u32;
    let agree = all_comparisons
        .iter()
        .filter(|c| c.mismatches.is_empty())
        .count() as u32;
    let mismatch = all_comparisons
        .iter()
        .filter(|c| {
            !c.mismatches.is_empty()
                && !c
                    .mismatches
                    .iter()
                    .any(|m| m.field == "presence")
        })
        .count() as u32;
    let field_missing = total - agree - mismatch;

    AuditResult {
        protocol: canonical_name.to_string(),
        sources_present: present,
        sources_missing: missing,
        field_comparisons: all_comparisons,
        total_fields: total,
        fields_agree: agree,
        fields_mismatch: mismatch,
        fields_missing: field_missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_field(name: &str, offset: u32, size: u32, ft: FieldType) -> FieldDef {
        FieldDef {
            name: name.to_string(),
            offset_bits: offset,
            size_bits: size,
            field_type: ft,
            endian: Endian::Na,
            description: String::new(),
            is_dispatch: false,
            is_length: false,
            length_multiplier: None,
            source_names: BTreeMap::new(),
        }
    }

    fn make_proto(name: &str, fields: Vec<FieldDef>) -> ProtocolDef {
        ProtocolDef {
            name: name.to_string(),
            min_header_bits: fields
                .last()
                .map(|f| f.offset_bits + f.size_bits)
                .unwrap_or(0),
            is_variable_length: false,
            fields,
            dispatch_field: None,
            dispatch_table: vec![],
            identifiers: BTreeMap::new(),
            sources: BTreeMap::new(),
        }
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
        assert_eq!(result.fields_mismatch, 0);
    }
}
