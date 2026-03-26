//! Cross-source field matching and comparison engine.
//!
//! Compares protocol definitions from different sources by matching
//! fields based on bit offset + size, then checking for mismatches
//! in type, endianness, and naming.
//!
//! Distinguishes between:
//! - **Structural agreement**: same offset + size (the layout matches)
//! - **Semantic agreement**: same offset + size + type + endian (full match)

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
        // Build unified field map: (offset, size) → Vec<(source_name, &FieldDef)>
        let mut field_map: BTreeMap<(u32, u32), Vec<(&str, &FieldDef)>> = BTreeMap::new();
        for (src_name, proto) in &field_sources {
            for field in &proto.fields {
                field_map
                    .entry((field.offset_bits, field.size_bits))
                    .or_default()
                    .push((src_name, field));
            }
        }

        for (key, slot_sources) in &field_map {
            let (offset, size) = *key;
            // Pick the first field's name as canonical
            let name = slot_sources[0].1.name.clone();

            // All sources that have a field at exactly this (offset, size)
            let slot_source_names: Vec<String> =
                slot_sources.iter().map(|(s, _)| s.to_string()).collect();

            // Check for overlaps from other sources that don't have this exact slot
            // but have fields that overlap with this bit range
            let mut overlap_mismatches = Vec::new();
            for (src_name, proto) in &field_sources {
                if slot_source_names.contains(&src_name.to_string()) {
                    continue;
                }
                // Check if this source has any field overlapping this range
                let overlaps: Vec<_> = proto
                    .fields
                    .iter()
                    .filter(|f| {
                        let f_start = f.offset_bits;
                        let f_end = f_start + f.size_bits;
                        let s_start = offset;
                        let s_end = offset + size;
                        f_start < s_end && s_start < f_end
                    })
                    .collect();

                if !overlaps.is_empty() {
                    let overlap_names: Vec<_> =
                        overlaps.iter().map(|f| f.name.clone()).collect();
                    overlap_mismatches.push(FieldMismatch {
                        source: src_name.to_string(),
                        field: "split".to_string(),
                        expected: format!("{}[{}:{}]", name, offset, offset + size),
                        actual: format!("overlaps with: {}", overlap_names.join(", ")),
                    });
                }
            }

            // Compare type+endian within the slot (all pairs, not just vs first)
            let mut type_mismatches = Vec::new();
            if slot_sources.len() >= 2 {
                for i in 0..slot_sources.len() {
                    for j in (i + 1)..slot_sources.len() {
                        let (_name_i, field_i) = &slot_sources[i];
                        let (name_j, field_j) = &slot_sources[j];

                        if field_i.field_type != field_j.field_type {
                            // Report mismatch from j's perspective vs i
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

            // Structural: all sources at this slot
            let sources_structural = slot_source_names.clone();

            // Semantic: only sources with no type/endian mismatch
            let mismatched_sources: std::collections::HashSet<&str> = type_mismatches
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
            for (src_name, _proto) in &field_sources {
                if slot_source_names.contains(&src_name.to_string()) {
                    continue;
                }
                // Already handled as overlap above?
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

            all_comparisons.push(FieldComparison {
                name,
                offset_bits: offset,
                size_bits: size,
                sources_agree,
                sources_structural,
                mismatches: all_mismatches,
            });
        }

        // Detect overlapping slots from the same source (field splits)
        // This is already handled above via overlap_mismatches
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

    let total = all_comparisons.len() as u32;

    // fields_agree: all present sources structurally agree (use structural for primary metric)
    let agree = all_comparisons
        .iter()
        .filter(|c| c.mismatches.is_empty())
        .count() as u32;

    // fields_type_differ: structural match but type/endian mismatch
    let type_differ = all_comparisons
        .iter()
        .filter(|c| {
            !c.mismatches.is_empty()
                && c.sources_structural.len() >= 2
                && c.mismatches
                    .iter()
                    .all(|m| m.field == "field_type" || m.field == "endian")
        })
        .count() as u32;

    // fields_mismatch: structural disagreement (split/overlap)
    let mismatch = all_comparisons
        .iter()
        .filter(|c| {
            c.mismatches.iter().any(|m| m.field == "split")
        })
        .count() as u32;

    let field_missing = all_comparisons
        .iter()
        .filter(|c| {
            c.mismatches.iter().any(|m| m.field == "presence")
                && !c.mismatches.iter().any(|m| m.field == "split")
        })
        .count() as u32;

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
}
