//! Findings report formatting.

use crate::ir::{AuditResult, FieldComparison};

/// Detailed cross-source disagreement findings.
///
/// Shows where kernel, scapy, and tshark define different field sizes
/// at the same bit offset — the interesting structural differences.
pub fn format_findings(results: &[AuditResult]) -> String {
    let mut out = String::new();

    out.push_str("Cross-Source Protocol Field Analysis\n");
    out.push_str(&"=".repeat(80));
    out.push('\n');

    // Section 1: XDP2 coverage assessment
    out.push_str("\n1. XDP2 COVERAGE\n");
    out.push_str(&"-".repeat(80));
    out.push('\n');
    out.push_str("\n");
    out.push_str("XDP2 proto_defs reference kernel structs rather than defining fields directly.\n");
    out.push_str("The parsing is correct — fields are resolved at runtime from kernel headers.\n\n");

    let xdp2_present = results
        .iter()
        .filter(|r| r.sources_present.contains(&"xdp2".to_string()))
        .count();
    let xdp2_missing = results
        .iter()
        .filter(|r| r.sources_missing.contains(&"xdp2".to_string()))
        .count();
    out.push_str(&format!(
        "  XDP2 has definitions for {}/{} audited protocols ({} missing)\n",
        xdp2_present,
        results.len(),
        xdp2_missing,
    ));

    let missing_protos: Vec<&str> = results
        .iter()
        .filter(|r| r.sources_missing.contains(&"xdp2".to_string()))
        .map(|r| r.protocol.as_str())
        .collect();
    if !missing_protos.is_empty() {
        out.push_str(&format!("  Missing from XDP2: {}\n", missing_protos.join(", ")));
    }

    // Section 2: Field layout disagreements
    out.push_str("\n\n2. FIELD LAYOUT DISAGREEMENTS\n");
    out.push_str(&"-".repeat(80));
    out.push('\n');
    out.push_str("\nFields where sources define DIFFERENT sizes at the same bit offset.\n");
    out.push_str("This reveals different granularity choices, not necessarily bugs.\n\n");

    let mut found_any = false;
    for r in results {
        let ext_present: Vec<&str> = r
            .sources_present
            .iter()
            .filter(|s| *s != "xdp2")
            .map(|s| s.as_str())
            .collect();
        if ext_present.len() < 2 {
            continue;
        }

        // Group fields by offset to find disagreements
        let mut by_offset: std::collections::BTreeMap<u32, Vec<(&FieldComparison, Vec<&str>)>> =
            std::collections::BTreeMap::new();
        for comp in &r.field_comparisons {
            let ext_sources: Vec<&str> = comp
                .sources_agree
                .iter()
                .filter(|s| *s != "xdp2")
                .map(|s| s.as_str())
                .collect();
            if !ext_sources.is_empty() {
                by_offset
                    .entry(comp.offset_bits)
                    .or_default()
                    .push((comp, ext_sources));
            }
        }

        let disagreements: Vec<(&u32, &Vec<(&FieldComparison, Vec<&str>)>)> = by_offset
            .iter()
            .filter(|(_, entries)| entries.len() > 1)
            .collect();

        if !disagreements.is_empty() {
            found_any = true;
            out.push_str(&format!(
                "  {} (sources: {})\n",
                r.protocol,
                ext_present.join(", ")
            ));

            for (offset, entries) in &disagreements {
                for (comp, srcs) in *entries {
                    out.push_str(&format!(
                        "    @{:>3}b {:>3} bits  {:<30} [{}]\n",
                        offset,
                        comp.size_bits,
                        comp.name,
                        srcs.join(", "),
                    ));
                }
            }
            out.push('\n');
        }
    }

    if !found_any {
        out.push_str("  No field layout disagreements found.\n");
    }

    // Section 3: Coverage gaps
    out.push_str("\n3. COVERAGE GAPS\n");
    out.push_str(&"-".repeat(80));
    out.push('\n');
    out.push_str("\nProtocols with only a single external source (no cross-validation possible).\n\n");

    out.push_str(&format!(
        "  {:<16} {:<12} {}\n",
        "Protocol", "Only Source", "Fields"
    ));
    out.push_str(&format!(
        "  {} {} {}\n",
        "-".repeat(16),
        "-".repeat(12),
        "-".repeat(8),
    ));

    for r in results {
        let ext_present: Vec<&str> = r
            .sources_present
            .iter()
            .filter(|s| *s != "xdp2")
            .map(|s| s.as_str())
            .collect();
        if ext_present.len() == 1 {
            let total_ext_fields: u32 = r
                .field_comparisons
                .iter()
                .filter(|c| c.sources_agree.iter().any(|s| s != "xdp2"))
                .count() as u32;
            out.push_str(&format!(
                "  {:<16} {:<12} {:>8}\n",
                r.protocol, ext_present[0], total_ext_fields
            ));
        }
    }

    let no_ext: Vec<&str> = results
        .iter()
        .filter(|r| r.sources_present.iter().all(|s| s == "xdp2"))
        .map(|r| r.protocol.as_str())
        .collect();
    if !no_ext.is_empty() {
        out.push_str(&format!(
            "\n  XDP2-only (no external validation): {}\n",
            no_ext.join(", ")
        ));
    }

    // Section 4: Type/endian annotation differences (informational)
    out.push_str("\n\n4. TYPE/ENDIAN ANNOTATION DIFFERENCES (informational)\n");
    out.push_str(&"-".repeat(80));
    out.push('\n');
    out.push_str("\nFields where sources agree on layout (offset+size) but infer different\n");
    out.push_str("types or endianness. These are annotation differences, not structural bugs.\n");

    let mut found_type_diffs = false;
    for r in results {
        let ext_present: Vec<&str> = r
            .sources_present
            .iter()
            .filter(|s| *s != "xdp2")
            .map(|s| s.as_str())
            .collect();
        if ext_present.len() < 2 {
            continue;
        }

        let type_diff_fields: Vec<_> = r
            .field_comparisons
            .iter()
            .filter(|c| {
                c.sources_structural.len() >= 2
                    && c.mismatches
                        .iter()
                        .any(|m| m.field == "field_type" || m.field == "endian")
            })
            .collect();

        if !type_diff_fields.is_empty() {
            found_type_diffs = true;
            out.push_str(&format!(
                "\n  {} (sources: {})\n",
                r.protocol,
                ext_present.join(", ")
            ));
            for comp in &type_diff_fields {
                let details: Vec<String> = comp
                    .mismatches
                    .iter()
                    .filter(|m| m.field == "field_type" || m.field == "endian")
                    .map(|m| format!("{} {}={}", m.source, m.field, m.actual))
                    .collect();
                out.push_str(&format!(
                    "    '{}' @{}b {}b [structural: {}]: {}\n",
                    comp.name,
                    comp.offset_bits,
                    comp.size_bits,
                    comp.sources_structural.join(","),
                    details.join("; "),
                ));
            }
        }
    }

    if !found_type_diffs {
        out.push_str("\n  No type/endian annotation differences found.\n");
    }

    // Section 5: Field boundary disagreements (structural splits)
    out.push_str("\n\n5. FIELD BOUNDARY DISAGREEMENTS\n");
    out.push_str(&"-".repeat(80));
    out.push('\n');

    let mut found_splits = false;
    for r in results {
        let ext_present: Vec<&str> = r
            .sources_present
            .iter()
            .filter(|s| *s != "xdp2")
            .map(|s| s.as_str())
            .collect();
        if ext_present.len() < 2 {
            continue;
        }

        let splits: Vec<_> = r
            .field_comparisons
            .iter()
            .filter(|c| c.mismatches.iter().any(|m| m.field == "split"))
            .collect();

        if !splits.is_empty() {
            found_splits = true;
            out.push_str(&format!(
                "\n  {} — field boundary disagreements:\n",
                r.protocol,
            ));
            for comp in &splits {
                let split_detail: Vec<String> = comp
                    .mismatches
                    .iter()
                    .filter(|m| m.field == "split")
                    .map(|m| format!("{}: {}", m.source, m.actual))
                    .collect();
                out.push_str(&format!(
                    "    '{}' @{}b {}b in [{}]: {}\n",
                    comp.name,
                    comp.offset_bits,
                    comp.size_bits,
                    comp.sources_structural.join(", "),
                    split_detail.join("; "),
                ));
            }
        }
    }

    if !found_splits {
        out.push_str("\n  No field boundary disagreements found.\n");
    }

    out
}

/// Format findings as JSON.
pub fn format_findings_json(results: &[AuditResult]) -> serde_json::Value {
    let mut out = serde_json::Map::new();

    // XDP2 coverage
    let xdp2_present = results
        .iter()
        .filter(|r| r.sources_present.contains(&"xdp2".to_string()))
        .count();
    let xdp2_missing: Vec<&str> = results
        .iter()
        .filter(|r| r.sources_missing.contains(&"xdp2".to_string()))
        .map(|r| r.protocol.as_str())
        .collect();
    out.insert(
        "xdp2_coverage".into(),
        serde_json::json!({
            "present": xdp2_present,
            "total": results.len(),
            "missing_protocols": xdp2_missing,
        }),
    );

    // Field layout disagreements
    let mut disagreements = Vec::new();
    for r in results {
        let ext_present: Vec<&str> = r
            .sources_present
            .iter()
            .filter(|s| *s != "xdp2")
            .map(|s| s.as_str())
            .collect();
        if ext_present.len() < 2 {
            continue;
        }

        let mut by_offset: std::collections::BTreeMap<u32, Vec<(&FieldComparison, Vec<&str>)>> =
            std::collections::BTreeMap::new();
        for comp in &r.field_comparisons {
            let ext_sources: Vec<&str> = comp
                .sources_agree
                .iter()
                .filter(|s| *s != "xdp2")
                .map(|s| s.as_str())
                .collect();
            if !ext_sources.is_empty() {
                by_offset
                    .entry(comp.offset_bits)
                    .or_default()
                    .push((comp, ext_sources));
            }
        }

        for (offset, entries) in &by_offset {
            if entries.len() > 1 {
                let fields: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|(comp, srcs)| {
                        serde_json::json!({
                            "name": comp.name,
                            "size_bits": comp.size_bits,
                            "sources": srcs,
                        })
                    })
                    .collect();

                disagreements.push(serde_json::json!({
                    "protocol": r.protocol,
                    "offset_bits": offset,
                    "fields": fields,
                }));
            }
        }
    }
    out.insert("field_disagreements".into(), disagreements.into());

    // Coverage gaps
    let mut single_source = Vec::new();
    for r in results {
        let ext_present: Vec<&str> = r
            .sources_present
            .iter()
            .filter(|s| *s != "xdp2")
            .map(|s| s.as_str())
            .collect();
        if ext_present.len() == 1 {
            single_source.push(serde_json::json!({
                "protocol": r.protocol,
                "only_source": ext_present[0],
            }));
        }
    }
    let xdp2_only: Vec<&str> = results
        .iter()
        .filter(|r| r.sources_present.iter().all(|s| s == "xdp2"))
        .map(|r| r.protocol.as_str())
        .collect();
    out.insert(
        "coverage_gaps".into(),
        serde_json::json!({
            "single_external_source": single_source,
            "xdp2_only": xdp2_only,
        }),
    );

    serde_json::Value::Object(out)
}
