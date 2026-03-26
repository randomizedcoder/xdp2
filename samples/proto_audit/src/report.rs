//! Report formatting for audit results.
//!
//! Outputs audit results as either human-readable text tables
//! or machine-readable JSON.

use crate::ir::{AuditResult, FieldComparison, ProtocolDef};

/// Format an AuditResult as a text summary.
pub fn format_audit_text(result: &AuditResult) -> String {
    let mut out = String::new();

    out.push_str(&format!("Protocol: {}\n", result.protocol));
    out.push_str(&format!(
        "Sources present: {}\n",
        result.sources_present.join(", ")
    ));
    if !result.sources_missing.is_empty() {
        out.push_str(&format!(
            "Sources missing: {}\n",
            result.sources_missing.join(", ")
        ));
    }
    out.push_str(&format!(
        "Fields: {} total, {} agree, {} type-differ, {} mismatch, {} missing\n",
        result.total_fields, result.fields_agree, result.fields_type_differ,
        result.fields_mismatch, result.fields_missing
    ));

    if !result.field_comparisons.is_empty() {
        out.push('\n');
        out.push_str(&format!(
            "  {:>4}  {:>4}  {:<24}  {:<12}  {}\n",
            "Off", "Size", "Name", "Sources", "Issues"
        ));
        out.push_str(&format!("  {}  {}  {}  {}  {}\n", "-".repeat(4), "-".repeat(4), "-".repeat(24), "-".repeat(12), "-".repeat(30)));

        for comp in &result.field_comparisons {
            let issues = if comp.mismatches.is_empty() {
                "OK".to_string()
            } else {
                comp.mismatches
                    .iter()
                    .map(|m| format!("{}:{}", m.field, m.actual))
                    .collect::<Vec<_>>()
                    .join("; ")
            };

            out.push_str(&format!(
                "  {:>4}  {:>4}  {:<24}  {:<12}  {}\n",
                comp.offset_bits,
                comp.size_bits,
                truncate(&comp.name, 24),
                comp.sources_agree.join(","),
                truncate(&issues, 50),
            ));
        }
    }

    out
}

/// Format a ProtocolDef as a text summary (single source).
pub fn format_protocol_text(proto: &ProtocolDef) -> String {
    let mut out = String::new();

    out.push_str(&format!("Protocol: {}\n", proto.name));
    out.push_str(&format!(
        "Min header: {} bits ({} bytes)\n",
        proto.min_header_bits,
        proto.min_header_bits / 8
    ));
    if proto.is_variable_length {
        out.push_str("Variable length: yes\n");
    }
    if let Some(ref df) = proto.dispatch_field {
        out.push_str(&format!("Dispatch field: {}\n", df));
    }

    if !proto.fields.is_empty() {
        out.push_str(&format!("\nFields ({}):\n", proto.fields.len()));
        out.push_str(&format!(
            "  {:>4}  {:>4}  {:<20}  {:<10}  {:<6}  {}\n",
            "Off", "Size", "Name", "Type", "Endian", "Flags"
        ));
        out.push_str(&format!(
            "  {}  {}  {}  {}  {}  {}\n",
            "-".repeat(4), "-".repeat(4), "-".repeat(20), "-".repeat(10), "-".repeat(6), "-".repeat(20)
        ));

        for f in &proto.fields {
            let mut flags = Vec::new();
            if f.is_dispatch {
                flags.push("dispatch");
            }
            if f.is_length {
                flags.push("length");
            }

            out.push_str(&format!(
                "  {:>4}  {:>4}  {:<20}  {:<10}  {:<6}  {}\n",
                f.offset_bits,
                f.size_bits,
                truncate(&f.name, 20),
                format!("{:?}", f.field_type),
                format!("{:?}", f.endian),
                flags.join(","),
            ));
        }
    }

    if !proto.dispatch_table.is_empty() {
        out.push_str(&format!("\nDispatch table ({} entries):\n", proto.dispatch_table.len()));
        for d in &proto.dispatch_table {
            out.push_str(&format!(
                "  0x{:04x} ({:>5}) -> {:<16}  [{}]\n",
                d.value,
                d.value,
                d.protocol,
                d.sources.join(", ")
            ));
        }
    }

    if !proto.sources.is_empty() {
        out.push_str("\nSources:\n");
        for (name, info) in &proto.sources {
            out.push_str(&format!(
                "  {}: {} ({}",
                name,
                info.source_name,
                if info.present { "present" } else { "absent" }
            ));
            if let Some(ref path) = info.file_path {
                out.push_str(&format!(", {}", path));
            }
            out.push_str(&format!(", {} fields", info.field_count));
            out.push_str(&format!(", {} bytes min", info.min_header_bytes));
            out.push_str(")\n");
            for note in &info.notes {
                out.push_str(&format!("    note: {}\n", note));
            }
        }
    }

    out
}

/// Format a list of XDP2 proto_def scan results.
pub fn format_xdp2_scan(
    defs: &[crate::extractors::xdp2::Xdp2ProtoDef],
) -> String {
    let mut out = String::new();

    out.push_str(&format!("XDP2 Proto Definitions: {} found\n\n", defs.len()));
    out.push_str(&format!(
        "  {:<35}  {:<25}  {:<15}  {:<10}  {}\n",
        "Variable Name", "Display Name", "Kernel Struct", "next_proto", "len"
    ));
    out.push_str(&format!(
        "  {}  {}  {}  {}  {}\n",
        "-".repeat(35), "-".repeat(25), "-".repeat(15), "-".repeat(10), "-".repeat(10)
    ));

    for d in defs {
        let ks = d
            .kernel_struct
            .as_deref()
            .unwrap_or("-");
        let np = if d.has_next_proto { "yes" } else { "-" };
        let len = if d.has_len { "yes" } else { "-" };

        out.push_str(&format!(
            "  {:<35}  {:<25}  {:<15}  {:<10}  {}\n",
            truncate(&d.var_name, 35),
            truncate(&d.display_name, 25),
            truncate(ks, 15),
            np,
            len,
        ));
    }

    out
}

/// Format a list of audit results as a summary table.
pub fn format_audit_summary(results: &[AuditResult]) -> String {
    let mut out = String::new();

    out.push_str(&format!("Audit Summary: {} protocols\n\n", results.len()));
    out.push_str(&format!(
        "  {:<20}  {:>7}  {:>5}  {:>5}  {:>5}  {:>5}  {}\n",
        "Protocol", "Sources", "Agree", "TDiff", "Split", "Miss.", "Status"
    ));
    out.push_str(&format!(
        "  {}  {}  {}  {}  {}  {}  {}\n",
        "-".repeat(20), "-".repeat(7), "-".repeat(5), "-".repeat(5),
        "-".repeat(5), "-".repeat(5), "-".repeat(12)
    ));

    for r in results {
        let status = if r.fields_mismatch == 0 && r.fields_missing == 0 && r.fields_type_differ == 0 {
            "OK"
        } else if r.fields_mismatch > 0 {
            "SPLIT"
        } else if r.fields_type_differ > 0 && r.fields_missing == 0 {
            "TYPE_DIFF"
        } else if r.fields_missing > 0 {
            "PARTIAL"
        } else {
            "PARTIAL"
        };

        out.push_str(&format!(
            "  {:<20}  {:>7}  {:>5}  {:>5}  {:>5}  {:>5}  {}\n",
            truncate(&r.protocol, 20),
            r.sources_present.len(),
            r.fields_agree,
            r.fields_type_differ,
            r.fields_mismatch,
            r.fields_missing,
            status,
        ));
    }

    out
}

/// Source-by-protocol coverage matrix.
///
/// Shows field counts per source, cross-source agreement, and XDP2 coverage.
pub fn format_matrix(results: &[AuditResult]) -> String {
    let mut out = String::new();
    let sources = ["kernel", "scapy", "tshark", "xdp2"];

    out.push_str(&format!(
        "Source × Protocol Coverage Matrix ({} protocols)\n\n",
        results.len()
    ));
    out.push_str(&format!(
        "  {:<16} {:>8} {:>8} {:>8} {:>8}  {:>6} {:>5} {:>5} {:>5}  {}\n",
        "Protocol", "kernel", "scapy", "tshark", "xdp2", "Agree", "TDiff", "Split", "Miss.", "Notes"
    ));
    out.push_str(&format!(
        "  {} {} {} {} {}  {} {} {} {}  {}\n",
        "-".repeat(16),
        "-".repeat(8),
        "-".repeat(8),
        "-".repeat(8),
        "-".repeat(8),
        "-".repeat(6),
        "-".repeat(5),
        "-".repeat(5),
        "-".repeat(5),
        "-".repeat(30),
    ));

    for r in results {
        let present: std::collections::HashSet<&str> =
            r.sources_present.iter().map(|s| s.as_str()).collect();

        // Count fields each source contributes via sources_structural (layout match)
        let mut src_fields: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
        for s in &sources {
            src_fields.insert(s, 0);
        }
        for comp in &r.field_comparisons {
            for s in &comp.sources_structural {
                if let Some(count) = src_fields.get_mut(s.as_str()) {
                    *count += 1;
                }
            }
        }

        let cell = |src: &str| -> String {
            if !present.contains(src) {
                "-".to_string()
            } else {
                let c = src_fields.get(src).copied().unwrap_or(0);
                if c == 0 {
                    "0*".to_string()
                } else {
                    c.to_string()
                }
            }
        };

        let mut notes = Vec::new();
        if present.contains("xdp2") && src_fields.get("xdp2").copied().unwrap_or(0) == 0 {
            notes.push("xdp2=struct-ref");
        }
        if r.fields_mismatch > 0 {
            notes.push("SPLIT");
        }
        if r.fields_type_differ > 0 {
            notes.push("TYPE_DIFF");
        }

        out.push_str(&format!(
            "  {:<16} {:>8} {:>8} {:>8} {:>8}  {:>6} {:>5} {:>5} {:>5}  {}\n",
            truncate(&r.protocol, 16),
            cell("kernel"),
            cell("scapy"),
            cell("tshark"),
            cell("xdp2"),
            r.fields_agree,
            r.fields_type_differ,
            r.fields_mismatch,
            r.fields_missing,
            notes.join(", "),
        ));
    }

    // Legend
    out.push_str("\n  0* = source present but extracted 0 fields (struct reference only)\n");
    out.push_str("  -  = source has no definition for this protocol\n");

    // Summary stats
    let total = results.len();
    let full_agree = results
        .iter()
        .filter(|r| r.fields_mismatch == 0 && r.fields_missing == 0 && r.total_fields > 0)
        .count();
    let has_mismatch = results.iter().filter(|r| r.fields_mismatch > 0).count();
    let multi_source = results
        .iter()
        .filter(|r| {
            r.sources_present
                .iter()
                .filter(|s| *s != "xdp2")
                .count()
                >= 2
        })
        .count();

    out.push_str(&format!(
        "\n  Summary: {} protocols, {} with 2+ external sources, {} full agreement, {} with field splits\n",
        total, multi_source, full_agree, has_mismatch
    ));

    out
}

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

/// Format matrix as JSON.
pub fn format_matrix_json(results: &[AuditResult]) -> serde_json::Value {
    let sources = ["kernel", "scapy", "tshark", "xdp2"];
    let mut entries = Vec::new();

    for r in results {
        let present: std::collections::HashSet<&str> =
            r.sources_present.iter().map(|s| s.as_str()).collect();

        // Use sources_structural for field counts (layout match)
        let mut src_fields: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
        for s in &sources {
            src_fields.insert(s, 0);
        }
        for comp in &r.field_comparisons {
            for s in &comp.sources_structural {
                if let Some(count) = src_fields.get_mut(s.as_str()) {
                    *count += 1;
                }
            }
        }

        let mut entry = serde_json::Map::new();
        entry.insert("protocol".into(), r.protocol.clone().into());
        for s in &sources {
            let val = if present.contains(s) {
                serde_json::Value::Number((*src_fields.get(s).unwrap_or(&0)).into())
            } else {
                serde_json::Value::Null
            };
            entry.insert((*s).into(), val);
        }
        entry.insert("fields_agree".into(), r.fields_agree.into());
        entry.insert("fields_type_differ".into(), r.fields_type_differ.into());
        entry.insert("fields_mismatch".into(), r.fields_mismatch.into());
        entry.insert("fields_missing".into(), r.fields_missing.into());
        entry.insert(
            "xdp2_struct_ref_only".into(),
            (present.contains("xdp2") && src_fields.get("xdp2").copied().unwrap_or(0) == 0).into(),
        );
        entries.push(serde_json::Value::Object(entry));
    }

    serde_json::Value::Array(entries)
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

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_format_audit_text() {
        let result = AuditResult {
            protocol: "IPv4".to_string(),
            sources_present: vec!["kernel".into(), "scapy".into()],
            sources_missing: vec!["xdp2".into(), "tshark".into()],
            field_comparisons: vec![FieldComparison {
                name: "version".to_string(),
                offset_bits: 0,
                size_bits: 4,
                sources_agree: vec!["kernel".into(), "scapy".into()],
                sources_structural: vec!["kernel".into(), "scapy".into()],
                mismatches: vec![],
            }],
            total_fields: 1,
            fields_agree: 1,
            fields_type_differ: 0,
            fields_mismatch: 0,
            fields_missing: 0,
        };

        let text = format_audit_text(&result);
        assert!(text.contains("Protocol: IPv4"));
        assert!(text.contains("kernel, scapy"));
        assert!(text.contains("1 agree"));
        assert!(text.contains("version"));
    }

    #[test]
    fn test_format_protocol_text() {
        let proto = ProtocolDef {
            name: "UDP".to_string(),
            min_header_bits: 64,
            is_variable_length: false,
            fields: vec![FieldDef {
                name: "sport".to_string(),
                offset_bits: 0,
                size_bits: 16,
                field_type: FieldType::Uint,
                endian: Endian::Big,
                description: "Source port".to_string(),
                is_dispatch: false,
                is_length: false,
                length_multiplier: None,
                source_names: BTreeMap::new(),
            }],
            dispatch_field: None,
            dispatch_table: vec![],
            identifiers: BTreeMap::new(),
            sources: BTreeMap::new(),
        };

        let text = format_protocol_text(&proto);
        assert!(text.contains("Protocol: UDP"));
        assert!(text.contains("64 bits (8 bytes)"));
        assert!(text.contains("sport"));
    }
}
