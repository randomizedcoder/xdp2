//! Matrix report formatting.

use crate::ir::AuditResult;

use super::truncate;

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
