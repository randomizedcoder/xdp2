//! Report formatting for audit results.
//!
//! Outputs audit results as either human-readable text tables
//! or machine-readable JSON.

mod findings;
mod matrix;

pub use findings::*;
pub use matrix::*;

use crate::ir::{AuditResult, ProtocolDef};

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
        "  {:<20}  {:>7}  {:>5}  {:>5}  {:>5}  {:>5}  {:<11}  {}\n",
        "Protocol", "Sources", "Agree", "TDiff", "Split", "Miss.", "Validation", "Status"
    ));
    out.push_str(&format!(
        "  {}  {}  {}  {}  {}  {}  {}  {}\n",
        "-".repeat(20), "-".repeat(7), "-".repeat(5), "-".repeat(5),
        "-".repeat(5), "-".repeat(5), "-".repeat(11), "-".repeat(12)
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

        let vtier = r
            .validation_tier
            .as_ref()
            .map(|t| t.to_string())
            .unwrap_or_else(|| "-".to_string());

        out.push_str(&format!(
            "  {:<20}  {:>7}  {:>5}  {:>5}  {:>5}  {:>5}  {:<11}  {}\n",
            truncate(&r.protocol, 20),
            r.sources_present.len(),
            r.fields_agree,
            r.fields_type_differ,
            r.fields_mismatch,
            r.fields_missing,
            vtier,
            status,
        ));
    }

    out
}

pub(crate) fn truncate(s: &str, max: usize) -> String {
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
            validation_tier: None,
        };

        let text = format_audit_text(&result);
        assert!(text.contains("Protocol: IPv4"));
        assert!(text.contains("kernel, scapy"));
        assert!(text.contains("1 agree"));
        assert!(text.contains("version"));
    }

    #[test]
    fn test_format_protocol_text() {
        let proto = ProtocolDef::new("UDP", 64)
            .with_fields(vec![
                FieldDef::new("sport", 0, 16, FieldType::Uint)
                    .with_endian(Endian::Big)
                    .with_description("Source port"),
            ]);

        let text = format_protocol_text(&proto);
        assert!(text.contains("Protocol: UDP"));
        assert!(text.contains("64 bits (8 bytes)"));
        assert!(text.contains("sport"));
    }
}
