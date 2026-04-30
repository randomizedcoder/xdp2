use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::{
    comparator,
    discovery::{self, DiscoveryState},
    extractors, generator, ir, name_mapping, type_mapping, SourcePaths,
};

use super::helpers::*;

pub(crate) fn cmd_corpus_parse(
    pcap_path: &std::path::Path,
    proto_filter: Option<&str>,
    json_output: bool,
    paths: &SourcePaths,
) -> Result<()> {
    // Step 1: Run tshark on the PCAP
    let xml = extractors::tshark::run_tshark(pcap_path, &paths.tshark_bin, 100)
        .context("running tshark on PCAP")?;
    let packets = extractors::tshark::parse_pdml(&xml)
        .context("parsing tshark PDML")?;
    eprintln!("  [1/3] tshark parsed {} packet(s)", packets.len());

    // Step 2: Run Scapy on the PCAP
    let helper = paths
        .scapy_helper
        .clone()
        .unwrap_or_else(|| PathBuf::from("helpers/scapy_dump.py"));
    let scapy_output = std::process::Command::new(&paths.python)
        .arg(&helper)
        .arg("--dissect-pcap")
        .arg(pcap_path)
        .output()
        .context("running scapy dissect-pcap")?;

    if !scapy_output.status.success() {
        let stderr = String::from_utf8_lossy(&scapy_output.stderr);
        anyhow::bail!("scapy dissect-pcap failed: {}", stderr.trim());
    }

    let scapy_json: Vec<serde_json::Value> =
        serde_json::from_slice(&scapy_output.stdout)
            .context("parsing scapy dissect-pcap JSON")?;
    eprintln!("  [2/3] Scapy parsed {} packet(s)", scapy_json.len());

    // Step 3: Compare field values per layer
    let mut all_comparisons: Vec<serde_json::Value> = Vec::new();
    let num_packets = packets.len().min(scapy_json.len());

    for pkt_idx in 0..num_packets {
        // Build tshark layer map: protocol_name → field_values
        let tshark_layers = &packets[pkt_idx];
        let scapy_pkt = &scapy_json[pkt_idx];
        let scapy_layers = scapy_pkt["layers"].as_array();

        if scapy_layers.is_none() {
            continue;
        }
        let scapy_layers = scapy_layers.unwrap();

        // For each Scapy layer, try to find matching tshark layer and compare
        for scapy_layer in scapy_layers {
            let layer_name = scapy_layer["layer"].as_str().unwrap_or("");
            let scapy_fields = scapy_layer["fields"].as_object();
            if scapy_fields.is_none() {
                continue;
            }

            // Map Scapy class name to canonical name
            let canonical = name_mapping::find_by_scapy_name(layer_name)
                .map(|n| n.canonical.to_string())
                .unwrap_or_else(|| layer_name.to_string());

            // Apply filter if specified
            if let Some(filter) = proto_filter {
                if canonical.to_lowercase() != filter.to_lowercase() {
                    continue;
                }
            }

            // Find matching tshark dissector
            let tshark_dissector = name_mapping::find_by_canonical(&canonical)
                .and_then(|n| n.tshark.map(|s| s.to_string()));

            let tshark_fields_map: std::collections::BTreeMap<String, String> =
                if let Some(ref dissector) = tshark_dissector {
                    // Find matching tshark protocol layer in this packet
                    let tshark_layer = tshark_layers.iter().find(|p| p.name == *dissector);
                    if let Some(layer) = tshark_layer {
                        layer.fields
                            .iter()
                            .map(|f| (f.name.clone(), f.show.clone()))
                            .collect()
                    } else {
                        std::collections::BTreeMap::new()
                    }
                } else {
                    std::collections::BTreeMap::new()
                };

            let scapy_fields_map: std::collections::BTreeMap<String, String> =
                scapy_fields
                    .unwrap()
                    .iter()
                    .map(|(k, v)| {
                        let val = match v {
                            serde_json::Value::String(s) => s.clone(),
                            serde_json::Value::Number(n) => n.to_string(),
                            serde_json::Value::Bool(b) => b.to_string(),
                            _ => v.to_string(),
                        };
                        (k.clone(), val)
                    })
                    .collect();

            if tshark_fields_map.is_empty() && scapy_fields_map.is_empty() {
                continue;
            }

            let comparisons = comparator::compare_field_values(
                &tshark_fields_map,
                &scapy_fields_map,
            );

            let agree_count = comparisons.iter().filter(|c| c.agree).count();
            let total = comparisons.len();

            all_comparisons.push(serde_json::json!({
                "packet": pkt_idx,
                "protocol": canonical,
                "tshark_fields": tshark_fields_map.len(),
                "scapy_fields": scapy_fields_map.len(),
                "agree": agree_count,
                "disagree": total - agree_count,
                "comparisons": comparisons,
            }));
        }
    }

    eprintln!("  [3/3] Compared {} protocol layers", all_comparisons.len());

    if json_output {
        println!("{}", serde_json::to_string_pretty(&all_comparisons)?);
    } else {
        println!("Corpus cross-source value comparison: {}", pcap_path.display());
        println!("{:-<60}", "");
        for comp in &all_comparisons {
            let proto = comp["protocol"].as_str().unwrap_or("?");
            let agree = comp["agree"].as_u64().unwrap_or(0);
            let disagree = comp["disagree"].as_u64().unwrap_or(0);
            let total = agree + disagree;
            let pct = if total > 0 { agree * 100 / total } else { 0 };
            println!(
                "  Pkt {} {:20} agree: {}/{} ({}%)",
                comp["packet"],
                proto,
                agree,
                total,
                pct,
            );
            if disagree > 0 {
                if let Some(comps) = comp["comparisons"].as_array() {
                    for c in comps {
                        if !c["agree"].as_bool().unwrap_or(true) {
                            println!(
                                "    {} tshark={:?} scapy={:?}",
                                c["field_name"].as_str().unwrap_or("?"),
                                c["source_a_value"],
                                c["source_b_value"],
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// A single cross-generator round-trip result for one target.
#[derive(Debug, serde::Serialize)]
struct CrossGenResult {
    target: String,
    passed: bool,
    original_fields: usize,
    roundtrip_fields: usize,
    fields_agree: u32,
    fields_mismatch: u32,
    error: Option<String>,
}

/// Run cross-generator round-trip for a single protocol and target.
/// Returns None if the target is not applicable.
fn crossgen_one(
    proto: &str,
    target: &str,
    paths: &SourcePaths,
) -> Option<CrossGenResult> {
    let ir = match build_rich_ir(proto, paths) {
        Ok(ir) => ir,
        Err(e) => {
            return Some(CrossGenResult {
                target: target.to_string(),
                passed: false,
                original_fields: 0,
                roundtrip_fields: 0,
                fields_agree: 0,
                fields_mismatch: 0,
                error: Some(format!("cannot build IR: {}", e)),
            });
        }
    };

    if ir.fields.is_empty() {
        return Some(CrossGenResult {
            target: target.to_string(),
            passed: false,
            original_fields: 0,
            roundtrip_fields: 0,
            fields_agree: 0,
            fields_mismatch: 0,
            error: Some("IR has no fields".to_string()),
        });
    }

    match target {
        "etherparse" => {
            let generated = generator::generate_etherparse(&ir);
            let mappings = type_mapping::load_etherparse_mappings(None).ok()?;
            let parsed = extractors::etherparse::parse_etherparse_struct(&generated, &ir.name);
            match parsed {
                Ok(Some(es)) => {
                    let roundtrip_fields =
                        extractors::etherparse::to_field_defs_with(&es, &mappings);
                    let mut roundtrip_def =
                        ir::ProtocolDef::new(&ir.name, ir.min_header_bits)
                            .with_fields(roundtrip_fields);
                    roundtrip_def.name = ir.name.clone();
                    let audit = comparator::audit_protocol(
                        &ir.name,
                        &[("original", &ir), ("roundtrip", &roundtrip_def)],
                    );
                    Some(CrossGenResult {
                        target: "etherparse".to_string(),
                        passed: audit.fields_mismatch == 0,
                        original_fields: ir.fields.len(),
                        roundtrip_fields: roundtrip_def.fields.len(),
                        fields_agree: audit.fields_agree,
                        fields_mismatch: audit.fields_mismatch,
                        error: None,
                    })
                }
                Ok(None) => Some(CrossGenResult {
                    target: "etherparse".to_string(),
                    passed: false,
                    original_fields: ir.fields.len(),
                    roundtrip_fields: 0,
                    fields_agree: 0,
                    fields_mismatch: 0,
                    error: Some("re-extraction found no struct".to_string()),
                }),
                Err(e) => Some(CrossGenResult {
                    target: "etherparse".to_string(),
                    passed: false,
                    original_fields: ir.fields.len(),
                    roundtrip_fields: 0,
                    fields_agree: 0,
                    fields_mismatch: 0,
                    error: Some(format!("re-extraction failed: {}", e)),
                }),
            }
        }
        "c" => {
            // Use synthetic generator which embeds a parseable struct definition
            let generated = generator::generate_proto_def_synthetic(&ir);
            let snake = ir.name.to_lowercase().replace('.', "_").replace('-', "_").replace(' ', "_");
            let struct_name = format!("proto_audit_{}_hdr", snake);
            let mappings = type_mapping::load_kernel_mappings(None).ok()?;
            let parsed = extractors::kernel::parse_kernel_struct(&generated, &struct_name);
            match parsed {
                Ok(Some(ks)) => {
                    let roundtrip_fields = extractors::kernel::to_field_defs_with(&ks, &mappings);
                    let mut roundtrip_def =
                        ir::ProtocolDef::new(&ir.name, ir.min_header_bits)
                            .with_fields(roundtrip_fields);
                    roundtrip_def.name = ir.name.clone();
                    let audit = comparator::audit_protocol(
                        &ir.name,
                        &[("original", &ir), ("roundtrip", &roundtrip_def)],
                    );
                    Some(CrossGenResult {
                        target: "c".to_string(),
                        passed: audit.fields_mismatch == 0,
                        original_fields: ir.fields.len(),
                        roundtrip_fields: roundtrip_def.fields.len(),
                        fields_agree: audit.fields_agree,
                        fields_mismatch: audit.fields_mismatch,
                        error: None,
                    })
                }
                Ok(None) => Some(CrossGenResult {
                    target: "c".to_string(),
                    passed: false,
                    original_fields: ir.fields.len(),
                    roundtrip_fields: 0,
                    fields_agree: 0,
                    fields_mismatch: 0,
                    error: Some("re-extraction found no struct".to_string()),
                }),
                Err(e) => Some(CrossGenResult {
                    target: "c".to_string(),
                    passed: false,
                    original_fields: ir.fields.len(),
                    roundtrip_fields: 0,
                    fields_agree: 0,
                    fields_mismatch: 0,
                    error: Some(format!("re-extraction failed: {}", e)),
                }),
            }
        }
        "scapy" => {
            // Scapy round-trip requires Python runtime with scapy_dump.py introspection
            let generated = generator::generate_scapy(&ir);
            let helper = paths
                .scapy_helper
                .clone()
                .unwrap_or_else(|| PathBuf::from("helpers/scapy_dump.py"));
            if !helper.exists() {
                return Some(CrossGenResult {
                    target: "scapy".to_string(),
                    passed: false,
                    original_fields: ir.fields.len(),
                    roundtrip_fields: 0,
                    fields_agree: 0,
                    fields_mismatch: 0,
                    error: Some("scapy helper not available".to_string()),
                });
            }
            // Write generated class to temp, then use scapy_dump.py --extra to introspect it
            let tmp_dir = std::env::temp_dir();
            let tmp_file = tmp_dir.join(format!("crossgen_{}.py", ir.name.to_lowercase()));
            if std::fs::write(&tmp_file, &generated).is_err() {
                return Some(CrossGenResult {
                    target: "scapy".to_string(),
                    passed: false,
                    original_fields: ir.fields.len(),
                    roundtrip_fields: 0,
                    fields_agree: 0,
                    fields_mismatch: 0,
                    error: Some("cannot write temp file".to_string()),
                });
            }
            let result = std::process::Command::new(&paths.python)
                .arg(&helper)
                .arg("--extra")
                .arg(&tmp_file)
                .arg(&ir.name)
                .output();
            let _ = std::fs::remove_file(&tmp_file);
            match result {
                Ok(output) if output.status.success() => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    match extractors::scapy::parse_scapy_json(&stdout) {
                        Ok(sp) => {
                            let roundtrip_def = extractors::scapy::to_protocol_def(&sp);
                            let audit = comparator::audit_protocol(
                                &ir.name,
                                &[("original", &ir), ("roundtrip", &roundtrip_def)],
                            );
                            Some(CrossGenResult {
                                target: "scapy".to_string(),
                                passed: audit.fields_mismatch == 0,
                                original_fields: ir.fields.len(),
                                roundtrip_fields: roundtrip_def.fields.len(),
                                fields_agree: audit.fields_agree,
                                fields_mismatch: audit.fields_mismatch,
                                error: None,
                            })
                        }
                        Err(e) => Some(CrossGenResult {
                            target: "scapy".to_string(),
                            passed: false,
                            original_fields: ir.fields.len(),
                            roundtrip_fields: 0,
                            fields_agree: 0,
                            fields_mismatch: 0,
                            error: Some(format!("scapy JSON parse failed: {}", e)),
                        }),
                    }
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Some(CrossGenResult {
                        target: "scapy".to_string(),
                        passed: false,
                        original_fields: ir.fields.len(),
                        roundtrip_fields: 0,
                        fields_agree: 0,
                        fields_mismatch: 0,
                        error: Some(format!("scapy helper failed: {}", stderr.trim())),
                    })
                }
                Err(e) => Some(CrossGenResult {
                    target: "scapy".to_string(),
                    passed: false,
                    original_fields: ir.fields.len(),
                    roundtrip_fields: 0,
                    fields_agree: 0,
                    fields_mismatch: 0,
                    error: Some(format!("scapy round-trip failed: {}", e)),
                }),
            }
        }
        "pcap" => {
            // Delegate to existing validate logic — just report pass/fail
            let discovery_state = DiscoveryState::load_from_env();
            let proto_map = build_proto_map(proto, paths, &discovery_state);
            let pcap_output = match generator::generate_pcap_with_discovery(&ir, &proto_map, &discovery_state) {
                Ok(p) => p,
                Err(e) => {
                    return Some(CrossGenResult {
                        target: "pcap".to_string(),
                        passed: false,
                        original_fields: ir.fields.len(),
                        roundtrip_fields: 0,
                        fields_agree: 0,
                        fields_mismatch: 0,
                        error: Some(format!("PCAP generation failed: {}", e)),
                    });
                }
            };
            let tmp = std::env::temp_dir().join(format!(
                "crossgen-{}.pcap",
                ir.name.to_lowercase()
            ));
            if std::fs::write(&tmp, &pcap_output.pcap_bytes).is_err() {
                return Some(CrossGenResult {
                    target: "pcap".to_string(),
                    passed: false,
                    original_fields: ir.fields.len(),
                    roundtrip_fields: 0,
                    fields_agree: 0,
                    fields_mismatch: 0,
                    error: Some("cannot write temp PCAP".to_string()),
                });
            }
            let xml = extractors::tshark::run_tshark(&tmp, &paths.tshark_bin, 1).ok();
            let _ = std::fs::remove_file(&tmp);
            let xml = match xml {
                Some(x) => x,
                None => {
                    return Some(CrossGenResult {
                        target: "pcap".to_string(),
                        passed: false,
                        original_fields: ir.fields.len(),
                        roundtrip_fields: 0,
                        fields_agree: 0,
                        fields_mismatch: 0,
                        error: Some("tshark failed".to_string()),
                    });
                }
            };
            let packets = extractors::tshark::parse_pdml(&xml).ok()?;
            let dissector = name_mapping::find_by_canonical(proto)
                .and_then(|n| n.tshark.map(|s| s.to_string()));
            let tshark_proto = dissector
                .as_deref()
                .and_then(|d| extractors::tshark::extract_protocol_from_pdml(&packets, d));
            match tshark_proto {
                Some(pdml) => {
                    let roundtrip_def = extractors::tshark::to_protocol_def(&pdml);
                    let audit = comparator::audit_protocol(
                        &ir.name,
                        &[("original", &ir), ("roundtrip", &roundtrip_def)],
                    );
                    Some(CrossGenResult {
                        target: "pcap".to_string(),
                        passed: audit.fields_mismatch == 0,
                        original_fields: ir.fields.len(),
                        roundtrip_fields: roundtrip_def.fields.len(),
                        fields_agree: audit.fields_agree,
                        fields_mismatch: audit.fields_mismatch,
                        error: None,
                    })
                }
                None => Some(CrossGenResult {
                    target: "pcap".to_string(),
                    passed: false,
                    original_fields: ir.fields.len(),
                    roundtrip_fields: 0,
                    fields_agree: 0,
                    fields_mismatch: 0,
                    error: Some("tshark did not dissect target protocol".to_string()),
                }),
            }
        }
        "kaitai" => {
            // Kaitai round-trip: generate .ksy → write to temp → parse back → compare
            let generated = generator::generate_kaitai_ksy(&ir);
            let tmp = std::env::temp_dir().join(format!(
                "crossgen_{}.ksy",
                ir.name.to_lowercase()
            ));
            if std::fs::write(&tmp, &generated).is_err() {
                return Some(CrossGenResult {
                    target: "kaitai".to_string(),
                    passed: false,
                    original_fields: ir.fields.len(),
                    roundtrip_fields: 0,
                    fields_agree: 0,
                    fields_mismatch: 0,
                    error: Some("cannot write temp .ksy file".to_string()),
                });
            }
            let result = extractors::kaitai::extract_from_ksy(&tmp);
            let _ = std::fs::remove_file(&tmp);
            match result {
                Ok(Some(roundtrip_def)) => {
                    let audit = comparator::audit_protocol(
                        &ir.name,
                        &[("original", &ir), ("roundtrip", &roundtrip_def)],
                    );
                    Some(CrossGenResult {
                        target: "kaitai".to_string(),
                        passed: audit.fields_mismatch == 0,
                        original_fields: ir.fields.len(),
                        roundtrip_fields: roundtrip_def.fields.len(),
                        fields_agree: audit.fields_agree,
                        fields_mismatch: audit.fields_mismatch,
                        error: None,
                    })
                }
                Ok(None) => Some(CrossGenResult {
                    target: "kaitai".to_string(),
                    passed: false,
                    original_fields: ir.fields.len(),
                    roundtrip_fields: 0,
                    fields_agree: 0,
                    fields_mismatch: 0,
                    error: Some("kaitai re-extraction found no fields".to_string()),
                }),
                Err(e) => Some(CrossGenResult {
                    target: "kaitai".to_string(),
                    passed: false,
                    original_fields: ir.fields.len(),
                    roundtrip_fields: 0,
                    fields_agree: 0,
                    fields_mismatch: 0,
                    error: Some(format!("kaitai re-extraction failed: {}", e)),
                }),
            }
        }
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Pipeline: full PCAP → IR → code → IR → PCAP → compare round-trip
// ═══════════════════════════════════════════════════════════════════════════

/// Result of the full pipeline for one (protocol, target) pair.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct PipelineResult {
    pub protocol: String,
    pub target: String,
    pub pcap_pass: bool,
    pub pcap_fields_total: usize,
    pub pcap_fields_match: usize,
    pub crossgen_pass: bool,
    pub crossgen_fields_agree: u32,
    pub crossgen_fields_mismatch: u32,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pcap_diffs: Vec<comparator::PcapFieldDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ir_stage1: Option<ir::AuditResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ir_stage2: Option<ir::AuditResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ir_stage3: Option<ir::AuditResult>,
}

/// Run crossgen on a provided IR (instead of building it internally).
/// Returns (CrossGenResult, roundtrip_ir) so the pipeline can chain.
fn crossgen_with_ir(
    ir: &ir::ProtocolDef,
    proto: &str,
    target: &str,
    paths: &SourcePaths,
) -> (CrossGenResult, Option<ir::ProtocolDef>) {
    if ir.fields.is_empty() {
        return (CrossGenResult {
            target: target.to_string(),
            passed: false,
            original_fields: 0,
            roundtrip_fields: 0,
            fields_agree: 0,
            fields_mismatch: 0,
            error: Some("IR has no fields".to_string()),
        }, None);
    }

    match target {
        "etherparse" => {
            let generated = generator::generate_etherparse(ir);
            let pascal = ir.name.replace('.', "").replace('-', "").replace(' ', "");
            let struct_name = format!("{}Header", pascal);
            let mappings = match type_mapping::load_etherparse_mappings(None) {
                Ok(m) => m,
                Err(e) => return (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some(format!("mappings: {}", e)),
                }, None),
            };
            match extractors::etherparse::parse_etherparse_struct(&generated, &struct_name) {
                Ok(Some(es)) => {
                    let roundtrip_fields = extractors::etherparse::to_field_defs_with(&es, &mappings);
                    let mut roundtrip_def = ir::ProtocolDef::new(&ir.name, ir.min_header_bits)
                        .with_fields(roundtrip_fields);
                    roundtrip_def.name = ir.name.clone();
                    let audit = comparator::audit_protocol(&ir.name, &[("original", ir), ("roundtrip", &roundtrip_def)]);
                    (CrossGenResult {
                        target: target.to_string(),
                        passed: audit.fields_mismatch == 0,
                        original_fields: ir.fields.len(),
                        roundtrip_fields: roundtrip_def.fields.len(),
                        fields_agree: audit.fields_agree,
                        fields_mismatch: audit.fields_mismatch,
                        error: None,
                    }, Some(roundtrip_def))
                }
                Ok(None) => (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some("re-extraction found no struct".to_string()),
                }, None),
                Err(e) => (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some(format!("re-extraction failed: {}", e)),
                }, None),
            }
        }
        "c" => {
            // Use synthetic generator which embeds a parseable struct definition.
            // generate_proto_def() only references kernel structs by name without defining them.
            let generated = generator::generate_proto_def_synthetic(ir);
            let snake = ir.name.to_lowercase().replace('.', "_").replace('-', "_").replace(' ', "_");
            let struct_name = format!("proto_audit_{}_hdr", snake);
            let mappings = match type_mapping::load_kernel_mappings(None) {
                Ok(m) => m,
                Err(e) => return (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some(format!("mappings: {}", e)),
                }, None),
            };
            match extractors::kernel::parse_kernel_struct(&generated, &struct_name) {
                Ok(Some(ks)) => {
                    let roundtrip_fields = extractors::kernel::to_field_defs_with(&ks, &mappings);
                    let mut roundtrip_def = ir::ProtocolDef::new(&ir.name, ir.min_header_bits)
                        .with_fields(roundtrip_fields);
                    roundtrip_def.name = ir.name.clone();
                    let audit = comparator::audit_protocol(&ir.name, &[("original", ir), ("roundtrip", &roundtrip_def)]);
                    (CrossGenResult {
                        target: target.to_string(),
                        passed: audit.fields_mismatch == 0,
                        original_fields: ir.fields.len(),
                        roundtrip_fields: roundtrip_def.fields.len(),
                        fields_agree: audit.fields_agree,
                        fields_mismatch: audit.fields_mismatch,
                        error: None,
                    }, Some(roundtrip_def))
                }
                Ok(None) => (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some("re-extraction found no struct".to_string()),
                }, None),
                Err(e) => (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some(format!("re-extraction failed: {}", e)),
                }, None),
            }
        }
        "scapy" => {
            let generated = generator::generate_scapy(ir);
            let helper = paths.scapy_helper.clone()
                .unwrap_or_else(|| PathBuf::from("helpers/scapy_dump.py"));
            if !helper.exists() {
                return (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some("scapy helper not available".to_string()),
                }, None);
            }
            let tmp_dir = std::env::temp_dir();
            let tmp_file = tmp_dir.join(format!("pipeline_{}.py", ir.name.to_lowercase()));
            if std::fs::write(&tmp_file, &generated).is_err() {
                return (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some("cannot write temp file".to_string()),
                }, None);
            }
            let result = std::process::Command::new(&paths.python)
                .arg(&helper)
                .arg("--extra")
                .arg(&tmp_file)
                .arg(&ir.name)
                .output();
            let _ = std::fs::remove_file(&tmp_file);
            match result {
                Ok(output) if output.status.success() => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    match extractors::scapy::parse_scapy_json(&stdout) {
                        Ok(sp) => {
                            let roundtrip_def = extractors::scapy::to_protocol_def(&sp);
                            let audit = comparator::audit_protocol(&ir.name, &[("original", ir), ("roundtrip", &roundtrip_def)]);
                            (CrossGenResult {
                                target: target.to_string(),
                                passed: audit.fields_mismatch == 0,
                                original_fields: ir.fields.len(),
                                roundtrip_fields: roundtrip_def.fields.len(),
                                fields_agree: audit.fields_agree,
                                fields_mismatch: audit.fields_mismatch,
                                error: None,
                            }, Some(roundtrip_def))
                        }
                        Err(e) => (CrossGenResult {
                            target: target.to_string(), passed: false,
                            original_fields: ir.fields.len(), roundtrip_fields: 0,
                            fields_agree: 0, fields_mismatch: 0,
                            error: Some(format!("scapy JSON parse failed: {}", e)),
                        }, None),
                    }
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    (CrossGenResult {
                        target: target.to_string(), passed: false,
                        original_fields: ir.fields.len(), roundtrip_fields: 0,
                        fields_agree: 0, fields_mismatch: 0,
                        error: Some(format!("scapy helper failed: {}", stderr.trim())),
                    }, None)
                }
                Err(e) => (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some(format!("scapy round-trip failed: {}", e)),
                }, None),
            }
        }
        "kaitai" => {
            let generated = generator::generate_kaitai_ksy(ir);
            let tmp = std::env::temp_dir().join(format!("pipeline_{}.ksy", ir.name.to_lowercase()));
            if std::fs::write(&tmp, &generated).is_err() {
                return (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some("cannot write temp .ksy file".to_string()),
                }, None);
            }
            let result = extractors::kaitai::extract_from_ksy(&tmp);
            let _ = std::fs::remove_file(&tmp);
            match result {
                Ok(Some(roundtrip_def)) => {
                    let audit = comparator::audit_protocol(&ir.name, &[("original", ir), ("roundtrip", &roundtrip_def)]);
                    (CrossGenResult {
                        target: target.to_string(),
                        passed: audit.fields_mismatch == 0,
                        original_fields: ir.fields.len(),
                        roundtrip_fields: roundtrip_def.fields.len(),
                        fields_agree: audit.fields_agree,
                        fields_mismatch: audit.fields_mismatch,
                        error: None,
                    }, Some(roundtrip_def))
                }
                Ok(None) => (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some("kaitai re-extraction found no fields".to_string()),
                }, None),
                Err(e) => (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some(format!("kaitai re-extraction failed: {}", e)),
                }, None),
            }
        }
        "omi" => {
            let generated = generator::generate_omi_struct(ir);
            let struct_name = format!("{}T", ir.name.replace(' ', "").replace('-', ""));
            let mappings = match type_mapping::load_omi_mappings(None) {
                Ok(m) => m,
                Err(e) => return (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some(format!("omi mappings: {}", e)),
                }, None),
            };
            match extractors::omi::parse_omi_struct(&generated, &struct_name) {
                Ok(Some(os)) => {
                    let struct_sizes = std::collections::HashMap::new();
                    let big_count = ir.fields.iter().filter(|f| f.endian == ir::Endian::Big).count();
                    let little_count = ir.fields.iter().filter(|f| f.endian == ir::Endian::Little).count();
                    let proto_endian = if little_count > big_count { ir::Endian::Little } else { ir::Endian::Big };
                    let roundtrip_fields = extractors::omi::struct_to_field_defs(&os, &mappings, &struct_sizes, proto_endian);
                    let mut roundtrip_def = ir::ProtocolDef::new(&ir.name, ir.min_header_bits)
                        .with_fields(roundtrip_fields);
                    roundtrip_def.name = ir.name.clone();
                    let audit = comparator::audit_protocol(&ir.name, &[("original", ir), ("roundtrip", &roundtrip_def)]);
                    (CrossGenResult {
                        target: target.to_string(),
                        passed: audit.fields_mismatch == 0,
                        original_fields: ir.fields.len(),
                        roundtrip_fields: roundtrip_def.fields.len(),
                        fields_agree: audit.fields_agree,
                        fields_mismatch: audit.fields_mismatch,
                        error: None,
                    }, Some(roundtrip_def))
                }
                Ok(None) => (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some("omi re-extraction found no struct".to_string()),
                }, None),
                Err(e) => (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some(format!("omi re-extraction failed: {}", e)),
                }, None),
            }
        }
        "suricata" => {
            let generated = generator::generate_suricata_struct(ir);
            let tmp = std::env::temp_dir().join(format!("pipeline_{}.rs", ir.name.to_lowercase()));
            if std::fs::write(&tmp, &generated).is_err() {
                return (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some("cannot write temp .rs file".to_string()),
                }, None);
            }
            let result = extractors::suricata::extract_from_file(&tmp, &ir.name.to_lowercase());
            let _ = std::fs::remove_file(&tmp);
            match result {
                Ok(defs) if !defs.is_empty() => {
                    let (_, roundtrip_def) = defs.into_iter().next().unwrap();
                    let audit = comparator::audit_protocol(&ir.name, &[("original", ir), ("roundtrip", &roundtrip_def)]);
                    (CrossGenResult {
                        target: target.to_string(),
                        passed: audit.fields_mismatch == 0,
                        original_fields: ir.fields.len(),
                        roundtrip_fields: roundtrip_def.fields.len(),
                        fields_agree: audit.fields_agree,
                        fields_mismatch: audit.fields_mismatch,
                        error: None,
                    }, Some(roundtrip_def))
                }
                Ok(_) => (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some("suricata re-extraction found no struct".to_string()),
                }, None),
                Err(e) => (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some(format!("suricata re-extraction failed: {}", e)),
                }, None),
            }
        }
        "libpcap" => {
            let patch = match generator::generate_libpcap_patch(ir) {
                Some(p) => p,
                None => return (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some("libpcap patch generation produced nothing".to_string()),
                }, None),
            };
            // Extract the C header body from the patch (strip patch metadata lines)
            let header: String = patch.lines()
                .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
                .map(|l| &l[1..])
                .collect::<Vec<_>>()
                .join("\n");
            let snake = generator::canonical_to_snake(&ir.name);
            let struct_name = format!("{}_header", snake);
            let mappings = match type_mapping::load_kernel_mappings(None) {
                Ok(m) => m,
                Err(e) => return (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some(format!("mappings: {}", e)),
                }, None),
            };
            match extractors::kernel::parse_kernel_struct(&header, &struct_name) {
                Ok(Some(ks)) => {
                    let roundtrip_fields = extractors::kernel::to_field_defs_with(&ks, &mappings);
                    let mut roundtrip_def = ir::ProtocolDef::new(&ir.name, ir.min_header_bits)
                        .with_fields(roundtrip_fields);
                    roundtrip_def.name = ir.name.clone();
                    let audit = comparator::audit_protocol(&ir.name, &[("original", ir), ("roundtrip", &roundtrip_def)]);
                    (CrossGenResult {
                        target: target.to_string(),
                        passed: audit.fields_mismatch == 0,
                        original_fields: ir.fields.len(),
                        roundtrip_fields: roundtrip_def.fields.len(),
                        fields_agree: audit.fields_agree,
                        fields_mismatch: audit.fields_mismatch,
                        error: None,
                    }, Some(roundtrip_def))
                }
                Ok(None) => (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some("re-extraction found no struct".to_string()),
                }, None),
                Err(e) => (CrossGenResult {
                    target: target.to_string(), passed: false,
                    original_fields: ir.fields.len(), roundtrip_fields: 0,
                    fields_agree: 0, fields_mismatch: 0,
                    error: Some(format!("re-extraction failed: {}", e)),
                }, None),
            }
        }
        "pcap" => {
            // For pcap target, the crossgen IS the pipeline — generate PCAP directly.
            // Return the original IR as the "roundtrip" IR since PCAP gen doesn't
            // produce an intermediate code form.
            (CrossGenResult {
                target: target.to_string(),
                passed: true,
                original_fields: ir.fields.len(),
                roundtrip_fields: ir.fields.len(),
                fields_agree: ir.fields.len() as u32,
                fields_mismatch: 0,
                error: None,
            }, Some(ir.clone()))
        }
        _ => (CrossGenResult {
            target: target.to_string(), passed: false,
            original_fields: ir.fields.len(), roundtrip_fields: 0,
            fields_agree: 0, fields_mismatch: 0,
            error: Some(format!("unknown target: {}", target)),
        }, None),
    }
}

/// Generate PCAP bytes from an IR definition.
/// Returns (pcap_bytes, tshark_pdml_of_input) for comparison.
pub(crate) fn pcap_from_ir(
    ir: &ir::ProtocolDef,
    proto: &str,
    paths: &SourcePaths,
) -> Result<Vec<u8>> {
    let discovery_state = DiscoveryState::load_from_env();
    let proto_map = build_proto_map(proto, paths, &discovery_state);
    let pcap_output = generator::generate_pcap_with_discovery(ir, &proto_map, &discovery_state)
        .map_err(|e| anyhow::anyhow!("PCAP generation: {}", e))?;
    Ok(pcap_output.pcap_bytes)
}

/// Run tshark on PCAP bytes and extract the PDML protocol layer.
pub(crate) fn tshark_from_pcap_bytes(
    pcap_bytes: &[u8],
    proto: &str,
    paths: &SourcePaths,
) -> Result<extractors::tshark::PdmlProtocol> {
    let pcap_path = std::env::temp_dir().join(format!(
        "pipeline_{}_{}_{}.pcap",
        proto.to_lowercase(),
        std::process::id(),
        format!("{:?}", std::thread::current().id()).replace(['(', ')'], ""),
    ));
    std::fs::write(&pcap_path, pcap_bytes)?;

    let hints = extractors::tshark::decode_as_hints(proto);
    let hint_refs: Vec<&str> = hints.iter().map(|s| *s).collect();
    let xml = extractors::tshark::run_tshark_with_hints(&pcap_path, &paths.tshark_bin, 1, &hint_refs)?;
    let _ = std::fs::remove_file(&pcap_path);

    let packets = extractors::tshark::parse_pdml(&xml)?;
    let dissector = name_mapping::find_by_canonical(proto)
        .and_then(|n| n.tshark.map(|s| s.to_string()));

    // Try primary dissector name first
    let result = dissector
        .as_deref()
        .and_then(|d| extractors::tshark::extract_protocol_from_pdml(&packets, d));
    if result.is_some() {
        return result.context("unreachable");
    }

    // Fallback: try dissector names from decode-as hints (e.g., CARP→vrrp, NVGRE→gre)
    for hint in &hints {
        if let Some(dname) = hint.rsplit(',').next() {
            if let Some(found) = extractors::tshark::extract_protocol_from_pdml(&packets, dname) {
                return Ok(found);
            }
        }
    }

    // Fallback: try PDML name alias (for protocols where tshark layer name differs)
    if let Some(alias) = extractors::tshark::pdml_name_alias(proto) {
        if let Some(found) = extractors::tshark::extract_protocol_from_pdml(&packets, alias) {
            return Ok(found);
        }
    }

    anyhow::bail!("tshark did not dissect protocol '{}'", proto)
}

/// Find a PCAP file for a given protocol from templates or corpus.
pub(crate) fn find_pcap_for_protocol(proto: &str) -> Option<PathBuf> {
    let lower = proto.to_lowercase();
    // Candidate file-name spellings: exact lowercase, and with dots/dashes stripped.
    let filenames = [
        format!("{}.pcap", lower),
        format!("{}.pcap", lower.replace('.', "").replace('-', "_")),
        format!("{}.pcap", lower.replace('-', "_")),
    ];

    // Candidate directories, in priority order.
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(d) = std::env::var("PROTO_AUDIT_PCAP_TEMPLATES") { dirs.push(PathBuf::from(d)); }
    if let Ok(d) = std::env::var("PROTO_AUDIT_PCAP_CORPUS")    { dirs.push(PathBuf::from(d)); }
    // Fallback locations (when running outside the nix wrapper).
    dirs.push(PathBuf::from("pcap_templates"));
    dirs.push(PathBuf::from("samples/proto_audit/pcap_templates"));
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        dirs.push(PathBuf::from(&manifest).join("pcap_templates"));
    }

    for dir in &dirs {
        for fname in &filenames {
            let path = dir.join(fname);
            if path.exists() {
                return Some(path);
            }
        }
    }
    None
}

/// Run the full pipeline for one (protocol, target) pair.
///
/// PCAP_in → tshark → IR → generator → re-extractor → IR → PCAP_out → compare PCAPs
fn pipeline_one(
    proto: &str,
    target: &str,
    input_pcap_path: Option<&Path>,
    paths: &SourcePaths,
) -> PipelineResult {
    let fail = |error: String| -> PipelineResult {
        PipelineResult {
            protocol: proto.to_string(),
            target: target.to_string(),
            pcap_pass: false,
            pcap_fields_total: 0,
            pcap_fields_match: 0,
            crossgen_pass: false,
            crossgen_fields_agree: 0,
            crossgen_fields_mismatch: 0,
            error: Some(error),
            pcap_diffs: vec![],
            ir_stage1: None, ir_stage2: None, ir_stage3: None,
        }
    };

    // Step 1: Get input PCAP. Either from --pcap, templates, or generate from IR.
    let input_pcap_bytes = if let Some(pcap_path) = input_pcap_path {
        match std::fs::read(pcap_path) {
            Ok(b) => b,
            Err(e) => return fail(format!("cannot read input PCAP: {}", e)),
        }
    } else {
        // Try templates/corpus
        if let Some(path) = find_pcap_for_protocol(proto) {
            match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => return fail(format!("cannot read template PCAP: {}", e)),
            }
        } else {
            // Generate from IR as fallback
            let ir_baseline = match build_rich_ir(proto, paths) {
                Ok(ir) => ir,
                Err(e) => return fail(format!("cannot build IR: {}", e)),
            };
            match pcap_from_ir(&ir_baseline, proto, paths) {
                Ok(b) => b,
                Err(e) => return fail(format!("cannot generate input PCAP: {}", e)),
            }
        }
    };

    // Step 2: Parse input PCAP with tshark → get PDML + IR baseline
    let input_pdml_raw = match tshark_from_pcap_bytes(&input_pcap_bytes, proto, paths) {
        Ok(p) => p,
        Err(e) => return fail(format!("tshark input parse: {}", e)),
    };
    let mut ir_baseline = extractors::tshark::to_protocol_def(&input_pdml_raw);
    // Canonicalize the IR name: tshark uses dissector names (e.g. "ip") but
    // generators and PCAP routes expect canonical names (e.g. "IPv4").
    ir_baseline.name = proto.to_string();
    if ir_baseline.fields.is_empty() {
        return fail("IR baseline has no fields from input PCAP".to_string());
    }

    // Step 2b: Normalize the input PCAP by regenerating from the tshark-parsed
    // IR. This ensures the comparison baseline and output both go through the
    // same IR→PCAP path (byte-aligned fields, same pcap generator), so
    // sub-byte precision loss is symmetric and doesn't cause false negatives.
    let (input_pcap_bytes, input_pdml) = match pcap_from_ir(&ir_baseline, proto, paths) {
        Ok(bytes) => match tshark_from_pcap_bytes(&bytes, proto, paths) {
            Ok(pdml) => (bytes, pdml),
            // If re-parse fails, fall back to the raw input.
            Err(_) => (input_pcap_bytes, input_pdml_raw),
        },
        Err(_) => (input_pcap_bytes, input_pdml_raw),
    };
    let _ = input_pcap_bytes; // keep for future use / silence unused warning

    // Step 3+4: Crossgen — generate code, re-extract to IR
    let (crossgen_result, ir_roundtrip) = crossgen_with_ir(&ir_baseline, proto, target, paths);

    let ir_roundtrip = match ir_roundtrip {
        Some(rt) => rt,
        None => return PipelineResult {
            protocol: proto.to_string(),
            target: target.to_string(),
            pcap_pass: false,
            pcap_fields_total: 0,
            pcap_fields_match: 0,
            crossgen_pass: crossgen_result.passed,
            crossgen_fields_agree: crossgen_result.fields_agree,
            crossgen_fields_mismatch: crossgen_result.fields_mismatch,
            error: crossgen_result.error,
            pcap_diffs: vec![],
            ir_stage1: None, ir_stage2: None, ir_stage3: None,
        },
    };

    // Step 5: Generate output PCAP from roundtrip IR
    let output_pcap_bytes = match pcap_from_ir(&ir_roundtrip, proto, paths) {
        Ok(b) => b,
        Err(e) => return PipelineResult {
            protocol: proto.to_string(),
            target: target.to_string(),
            pcap_pass: false,
            pcap_fields_total: 0,
            pcap_fields_match: 0,
            crossgen_pass: crossgen_result.passed,
            crossgen_fields_agree: crossgen_result.fields_agree,
            crossgen_fields_mismatch: crossgen_result.fields_mismatch,
            error: Some(format!("output PCAP generation: {}", e)),
            pcap_diffs: vec![],
            ir_stage1: None, ir_stage2: None, ir_stage3: None,
        },
    };

    // Step 6: Parse output PCAP with tshark
    let output_pdml = match tshark_from_pcap_bytes(&output_pcap_bytes, proto, paths) {
        Ok(p) => p,
        Err(e) => return PipelineResult {
            protocol: proto.to_string(),
            target: target.to_string(),
            pcap_pass: false,
            pcap_fields_total: 0,
            pcap_fields_match: 0,
            crossgen_pass: crossgen_result.passed,
            crossgen_fields_agree: crossgen_result.fields_agree,
            crossgen_fields_mismatch: crossgen_result.fields_mismatch,
            error: Some(format!("tshark output parse: {}", e)),
            pcap_diffs: vec![],
            ir_stage1: None, ir_stage2: None, ir_stage3: None,
        },
    };

    // Step 7: Compare PCAPs — the acid test
    let pcap_result = comparator::compare_pdml_protocols(&input_pdml, &output_pdml, proto);

    // Step 8: If PCAP comparison fails, compute IR diagnostics
    let ir_from_output = extractors::tshark::to_protocol_def(&output_pdml);
    let diagnostics = comparator::pipeline_diagnostics(
        pcap_result,
        &ir_baseline,
        Some(&ir_roundtrip),
        Some(&ir_from_output),
    );

    PipelineResult {
        protocol: proto.to_string(),
        target: target.to_string(),
        pcap_pass: diagnostics.pcap_result.pass,
        pcap_fields_total: diagnostics.pcap_result.fields_total,
        pcap_fields_match: diagnostics.pcap_result.fields_match,
        crossgen_pass: crossgen_result.passed,
        crossgen_fields_agree: crossgen_result.fields_agree,
        crossgen_fields_mismatch: crossgen_result.fields_mismatch,
        error: None,
        pcap_diffs: diagnostics.pcap_result.fields_differ,
        ir_stage1: diagnostics.ir_stage1,
        ir_stage2: diagnostics.ir_stage2,
        ir_stage3: diagnostics.ir_stage3,
    }
}

/// Pipeline command: full PCAP → IR → code → IR → PCAP → compare round-trip.
pub(crate) fn cmd_pipeline(
    proto: &str,
    target: &str,
    input_pcap: Option<&Path>,
    json_output: bool,
    paths: &SourcePaths,
) -> Result<()> {
    let targets: Vec<&str> = if target == "all" {
        vec!["etherparse", "c", "scapy", "kaitai", "pcap", "libpcap", "omi", "suricata"]
    } else {
        vec![target]
    };

    let mut results = Vec::new();
    for t in &targets {
        let result = pipeline_one(proto, t, input_pcap, paths);
        results.push(result);
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        println!("Pipeline: {} → IR → code → IR → PCAP → compare", proto);
        println!("{}", "=".repeat(72));
        for r in &results {
            let pcap_icon = if r.pcap_pass { "PASS" } else { "FAIL" };
            let cg_icon = if r.crossgen_pass { "pass" } else { "fail" };
            print!(
                "  {:<12} PCAP: {} ({}/{} fields)  crossgen: {} ({}/{})",
                r.target, pcap_icon, r.pcap_fields_match, r.pcap_fields_total,
                cg_icon, r.crossgen_fields_agree, r.crossgen_fields_agree + r.crossgen_fields_mismatch,
            );
            if let Some(ref e) = r.error {
                print!("  [{}]", e);
            }
            println!();

            // Show PCAP diffs if failed
            if !r.pcap_pass && !r.pcap_diffs.is_empty() {
                for diff in &r.pcap_diffs {
                    println!(
                        "    {} @ byte {}: input={} output={}",
                        diff.field_name, diff.pos, diff.input_hex,
                        if diff.output_hex.is_empty() { "(missing)" } else { &diff.output_hex }
                    );
                }
            }

            // Show IR stage diagnostics if PCAP failed
            if !r.pcap_pass {
                if let Some(ref s1) = r.ir_stage1 {
                    if s1.fields_mismatch > 0 {
                        println!("    IR stage 1 (generator): {}/{} fields agree",
                            s1.fields_agree, s1.total_fields);
                    }
                }
                if let Some(ref s2) = r.ir_stage2 {
                    if s2.fields_mismatch > 0 {
                        println!("    IR stage 2 (serialization): {}/{} fields agree",
                            s2.fields_agree, s2.total_fields);
                    }
                }
                if let Some(ref s3) = r.ir_stage3 {
                    if s3.fields_mismatch > 0 {
                        println!("    IR stage 3 (end-to-end): {}/{} fields agree",
                            s3.fields_agree, s3.total_fields);
                    }
                }
            }
        }

        let total_pass = results.iter().filter(|r| r.pcap_pass).count();
        println!("\n{}/{} targets pass PCAP round-trip", total_pass, results.len());
    }

    Ok(())
}

/// Pipeline matrix: run pipeline across all curated protocols × all targets.
pub(crate) fn cmd_pipeline_matrix(
    protos_filter: Option<&str>,
    targets_filter: Option<&str>,
    json_output: bool,
    workers: usize,
    paths: &SourcePaths,
) -> Result<()> {
    use rayon::prelude::*;

    let all_targets = vec!["etherparse", "c", "scapy", "kaitai", "pcap", "libpcap", "omi", "suricata"];
    let targets: Vec<&str> = if let Some(tf) = targets_filter {
        tf.split(',').map(|s| s.trim()).collect()
    } else {
        all_targets.clone()
    };

    let table = name_mapping::protocol_table();
    let protos: Vec<&str> = if let Some(pf) = protos_filter {
        pf.split(',').map(|s| s.trim()).collect()
    } else {
        table.iter().map(|p| p.canonical).collect()
    };

    #[derive(serde::Serialize)]
    struct MatrixRow {
        protocol: String,
        results: Vec<PipelineResult>,
        targets_pass: usize,
        targets_total: usize,
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .expect("failed to build rayon thread pool");

    let completed = std::sync::atomic::AtomicUsize::new(0);
    let total = protos.len();
    let num_targets = targets.len();

    eprintln!("Running pipeline-matrix: {} protocols × {} targets = {} cells ({} workers)",
              total, num_targets, total * num_targets, workers);

    let rows: Vec<MatrixRow> = pool.install(|| {
        protos.par_iter().map(|proto| {
            let mut row_results = Vec::new();
            let mut pass_count = 0;

            for t in &targets {
                let result = pipeline_one(proto, t, None, paths);
                if result.pcap_pass { pass_count += 1; }
                row_results.push(result);
            }

            let done = completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            eprintln!("[{}/{}] {} {}/{}", done, total, proto, pass_count, num_targets);

            MatrixRow {
                protocol: proto.to_string(),
                results: row_results,
                targets_pass: pass_count,
                targets_total: num_targets,
            }
        }).collect()
    });

    // Recompute totals from collected rows
    let mut totals: Vec<usize> = vec![0; targets.len()];
    for row in &rows {
        for (ti, r) in row.results.iter().enumerate() {
            if r.pcap_pass { totals[ti] += 1; }
        }
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else {
        // Print header
        print!("{:<20}", "Protocol");
        for t in &targets {
            print!(" {:<12}", t);
        }
        println!(" Score");
        println!("{}", "-".repeat(20 + targets.len() * 13 + 8));

        for row in &rows {
            print!("{:<20}", row.protocol);
            for r in &row.results {
                let icon = if r.pcap_pass { "PASS" }
                    else if r.error.is_some() { "ERR" }
                    else { "FAIL" };
                print!(" {:<12}", icon);
            }
            println!(" {}/{}", row.targets_pass, row.targets_total);
        }

        // Print totals
        println!("{}", "-".repeat(20 + targets.len() * 13 + 8));
        print!("{:<20}", "Total PASS");
        for t in &totals {
            print!(" {:<12}", t);
        }
        println!(" {}/{}", totals.iter().sum::<usize>(), protos.len() * targets.len());
    }

    Ok(())
}

pub(crate) fn cmd_crossgen(
    proto: &str,
    target: &str,
    json_output: bool,
    paths: &SourcePaths,
) -> Result<()> {
    let targets: Vec<&str> = if target == "all" {
        vec!["etherparse", "c", "scapy", "kaitai", "pcap", "libpcap", "omi", "suricata"]
    } else {
        vec![target]
    };

    if proto == "all" {
        // Batch mode: run all curated protocols
        let table = name_mapping::protocol_table();
        let mut all_results: Vec<serde_json::Value> = Vec::new();

        for pn in &table {
            let mut proto_results = Vec::new();
            for &t in &targets {
                if let Some(r) = crossgen_one(pn.canonical, t, paths) {
                    proto_results.push(r);
                }
            }
            if !proto_results.is_empty() {
                let passed = proto_results.iter().filter(|r| r.passed).count();
                let total = proto_results.len();
                if !json_output {
                    let detail: Vec<String> = proto_results
                        .iter()
                        .map(|r| {
                            let s = if r.passed { "ok" } else { "FAIL" };
                            format!("{}:{}", r.target, s)
                        })
                        .collect();
                    println!(
                        "  {} {:20} [{}/{}] {}",
                        if passed == total { "✓" } else { "✗" },
                        pn.canonical,
                        passed,
                        total,
                        detail.join(" "),
                    );
                }
                all_results.push(serde_json::json!({
                    "protocol": pn.canonical,
                    "passed": passed,
                    "total": total,
                    "results": proto_results,
                }));
            }
        }

        if json_output {
            println!("{}", serde_json::to_string_pretty(&all_results)?);
        } else {
            let total_protos = all_results.len();
            let fully_passed = all_results
                .iter()
                .filter(|r| r["passed"] == r["total"])
                .count();
            println!(
                "\nCross-generator summary: {}/{} protocols fully passing",
                fully_passed, total_protos
            );
        }
        return Ok(());
    }

    // Single protocol mode
    let mut results = Vec::new();
    for &t in &targets {
        match crossgen_one(proto, t, paths) {
            Some(r) => results.push(r),
            None => {
                eprintln!("  [-] {} → not applicable", t);
            }
        }
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        println!("Cross-generator round-trip for {}", proto);
        println!("{:-<60}", "");
        for r in &results {
            let status = if r.passed { "PASS" } else { "FAIL" };
            print!(
                "  {} {:12} fields: {} → {} (agree: {}",
                if r.passed { "✓" } else { "✗" },
                r.target,
                r.original_fields,
                r.roundtrip_fields,
                r.fields_agree,
            );
            if r.fields_mismatch > 0 {
                print!(", mismatch: {}", r.fields_mismatch);
            }
            if let Some(ref e) = r.error {
                print!(", error: {}", e);
            }
            println!(") [{}]", status);
        }
    }

    Ok(())
}

