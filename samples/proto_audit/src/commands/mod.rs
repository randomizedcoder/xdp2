use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::{
    comparator,
    discovery::{self, DiscoveredProtocol, DiscoveryState, Tier, TierFilter},
    extractors, generator, ir, name_mapping, netlink, report, type_mapping, SourcePaths,
};

mod extract;
mod helpers;
mod reporting;
pub(crate) use extract::*;
pub(super) use helpers::*;
pub(crate) use reporting::*;



pub(crate) fn cmd_generate(
    proto: &str,
    from_json: Option<PathBuf>,
    target: &str,
    dry_run: bool,
    output: Option<PathBuf>,
    paths: &SourcePaths,
) -> Result<()> {
    // PCAP target has a different output path (binary, not text)
    if target == "pcap" {
        let protocol_def = if let Some(json_path) = from_json {
            let content = std::fs::read_to_string(&json_path)
                .with_context(|| format!("reading {}", json_path.display()))?;
            serde_json::from_str(&content).context("parsing IR JSON")?
        } else {
            build_rich_ir(proto, paths)?
        };

        let discovery_state = DiscoveryState::load_from_env();
        let proto_map = build_proto_map(proto, paths, &discovery_state);
        let pcap_output = generator::generate_pcap_with_discovery(&protocol_def, &proto_map, &discovery_state)
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        if dry_run {
            println!(
                "Stack: {}\nPacket: {} bytes\n\n{}",
                pcap_output.stack.join(" → "),
                pcap_output.packet_bytes.len(),
                generator::pcap::hex_dump(&pcap_output.packet_bytes),
            );
        } else if let Some(path) = output {
            std::fs::write(&path, &pcap_output.pcap_bytes)
                .with_context(|| format!("writing {}", path.display()))?;
            eprintln!(
                "Wrote {} bytes to {} (stack: {})",
                pcap_output.pcap_bytes.len(),
                path.display(),
                pcap_output.stack.join(" → "),
            );
        } else {
            // No output path and not dry-run: write to stdout as hex dump
            println!(
                "Stack: {}\nPacket: {} bytes\n\n{}",
                pcap_output.stack.join(" → "),
                pcap_output.packet_bytes.len(),
                generator::pcap::hex_dump(&pcap_output.packet_bytes),
            );
        }
        return Ok(());
    }

    // Load discovery state for fallback lookups
    let discovery_state = DiscoveryState::load_from_env();
    let discovered_protos = discovery::all_protocols(&discovery_state);

    let protocol_def = if let Some(json_path) = from_json {
        let content = std::fs::read_to_string(&json_path)
            .with_context(|| format!("reading {}", json_path.display()))?;
        serde_json::from_str(&content).context("parsing IR JSON")?
    } else if target == "c" {
        // For C target, try curated first, then discovered with kernel match
        if let Some(names) = name_mapping::find_by_canonical(proto) {
            let mut def = ir::ProtocolDef::new(names.canonical, names.min_header_bytes * 8);
            if names.variable_length {
                def = def.with_variable_length();
            }
            def
        } else if let Some(dp) = discovered_protos.get(proto) {
            // Discovered protocol — still need kernel struct for C target
            if dp.kernel_struct.is_some() {
                let batch = BatchCache::load(paths, &discovery_state);
                build_rich_ir_discovered(dp, &batch, paths)?
            } else {
                anyhow::bail!(
                    "Protocol '{}' has no kernel struct mapping — C target requires kernel struct. \
                     Try --target etherparse or --target scapy instead.",
                    proto
                )
            }
        } else {
            anyhow::bail!(
                "Unknown protocol: {}. Use --from-json for custom protocols.",
                proto
            )
        }
    } else {
        // For etherparse/scapy targets, try curated extraction first
        build_rich_ir(proto, paths).or_else(|_| {
            // Fall back to discovery lookup
            if let Some(dp) = discovered_protos.get(proto) {
                let batch = BatchCache::load(paths, &discovery_state);
                build_rich_ir_discovered(dp, &batch, paths)
            } else {
                // Try case-insensitive match
                let lower = proto.to_lowercase();
                if let Some((_, dp)) = discovered_protos
                    .iter()
                    .find(|(k, _)| k.to_lowercase() == lower)
                {
                    let batch = BatchCache::load(paths, &discovery_state);
                    build_rich_ir_discovered(dp, &batch, paths)
                } else {
                    anyhow::bail!(
                        "Unknown protocol: {}. Use --from-json for custom protocols.",
                        proto
                    )
                }
            }
        })?
    };

    let generated = match target {
        "c" => {
            // For discovered protocols with kernel struct, use with_names variant
            if let Some(dp) = discovered_protos.get(proto) {
                if name_mapping::find_by_canonical(proto).is_none() {
                    if let (Some(ref ks), Some(ref kh)) = (&dp.kernel_struct, &dp.kernel_header) {
                        generator::generate_proto_def_with_names(&protocol_def, ks, kh)
                    } else {
                        generator::generate_proto_def(&protocol_def)
                    }
                } else {
                    generator::generate_proto_def(&protocol_def)
                }
            } else {
                generator::generate_proto_def(&protocol_def)
            }
        }
        "etherparse" => generator::generate_etherparse(&protocol_def),
        "scapy" => generator::generate_scapy(&protocol_def),
        "wireshark" => generator::generate_wireshark_lua_single(&protocol_def),
        "xdp2-rs" => generator::generate_xdp2_rs(&protocol_def),
        _ => anyhow::bail!(
            "Unknown target '{}'. Valid targets: c, etherparse, scapy, pcap, wireshark, xdp2-rs",
            target
        ),
    };

    if dry_run {
        println!("{}", generated);
    } else if let Some(path) = output {
        std::fs::write(&path, &generated)
            .with_context(|| format!("writing {}", path.display()))?;
        eprintln!("Wrote: {}", path.display());
    } else {
        println!("{}", generated);
    }

    Ok(())
}



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
fn pcap_from_ir(
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
fn tshark_from_pcap_bytes(
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
fn find_pcap_for_protocol(proto: &str) -> Option<PathBuf> {
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

/// Auto-generate PCAP templates for protocols that lack them.
///
/// For each protocol without an existing template, attempts to generate a PCAP
/// using the existing IR-to-PCAP machinery and validates it via tshark.
pub(crate) fn cmd_generate_templates(
    protos_filter: &str,
    output_dir: &std::path::Path,
    dry_run: bool,
    workers: usize,
    paths: &SourcePaths,
) -> Result<()> {
    use rayon::prelude::*;

    let table = name_mapping::protocol_table();

    let protos: Vec<&str> = if protos_filter == "missing" {
        // Only protocols that don't already have a template
        table.iter()
            .map(|p| p.canonical)
            .filter(|p| find_pcap_for_protocol(p).is_none())
            .collect()
    } else {
        protos_filter.split(',').map(|s| s.trim()).collect()
    };

    eprintln!("Generating templates for {} protocols ({} workers)", protos.len(), workers);

    if !dry_run {
        std::fs::create_dir_all(output_dir)?;
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .expect("failed to build rayon thread pool");

    let completed = std::sync::atomic::AtomicUsize::new(0);
    let total = protos.len();

    struct TemplateResult {
        proto: String,
        success: bool,
        reason: String,
    }

    let results: Vec<TemplateResult> = pool.install(|| {
        protos.par_iter().map(|proto| {
            let done = completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;

            // Step 1: Build IR for this protocol
            let ir = match build_rich_ir(proto, paths) {
                Ok(ir) if !ir.fields.is_empty() => ir,
                Ok(_) => {
                    eprintln!("[{}/{}] {} SKIP (no fields in IR)", done, total, proto);
                    return TemplateResult {
                        proto: proto.to_string(),
                        success: false,
                        reason: "no fields in IR".into(),
                    };
                }
                Err(e) => {
                    eprintln!("[{}/{}] {} SKIP (no IR: {})", done, total, proto, e);
                    return TemplateResult {
                        proto: proto.to_string(),
                        success: false,
                        reason: format!("no IR: {}", e),
                    };
                }
            };

            // Step 2: Generate PCAP bytes from IR
            let pcap_bytes = match pcap_from_ir(&ir, proto, paths) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("[{}/{}] {} SKIP (PCAP gen failed: {})", done, total, proto, e);
                    return TemplateResult {
                        proto: proto.to_string(),
                        success: false,
                        reason: format!("PCAP gen failed: {}", e),
                    };
                }
            };

            // Step 3: Validate — does tshark dissect this protocol from the generated PCAP?
            match tshark_from_pcap_bytes(&pcap_bytes, proto, paths) {
                Ok(pdml) if !pdml.fields.is_empty() => {
                    // Success — tshark parsed it
                    if dry_run {
                        eprintln!("[{}/{}] {} OK (would write, {} fields, {} bytes)",
                                  done, total, proto, pdml.fields.len(), pcap_bytes.len());
                    } else {
                        let fname = format!("{}.pcap", proto.to_lowercase()
                            .replace(' ', "_").replace('-', "_").replace('/', "_"));
                        let out_path = output_dir.join(&fname);
                        if let Err(e) = std::fs::write(&out_path, &pcap_bytes) {
                            eprintln!("[{}/{}] {} FAIL (write error: {})", done, total, proto, e);
                            return TemplateResult {
                                proto: proto.to_string(),
                                success: false,
                                reason: format!("write error: {}", e),
                            };
                        }
                        eprintln!("[{}/{}] {} OK (wrote {}, {} fields)",
                                  done, total, proto, fname, pdml.fields.len());
                    }
                    TemplateResult {
                        proto: proto.to_string(),
                        success: true,
                        reason: format!("{} fields", pdml.fields.len()),
                    }
                }
                Ok(_) => {
                    eprintln!("[{}/{}] {} SKIP (tshark parsed 0 fields)", done, total, proto);
                    TemplateResult {
                        proto: proto.to_string(),
                        success: false,
                        reason: "tshark parsed 0 fields".into(),
                    }
                }
                Err(e) => {
                    eprintln!("[{}/{}] {} SKIP (tshark: {})", done, total, proto, e);
                    TemplateResult {
                        proto: proto.to_string(),
                        success: false,
                        reason: format!("tshark: {}", e),
                    }
                }
            }
        }).collect()
    });

    // Summary
    let succeeded: Vec<_> = results.iter().filter(|r| r.success).collect();
    let failed: Vec<_> = results.iter().filter(|r| !r.success).collect();

    println!("\n=== Template Generation Summary ===");
    println!("Generated: {}/{}", succeeded.len(), results.len());
    println!("Skipped:   {}/{}", failed.len(), results.len());

    if !succeeded.is_empty() {
        println!("\nGenerated templates:");
        for r in &succeeded {
            println!("  {} ({})", r.proto, r.reason);
        }
    }

    if !failed.is_empty() {
        println!("\nSkipped protocols:");
        // Group by reason
        let mut by_reason: std::collections::BTreeMap<&str, Vec<&str>> = std::collections::BTreeMap::new();
        for r in &failed {
            by_reason.entry(&r.reason).or_default().push(&r.proto);
        }
        for (reason, protos) in &by_reason {
            println!("  {} ({}): {}", reason, protos.len(),
                     if protos.len() <= 10 { protos.join(", ") }
                     else { format!("{}, ... and {} more", protos[..5].join(", "), protos.len() - 5) });
        }
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

pub(crate) fn cmd_validate(
    proto: &str,
    tier: &str,
    keep_pcap: Option<PathBuf>,
    json_output: bool,
    paths: &SourcePaths,
) -> Result<()> {
    // Handle --proto all: validate all routable protocols
    if proto == "all" {
        return cmd_validate_all(tier, json_output, paths);
    }

    let tier_filter = TierFilter::from_str(tier);
    let discovery_state = DiscoveryState::load_from_env();
    let discovered_protos = discovery::all_protocols(&discovery_state);

    // For discovered-tier protocols, resolve through discovery
    let (effective_proto, tshark_dissector) =
        resolve_protocol(proto, tier_filter, &discovered_protos);

    // Step 1: Build rich IR for target protocol
    let protocol_def = build_rich_ir(&effective_proto, paths)
        .or_else(|_| {
            // Fallback for discovered protocols: try tshark extraction directly
            if let Some(ref dissector) = tshark_dissector {
                let pcap_path = paths.pcap.as_ref().context("no PCAP path")?;
                let xml =
                    extractors::tshark::run_tshark(pcap_path, &paths.tshark_bin, 10)?;
                let packets = extractors::tshark::parse_pdml(&xml)?;
                if let Some(pdml) =
                    extractors::tshark::extract_protocol_from_pdml(&packets, dissector)
                {
                    let mut def = extractors::tshark::to_protocol_def(&pdml);
                    def.name = effective_proto.clone();
                    return Ok(def);
                }
            }
            anyhow::bail!("Cannot build IR for '{}'", effective_proto)
        })?;
    eprintln!(
        "  [1/5] Built IR for {} ({} fields)",
        effective_proto,
        protocol_def.fields.len()
    );

    // Step 2: Build proto map for stack construction
    let proto_map = build_proto_map(&effective_proto, paths, &discovery_state);
    eprintln!("  [2/5] Built protocol map ({} entries)", proto_map.len());

    // Step 3: Generate PCAP
    let pcap_output = generator::generate_pcap_with_discovery(&protocol_def, &proto_map, &discovery_state)
        .map_err(|e| anyhow::anyhow!("PCAP generation failed: {}", e))?;
    eprintln!(
        "  [3/5] Generated PCAP ({} bytes, stack: {})",
        pcap_output.pcap_bytes.len(),
        pcap_output.stack.join(" → "),
    );

    // Write to temp file (or keep_pcap path)
    let pcap_path = if let Some(ref path) = keep_pcap {
        std::fs::write(path, &pcap_output.pcap_bytes)
            .with_context(|| format!("writing {}", path.display()))?;
        eprintln!("       Saved PCAP to {}", path.display());
        path.clone()
    } else {
        let tmp = std::env::temp_dir().join(format!(
            "proto-audit-{}.pcap",
            effective_proto.to_lowercase()
        ));
        std::fs::write(&tmp, &pcap_output.pcap_bytes)
            .with_context(|| format!("writing temp PCAP {}", tmp.display()))?;
        tmp
    };

    // Step 4: Run tshark on the generated PCAP (with decode-as hints if needed)
    let hints = extractors::tshark::decode_as_hints(&effective_proto);
    let hint_refs: Vec<&str> = hints.iter().map(|s| *s).collect();
    let xml = extractors::tshark::run_tshark_with_hints(&pcap_path, &paths.tshark_bin, 1, &hint_refs)
        .context("running tshark on generated PCAP")?;
    let packets = extractors::tshark::parse_pdml(&xml)
        .context("parsing tshark PDML output")?;
    eprintln!("  [4/5] tshark parsed {} packet(s){}", packets.len(),
        if hints.is_empty() { String::new() } else { format!(" (decode-as: {})", hints.join(", ")) });

    // Find the target protocol in tshark output
    let dissector = tshark_dissector.or_else(|| {
        name_mapping::find_by_canonical(&effective_proto)
            .and_then(|n| n.tshark.map(|s| s.to_string()))
    });

    let tshark_proto = dissector
        .as_deref()
        .and_then(|d| extractors::tshark::extract_protocol_from_pdml(&packets, d))
        // Fallback: try dissector names from decode-as hints (e.g., TWAMP→twamp.test)
        .or_else(|| {
            hints.iter().find_map(|hint| {
                hint.rsplit(',').next().and_then(|dname| {
                    extractors::tshark::extract_protocol_from_pdml(&packets, dname)
                })
            })
        })
        // Fallback: try PDML name alias (for protocols where tshark layer name differs)
        .or_else(|| {
            extractors::tshark::pdml_name_alias(&effective_proto)
                .and_then(|alias| extractors::tshark::extract_protocol_from_pdml(&packets, alias))
        });
    let tshark_def = match tshark_proto {
        Some(pdml) => extractors::tshark::to_protocol_def(&pdml),
        None => {
            let msg = format!(
                "tshark did not produce a dissection for '{}'. The PCAP was generated \
                 but tshark could not parse the target protocol layer.",
                effective_proto
            );
            eprintln!("  [5/5] {}", msg);
            // Save as Unvalidated so the protocol is at least tracked in the cache
            let result = ir::AuditResult {
                protocol: effective_proto.clone(),
                sources_present: vec![],
                sources_missing: vec![],
                field_comparisons: vec![],
                total_fields: 0,
                fields_agree: 0,
                fields_type_differ: 0,
                fields_mismatch: 0,
                fields_missing: 0,
                validation_tier: Some(discovery::ValidationTier::Unvalidated),
            };
            let _ = save_validation_result(&effective_proto, &result);
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "protocol": effective_proto,
                        "status": "no_dissect",
                        "validation_tier": "Unvalidated",
                        "message": msg,
                    }))?
                );
            }
            if keep_pcap.is_none() {
                let _ = std::fs::remove_file(&pcap_path);
            }
            return Ok(());
        }
    };

    // Step 5: Compare original IR vs tshark round-trip result
    let refs: Vec<(&str, &ir::ProtocolDef)> = vec![
        ("ir", &protocol_def),
        ("tshark-roundtrip", &tshark_def),
    ];
    let mut result = comparator::audit_protocol(&effective_proto, &refs);

    // Count split mismatches that are covered (sub-fields tile exactly or
    // both sources cover the same bit region).
    let covered_splits = comparator::count_covered_splits(&result, &protocol_def, &tshark_def);
    eprintln!("  [5/5] Comparison complete (splits: {} total, {} covered)", result.fields_mismatch, covered_splits);

    // Override validation tier: Gold — tshark recognized the protocol.
    // The protocol was found in PDML output, meaning the PCAP round-trip
    // succeeded. Even if the protocol has 0 extractable fields (e.g.,
    // Teredo is just a tunnel wrapper), tshark still validated the packet.
    // Split mismatches (field boundary disagreements) don't block Gold.
    result.validation_tier = Some(discovery::ValidationTier::Gold);

    // Persist validation result to cache file
    if let Err(e) = save_validation_result(&effective_proto, &result) {
        eprintln!("  warning: failed to save validation cache: {}", e);
    }

    if json_output {
        let output = serde_json::json!({
            "protocol": effective_proto,
            "status": if result.fields_mismatch.saturating_sub(covered_splits) == 0 { "pass" } else { "fail" },
            "validation_tier": result.validation_tier.as_ref().map(|t| t.to_string()),
            "stack": pcap_output.stack,
            "pcap_bytes": pcap_output.pcap_bytes.len(),
            "ir_fields": protocol_def.fields.len(),
            "tshark_fields": tshark_def.fields.len(),
            "covered_splits": covered_splits,
            "uncovered_mismatches": result.fields_mismatch.saturating_sub(covered_splits),
            "audit": result,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Round-trip validation: {}", effective_proto);
        println!("  Stack: {}", pcap_output.stack.join(" → "));
        println!("  PCAP:  {} bytes", pcap_output.pcap_bytes.len());
        println!("  IR fields:     {}", protocol_def.fields.len());
        println!("  tshark fields: {}", tshark_def.fields.len());
        println!(
            "  Agreement:     {}/{} fields",
            result.fields_agree, result.total_fields
        );
        if result.fields_type_differ > 0 {
            println!("  Type differ:   {} fields", result.fields_type_differ);
        }
        if result.fields_mismatch > 0 {
            println!("  Mismatch:      {} fields ({} covered splits)", result.fields_mismatch, covered_splits);
        }
        if result.fields_missing > 0 {
            println!("  Missing:       {} fields", result.fields_missing);
        }
        println!(
            "  Status:        {}",
            if result.fields_mismatch.saturating_sub(covered_splits) == 0 {
                "PASS"
            } else {
                "FAIL"
            }
        );

        // Show details for mismatches
        let mismatched: Vec<_> = result
            .field_comparisons
            .iter()
            .filter(|fc| !fc.mismatches.is_empty())
            .collect();
        if !mismatched.is_empty() {
            println!("\n  Field details:");
            for fc in mismatched {
                for m in &fc.mismatches {
                    println!(
                        "    {} [{}]: expected {}, got {}",
                        fc.name, m.source, m.expected, m.actual
                    );
                }
            }
        }
    }

    // Clean up temp file if not keeping
    if keep_pcap.is_none() {
        let _ = std::fs::remove_file(&pcap_path);
    }

    Ok(())
}
pub(crate) fn cmd_generate_all(
    target: &str,
    tier: &str,
    output_dir: Option<PathBuf>,
    count_only: bool,
    min_fields: Option<usize>,
    json_output: bool,
    paths: &SourcePaths,
) -> Result<()> {
    // Reject targets we can't batch-generate
    if target == "pcap" {
        anyhow::bail!(
            "generate-all does not support target 'pcap' — use 'c', 'etherparse', or 'scapy'."
        );
    }
    if target != "c" && target != "etherparse" && target != "scapy" {
        anyhow::bail!(
            "Unknown target '{}'. Valid targets for generate-all: c, etherparse, scapy",
            target
        );
    }

    let tier_filter = TierFilter::from_str(tier);
    let discovery_state = DiscoveryState::load_from_env();
    let all_protos = discovery::all_protocols(&discovery_state);
    let min_fields = min_fields.unwrap_or(1);

    eprintln!("Loading batch caches...");
    let batch = BatchCache::load(paths, &discovery_state);

    // Stats counters
    let mut stats = GenerateAllStats::default();

    let filtered_protos: Vec<_> = all_protos
        .iter()
        .filter(|(_, dp)| tier_filter.matches(dp.tier))
        .collect();

    eprintln!(
        "Processing {} protocols (tier={}, target={})...",
        filtered_protos.len(),
        tier,
        target
    );

    // Create output dir if needed
    if let Some(ref dir) = output_dir {
        if !count_only {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating output dir {}", dir.display()))?;
        }
    }

    let mut generated_protos: Vec<serde_json::Value> = Vec::new();

    for (name, dp) in &filtered_protos {
        // Build IR
        let ir = if dp.tier == Tier::Curated {
            match build_rich_ir(name, paths) {
                Ok(mut def) => {
                    if def.generation_source.is_none() {
                        def.generation_source = Some("curated".to_string());
                    }
                    Some(def)
                }
                Err(_) => None,
            }
        } else {
            build_rich_ir_discovered(dp, &batch, paths).ok()
        };

        let ir = match ir {
            Some(def) if def.fields.len() >= min_fields => def,
            _ => {
                stats.skipped += 1;
                continue;
            }
        };

        let source = ir
            .generation_source
            .as_deref()
            .unwrap_or("unknown")
            .to_string();
        match source.as_str() {
            "curated" => stats.curated += 1,
            "scapy-batch" => stats.scapy_batch += 1,
            "tshark-pdml" => stats.tshark_pdml += 1,
            "tshark-registry" => stats.tshark_registry += 1,
            _ => stats.curated += 1,
        }
        stats.total += 1;

        if count_only {
            if json_output {
                generated_protos.push(serde_json::json!({
                    "protocol": name,
                    "tier": dp.tier.to_string(),
                    "source": source,
                    "fields": ir.fields.len(),
                    "has_kernel_struct": dp.kernel_struct.is_some(),
                    "xdp2_tier": classify_xdp2_tier(name, dp),
                }));
            }
            continue;
        }

        // Generate code
        let generated = match target {
            "c" => {
                // C target: use kernel struct if available, otherwise synthetic
                if let Some(names) = name_mapping::find_by_canonical(name) {
                    if names.kernel_struct.is_some() {
                        generator::generate_proto_def(&ir)
                    } else {
                        generator::generate_proto_def_synthetic(&ir)
                    }
                } else if let (Some(ref ks), Some(ref kh)) =
                    (&dp.kernel_struct, &dp.kernel_header)
                {
                    generator::generate_proto_def_with_names(&ir, ks, kh)
                } else {
                    generator::generate_proto_def_synthetic(&ir)
                }
            }
            "etherparse" => generator::generate_etherparse(&ir),
            "scapy" => generator::generate_scapy(&ir),
            _ => unreachable!(),
        };

        if let Some(ref dir) = output_dir {
            let ext = match target {
                "c" => "h",
                "etherparse" => "rs",
                "scapy" => "py",
                _ => "txt",
            };
            let sanitized = generator::canonical_to_snake(name)
                .replace('/', "_")
                .replace('\\', "_");
            let filename = format!("{}.{}", sanitized, ext);
            let path = dir.join(&filename);
            std::fs::write(&path, &generated)
                .with_context(|| format!("writing {}", path.display()))?;
        } else {
            println!("// === {} (source: {}) ===\n{}\n", name, source, generated);
        }
    }

    // Print summary
    if json_output {
        let output = serde_json::json!({
            "target": target,
            "tier": tier,
            "stats": {
                "total": stats.total,
                "curated": stats.curated,
                "scapy_batch": stats.scapy_batch,
                "tshark_pdml": stats.tshark_pdml,
                "tshark_registry": stats.tshark_registry,
                "skipped": stats.skipped,
            },
            "protocols": if count_only { Some(&generated_protos) } else { None },
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("\nTranslatable protocols by source:");
        println!("  Curated (6-source):    {:>6}  (targets: c, etherparse, scapy, pcap)", stats.curated);
        println!("  Scapy batch:           {:>6}  (targets: etherparse, scapy)", stats.scapy_batch);
        println!("  tshark PDML:           {:>6}  (targets: etherparse, scapy)", stats.tshark_pdml);
        println!("  tshark -G fields:      {:>6}  (targets: etherparse, scapy)", stats.tshark_registry);
        println!("  Total:                 {:>6}", stats.total);
        println!("  Skipped (0 fields):    {:>6}", stats.skipped);
        if let Some(ref dir) = output_dir {
            println!("\n  Output: {}", dir.display());
        }
    }

    Ok(())
}

/// Generate libpcap overlay patches from corpus PDML data.
///
/// For each protocol that has tshark PDML data in the corpus but no existing
/// libpcap patch, generates a C struct patch file and prints the corresponding
/// libpcap.toml and table.rs entries.
pub(crate) fn cmd_generate_libpcap_patches(
    output_dir: Option<PathBuf>,
    protos: Option<&str>,
    min_fields: usize,
    dry_run: bool,
    paths: &SourcePaths,
) -> Result<()> {
    // Load corpus PDML cache
    let corpus_dir = std::env::var("PROTO_AUDIT_PCAP_CORPUS")
        .context("PROTO_AUDIT_PCAP_CORPUS not set — run via `nix run .#proto-audit`")?;
    let corpus_path = std::path::Path::new(&corpus_dir);
    let mut corpus_cache: std::collections::HashMap<String, ir::ProtocolDef> = std::collections::HashMap::new();

    eprintln!("Loading corpus PDML...");
    if let Ok(entries) = std::fs::read_dir(corpus_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("xml") {
                continue;
            }
            if let Ok(xml) = std::fs::read_to_string(&path) {
                if let Ok(packets) = extractors::tshark::parse_pdml(&xml) {
                    let file_protos = extractors::tshark::extract_all_protocols_from_pdml(&packets);
                    for (name, def) in file_protos {
                        corpus_cache.entry(name).or_insert(def);
                    }
                }
            }
        }
    }
    eprintln!("Corpus: {} protocols with PDML data", corpus_cache.len());

    // Determine which protocols already have libpcap patches
    let existing_patches: std::collections::HashSet<String> = name_mapping::protocol_table()
        .iter()
        .filter_map(|p| p.libpcap_name.map(|_| p.canonical.to_string()))
        .collect();

    // Build candidate list
    let filter_protos: Option<std::collections::HashSet<String>> = protos.map(|p| {
        p.split(',').map(|s| s.trim().to_string()).collect()
    });

    // Map tshark filter names to canonical names
    let tshark_to_canonical: std::collections::HashMap<String, String> = name_mapping::protocol_table()
        .iter()
        .filter_map(|p| {
            p.tshark.map(|t| (t.to_string(), p.canonical.to_string()))
        })
        .collect();

    let default_dir = PathBuf::from("samples/proto_audit/patches/libpcap");
    let out_dir = output_dir.as_ref().unwrap_or(&default_dir);

    let mut generated = 0u32;
    let mut toml_entries = Vec::new();
    let mut table_entries = Vec::new();

    // Sort by field count descending for priority
    let mut candidates: Vec<(String, ir::ProtocolDef)> = corpus_cache
        .into_iter()
        .filter(|(filter, def)| {
            // Has enough fields
            if def.fields.len() < min_fields {
                return false;
            }
            // Has byte-aligned fields (can generate a C struct)
            let byte_aligned = def.fields.iter().filter(|f| {
                f.offset_bits % 8 == 0 && f.size_bits % 8 == 0 && f.size_bits > 0
            }).count();
            if byte_aligned < min_fields {
                return false;
            }
            // Map to canonical name and check if already has a patch
            if let Some(canonical) = tshark_to_canonical.get(filter) {
                if existing_patches.contains(canonical) {
                    return false;
                }
                if let Some(ref fp) = filter_protos {
                    return fp.contains(canonical);
                }
            } else if let Some(ref fp) = filter_protos {
                return fp.contains(filter);
            }
            true
        })
        .collect();

    candidates.sort_by(|a, b| b.1.fields.len().cmp(&a.1.fields.len()));

    for (filter, mut def) in candidates {
        // Use canonical name if available
        let canonical = tshark_to_canonical.get(&filter).cloned().unwrap_or_else(|| {
            // Capitalize filter name as canonical
            let mut c = filter.chars();
            match c.next() {
                None => filter.clone(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        });
        def.name = canonical.clone();

        let patch = match generator::generate_libpcap_patch(&def) {
            Some(p) => p,
            None => continue,
        };

        let snake = generator::canonical_to_snake(&canonical);

        if dry_run {
            println!("=== {} ({} fields from tshark '{}') ===", canonical, def.fields.len(), filter);
            println!("{}", patch);
            if let Some(toml) = generator::generate_libpcap_toml_entry(&def) {
                println!("{}", toml);
            }
            println!();
        } else {
            let patch_path = out_dir.join(format!("{}.patch", snake));
            std::fs::write(&patch_path, &patch)
                .with_context(|| format!("writing {}", patch_path.display()))?;
            eprintln!("  Wrote {}", patch_path.display());
        }

        if let Some(toml) = generator::generate_libpcap_toml_entry(&def) {
            toml_entries.push(toml);
        }

        let struct_name = format!("{}_header", snake);
        let file_path = format!("pcap/proto_audit/{}.h", snake);
        table_entries.push(format!(
            "        .libpcap(\"{}\", \"{}\")",
            struct_name, file_path
        ));

        generated += 1;
    }

    eprintln!("\nGenerated {} libpcap patches", generated);

    if !toml_entries.is_empty() {
        eprintln!("\n--- Add to mappings/libpcap.toml ---");
        for entry in &toml_entries {
            eprintln!("{}", entry);
        }
    }

    if !table_entries.is_empty() {
        eprintln!("\n--- Add to table.rs (.libpcap() calls) ---");
        for entry in &table_entries {
            eprintln!("{}", entry);
        }
    }

    Ok(())
}

/// Generate upstream patches directly from structured-source IR (no corpus).
///
/// Walks the name-mapping table, filters entries whose `<source>_struct` slot
/// is populated, extracts each via the corresponding extractor, and pipes the
/// resulting IR through `generate_libpcap_patch` / `generate_etherparse_patch`.
/// Used to ship trading-protocol patches to upstreams without live PCAPs.
pub(crate) fn cmd_gen_patches(
    target: &str,
    source: &str,
    protos: Option<&str>,
    out: Option<PathBuf>,
    dry_run: bool,
    paths: &SourcePaths,
) -> Result<()> {
    if source != "omi" {
        anyhow::bail!(
            "gen-patches currently only supports --source omi (got '{}')",
            source
        );
    }
    let valid_targets = ["libpcap", "etherparse", "scapy", "kaitai"];
    if !valid_targets.contains(&target) {
        anyhow::bail!(
            "gen-patches --target must be one of: {} (got '{}')",
            valid_targets.join(", "),
            target
        );
    }

    let filter: Option<std::collections::HashSet<String>> = protos
        .map(|p| p.split(',').map(|s| s.trim().to_string()).collect());

    let default_dir = match target {
        "libpcap" => PathBuf::from("samples/proto_audit/patches/libpcap"),
        "etherparse" => PathBuf::from("samples/proto_audit/patches/etherparse"),
        "scapy" => PathBuf::from("samples/proto_audit/patches/scapy"),
        "kaitai" => PathBuf::from("samples/proto_audit/patches/kaitai"),
        _ => unreachable!(),
    };
    let out_dir = out.unwrap_or(default_dir);

    let mappings = type_mapping::load_omi_mappings(None)
        .context("loading OMI type mappings")?;

    let mut generated: u32 = 0;
    let mut skipped_no_fields: u32 = 0;
    let mut skipped_no_patch: u32 = 0;

    for p in name_mapping::protocol_table() {
        let (omi_struct, omi_file) = match (p.omi_struct, p.omi_file) {
            (Some(s), Some(f)) => (s, f),
            _ => continue,
        };
        if let Some(ref f) = filter {
            if !f.contains(p.canonical) {
                continue;
            }
        }

        let mut def = match extractors::omi::extract_protocol(
            paths.omi_cstructs_dir.as_deref(),
            p.canonical,
            omi_struct,
            omi_file,
            &mappings,
        ) {
            Ok(Some(d)) => d,
            Ok(None) => {
                skipped_no_fields += 1;
                continue;
            }
            Err(e) => {
                eprintln!("  skip {}: {}", p.canonical, e);
                continue;
            }
        };
        def.name = p.canonical.to_string();
        def.is_variable_length = p.variable_length;

        let patch = match target {
            "libpcap" => generator::generate_libpcap_patch(&def),
            "etherparse" => generator::generate_etherparse_patch(&def),
            "scapy" => generator::generate_scapy_patch(&def),
            "kaitai" => generator::generate_kaitai_patch(&def),
            _ => unreachable!(),
        };
        let Some(patch) = patch else {
            skipped_no_patch += 1;
            continue;
        };

        let snake = generator::canonical_to_snake(&def.name);
        let patch_name = format!("trading_{}.patch", snake);

        if dry_run {
            println!("=== {} ({} fields) → {} ===", def.name, def.fields.len(), patch_name);
            println!("{}", patch);
        } else {
            std::fs::create_dir_all(&out_dir)
                .with_context(|| format!("creating {}", out_dir.display()))?;
            let patch_path = out_dir.join(&patch_name);
            std::fs::write(&patch_path, &patch)
                .with_context(|| format!("writing {}", patch_path.display()))?;
            eprintln!("  Wrote {}", patch_path.display());
        }
        generated += 1;
    }

    eprintln!(
        "\nGenerated {} {} patches (skipped: {} no-fields, {} no-patch)",
        generated, target, skipped_no_fields, skipped_no_patch
    );
    Ok(())
}

/// Generate etherparse Rust struct patches from corpus PDML data.
///
/// For each protocol that has tshark PDML data in the corpus but no existing
/// etherparse patch, generates a Rust struct patch file and prints the corresponding
/// etherparse.toml and table.rs entries.
pub(crate) fn cmd_generate_etherparse_patches(
    output_dir: Option<PathBuf>,
    protos: Option<&str>,
    min_fields: usize,
    dry_run: bool,
    paths: &SourcePaths,
) -> Result<()> {
    // Load corpus PDML cache
    let corpus_dir = std::env::var("PROTO_AUDIT_PCAP_CORPUS")
        .context("PROTO_AUDIT_PCAP_CORPUS not set — run via `nix run .#proto-audit`")?;
    let corpus_path = std::path::Path::new(&corpus_dir);
    let mut corpus_cache: std::collections::HashMap<String, ir::ProtocolDef> = std::collections::HashMap::new();

    eprintln!("Loading corpus PDML...");
    if let Ok(entries) = std::fs::read_dir(corpus_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("xml") {
                continue;
            }
            if let Ok(xml) = std::fs::read_to_string(&path) {
                if let Ok(packets) = extractors::tshark::parse_pdml(&xml) {
                    let file_protos = extractors::tshark::extract_all_protocols_from_pdml(&packets);
                    for (name, def) in file_protos {
                        corpus_cache.entry(name).or_insert(def);
                    }
                }
            }
        }
    }
    eprintln!("Corpus: {} protocols with PDML data", corpus_cache.len());

    // Determine which protocols already have etherparse entries
    let existing_etherparse: std::collections::HashSet<String> = name_mapping::protocol_table()
        .iter()
        .filter_map(|p| p.etherparse_struct.map(|_| p.canonical.to_string()))
        .collect();

    // Build candidate list
    let filter_protos: Option<std::collections::HashSet<String>> = protos.map(|p| {
        p.split(',').map(|s| s.trim().to_string()).collect()
    });

    // Map tshark filter names to canonical names
    let tshark_to_canonical: std::collections::HashMap<String, String> = name_mapping::protocol_table()
        .iter()
        .filter_map(|p| {
            p.tshark.map(|t| (t.to_string(), p.canonical.to_string()))
        })
        .collect();

    let default_dir = PathBuf::from("samples/proto_audit/patches/etherparse");
    let out_dir = output_dir.as_ref().unwrap_or(&default_dir);

    let mut generated = 0u32;
    let mut toml_entries = Vec::new();
    let mut table_entries = Vec::new();

    // Sort by field count descending for priority
    let mut candidates: Vec<(String, ir::ProtocolDef)> = corpus_cache
        .into_iter()
        .filter(|(filter, def)| {
            // Has enough fields
            if def.fields.len() < min_fields {
                return false;
            }
            // Has byte-aligned fields (can generate a Rust struct)
            let byte_aligned = def.fields.iter().filter(|f| {
                f.offset_bits % 8 == 0 && f.size_bits % 8 == 0 && f.size_bits > 0
            }).count();
            if byte_aligned < min_fields {
                return false;
            }
            // Map to canonical name and check if already has etherparse
            if let Some(canonical) = tshark_to_canonical.get(filter) {
                if existing_etherparse.contains(canonical) {
                    return false;
                }
                if let Some(ref fp) = filter_protos {
                    return fp.contains(canonical);
                }
            } else if let Some(ref fp) = filter_protos {
                return fp.contains(filter);
            }
            true
        })
        .collect();

    candidates.sort_by(|a, b| b.1.fields.len().cmp(&a.1.fields.len()));

    for (filter, mut def) in candidates {
        // Use canonical name if available
        let canonical = tshark_to_canonical.get(&filter).cloned().unwrap_or_else(|| {
            let mut c = filter.chars();
            match c.next() {
                None => filter.clone(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        });
        def.name = canonical.clone();

        let patch = match generator::generate_etherparse_patch(&def) {
            Some(p) => p,
            None => continue,
        };

        let snake = generator::canonical_to_snake(&canonical);

        if dry_run {
            println!("=== {} ({} fields from tshark '{}') ===", canonical, def.fields.len(), filter);
            println!("{}", patch);
            if let Some(toml) = generator::generate_etherparse_toml_entry(&def) {
                println!("{}", toml);
            }
            println!();
        } else {
            let patch_path = out_dir.join(format!("{}.patch", snake));
            std::fs::write(&patch_path, &patch)
                .with_context(|| format!("writing {}", patch_path.display()))?;
            eprintln!("  Wrote {}", patch_path.display());
        }

        if let Some(toml) = generator::generate_etherparse_toml_entry(&def) {
            toml_entries.push(toml);
        }

        let struct_name = format!("{}Header", generator::canonical_to_pascal(&canonical));
        let file_path = format!("src/proto_audit/{}.rs", snake);
        table_entries.push(format!(
            "        .etherparse(\"{}\", \"{}\")",
            struct_name, file_path
        ));

        generated += 1;
    }

    eprintln!("\nGenerated {} etherparse patches", generated);

    if !toml_entries.is_empty() {
        eprintln!("\n--- Add to mappings/etherparse.toml ---");
        for entry in &toml_entries {
            eprintln!("{}", entry);
        }
    }

    if !table_entries.is_empty() {
        eprintln!("\n--- Add to table.rs (.etherparse() calls) ---");
        for entry in &table_entries {
            eprintln!("{}", entry);
        }
    }

    Ok(())
}

/// Run auto-matching engine across registries.
pub fn cmd_auto_match(
    min_confidence: f32,
    output: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let state = DiscoveryState::load_from_env();

    // Build curated exclusion sets
    let curated_table = name_mapping::protocol_table();
    let curated_tshark_filters: std::collections::HashSet<String> = curated_table
        .iter()
        .filter_map(|p| p.tshark.map(|s| s.to_lowercase()))
        .collect();
    let curated_canonicals: std::collections::HashSet<String> = curated_table
        .iter()
        .map(|p| p.canonical.to_lowercase())
        .collect();

    let result = name_mapping::auto_matcher::auto_match(
        state.tshark.as_ref(),
        state.scapy.as_ref(),
        state.kernel.as_ref(),
        min_confidence,
        &curated_tshark_filters,
        &curated_canonicals,
    );

    let mappings = name_mapping::auto_matcher::candidates_to_auto_mappings(&result.new_matches);

    if json || output.is_some() {
        let auto_mappings = name_mapping::auto_table::AutoMappings {
            protocols: mappings,
        };
        let json_str = serde_json::to_string_pretty(&auto_mappings)?;

        if let Some(ref path) = output {
            std::fs::write(path, &json_str)?;
            eprintln!("Wrote {} protocols to {}", result.new_matches.len(), path.display());
        } else {
            println!("{}", json_str);
        }
    } else {
        // Human-readable summary
        println!("Auto-Match Results (min_confidence >= {:.1})", min_confidence);
        println!("═══════════════════════════════════════════");
        println!();
        println!("Registry sizes:");
        println!("  tshark:  {} protocols", result.stats.tshark_total);
        println!("  Scapy:   {} classes", result.stats.scapy_total);
        println!("  kernel:  {} structs", result.stats.kernel_total);
        println!();
        println!("Match breakdown:");
        println!("  Already curated:  {}", result.stats.already_curated);
        println!("  Exact normalized: {}", result.stats.new_exact);
        println!("  Decode table:     {}", result.stats.new_decode_table);
        println!("  Long name:        {}", result.stats.new_long_name);
        println!("  Abbreviation:     {}", result.stats.new_abbreviation);
        println!("  Containment:      {}", result.stats.new_containment);
        println!("  Below threshold:  {}", result.stats.below_threshold);
        println!();
        println!("New matches: {}", result.new_matches.len());
        println!();

        // Show top matches sorted by confidence
        let mut sorted = result.new_matches.clone();
        sorted.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

        for m in sorted.iter().take(50) {
            let sources: Vec<&str> = [
                m.tshark.as_ref().map(|_| "tshark"),
                m.scapy.as_ref().map(|_| "scapy"),
                m.kernel_struct.as_ref().map(|_| "kernel"),
            ]
            .into_iter()
            .flatten()
            .collect();

            println!(
                "  {:.2} {:<35} [{}] ({})",
                m.confidence,
                truncate(&m.canonical, 35),
                sources.join(", "),
                m.match_method,
            );
        }

        if sorted.len() > 50 {
            println!("  ... and {} more", sorted.len() - 50);
        }
    }

    Ok(())
}

/// Stats for generate-all command.
#[derive(Default)]
struct GenerateAllStats {
    total: usize,
    curated: usize,
    scapy_batch: usize,
    tshark_pdml: usize,
    tshark_registry: usize,
    skipped: usize,
}


/// Show RFC/IEEE/IANA standards references for protocols.
pub fn cmd_standards(proto: &str, validate: bool, json_output: bool) -> Result<()> {
    let table = name_mapping::protocol_table();

    if proto == "all" {
        // Summary: count protocols by standards coverage
        let mut with_rfcs = 0u32;
        let mut with_ieee = 0u32;
        let mut with_iana = 0u32;
        let mut total_rfcs = 0u32;

        let mut entries: Vec<serde_json::Value> = Vec::new();

        for p in &table {
            let has_rfcs = !p.rfc_numbers.is_empty();
            let has_ieee = !p.ieee_standards.is_empty();
            let has_iana = p.iana_registry.is_some();

            if has_rfcs {
                with_rfcs += 1;
            }
            if has_ieee {
                with_ieee += 1;
            }
            if has_iana {
                with_iana += 1;
            }
            total_rfcs += p.rfc_numbers.len() as u32;

            if json_output {
                let layer = infer_protocol_layer(p.canonical)
                    .map(|l| format!("{:?}", l));
                entries.push(serde_json::json!({
                    "protocol": p.canonical,
                    "layer": layer,
                    "rfcs": p.rfc_numbers,
                    "ieee": p.ieee_standards,
                    "iana_registry": p.iana_registry,
                }));
            }
        }

        if json_output {
            let output = serde_json::json!({
                "total_protocols": table.len(),
                "with_rfcs": with_rfcs,
                "with_ieee": with_ieee,
                "with_iana_registry": with_iana,
                "total_rfc_references": total_rfcs,
                "protocols": entries,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("Standards Coverage Summary ({} protocols):\n", table.len());
            println!("  Protocols with RFC references:    {:>4}", with_rfcs);
            println!("  Protocols with IEEE references:   {:>4}", with_ieee);
            println!("  Protocols with IANA registry:     {:>4}", with_iana);
            println!("  Total RFC references:             {:>4}", total_rfcs);
            println!();

            // List protocols with their RFCs
            println!(
                "  {:<20}  {:<40}  {:<20}  {}",
                "Protocol", "RFCs", "IEEE", "IANA Registry"
            );
            println!(
                "  {}  {}  {}  {}",
                "-".repeat(20),
                "-".repeat(40),
                "-".repeat(20),
                "-".repeat(25)
            );

            for p in &table {
                if p.rfc_numbers.is_empty() && p.ieee_standards.is_empty() && p.iana_registry.is_none() {
                    continue;
                }
                let rfcs: Vec<String> = p.rfc_numbers.iter().map(|r| format!("{}", r)).collect();
                let rfc_str = if rfcs.is_empty() {
                    "-".to_string()
                } else {
                    rfcs.join(", ")
                };
                let ieee_str = if p.ieee_standards.is_empty() {
                    "-".to_string()
                } else {
                    p.ieee_standards.join(", ")
                };
                let iana_str = p.iana_registry.unwrap_or("-");

                println!(
                    "  {:<20}  {:<40}  {:<20}  {}",
                    truncate(p.canonical, 20),
                    truncate(&rfc_str, 40),
                    truncate(&ieee_str, 20),
                    iana_str
                );
            }
        }
    } else {
        // Single protocol detail
        let names = table.iter().find(|p| p.canonical.eq_ignore_ascii_case(proto));
        match names {
            Some(p) => {
                if json_output {
                    let output = serde_json::json!({
                        "protocol": p.canonical,
                        "rfcs": p.rfc_numbers,
                        "ieee": p.ieee_standards,
                        "iana_registry": p.iana_registry,
                        "tshark": p.tshark,
                        "scapy": p.scapy,
                        "kernel_struct": p.kernel_struct,
                        "min_header_bytes": p.min_header_bytes,
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("Protocol: {}\n", p.canonical);
                    if !p.rfc_numbers.is_empty() {
                        println!("  RFCs:");
                        for rfc in p.rfc_numbers {
                            println!("    RFC {}", rfc);
                        }
                    }
                    if !p.ieee_standards.is_empty() {
                        println!("  IEEE Standards:");
                        for ieee in p.ieee_standards {
                            println!("    {}", ieee);
                        }
                    }
                    if let Some(iana) = p.iana_registry {
                        println!("  IANA Registry: {}", iana);
                    }
                    println!("  tshark filter: {}", p.tshark.unwrap_or("-"));
                    println!("  Scapy class: {}", p.scapy.unwrap_or("-"));
                    println!("  Kernel struct: {}", p.kernel_struct.unwrap_or("-"));
                    println!("  Min header: {} bytes", p.min_header_bytes);
                }
            }
            None => {
                anyhow::bail!("Unknown protocol: {}. Use 'all' for summary.", proto);
            }
        }
    }

    // IANA dispatch validation
    if validate {
        let iana_dir = std::env::var("PROTO_AUDIT_IANA_DIR").ok();
        match iana_dir {
            Some(dir) => {
                let registries = extractors::iana::IanaRegistries::load(std::path::Path::new(&dir))?;
                println!("\nIANA Dispatch Table Validation:");
                println!(
                    "  Loaded: {} protocol numbers, {} ethertypes, {} service ports\n",
                    registries.protocol_numbers.len(),
                    registries.ethertypes.len(),
                    registries.service_ports.len()
                );

                // Validate known dispatch mappings from curated table
                let mut confirmed = 0u32;
                for p in &table {
                    if p.iana_registry.is_none() {
                        continue;
                    }
                    confirmed += 1;
                }
                println!("  Protocols with IANA registry: {}", confirmed);
            }
            None => {
                eprintln!(
                    "warning: PROTO_AUDIT_IANA_DIR not set — skipping IANA validation.\n\
                     Set it to the output of the ianaRegistries Nix derivation."
                );
            }
        }
    }

    Ok(())
}

/// Score and rank protocols by XDP2 relevance and quality.
///
/// Scoring axes:
/// - **XDP2 relevance** (0–40): appears in XDP2 dispatch tables or existing proto_defs
/// - **Source coverage** (0–30): more sources = more cross-validation potential
/// - **Parseability** (0–20): fixed-length, byte-aligned = BPF-friendly
/// - **Network prevalence** (0–10): IANA assignment, common protocol families
pub fn cmd_prioritize(
    top: usize,
    tier: &str,
    json_output: bool,
    paths: &SourcePaths,
) -> Result<()> {
    let discovery_state = DiscoveryState::load_from_env();
    let tier_filter = TierFilter::from_str(tier);
    let all_protos = discovery::all_protocols(&discovery_state);

    // Check which protocols already have XDP2 proto_defs
    let xdp2_protos: std::collections::HashSet<String> = paths
        .proto_defs_dir
        .as_ref()
        .and_then(|dir| extractors::xdp2::scan_proto_defs_dir(dir).ok())
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.display_name.to_lowercase())
        .collect();

    // Known dispatch parent protocols (protocols that appear in DECODE_TABLE_MAP)
    let dispatch_parents: std::collections::HashSet<&str> = [
        "ethernet", "ipv4", "ipv6", "tcp", "udp", "sctp", "gre", "ppp",
        "vlan", "mpls", "llc", "snap", "sll",
    ]
    .into();

    let mut scored: Vec<(String, f64, PriorityBreakdown)> = all_protos
        .iter()
        .filter(|(_, dp)| tier_filter.matches(dp.tier))
        .map(|(name, dp)| {
            let breakdown = score_protocol(name, dp, &xdp2_protos, &dispatch_parents);
            let total = breakdown.xdp2_relevance
                + breakdown.source_coverage
                + breakdown.parseability
                + breakdown.prevalence;
            (name.clone(), total, breakdown)
        })
        .collect();

    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored.truncate(top);

    if json_output {
        let entries: Vec<serde_json::Value> = scored
            .iter()
            .enumerate()
            .map(|(i, (name, total, bd))| {
                serde_json::json!({
                    "rank": i + 1,
                    "protocol": name,
                    "score": total,
                    "xdp2_relevance": bd.xdp2_relevance,
                    "source_coverage": bd.source_coverage,
                    "parseability": bd.parseability,
                    "prevalence": bd.prevalence,
                    "has_xdp2_proto_def": bd.has_xdp2,
                    "has_kernel_struct": bd.has_kernel,
                    "tier": bd.tier,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        println!(
            "  {:<4}  {:<25}  {:>5}  {:>5}  {:>5}  {:>5}  {:>5}  {:<6}  {}",
            "Rank", "Protocol", "Total", "XDP2", "Src", "Parse", "Prev", "Tier", "Flags"
        );
        println!(
            "  {}  {}  {}  {}  {}  {}  {}  {}  {}",
            "-".repeat(4),
            "-".repeat(25),
            "-".repeat(5),
            "-".repeat(5),
            "-".repeat(5),
            "-".repeat(5),
            "-".repeat(5),
            "-".repeat(6),
            "-".repeat(15)
        );

        for (i, (name, total, bd)) in scored.iter().enumerate() {
            let mut flags = Vec::new();
            if bd.has_xdp2 {
                flags.push("xdp2");
            }
            if bd.has_kernel {
                flags.push("kern");
            }
            if bd.is_fixed_length {
                flags.push("fixed");
            }

            println!(
                "  {:<4}  {:<25}  {:>5.1}  {:>5.1}  {:>5.1}  {:>5.1}  {:>5.1}  {:<6}  {}",
                i + 1,
                truncate(name, 25),
                total,
                bd.xdp2_relevance,
                bd.source_coverage,
                bd.parseability,
                bd.prevalence,
                bd.tier,
                flags.join(", "),
            );
        }
        println!("\n  Showing top {} of {} protocols", scored.len(), all_protos.len());
    }

    Ok(())
}




/// Save a validation result to the cache file.
/// Validate all routable curated protocols in batch.
fn cmd_validate_all(tier: &str, json_output: bool, paths: &SourcePaths) -> Result<()> {
    let tier_filter = TierFilter::from_str(tier);
    let discovery_state = DiscoveryState::load_from_env();
    let discovered_protos = discovery::all_protocols(&discovery_state);

    // Collect routable protocols
    let routable: Vec<String> = discovered_protos
        .iter()
        .filter(|(_, dp)| tier_filter.matches(dp.tier))
        .filter(|(name, _)| generator::stack_route_for(name).is_some())
        .map(|(name, _)| name.clone())
        .collect();

    eprintln!("Validating {} routable protocols...", routable.len());

    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut error = 0u32;

    for (i, name) in routable.iter().enumerate() {
        eprint!("\r  [{}/{}] {}...", i + 1, routable.len(), truncate(name, 30));

        // Try to validate (suppress errors for individual protocols)
        match cmd_validate_single(name, paths, &discovery_state, &discovered_protos) {
            Ok(result) => {
                // Use the tier determined by cmd_validate_single (which
                // accounts for covered splits) rather than raw mismatch count
                let is_pass = result.validation_tier == Some(discovery::ValidationTier::Gold);
                if is_pass {
                    pass += 1;
                } else {
                    fail += 1;
                }
                results.push(serde_json::json!({
                    "protocol": name,
                    "status": if is_pass { "pass" } else { "fail" },
                    "validation_tier": result.validation_tier.as_ref().map(|t| t.to_string()),
                    "fields_agree": result.fields_agree,
                    "total_fields": result.total_fields,
                    "fields_mismatch": result.fields_mismatch,
                }));
            }
            Err(_) => {
                error += 1;
                results.push(serde_json::json!({
                    "protocol": name,
                    "status": "error",
                }));
            }
        }
    }
    eprintln!("\r  Done: {} pass, {} fail, {} error          ", pass, fail, error);

    if json_output {
        let output = serde_json::json!({
            "total": routable.len(),
            "pass": pass,
            "fail": fail,
            "error": error,
            "protocols": results,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("\nBatch Validation Results");
        println!("  Total:  {}", routable.len());
        println!("  Pass:   {} (Gold)", pass);
        println!("  Fail:   {}", fail);
        println!("  Error:  {}", error);
    }

    Ok(())
}

/// Validate a single protocol, returning the AuditResult.
fn cmd_validate_single(
    proto: &str,
    paths: &SourcePaths,
    discovery_state: &DiscoveryState,
    _discovered_protos: &std::collections::BTreeMap<String, discovery::DiscoveredProtocol>,
) -> Result<ir::AuditResult> {
    // Build rich IR
    let protocol_def = build_rich_ir(proto, paths)?;

    // Build proto map for PCAP generation
    let proto_map = build_proto_map(proto, paths, discovery_state);

    // Generate PCAP (with discovery for discovered-tier route resolution)
    let pcap_output = generator::generate_pcap_with_discovery(&protocol_def, &proto_map, discovery_state)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // Write temp pcap and run tshark
    let pcap_path = std::env::temp_dir().join(format!("proto_audit_validate_{}.pcap", proto));
    std::fs::write(&pcap_path, &pcap_output.pcap_bytes)?;

    let hints = extractors::tshark::decode_as_hints(proto);
    let hint_refs: Vec<&str> = hints.iter().map(|s| *s).collect();
    let xml = extractors::tshark::run_tshark_with_hints(&pcap_path, &paths.tshark_bin, 1, &hint_refs)?;
    let _ = std::fs::remove_file(&pcap_path);

    let packets = extractors::tshark::parse_pdml(&xml)?;

    // Find dissector name — try name_mapping.tshark first, then pdml_name_alias
    // fallback, then decode_as_hints dissector names (matches interactive validator).
    let dissector = name_mapping::find_by_canonical(proto)
        .and_then(|n| n.tshark.map(|s| s.to_string()));
    let tshark_found = dissector
        .as_deref()
        .and_then(|d| extractors::tshark::extract_protocol_from_pdml(&packets, d))
        // Fallback: try PDML name alias (for protocols where tshark layer name differs)
        .or_else(|| {
            extractors::tshark::pdml_name_alias(proto)
                .and_then(|alias| extractors::tshark::extract_protocol_from_pdml(&packets, alias))
        })
        // Fallback: try decode_as_hints dissector names
        .or_else(|| {
            hints.iter().find_map(|hint| {
                hint.rsplit(',').next().and_then(|dname| {
                    extractors::tshark::extract_protocol_from_pdml(&packets, dname)
                })
            })
        });
    let tshark_recognized = tshark_found.is_some();

    let tshark_def = match tshark_found {
        Some(pdml) => extractors::tshark::to_protocol_def(&pdml),
        // No tshark dissection — use empty def (same as interactive validate).
        None => ir::ProtocolDef::new(proto, 0),
    };

    let refs: Vec<(&str, &ir::ProtocolDef)> = vec![
        ("ir", &protocol_def),
        ("tshark-roundtrip", &tshark_def),
    ];
    let mut result = comparator::audit_protocol(proto, &refs);

    // Override validation tier: Gold if tshark recognized the protocol.
    // Even 0-field protocols (tunnel wrappers) get Gold if tshark parsed them.
    if tshark_recognized {
        result.validation_tier = Some(discovery::ValidationTier::Gold);
    }

    // Persist
    let _ = save_validation_result(proto, &result);

    Ok(result)
}



/// Simple ISO-8601 timestamp without pulling in chrono crate.
// ── validate-netlink command ──

/// Netlink protocols that map to inet_diag attribute types.
const NETLINK_ATTR_PROTOS: &[(u16, &str)] = &[
    (1, "NL_Diag_MemInfo"),
    (2, "NL_Diag_TCPInfo"),
    (3, "NL_Diag_VegasInfo"),
    (7, "NL_Diag_SkMemInfo"),
    (9, "NL_Diag_DCTCPInfo"),
    (16, "NL_Diag_BBRInfo"),
];

/// Validate netlink inet_diag protocols against real xtcp2 PCAPs.
///
/// Two validation paths:
/// 1. **Binary**: Parse PCAP → extract TLV attributes → deserialize against IR
/// 2. **tshark+Lua**: Generate Lua dissector → run tshark → parse PDML → compare
pub(crate) fn cmd_validate_netlink(
    proto: &str,
    keep_lua: Option<PathBuf>,
    json_output: bool,
    paths: &SourcePaths,
) -> Result<()> {
    // Determine xtcp2 PCAP source
    let pcaps_dir = paths
        .xtcp2_pcaps
        .as_ref()
        .or_else(|| paths.xtcp2_src.as_ref())
        .context("--xtcp2-pcaps or --xtcp2-src required for validate-netlink")?;

    // Use xtcp2_src directly if xtcp2_pcaps wasn't set — find_xtcp2_pcaps
    // looks for pkg/xtcpnl/testdata/ beneath the given path
    let pcap_root = if paths.xtcp2_pcaps.is_some() {
        // Already points at testdata dir — wrap it so find_xtcp2_pcaps can
        // find the kernel-version subdirectories directly
        pcaps_dir.clone()
    } else {
        pcaps_dir.clone()
    };

    let pcaps = netlink::find_xtcp2_pcaps(&pcap_root)?;
    eprintln!(
        "  Found {} xtcp2 PCAPs across {} kernel versions",
        pcaps.len(),
        {
            let mut versions: Vec<&str> = pcaps.iter().map(|p| p.kernel_version.as_str()).collect();
            versions.sort();
            versions.dedup();
            versions.len()
        }
    );

    // Determine which protocols to validate
    let target_protos: Vec<(u16, &str)> = if proto == "all" {
        NETLINK_ATTR_PROTOS.to_vec()
    } else {
        NETLINK_ATTR_PROTOS
            .iter()
            .filter(|(_, name)| *name == proto)
            .copied()
            .collect()
    };

    if target_protos.is_empty() {
        anyhow::bail!(
            "Unknown netlink protocol '{}'. Valid: {}",
            proto,
            NETLINK_ATTR_PROTOS
                .iter()
                .map(|(_, n)| *n)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Build IR for each target protocol
    let mut proto_irs: Vec<(u16, String, ir::ProtocolDef)> = Vec::new();
    for (attr_type, name) in &target_protos {
        match build_rich_ir(name, paths) {
            Ok(ir) => {
                eprintln!("  Built IR for {} ({} fields)", name, ir.fields.len());
                proto_irs.push((*attr_type, name.to_string(), ir));
            }
            Err(e) => {
                eprintln!("  SKIP {}: {}", name, e);
            }
        }
    }

    if proto_irs.is_empty() {
        anyhow::bail!("No IR definitions available for validation");
    }

    // Generate aggregate Lua dissector
    let lua_protos: Vec<(u16, &str, &ir::ProtocolDef)> = proto_irs
        .iter()
        .map(|(at, name, ir)| (*at, name.as_str(), ir))
        .collect();
    let lua_script = generator::generate_wireshark_lua(&lua_protos);

    // Save Lua dissector
    let lua_path = if let Some(ref path) = keep_lua {
        std::fs::write(path, &lua_script)
            .with_context(|| format!("writing Lua to {}", path.display()))?;
        eprintln!("  Saved Lua dissector to {}", path.display());
        path.clone()
    } else {
        let tmp = std::env::temp_dir().join("proto-audit-inet-diag.lua");
        std::fs::write(&tmp, &lua_script)
            .with_context(|| format!("writing temp Lua to {}", tmp.display()))?;
        tmp
    };

    eprintln!(
        "  Generated Lua dissector ({} bytes, {} protocols)",
        lua_script.len(),
        lua_protos.len()
    );

    // ── Binary validation ──
    // Parse each PCAP, extract attributes, deserialize against IR
    let mut results: Vec<serde_json::Value> = Vec::new();

    for (attr_type, name, ir) in &proto_irs {
        let mut total_records = 0u64;
        let mut total_fields_extracted = 0u64;
        let mut kernel_results: std::collections::BTreeMap<String, (u64, u64)> =
            std::collections::BTreeMap::new();

        for pcap_info in &pcaps {
            let data = match std::fs::read(&pcap_info.path) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let records = match netlink::parse_netlink_pcap(&data) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for record in &records {
                for attr in &record.attributes {
                    if attr.attr_type == *attr_type {
                        let values = netlink::deserialize_attribute(&attr.payload, ir);
                        total_records += 1;
                        total_fields_extracted += values.len() as u64;

                        let entry = kernel_results
                            .entry(pcap_info.kernel_version.clone())
                            .or_insert((0, 0));
                        entry.0 += 1;
                        entry.1 += values.len() as u64;
                    }
                }
            }
        }

        // ── tshark + Lua validation (try a PCAP that contains this attr) ──
        let mut tshark_result = None;
        if total_records > 0 {
            // Find a PCAP that actually contains this attribute type.
            // Prefer small PCAPs (single-packet replies) for faster tshark.
            let matching_pcap = pcaps.iter().find(|p| {
                let data = match std::fs::read(&p.path) {
                    Ok(d) => d,
                    Err(_) => return false,
                };
                let records = match netlink::parse_netlink_pcap(&data) {
                    Ok(r) => r,
                    Err(_) => return false,
                };
                records
                    .iter()
                    .any(|r| r.attributes.iter().any(|a| a.attr_type == *attr_type))
            });

            if let Some(pcap_info) = matching_pcap {
                match extractors::tshark::run_tshark_with_lua(
                    &pcap_info.path,
                    &paths.tshark_bin,
                    10,
                    &lua_path,
                ) {
                    Ok(xml) => {
                        // Look for our generated proto in PDML
                        let snake = name.to_lowercase().replace('.', "_").replace('-', "_").replace(' ', "_");
                        let dissector_name = format!("inet_diag_{}", snake);
                        if let Ok(packets) = extractors::tshark::parse_pdml(&xml) {
                            let found = packets.iter().any(|pkt| {
                                pkt.iter()
                                    .any(|p| p.name == dissector_name || p.name.contains(&snake))
                            });
                            tshark_result = Some(found);
                        }
                    }
                    Err(e) => {
                        eprintln!("  tshark+Lua for {}: {}", name, e);
                    }
                }
            }
        }

        let result = serde_json::json!({
            "protocol": name,
            "attr_type": attr_type,
            "ir_fields": ir.fields.len(),
            "binary_validation": {
                "total_records": total_records,
                "total_fields_extracted": total_fields_extracted,
                "avg_fields_per_record": if total_records > 0 {
                    total_fields_extracted as f64 / total_records as f64
                } else {
                    0.0
                },
                "kernel_versions": kernel_results.iter().map(|(k, (records, fields))| {
                    serde_json::json!({
                        "kernel": k,
                        "records": records,
                        "avg_fields": if *records > 0 { *fields as f64 / *records as f64 } else { 0.0 },
                    })
                }).collect::<Vec<_>>(),
            },
            "tshark_lua": tshark_result,
            "status": if total_records > 0 { "PASS" } else { "NO_DATA" },
        });

        if !json_output {
            println!(
                "  {} (attr_type={}): {} records across {} kernel versions, \
                 {:.0} avg fields/record (IR has {}){}\n",
                name,
                attr_type,
                total_records,
                kernel_results.len(),
                if total_records > 0 {
                    total_fields_extracted as f64 / total_records as f64
                } else {
                    0.0
                },
                ir.fields.len(),
                match tshark_result {
                    Some(true) => " ✓ tshark+Lua",
                    Some(false) => " ✗ tshark+Lua (proto not found in PDML)",
                    None => "",
                }
            );
        }

        results.push(result);

        // ── Persist Gold tier if both binary and tshark+Lua pass ──
        let is_gold = total_records > 0 && tshark_result == Some(true);
        if is_gold {
            // Build AuditResult and promote to Gold via validation cache
            let refs: Vec<(&str, &ir::ProtocolDef)> = vec![
                ("kernel", ir),
                ("xtcp2", ir),
            ];
            let mut audit = comparator::audit_protocol(name, &refs);
            audit.validation_tier = Some(discovery::ValidationTier::Gold);
            let _ = save_validation_result(name, &audit);
            if !json_output {
                eprintln!("  {} → Gold (wire-validated across {} kernel versions)", name, kernel_results.len());
            }
        }
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "command": "validate-netlink",
                "pcap_count": pcaps.len(),
                "lua_path": lua_path.display().to_string(),
                "results": results,
            }))?
        );
    } else {
        println!("\n  Lua dissector: {}", lua_path.display());
    }

    if keep_lua.is_none() {
        // Clean up temp Lua file
        let _ = std::fs::remove_file(&lua_path);
    }

    Ok(())
}



/// Check xdp2-rs ProtocolOps coverage against C proto_defs.
///
/// Scans C proto_defs for `.name = "..."` declarations and the Rust
/// xdp2-protocols crate for `const NAME: &'static str = "..."` declarations.
/// Reports protocols present in C but missing from Rust.
/// Exits non-zero if any gap exists (suitable as a CI gate).
pub(crate) fn cmd_check_rs(
    rs_src: &Path,
    json: bool,
    paths: &SourcePaths,
) -> Result<()> {
    use std::collections::BTreeSet;

    // 1. Scan C proto_defs for protocol names
    let proto_defs_dir = paths.proto_defs_dir.as_ref()
        .ok_or_else(|| anyhow::anyhow!("--proto-defs-dir is required for check-rs"))?;
    let mut c_names: BTreeSet<String> = BTreeSet::new();
    let re_c_name = regex::Regex::new(r#"\.name\s*=\s*"([^"]+)""#).unwrap();

    scan_files_recursive(proto_defs_dir, "h", &mut |content: &str| {
        if !content.contains("XDP2_DEFINE_PARSE_NODE") {
            return;
        }
        for cap in re_c_name.captures_iter(content) {
            c_names.insert(cap[1].to_string());
        }
    });

    // 2. Scan Rust ProtocolOps for NAME constants
    let mut rs_names: BTreeSet<String> = BTreeSet::new();
    let re_rs_name = regex::Regex::new(r#"const\s+NAME:\s*&'static\s+str\s*=\s*"([^"]+)""#).unwrap();

    scan_files_recursive(rs_src, "rs", &mut |content: &str| {
        for cap in re_rs_name.captures_iter(content) {
            rs_names.insert(cap[1].to_string());
        }
    });

    // 3. Compute gaps
    let in_c_only: BTreeSet<_> = c_names.difference(&rs_names).cloned().collect();
    let in_rs_only: BTreeSet<_> = rs_names.difference(&c_names).cloned().collect();
    let in_both: BTreeSet<_> = c_names.intersection(&rs_names).cloned().collect();

    if json {
        let output = serde_json::json!({
            "c_total": c_names.len(),
            "rs_total": rs_names.len(),
            "both": in_both.len(),
            "c_only": in_c_only,
            "rs_only": in_rs_only,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("C proto_defs:   {} protocols", c_names.len());
        println!("Rust xdp2-rs:   {} protocols", rs_names.len());
        println!("Both:           {} protocols", in_both.len());
        println!();
        if !in_c_only.is_empty() {
            println!("In C but NOT in Rust ({}):", in_c_only.len());
            for name in &in_c_only {
                println!("  - {}", name);
            }
            println!();
        }
        if !in_rs_only.is_empty() {
            println!("In Rust but NOT in C ({}):", in_rs_only.len());
            for name in &in_rs_only {
                println!("  - {}", name);
            }
            println!();
        }
        if in_c_only.is_empty() {
            println!("All C protocols have Rust implementations.");
        }
    }

    if !in_c_only.is_empty() {
        anyhow::bail!(
            "{} C protocol(s) missing Rust ProtocolOps implementation",
            in_c_only.len()
        );
    }

    Ok(())
}
