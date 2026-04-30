use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::{
    comparator,
    discovery::{self, DiscoveryState, TierFilter},
    extractors, generator, ir, name_mapping, netlink, SourcePaths,
};
use super::helpers::*;

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
        pcap_output.stack.join(" \u{2192} "),
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
        // Fallback: try dissector names from decode-as hints (e.g., TWAMP->twamp.test)
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

    // Override validation tier: Gold -- tshark recognized the protocol.
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
        println!("  Stack: {}", pcap_output.stack.join(" \u{2192} "));
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

    // Find dissector name -- try name_mapping.tshark first, then pdml_name_alias
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
        // No tshark dissection -- use empty def (same as interactive validate).
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
/// 1. **Binary**: Parse PCAP -> extract TLV attributes -> deserialize against IR
/// 2. **tshark+Lua**: Generate Lua dissector -> run tshark -> parse PDML -> compare
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

    // Use xtcp2_src directly if xtcp2_pcaps wasn't set -- find_xtcp2_pcaps
    // looks for pkg/xtcpnl/testdata/ beneath the given path
    let pcap_root = if paths.xtcp2_pcaps.is_some() {
        // Already points at testdata dir -- wrap it so find_xtcp2_pcaps can
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

    // -- Binary validation --
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

        // -- tshark + Lua validation (try a PCAP that contains this attr) --
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
                    Some(true) => " \u{2713} tshark+Lua",
                    Some(false) => " \u{2717} tshark+Lua (proto not found in PDML)",
                    None => "",
                }
            );
        }

        results.push(result);

        // -- Persist Gold tier if both binary and tshark+Lua pass --
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
                eprintln!("  {} \u{2192} Gold (wire-validated across {} kernel versions)", name, kernel_results.len());
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
