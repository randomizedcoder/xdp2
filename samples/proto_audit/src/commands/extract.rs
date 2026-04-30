use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::{
    comparator,
    discovery::{self, DiscoveryState, TierFilter},
    extractors, ir, name_mapping, report, SourcePaths,
};
use super::helpers::*;

pub(crate) fn cmd_extract(
    source: &str,
    proto: &str,
    paths: &SourcePaths,
    json_output: bool,
) -> Result<()> {
    let protocol_def = try_extract(source, proto, paths)
        .with_context(|| format!("Failed to extract {} from source '{}'", proto, source))?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&protocol_def)?);
    } else {
        print!("{}", report::format_protocol_text(&protocol_def));
    }

    Ok(())
}


pub(crate) fn cmd_compare(
    proto: &str,
    sources: Option<&str>,
    paths: &SourcePaths,
    json_output: bool,
) -> Result<()> {
    let source_list = parse_source_list(sources);

    // Extract from each available source
    let mut extracted: Vec<(String, ir::ProtocolDef)> = Vec::new();
    for source in &source_list {
        match try_extract(source, proto, paths) {
            Some(def) => {
                eprintln!("  [+] {} → {} fields", source, def.fields.len());
                extracted.push((source.clone(), def));
            }
            None => {
                eprintln!("  [-] {} → not available", source);
            }
        }
    }

    if extracted.is_empty() {
        anyhow::bail!(
            "No sources available for '{}'. Provide --proto-defs-dir, --kernel-src, etc.",
            proto
        );
    }

    // Build reference pairs for the comparator
    let refs: Vec<(&str, &ir::ProtocolDef)> = extracted
        .iter()
        .map(|(name, def)| (name.as_str(), def))
        .collect();

    let result = comparator::audit_protocol(proto, &refs);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print!("{}", report::format_audit_text(&result));
    }

    Ok(())
}

pub(crate) fn cmd_audit(
    protos: Option<&str>,
    sources: Option<&str>,
    tier: &str,
    compact: bool,
    limit: Option<usize>,
    paths: &SourcePaths,
    json_output: bool,
) -> Result<()> {
    let tier_filter = TierFilter::from_str(tier);
    let source_list = parse_source_list(sources);
    let discovery_state = DiscoveryState::load_from_env();

    let proto_count = match protos {
        Some(p) => p.split(',').count(),
        None if tier_filter == TierFilter::Curated => name_mapping::protocol_table().len(),
        None => discovery::all_protocols(&discovery_state).len(),
    };

    eprintln!(
        "Auditing {} protocols (tier={}) across sources: {}",
        proto_count,
        tier,
        source_list.join(", ")
    );

    let mut results = run_audit(protos, sources, tier, &discovery_state, paths);

    // Sync with validation cache: promote to Gold if cached, save Silver/Bronze otherwise.
    {
        let existing_cache = load_validation_cache();
        for r in &mut results {
            let cache_key = r.protocol.trim_end_matches(" [D]").to_string();
            let existing_tier = existing_cache.get(&cache_key);
            if existing_tier == Some(&discovery::ValidationTier::Gold) {
                // Promote to Gold from cache (wire-validated via validate-netlink)
                r.validation_tier = Some(discovery::ValidationTier::Gold);
            } else if let Some(ref vtier) = r.validation_tier {
                if *vtier != discovery::ValidationTier::Unvalidated {
                    let _ = save_validation_result(&cache_key, r);
                }
            }
        }
    }

    let results = apply_filters(results, compact, limit);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        print!("{}", report::format_audit_summary(&results));

        // Print detailed results for protocols with mismatches
        let problematic: Vec<_> = results
            .iter()
            .filter(|r| r.fields_mismatch > 0 || r.fields_missing > 0 || r.fields_type_differ > 0)
            .collect();

        if !problematic.is_empty() {
            println!(
                "\n--- Detailed results for {} protocols with issues ---\n",
                problematic.len()
            );
            for r in problematic {
                print!("{}", report::format_audit_text(r));
                println!();
            }
        }
    }

    Ok(())
}

pub(crate) fn cmd_scan(proto_defs_dir: &PathBuf, json_output: bool) -> Result<()> {
    let defs = extractors::xdp2::scan_proto_defs_dir(proto_defs_dir)?;

    if json_output {
        // Serialize as JSON array
        let json_defs: Vec<_> = defs
            .iter()
            .map(|d| {
                serde_json::json!({
                    "var_name": d.var_name,
                    "display_name": d.display_name,
                    "kernel_struct": d.kernel_struct,
                    "has_next_proto": d.has_next_proto,
                    "has_len": d.has_len,
                    "is_tlv": d.is_tlv,
                    "is_overlay": d.is_overlay,
                    "file_path": d.file_path,
                    "kernel_include": d.kernel_include,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json_defs)?);
    } else {
        print!("{}", report::format_xdp2_scan(&defs));
    }

    Ok(())
}
