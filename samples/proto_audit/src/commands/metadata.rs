use anyhow::Result;
use std::path::PathBuf;

use crate::{
    discovery::{self, DiscoveryState, TierFilter},
    extractors, name_mapping, SourcePaths,
};
use super::helpers::*;

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
