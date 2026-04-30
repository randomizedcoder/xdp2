use anyhow::Result;

use crate::{
    discovery::{self, DiscoveredProtocol, DiscoveryState, Tier, TierFilter},
    extractors, generator, ir, name_mapping, report, SourcePaths,
};
use super::helpers::*;


pub(crate) fn cmd_matrix(
    protos: Option<&str>,
    sources: Option<&str>,
    tier: &str,
    compact: bool,
    limit: Option<usize>,
    paths: &SourcePaths,
    json_output: bool,
) -> Result<()> {
    let discovery_state = DiscoveryState::load_from_env();
    let results = run_audit(protos, sources, tier, &discovery_state, paths);
    let results = apply_filters(results, compact, limit);

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&report::format_matrix_json(&results))?
        );
    } else {
        print!("{}", report::format_matrix(&results));
    }

    Ok(())
}

pub(crate) fn cmd_findings(
    protos: Option<&str>,
    sources: Option<&str>,
    tier: &str,
    compact: bool,
    limit: Option<usize>,
    paths: &SourcePaths,
    json_output: bool,
) -> Result<()> {
    let discovery_state = DiscoveryState::load_from_env();
    let results = run_audit(protos, sources, tier, &discovery_state, paths);

    // For findings, compact means omit protocols with no findings
    let results = if compact {
        results
            .into_iter()
            .filter(|r| {
                r.fields_mismatch > 0 || r.fields_missing > 0 || r.fields_type_differ > 0
            })
            .collect()
    } else {
        results
    };

    let results = if let Some(n) = limit {
        results.into_iter().take(n).collect()
    } else {
        results
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&report::format_findings_json(&results))?
        );
    } else {
        print!("{}", report::format_findings(&results));
    }

    Ok(())
}

pub(crate) fn cmd_list(tier: &str, json_output: bool) -> Result<()> {
    let tier_filter = TierFilter::from_str(tier);

    if tier_filter == TierFilter::Curated {
        // Original curated-only list
        let table = name_mapping::protocol_table();

        if json_output {
            let json_list: Vec<_> = table
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "canonical": p.canonical,
                        "tier": "C",
                        "xdp2": p.xdp2,
                        "kernel_struct": p.kernel_struct,
                        "kernel_header": p.kernel_header,
                        "scapy": p.scapy,
                        "tshark": p.tshark,
                        "etherparse_struct": p.etherparse_struct,
                        "etherparse_file": p.etherparse_file,
                        "libpcap_name": p.libpcap_name,
                        "libpcap_file": p.libpcap_file,
                        "min_header_bytes": p.min_header_bytes,
                        "variable_length": p.variable_length,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_list)?);
        } else {
            println!(
                "  {:<4}  {:<16}  {:<30}  {:<14}  {:<8}  {:<8}  {:<20}  {:<12}  {:<8}  {:>4}",
                "Tier", "Protocol", "XDP2", "Kernel", "Scapy", "tshark", "etherparse", "libpcap",
                "kaitai", "Bytes"
            );
            println!(
                "  {}  {}  {}  {}  {}  {}  {}  {}  {}",
                "-".repeat(4),
                "-".repeat(16),
                "-".repeat(30),
                "-".repeat(14),
                "-".repeat(8),
                "-".repeat(8),
                "-".repeat(20),
                "-".repeat(12),
                "-".repeat(4)
            );
            for p in &table {
                println!(
                    "  {:<4}  {:<16}  {:<30}  {:<14}  {:<8}  {:<8}  {:<20}  {:<12}  {:>4}",
                    "[C]",
                    p.canonical,
                    p.xdp2.unwrap_or("-"),
                    p.kernel_struct.unwrap_or("-"),
                    p.scapy.unwrap_or("-"),
                    p.tshark.unwrap_or("-"),
                    p.etherparse_struct.unwrap_or("-"),
                    p.libpcap_name.unwrap_or("-"),
                    p.min_header_bytes,
                );
            }
            println!("\n  Total: {} protocols", table.len());
        }
    } else {
        // Merged list with discovery
        let discovery_state = DiscoveryState::load_from_env();
        let all_protos = discovery::all_protocols(&discovery_state);
        let vcache = load_validation_cache();

        let filtered: Vec<_> = all_protos
            .values()
            .filter(|dp| tier_filter.matches(dp.tier))
            .collect();

        if json_output {
            let json_list: Vec<_> = filtered
                .iter()
                .map(|dp| {
                    let vtier = dp.validation_tier.as_ref()
                        .or_else(|| vcache.get(&dp.canonical))
                        .map(|t| t.to_string());
                    serde_json::json!({
                        "canonical": dp.canonical,
                        "tier": dp.tier.to_string(),
                        "tshark_filter": dp.tshark_filter,
                        "scapy_class": dp.scapy_class,
                        "kernel_struct": dp.kernel_struct,
                        "kernel_header": dp.kernel_header,
                        "libpcap_name": dp.libpcap_name,
                        "libpcap_file": dp.libpcap_file,
                        "estimated_field_count": dp.estimated_field_count,
                        "min_header_bytes": dp.min_header_bytes,
                        "validation_tier": vtier,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_list)?);
        } else {
            println!(
                "  {:<4}  {:<40}  {:<16}  {:<16}  {:<16}  {:>6}  {:<11}",
                "Tier", "Protocol", "tshark", "Scapy", "Kernel", "Fields", "Validation"
            );
            println!(
                "  {}  {}  {}  {}  {}  {}  {}",
                "-".repeat(4),
                "-".repeat(40),
                "-".repeat(16),
                "-".repeat(16),
                "-".repeat(16),
                "-".repeat(6),
                "-".repeat(11)
            );
            for dp in &filtered {
                let vtier = dp.validation_tier.as_ref()
                    .or_else(|| vcache.get(&dp.canonical))
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "  [{}]  {:<40}  {:<16}  {:<16}  {:<16}  {:>6}  {:<11}",
                    dp.tier,
                    truncate(&dp.canonical, 40),
                    dp.tshark_filter.as_deref().unwrap_or("-"),
                    dp.scapy_class.as_deref().unwrap_or("-"),
                    dp.kernel_struct.as_deref().unwrap_or("-"),
                    dp.estimated_field_count,
                    vtier,
                );
            }
            let gold_count = filtered.iter().filter(|dp| {
                dp.validation_tier.as_ref()
                    .or_else(|| vcache.get(&dp.canonical))
                    == Some(&discovery::ValidationTier::Gold)
            }).count();
            let with_tshark = filtered.iter().filter(|dp| dp.tshark_filter.is_some()).count();
            let with_scapy = filtered.iter().filter(|dp| dp.scapy_class.is_some()).count();
            let with_kernel = filtered.iter().filter(|dp| dp.kernel_struct.is_some()).count();
            let with_libpcap = filtered.iter().filter(|dp| dp.libpcap_name.is_some()).count();
            let multi_source = filtered.iter().filter(|dp| {
                let n = dp.tshark_filter.is_some() as u32
                    + dp.scapy_class.is_some() as u32
                    + dp.kernel_struct.is_some() as u32
                    + dp.libpcap_name.is_some() as u32;
                n >= 2
            }).count();
            println!(
                "\n  Total: {} protocols ({} curated, {} discovered, {} Gold-validated)",
                filtered.len(),
                filtered.iter().filter(|dp| dp.tier == Tier::Curated).count(),
                filtered
                    .iter()
                    .filter(|dp| dp.tier == Tier::Discovered)
                    .count(),
                gold_count,
            );
            println!(
                "  Sources: {} tshark, {} Scapy, {} kernel, {} libpcap, {} multi-source (2+)",
                with_tshark, with_scapy, with_kernel, with_libpcap, multi_source,
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_quality(tier: &str, json_output: bool) -> Result<()> {
    let tier_filter = TierFilter::from_str(tier);
    let discovery_state = DiscoveryState::load_from_env();
    let all_protos = discovery::all_protocols(&discovery_state);
    let vcache = load_validation_cache();

    let filtered: Vec<_> = all_protos
        .iter()
        .filter(|(_, dp)| tier_filter.matches(dp.tier))
        .collect();

    // Confidence distribution
    let mut conf_buckets: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for (_, dp) in &filtered {
        let bucket = match dp.match_confidence {
            Some(c) if c >= 0.9 => "0.9-1.0 (high)",
            Some(c) if c >= 0.8 => "0.8-0.9 (good)",
            Some(c) if c >= 0.7 => "0.7-0.8 (moderate)",
            Some(c) if c >= 0.5 => "0.5-0.7 (low)",
            Some(_) => "< 0.5 (very low)",
            None => "1.0 (curated)",
        };
        *conf_buckets.entry(bucket.to_string()).or_default() += 1;
    }

    // Source coverage breakdown
    let mut source_counts = [0usize; 7]; // 0-source through 6-source
    for (_, dp) in &filtered {
        let mut n = 0u32;
        if dp.tshark_filter.is_some() { n += 1; }
        if dp.scapy_class.is_some() { n += 1; }
        if dp.kernel_struct.is_some() { n += 1; }
        // Curated protocols also have xdp2, etherparse, libpcap in name_mapping
        if dp.tier == Tier::Curated {
            if let Some(names) = name_mapping::find_by_canonical(&dp.canonical) {
                if names.xdp2.is_some() { n += 1; }
                if names.etherparse_struct.is_some() { n += 1; }
                if names.libpcap_name.is_some() { n += 1; }
            }
        }
        let idx = std::cmp::min(n as usize, 6);
        source_counts[idx] += 1;
    }

    // Match method distribution
    let mut method_counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for (_, dp) in &filtered {
        let method = dp.match_method.as_deref().unwrap_or("curated");
        *method_counts.entry(method.to_string()).or_default() += 1;
    }

    // Validation tier distribution
    let mut vtier_counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for (_, dp) in &filtered {
        let vtier = dp.validation_tier.as_ref()
            .or_else(|| vcache.get(&dp.canonical))
            .map(|t| t.to_string())
            .unwrap_or_else(|| "Unvalidated".to_string());
        *vtier_counts.entry(vtier).or_default() += 1;
    }

    // Code generation readiness
    let with_min_hdr = filtered.iter().filter(|(_, dp)| dp.min_header_bytes > 0).count();
    let fixed_length = filtered.iter().filter(|(_, dp)| {
        dp.min_header_bytes > 0 && !name_mapping::find_by_canonical(&dp.canonical)
            .map(|n| n.variable_length)
            .unwrap_or(true) // default to variable for discovered
    }).count();

    if json_output {
        let output = serde_json::json!({
            "total": filtered.len(),
            "confidence_distribution": conf_buckets,
            "source_coverage": {
                "0_sources": source_counts[0],
                "1_source": source_counts[1],
                "2_sources": source_counts[2],
                "3_sources": source_counts[3],
                "4_sources": source_counts[4],
                "5_sources": source_counts[5],
                "6_sources": source_counts[6],
            },
            "match_method": method_counts,
            "validation_tier": vtier_counts,
            "code_gen_readiness": {
                "with_min_header": with_min_hdr,
                "fixed_length": fixed_length,
            },
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Protocol Quality Report ({} protocols, tier={})\n", filtered.len(), tier);

        println!("  Confidence Distribution:");
        for (bucket, count) in &conf_buckets {
            let pct = *count as f64 / filtered.len() as f64 * 100.0;
            println!("    {:<25} {:>6}  ({:.1}%)", bucket, count, pct);
        }

        println!("\n  Source Coverage:");
        for i in 0..=6 {
            if source_counts[i] > 0 {
                let label = match i {
                    0 => "0 sources (no data)   ",
                    1 => "1 source              ",
                    2 => "2 sources (Silver-able)",
                    3 => "3 sources             ",
                    4 => "4 sources             ",
                    5 => "5 sources             ",
                    6 => "6 sources (full)      ",
                    _ => unreachable!(),
                };
                let pct = source_counts[i] as f64 / filtered.len() as f64 * 100.0;
                println!("    {} {:>6}  ({:.1}%)", label, source_counts[i], pct);
            }
        }

        println!("\n  Match Method:");
        let mut methods: Vec<_> = method_counts.iter().collect();
        methods.sort_by(|a, b| b.1.cmp(a.1));
        for (method, count) in methods {
            let pct = *count as f64 / filtered.len() as f64 * 100.0;
            println!("    {:<25} {:>6}  ({:.1}%)", method, count, pct);
        }

        println!("\n  Validation Tier:");
        for tier_name in &["Gold", "Silver", "Bronze", "Unvalidated"] {
            let count = vtier_counts.get(*tier_name).unwrap_or(&0);
            let pct = *count as f64 / filtered.len() as f64 * 100.0;
            println!("    {:<25} {:>6}  ({:.1}%)", tier_name, count, pct);
        }

        println!("\n  Code Generation Readiness:");
        println!("    With min_header > 0:  {:>6}", with_min_hdr);
        println!("    Fixed-length (BPF):   {:>6}", fixed_length);
    }

    Ok(())
}

pub(crate) fn cmd_search(
    query: &str,
    tier: &str,
    limit: Option<usize>,
    json_output: bool,
) -> Result<()> {
    let tier_filter = TierFilter::from_str(tier);
    let discovery_state = DiscoveryState::load_from_env();
    let all_protos = discovery::all_protocols(&discovery_state);
    let query_lower = query.to_lowercase();

    let mut matches: Vec<_> = all_protos
        .iter()
        .filter(|(_, dp)| tier_filter.matches(dp.tier))
        .filter(|(name, dp)| {
            let name_lower = name.to_lowercase();
            if name_lower.contains(&query_lower) {
                return true;
            }
            if let Some(ref tf) = dp.tshark_filter {
                if tf.to_lowercase().contains(&query_lower) {
                    return true;
                }
            }
            if let Some(ref sc) = dp.scapy_class {
                if sc.to_lowercase().contains(&query_lower) {
                    return true;
                }
            }
            if let Some(ref ks) = dp.kernel_struct {
                if ks.to_lowercase().contains(&query_lower) {
                    return true;
                }
            }
            false
        })
        .collect();

    // Sort: exact canonical name matches first, then alphabetical
    matches.sort_by(|(a_name, _), (b_name, _)| {
        let a_exact = a_name.to_lowercase() == query_lower;
        let b_exact = b_name.to_lowercase() == query_lower;
        match (a_exact, b_exact) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a_name.cmp(b_name),
        }
    });

    let total = matches.len();
    if let Some(lim) = limit {
        matches.truncate(lim);
    }

    if json_output {
        let results: Vec<serde_json::Value> = matches
            .iter()
            .map(|(name, dp)| {
                serde_json::json!({
                    "canonical": name,
                    "tier": dp.tier.to_string(),
                    "tshark_filter": dp.tshark_filter,
                    "scapy_class": dp.scapy_class,
                    "kernel_struct": dp.kernel_struct,
                    "min_header_bytes": dp.min_header_bytes,
                })
            })
            .collect();
        let output = serde_json::json!({
            "query": query,
            "total_matches": total,
            "results": results,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "Search: \"{}\" — {} match{}\n",
            query,
            total,
            if total == 1 { "" } else { "es" }
        );

        if matches.is_empty() {
            println!("  No protocols found matching '{}'.", query);
        } else {
            println!(
                "  {:<35} {:<12} {:<20} {:<15} {:>6}",
                "Protocol", "Tier", "tshark", "Scapy", "MinHdr"
            );
            println!("  {}", "─".repeat(90));

            for (name, dp) in &matches {
                let tshark = dp
                    .tshark_filter
                    .as_deref()
                    .unwrap_or("—");
                let scapy = dp
                    .scapy_class
                    .as_deref()
                    .unwrap_or("—");
                println!(
                    "  {:<35} {:<12} {:<20} {:<15} {:>4} B",
                    name,
                    dp.tier.to_string(),
                    tshark,
                    scapy,
                    dp.min_header_bytes,
                );
            }

            if total > matches.len() {
                println!(
                    "\n  ... and {} more (use --limit to see more)",
                    total - matches.len()
                );
            }
        }
    }

    Ok(())
}

/// Show PCAP corpus coverage.
pub fn cmd_corpus(proto_filter: Option<&str>, json_output: bool) -> Result<()> {
    let corpus_dir = std::env::var("PROTO_AUDIT_PCAP_CORPUS")
        .unwrap_or_default();

    if corpus_dir.is_empty() {
        anyhow::bail!(
            "PROTO_AUDIT_PCAP_CORPUS not set. Run via `nix run .#proto-audit -- corpus`"
        );
    }

    let corpus_path = std::path::Path::new(&corpus_dir);
    if !corpus_path.exists() {
        anyhow::bail!("Corpus directory does not exist: {}", corpus_dir);
    }

    // Check for pre-built corpus_summary.json (from Nix build)
    let summary_path = corpus_path.parent()
        .map(|p| p.join("corpus_summary.json"))
        .unwrap_or_default();

    if summary_path.exists() {
        let data = std::fs::read_to_string(&summary_path)?;
        let summary: serde_json::Value = serde_json::from_str(&data)?;

        if json_output {
            if let Some(filter) = proto_filter {
                let norm = discovery::normalize_name(filter);
                if let Some(protos) = summary.get("protocols").and_then(|p| p.as_object()) {
                    let filtered: serde_json::Map<String, serde_json::Value> = protos.iter()
                        .filter(|(k, _)| discovery::normalize_name(k).contains(&norm))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&filtered)?);
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            }
        } else {
            let proto_count = summary.get("protocol_count")
                .and_then(|v| v.as_u64()).unwrap_or(0);
            let pcap_count = summary.get("pcap_file_count")
                .and_then(|v| v.as_u64()).unwrap_or(0);

            println!("PCAP Corpus Summary");
            println!("  PDML files:      {}", pcap_count);
            println!("  Unique protocols: {}", proto_count);

            if let Some(protos) = summary.get("protocols").and_then(|p| p.as_object()) {
                let norm_filter = proto_filter.map(|f| discovery::normalize_name(f));
                let mut entries: Vec<_> = protos.iter()
                    .filter(|(k, _)| {
                        norm_filter.as_ref()
                            .map(|f| discovery::normalize_name(k).contains(f.as_str()))
                            .unwrap_or(true)
                    })
                    .collect();
                entries.sort_by(|a, b| {
                    let ac = a.1.get("pcap_count").and_then(|v| v.as_u64()).unwrap_or(0);
                    let bc = b.1.get("pcap_count").and_then(|v| v.as_u64()).unwrap_or(0);
                    bc.cmp(&ac)
                });

                println!("\n  {:<30}  {:>5}  {:>6}  {:>8}  {:>8}",
                    "Protocol", "PCAPs", "Fields", "MinBytes", "MaxBytes");
                println!("  {}  {}  {}  {}  {}",
                    "-".repeat(30), "-".repeat(5), "-".repeat(6),
                    "-".repeat(8), "-".repeat(8));

                for (name, info) in &entries {
                    let pcaps = info.get("pcap_count").and_then(|v| v.as_u64()).unwrap_or(0);
                    let fields = info.get("field_count").and_then(|v| v.as_u64()).unwrap_or(0);
                    let min_b = info.get("min_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                    let max_b = info.get("max_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                    println!("  {:<30}  {:>5}  {:>6}  {:>8}  {:>8}",
                        truncate(name, 30), pcaps, fields, min_b, max_b);
                }
                println!("\n  Showing {} protocols", entries.len());
            }
        }
        return Ok(());
    }

    // Fallback: scan PDML directory directly
    let mut proto_pcap_count: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut total_files = 0u32;

    if let Ok(entries) = std::fs::read_dir(corpus_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "xml").unwrap_or(false) {
                total_files += 1;
                if let Ok(xml) = std::fs::read_to_string(&path) {
                    if let Ok(packets) = extractors::tshark::parse_pdml(&xml) {
                        for packet in &packets {
                            for proto in packet {
                                *proto_pcap_count.entry(proto.name.clone()).or_default() += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    let norm_filter = proto_filter.map(|f| discovery::normalize_name(f));
    let filtered: Vec<_> = proto_pcap_count.iter()
        .filter(|(k, _)| {
            norm_filter.as_ref()
                .map(|f| discovery::normalize_name(k).contains(f.as_str()))
                .unwrap_or(true)
        })
        .collect();

    if json_output {
        let out: serde_json::Map<String, serde_json::Value> = filtered.iter()
            .map(|(k, v)| (k.to_string(), serde_json::json!({"pcap_count": v})))
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("PCAP Corpus (live scan)");
        println!("  PDML files: {}", total_files);
        println!("  Unique protocols: {}", filtered.len());

        let mut sorted: Vec<_> = filtered;
        sorted.sort_by(|a, b| b.1.cmp(a.1));

        println!("\n  {:<30}  {:>5}", "Protocol", "Count");
        println!("  {}  {}", "-".repeat(30), "-".repeat(5));
        for (name, count) in &sorted {
            println!("  {:<30}  {:>5}", truncate(name, 30), count);
        }
    }

    Ok(())
}

/// Show cross-source coverage gaps and improvement opportunities.
pub fn cmd_coverage(tier: &str, json_output: bool, paths: &SourcePaths) -> Result<()> {
    let tier_filter = TierFilter::from_str(tier);
    let discovery_state = DiscoveryState::load_from_env();
    let all_protos = discovery::all_protocols(&discovery_state);
    let vcache = load_validation_cache();

    let filtered: Vec<_> = all_protos
        .iter()
        .filter(|(_, dp)| tier_filter.matches(dp.tier))
        .collect();

    // Classify each protocol's coverage
    struct CoverageEntry {
        name: String,
        has_xdp2: bool,
        has_kernel: bool,
        has_scapy: bool,
        has_tshark: bool,
        has_etherparse: bool,
        has_libpcap: bool,
        source_count: u32,
        is_routable: bool,
        validation: String,
        xdp2_tier: &'static str,
    }

    let mut entries: Vec<CoverageEntry> = Vec::new();

    for (name, dp) in &filtered {
        let names = name_mapping::find_by_canonical(name);

        let has_xdp2 = names.as_ref().and_then(|n| n.xdp2).is_some();
        let has_kernel = dp.kernel_struct.is_some()
            || names.as_ref().and_then(|n| n.kernel_struct).is_some();
        let has_scapy = dp.scapy_class.is_some()
            || names.as_ref().and_then(|n| n.scapy).is_some();
        let has_tshark = dp.tshark_filter.is_some()
            || names.as_ref().and_then(|n| n.tshark).is_some();
        let has_etherparse = names.as_ref().and_then(|n| n.etherparse_struct).is_some();
        let has_libpcap = names.as_ref().and_then(|n| n.libpcap_name).is_some();

        let source_count = [has_xdp2, has_kernel, has_scapy, has_tshark, has_etherparse, has_libpcap]
            .iter()
            .filter(|&&x| x)
            .count() as u32;

        let is_routable = generator::stack_route_for(name).is_some();

        let validation = dp.validation_tier.as_ref()
            .or_else(|| vcache.get(name.as_str()))
            .map(|t| t.to_string())
            .unwrap_or_else(|| "-".to_string());

        let xdp2_tier = classify_xdp2_tier(name, dp);

        entries.push(CoverageEntry {
            name: name.to_string(),
            has_xdp2,
            has_kernel,
            has_scapy,
            has_tshark,
            has_etherparse,
            has_libpcap,
            source_count,
            is_routable,
            validation,
            xdp2_tier,
        });
    }

    // Sort: most sources first, then by name
    entries.sort_by(|a, b| b.source_count.cmp(&a.source_count).then(a.name.cmp(&b.name)));

    if json_output {
        let json_entries: Vec<_> = entries.iter().map(|e| {
            serde_json::json!({
                "protocol": e.name,
                "sources": e.source_count,
                "xdp2": e.has_xdp2,
                "kernel": e.has_kernel,
                "scapy": e.has_scapy,
                "tshark": e.has_tshark,
                "etherparse": e.has_etherparse,
                "libpcap": e.has_libpcap,
                "routable": e.is_routable,
                "validation": e.validation,
                "xdp2_tier": e.xdp2_tier,
            })
        }).collect();

        let summary = serde_json::json!({
            "total": entries.len(),
            "with_xdp2": entries.iter().filter(|e| e.has_xdp2).count(),
            "with_2_plus_sources": entries.iter().filter(|e| e.source_count >= 2).count(),
            "routable": entries.iter().filter(|e| e.is_routable).count(),
            "protocols": json_entries,
        });
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        // Summary stats
        let total = entries.len();
        let with_xdp2 = entries.iter().filter(|e| e.has_xdp2).count();
        let multi_source = entries.iter().filter(|e| e.source_count >= 2).count();
        let routable = entries.iter().filter(|e| e.is_routable).count();
        let gold = entries.iter().filter(|e| e.validation == "Gold").count();

        println!("Cross-Source Coverage Report (tier: {})", tier);
        println!("  Total protocols:     {:>4}", total);
        println!("  With XDP2 proto_def: {:>4}  ({:.0}%)", with_xdp2,
            100.0 * with_xdp2 as f64 / total.max(1) as f64);
        println!("  Multi-source (2+):   {:>4}  ({:.0}%)", multi_source,
            100.0 * multi_source as f64 / total.max(1) as f64);
        println!("  Routable (PCAP gen): {:>4}  ({:.0}%)", routable,
            100.0 * routable as f64 / total.max(1) as f64);
        println!("  Gold-validated:      {:>4}  ({:.0}%)", gold,
            100.0 * gold as f64 / total.max(1) as f64);

        // Gap analysis: protocols missing from important sources
        let missing_xdp2: Vec<_> = entries.iter()
            .filter(|e| !e.has_xdp2 && matches!(e.xdp2_tier, "1-core" | "2-production"))
            .collect();
        if !missing_xdp2.is_empty() {
            println!("\n  Missing from XDP2 (tier 1-2 candidates):");
            for e in &missing_xdp2 {
                println!("    {:<30}  sources: {}  routable: {}",
                    truncate(&e.name, 30), e.source_count,
                    if e.is_routable { "yes" } else { "no" });
            }
        }

        let single_source: Vec<_> = entries.iter()
            .filter(|e| e.source_count == 1 && e.has_tshark)
            .take(20)
            .collect();
        if !single_source.is_empty() {
            println!("\n  Single-source (tshark only, need cross-validation):");
            for e in &single_source {
                println!("    {:<30}  validation: {}", truncate(&e.name, 30), e.validation);
            }
        }

        // Coverage matrix header
        println!("\n  {:<30}  {:>3}  {:<6}  {:<6}  {:<6}  {:<6}  {:<6}  {:<6}  {:<5}  {:<11}",
            "Protocol", "Src", "XDP2", "Kernel", "Scapy", "tshark", "EParse", "libpcap", "Route", "Valid.");
        println!("  {}  {}  {}  {}  {}  {}  {}  {}  {}  {}",
            "-".repeat(30), "-".repeat(3), "-".repeat(6), "-".repeat(6),
            "-".repeat(6), "-".repeat(6), "-".repeat(6), "-".repeat(6),
            "-".repeat(5), "-".repeat(11));

        for e in &entries {
            println!("  {:<30}  {:>3}  {:<6}  {:<6}  {:<6}  {:<6}  {:<6}  {:<6}  {:<5}  {:<11}",
                truncate(&e.name, 30),
                e.source_count,
                if e.has_xdp2 { "\u{2713}" } else { "-" },
                if e.has_kernel { "\u{2713}" } else { "-" },
                if e.has_scapy { "\u{2713}" } else { "-" },
                if e.has_tshark { "\u{2713}" } else { "-" },
                if e.has_etherparse { "\u{2713}" } else { "-" },
                if e.has_libpcap { "\u{2713}" } else { "-" },
                if e.is_routable { "\u{2713}" } else { "-" },
                e.validation,
            );
        }
    }

    Ok(())
}

/// Show comprehensive system statistics.
pub fn cmd_stats(json_output: bool, paths: &SourcePaths) -> Result<()> {
    let discovery_state = DiscoveryState::load_from_env();
    let all_protos = discovery::all_protocols(&discovery_state);
    let curated_table = name_mapping::protocol_table();

    // Count by tier
    let curated_count = all_protos.values().filter(|dp| dp.tier == Tier::Curated).count();
    let discovered_count = all_protos.values().filter(|dp| dp.tier == Tier::Discovered).count();

    // Source coverage
    let with_tshark = all_protos.values().filter(|dp| dp.tshark_filter.is_some()).count();
    let with_scapy = all_protos.values().filter(|dp| dp.scapy_class.is_some()).count();
    let with_kernel = all_protos.values().filter(|dp| dp.kernel_struct.is_some()).count();
    let multi_source = all_protos.values().filter(|dp| {
        let n = dp.tshark_filter.is_some() as u32
            + dp.scapy_class.is_some() as u32
            + dp.kernel_struct.is_some() as u32;
        n >= 2
    }).count();

    // Validation cache
    let vcache = load_validation_cache();
    let gold_count = vcache.values().filter(|t| **t == discovery::ValidationTier::Gold).count();
    let silver_count = vcache.values().filter(|t| **t == discovery::ValidationTier::Silver).count();
    let bronze_count = vcache.values().filter(|t| **t == discovery::ValidationTier::Bronze).count();

    // Standards coverage
    let with_rfcs = curated_table.iter().filter(|p| !p.rfc_numbers.is_empty()).count();
    let with_ieee = curated_table.iter().filter(|p| !p.ieee_standards.is_empty()).count();
    let with_iana = curated_table.iter().filter(|p| p.iana_registry.is_some()).count();
    let total_rfcs: usize = curated_table.iter().map(|p| p.rfc_numbers.len()).sum();

    // Curated source coverage (etherparse, libpcap)
    let with_etherparse = curated_table.iter().filter(|p| p.etherparse_struct.is_some()).count();
    let with_libpcap = curated_table.iter().filter(|p| p.libpcap_name.is_some()).count();
    let with_xdp2_curated = curated_table.iter().filter(|p| p.xdp2.is_some()).count();

    // XDP2 proto_defs (from filesystem scan)
    let xdp2_count = paths
        .proto_defs_dir
        .as_ref()
        .and_then(|dir| extractors::xdp2::scan_proto_defs_dir(dir).ok())
        .map(|d| d.len())
        .unwrap_or(0);

    // Registry stats
    let tshark_reg_count = discovery_state
        .tshark
        .as_ref()
        .map(|r| r.protocols.len())
        .unwrap_or(0);
    let scapy_reg_count = discovery_state
        .scapy
        .as_ref()
        .map(|r| r.classes.len())
        .unwrap_or(0);
    let kernel_reg_count = discovery_state
        .kernel
        .as_ref()
        .map(|r| r.structs.len())
        .unwrap_or(0);

    // Decode table entries
    let decode_table_count = discovery::routes::decode_table_count();

    if json_output {
        let output = serde_json::json!({
            "protocols": {
                "total": all_protos.len(),
                "curated": curated_count,
                "discovered": discovered_count,
            },
            "source_coverage": {
                "tshark_filter": with_tshark,
                "scapy_class": with_scapy,
                "kernel_struct": with_kernel,
                "multi_source_2plus": multi_source,
                "xdp2_proto_defs": xdp2_count,
                "xdp2_curated": with_xdp2_curated,
                "etherparse_struct": with_etherparse,
                "libpcap_name": with_libpcap,
            },
            "validation": {
                "gold": gold_count,
                "silver": silver_count,
                "bronze": bronze_count,
                "cached_total": vcache.len(),
            },
            "registries": {
                "tshark_protocols": tshark_reg_count,
                "scapy_classes": scapy_reg_count,
                "kernel_structs": kernel_reg_count,
            },
            "standards": {
                "protocols_with_rfcs": with_rfcs,
                "protocols_with_ieee": with_ieee,
                "protocols_with_iana": with_iana,
                "total_rfc_references": total_rfcs,
            },
            "infrastructure": {
                "decode_table_entries": decode_table_count,
            },
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Proto-Audit System Statistics\n");
        println!("  Protocols:");
        println!("    Total tracked:        {:>6}", all_protos.len());
        println!("    Curated (Tier 1):     {:>6}", curated_count);
        println!("    Discovered (Tier 2):  {:>6}", discovered_count);
        println!();
        println!("  Source Coverage:");
        println!("    With tshark filter:   {:>6}", with_tshark);
        println!("    With Scapy class:     {:>6}", with_scapy);
        println!("    With kernel struct:   {:>6}", with_kernel);
        println!("    Multi-source (2+):    {:>6}", multi_source);
        println!("    XDP2 proto_defs:      {:>6} ({} curated)", xdp2_count, with_xdp2_curated);
        println!("    Etherparse structs:   {:>6}/{}", with_etherparse, curated_count);
        println!("    Libpcap overlays:     {:>6}/{}", with_libpcap, curated_count);
        println!();
        println!("  Validation (cached):");
        println!("    Gold (round-trip):    {:>6}", gold_count);
        println!("    Silver (2+ agree):    {:>6}", silver_count);
        println!("    Bronze (single-src):  {:>6}", bronze_count);
        println!();
        println!("  Registries Loaded:");
        println!("    tshark protocols:     {:>6}", tshark_reg_count);
        println!("    Scapy classes:        {:>6}", scapy_reg_count);
        println!("    Kernel structs:       {:>6}", kernel_reg_count);
        println!();
        println!("  Standards Coverage (curated):");
        println!("    With RFC references:  {:>6}", with_rfcs);
        println!("    With IEEE references: {:>6}", with_ieee);
        println!("    With IANA registry:   {:>6}", with_iana);
        println!("    Total RFC references: {:>6}", total_rfcs);
        println!();
        println!("  Infrastructure:");
        println!("    Decode table entries:  {:>5}", decode_table_count);
    }

    Ok(())
}
