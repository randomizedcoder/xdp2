use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::{
    discovery::{self, DiscoveryState, Tier, TierFilter},
    extractors, generator, ir, name_mapping, type_mapping, SourcePaths,
};

use super::helpers::*;

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
            .filter(|p| super::find_pcap_for_protocol(p).is_none())
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
            let pcap_bytes = match super::pcap_from_ir(&ir, proto, paths) {
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
            match super::tshark_from_pcap_bytes(&pcap_bytes, proto, paths) {
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
