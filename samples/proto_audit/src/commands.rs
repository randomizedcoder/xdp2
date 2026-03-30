use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::{
    comparator,
    discovery::{self, DiscoveredProtocol, DiscoveryState, Tier, TierFilter},
    extractors, generator, ir, name_mapping, report, type_mapping, SourcePaths,
};

/// Try to extract a protocol from a single source. Returns None on failure
/// (missing path, protocol not found) rather than hard error.
fn try_extract(
    source: &str,
    proto: &str,
    paths: &SourcePaths,
) -> Option<ir::ProtocolDef> {
    match source {
        "xdp2" => {
            let dir = paths.proto_defs_dir.as_ref()?;
            let all_defs = extractors::xdp2::scan_proto_defs_dir(dir).ok()?;
            let matching = all_defs
                .iter()
                .find(|d| {
                    d.display_name.to_lowercase() == proto.to_lowercase()
                        || d.var_name.to_lowercase().contains(&proto.to_lowercase())
                })?;
            Some(extractors::xdp2::to_protocol_def(matching))
        }
        "kernel" => {
            let src = paths.kernel_src.as_ref()?;
            let names = name_mapping::find_by_canonical(proto)?;
            let struct_name = names.kernel_struct?;
            let header = names.kernel_header?;
            // Try kernel source tree layout first, then glibc-dev layout
            let header_path = src.join(format!("include/uapi/{}", header));
            let header_path = if header_path.exists() {
                header_path
            } else {
                src.join(format!("include/{}", header))
            };
            let content = std::fs::read_to_string(&header_path).ok()?;
            let mut def = extractors::kernel::extract_protocol(&content, struct_name, header)
                .ok()
                .flatten()?;
            // Use canonical name, not kernel struct name
            def.name = names.canonical.to_string();
            def.is_variable_length = names.variable_length;
            Some(def)
        }
        "scapy" => {
            let helper = paths
                .scapy_helper
                .clone()
                .unwrap_or_else(|| PathBuf::from("helpers/scapy_dump.py"));
            let names = name_mapping::find_by_canonical(proto);
            let scapy_name = names.as_ref().and_then(|n| n.scapy)?;
            let sp =
                extractors::scapy::run_scapy_helper(&helper, scapy_name, &paths.python).ok()?;
            Some(extractors::scapy::to_protocol_def(&sp))
        }
        "tshark" => {
            let pcap_path = paths.pcap.as_ref()?;
            let names = name_mapping::find_by_canonical(proto);
            let dissector = names.as_ref().and_then(|n| n.tshark)?;
            let xml = extractors::tshark::run_tshark(pcap_path, &paths.tshark_bin, 10).ok()?;
            let packets = extractors::tshark::parse_pdml(&xml).ok()?;
            let pdml =
                extractors::tshark::extract_protocol_from_pdml(&packets, dissector)?;
            Some(extractors::tshark::to_protocol_def(&pdml))
        }
        "etherparse" => {
            let src = paths.etherparse_src.as_ref()?;
            let names = name_mapping::find_by_canonical(proto)?;
            let struct_name = names.etherparse_struct?;
            let source_file = names.etherparse_file?;
            let file_path = src.join(source_file);
            let content = std::fs::read_to_string(&file_path).ok()?;
            let mut def = extractors::etherparse::extract_protocol(
                &content, struct_name, source_file,
            )
            .ok()
            .flatten()?;
            def.name = names.canonical.to_string();
            def.is_variable_length = names.variable_length;
            Some(def)
        }
        "libpcap" => {
            let names = name_mapping::find_by_canonical(proto)?;
            let libpcap_name = names.libpcap_name?;
            let libpcap_file = names.libpcap_file?;
            let mappings = type_mapping::load_libpcap_mappings(None).ok()?;
            let mut def = extractors::libpcap::extract_protocol(
                paths.libpcap_src.as_deref(),
                proto,
                libpcap_name,
                libpcap_file,
                &mappings,
            )
            .ok()
            .flatten()?;
            def.name = names.canonical.to_string();
            def.is_variable_length = names.variable_length;
            Some(def)
        }
        _ => None,
    }
}

/// Try to extract a Tier 2 (discovered) protocol from a source.
///
/// For discovered protocols, we use tshark_filter/scapy_class/kernel_struct
/// directly from the discovery record instead of going through name_mapping.
fn try_extract_discovered(
    source: &str,
    dp: &DiscoveredProtocol,
    paths: &SourcePaths,
) -> Option<ir::ProtocolDef> {
    match source {
        "tshark" => {
            let pcap_path = paths.pcap.as_ref()?;
            let dissector = dp.tshark_filter.as_deref()?;
            let xml = extractors::tshark::run_tshark(pcap_path, &paths.tshark_bin, 10).ok()?;
            let packets = extractors::tshark::parse_pdml(&xml).ok()?;
            let pdml = extractors::tshark::extract_protocol_from_pdml(&packets, dissector)?;
            let mut def = extractors::tshark::to_protocol_def(&pdml);
            def.name = dp.canonical.clone();
            Some(def)
        }
        "scapy" => {
            let helper = paths
                .scapy_helper
                .clone()
                .unwrap_or_else(|| PathBuf::from("helpers/scapy_dump.py"));
            let scapy_name = dp.scapy_class.as_deref()?;
            let sp =
                extractors::scapy::run_scapy_helper(&helper, scapy_name, &paths.python).ok()?;
            let mut def = extractors::scapy::to_protocol_def(&sp);
            def.name = dp.canonical.clone();
            Some(def)
        }
        "kernel" => {
            let src = paths.kernel_src.as_ref()?;
            let struct_name = dp.kernel_struct.as_deref()?;
            let header = dp.kernel_header.as_deref()?;
            let header_path = src.join(format!("include/uapi/{}", header));
            let header_path = if header_path.exists() {
                header_path
            } else {
                src.join(format!("include/{}", header))
            };
            let content = std::fs::read_to_string(&header_path).ok()?;
            let mut def = extractors::kernel::extract_protocol(&content, struct_name, header)
                .ok()
                .flatten()?;
            def.name = dp.canonical.clone();
            Some(def)
        }
        // xdp2, etherparse, libpcap not available for discovered protocols
        _ => None,
    }
}

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

const ALL_SOURCES: &[&str] = &["xdp2", "kernel", "scapy", "tshark", "etherparse", "libpcap"];

fn parse_source_list(sources: Option<&str>) -> Vec<String> {
    match sources {
        Some(s) => s.split(',').map(|s| s.trim().to_string()).collect(),
        None => ALL_SOURCES.iter().map(|s| s.to_string()).collect(),
    }
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

    let results = run_audit(protos, sources, tier, &discovery_state, paths);

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
        _ => anyhow::bail!(
            "Unknown target '{}'. Valid targets: c, etherparse, scapy, pcap",
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

/// Build a proto map for PCAP stack construction by walking STACK_ROUTES from
/// target back to the root, extracting each protocol along the way.
fn build_proto_map(
    target_proto: &str,
    paths: &SourcePaths,
    discovery_state: &DiscoveryState,
) -> std::collections::BTreeMap<String, ir::ProtocolDef> {
    let mut map = std::collections::BTreeMap::new();
    let discovered_protos = discovery::all_protocols(discovery_state);

    // Walk the route from target to root, collecting all protocol names on the path
    let mut protos_needed: Vec<String> = vec![target_proto.to_string()];
    let mut current = target_proto.to_string();
    for _ in 0..10 {
        if generator::is_root(&current) {
            protos_needed.push(current.clone());
            break;
        }
        // Try curated STACK_ROUTES first
        if let Some((_, parent, _, _)) = generator::stack_route_for(&current) {
            protos_needed.push(parent.to_string());
            current = parent.to_string();
        }
        // Then try discovered routes
        else if let Some(route) = try_discovered_route(&current, discovery_state, &discovered_protos) {
            protos_needed.push(route.parent.clone());
            current = route.parent;
        } else {
            break;
        }
    }

    // Try to extract each protocol from available sources
    for proto_name in &protos_needed {
        if let Some(def) = try_extract("kernel", proto_name, paths)
            .or_else(|| try_extract("scapy", proto_name, paths))
            .or_else(|| try_extract("etherparse", proto_name, paths))
        {
            map.insert(proto_name.to_string(), def);
        }
    }
    map
}

/// Try to find a discovered route for a protocol from the tshark registry.
/// Accepts a pre-built protocol map to avoid rebuilding it on every call.
fn try_discovered_route(
    proto: &str,
    state: &DiscoveryState,
    discovered_protos: &std::collections::BTreeMap<String, DiscoveredProtocol>,
) -> Option<discovery::routes::StackRoute> {
    let registry = state.tshark.as_ref()?;
    let dp = discovered_protos.get(proto)?;
    let filter = dp.tshark_filter.as_deref()?;
    discovery::routes::discovered_route(filter, registry)
}

pub(crate) fn cmd_validate(
    proto: &str,
    tier: &str,
    keep_pcap: Option<PathBuf>,
    json_output: bool,
    paths: &SourcePaths,
) -> Result<()> {
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

    // Step 4: Run tshark on the generated PCAP
    let xml = extractors::tshark::run_tshark(&pcap_path, &paths.tshark_bin, 1)
        .context("running tshark on generated PCAP")?;
    let packets = extractors::tshark::parse_pdml(&xml)
        .context("parsing tshark PDML output")?;
    eprintln!("  [4/5] tshark parsed {} packet(s)", packets.len());

    // Find the target protocol in tshark output
    let dissector = tshark_dissector.or_else(|| {
        name_mapping::find_by_canonical(&effective_proto)
            .and_then(|n| n.tshark.map(|s| s.to_string()))
    });

    let tshark_proto = dissector
        .as_deref()
        .and_then(|d| extractors::tshark::extract_protocol_from_pdml(&packets, d));

    let tshark_def = match tshark_proto {
        Some(pdml) => extractors::tshark::to_protocol_def(&pdml),
        None => {
            let msg = format!(
                "tshark did not produce a dissection for '{}'. The PCAP was generated \
                 but tshark could not parse the target protocol layer.",
                effective_proto
            );
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "protocol": effective_proto,
                        "status": "error",
                        "message": msg,
                    }))?
                );
            } else {
                eprintln!("  [5/5] {}", msg);
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
    let result = comparator::audit_protocol(&effective_proto, &refs);
    eprintln!("  [5/5] Comparison complete");

    if json_output {
        let output = serde_json::json!({
            "protocol": effective_proto,
            "status": if result.fields_mismatch == 0 { "pass" } else { "fail" },
            "stack": pcap_output.stack,
            "pcap_bytes": pcap_output.pcap_bytes.len(),
            "ir_fields": protocol_def.fields.len(),
            "tshark_fields": tshark_def.fields.len(),
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
            println!("  Mismatch:      {} fields", result.fields_mismatch);
        }
        if result.fields_missing > 0 {
            println!("  Missing:       {} fields", result.fields_missing);
        }
        println!(
            "  Status:        {}",
            if result.fields_mismatch == 0 {
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

/// Build a rich IR ProtocolDef by extracting from available sources and merging.
/// Prefers kernel fields (most accurate struct layout), supplemented by scapy defaults.
fn build_rich_ir(proto: &str, paths: &SourcePaths) -> Result<ir::ProtocolDef> {
    // Try each source in priority order
    let source_priority = ["kernel", "scapy", "tshark", "etherparse"];
    let mut best: Option<ir::ProtocolDef> = None;

    for source in &source_priority {
        if let Some(def) = try_extract(source, proto, paths) {
            if best.as_ref().map_or(true, |b| def.fields.len() > b.fields.len()) {
                best = Some(def);
            }
        }
    }

    best.or_else(|| {
        // Fallback: minimal def from name mapping
        let names = name_mapping::find_by_canonical(proto)?;
        let mut def = ir::ProtocolDef::new(names.canonical, names.min_header_bytes * 8);
        if names.variable_length {
            def = def.with_variable_length();
        }
        Some(def)
    })
    .context(format!(
        "Unknown protocol: {}. Use --from-json for custom protocols.",
        proto
    ))
}

/// Build a rich IR for a discovered (non-curated) protocol.
/// Priority: scapy batch → tshark PDML batch → tshark registry → per-protocol fallback.
fn build_rich_ir_discovered(
    dp: &DiscoveredProtocol,
    batch: &BatchCache,
    paths: &SourcePaths,
) -> Result<ir::ProtocolDef> {
    // Try scapy batch first (highest quality for discovered)
    if let Some(mut def) = batch.get("scapy", dp) {
        def.generation_source = Some("scapy-batch".to_string());
        return Ok(def);
    }

    // Try tshark PDML batch (requires PCAP)
    if let Some(mut def) = batch.get("tshark", dp) {
        def.generation_source = Some("tshark-pdml".to_string());
        return Ok(def);
    }

    // Try tshark registry (no PCAP needed, approximate offsets)
    if let Some(def) = batch.get_from_registry(dp) {
        return Ok(def);
    }

    // Per-protocol fallback: try scapy/tshark extraction individually
    if let Some(mut def) = try_extract_discovered("scapy", dp, paths) {
        def.generation_source = Some("scapy-batch".to_string());
        return Ok(def);
    }
    if let Some(mut def) = try_extract_discovered("tshark", dp, paths) {
        def.generation_source = Some("tshark-pdml".to_string());
        return Ok(def);
    }

    anyhow::bail!(
        "Cannot build IR for discovered protocol '{}' — no source available",
        dp.canonical
    )
}

/// Resolve a protocol name to its canonical form and tshark dissector.
/// For discovered-tier protocols, looks up the discovery state.
fn resolve_protocol(
    proto: &str,
    tier_filter: TierFilter,
    discovered_protos: &std::collections::BTreeMap<String, DiscoveredProtocol>,
) -> (String, Option<String>) {
    // First try curated lookup
    if let Some(names) = name_mapping::find_by_canonical(proto) {
        return (
            names.canonical.to_string(),
            names.tshark.map(|s| s.to_string()),
        );
    }

    // Try discovery state for tier=all or tier=discovered
    if tier_filter != TierFilter::Curated {
        if let Some(dp) = discovered_protos.get(proto) {
            return (
                dp.canonical.clone(),
                dp.tshark_filter.clone(),
            );
        }
        // Fuzzy match: try case-insensitive
        let lower = proto.to_lowercase();
        for (canonical, dp) in discovered_protos {
            if canonical.to_lowercase() == lower {
                return (
                    dp.canonical.clone(),
                    dp.tshark_filter.clone(),
                );
            }
        }
    }

    (proto.to_string(), None)
}

/// Pre-loaded batch extraction caches (tshark PDML + Scapy dump-all + tshark registry).
/// Loaded once, reused across all discovered protocol extractions.
pub(crate) struct BatchCache {
    /// tshark: dissector_name → ProtocolDef (from parsing PCAP once)
    tshark_cache: Option<std::collections::HashMap<String, ir::ProtocolDef>>,
    /// scapy: class_name → ProtocolDef (from --dump-all once)
    scapy_cache: Option<std::collections::HashMap<String, ir::ProtocolDef>>,
    /// tshark registry: filter_name → ProtocolDef (from `tshark -G fields` metadata)
    tshark_registry_cache: Option<std::collections::HashMap<String, ir::ProtocolDef>>,
}

impl BatchCache {
    /// Load batch caches for discovered-tier extraction.
    pub(crate) fn load(paths: &SourcePaths, discovery_state: &DiscoveryState) -> Self {
        // Batch tshark: run tshark once, parse all protocols from PDML
        let tshark_cache = paths.pcap.as_ref().and_then(|pcap_path| {
            eprintln!("  [batch] Pre-parsing tshark PDML...");
            let xml = extractors::tshark::run_tshark(pcap_path, &paths.tshark_bin, 20).ok()?;
            let packets = extractors::tshark::parse_pdml(&xml).ok()?;
            let cache = extractors::tshark::extract_all_protocols_from_pdml(&packets);
            eprintln!("  [batch] Cached {} tshark protocols", cache.len());
            Some(cache)
        });

        // Batch scapy: run --dump-all once
        let scapy_cache = {
            let helper = paths
                .scapy_helper
                .clone()
                .unwrap_or_else(|| PathBuf::from("helpers/scapy_dump.py"));
            eprintln!("  [batch] Running scapy --dump-all...");
            match extractors::scapy::run_scapy_dump_all(&helper, &paths.python) {
                Ok(cache) => {
                    eprintln!("  [batch] Cached {} scapy protocols", cache.len());
                    Some(cache)
                }
                Err(e) => {
                    eprintln!("  [batch] scapy --dump-all failed: {}", e);
                    None
                }
            }
        };

        // Load PCAP corpus PDML files (pre-extracted at Nix build time)
        let tshark_cache = {
            let mut cache = tshark_cache.unwrap_or_default();
            if let Ok(corpus_dir) = std::env::var("PROTO_AUDIT_PCAP_CORPUS") {
                let corpus_path = std::path::Path::new(&corpus_dir);
                if corpus_path.is_dir() {
                    let before = cache.len();
                    if let Ok(entries) = std::fs::read_dir(corpus_path) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.extension().and_then(|e| e.to_str()) != Some("xml") {
                                continue;
                            }
                            if let Ok(xml) = std::fs::read_to_string(&path) {
                                if let Ok(packets) = extractors::tshark::parse_pdml(&xml) {
                                    let file_protos =
                                        extractors::tshark::extract_all_protocols_from_pdml(
                                            &packets,
                                        );
                                    for (name, def) in file_protos {
                                        cache.entry(name).or_insert(def);
                                    }
                                }
                            }
                        }
                    }
                    let added = cache.len() - before;
                    if added > 0 {
                        eprintln!(
                            "  [batch] Loaded {} new protocols from PCAP corpus ({} total tshark)",
                            added,
                            cache.len()
                        );
                    }
                }
            }
            if cache.is_empty() {
                None
            } else {
                Some(cache)
            }
        };

        // Build tshark registry cache from DiscoveryState
        let tshark_registry_cache = discovery_state.tshark.as_ref().map(|reg| {
            eprintln!("  [batch] Building tshark registry IR cache...");
            let cache = extractors::tshark_registry::registry_to_ir_map(reg);
            eprintln!("  [batch] Cached {} tshark registry protocols", cache.len());
            cache
        });

        BatchCache {
            tshark_cache,
            scapy_cache,
            tshark_registry_cache,
        }
    }

    /// Look up a protocol from the batch cache by source.
    fn get(&self, source: &str, dp: &DiscoveredProtocol) -> Option<ir::ProtocolDef> {
        match source {
            "tshark" => {
                let dissector = dp.tshark_filter.as_deref()?;
                let mut def = self.tshark_cache.as_ref()?.get(dissector)?.clone();
                def.name = dp.canonical.clone();
                Some(def)
            }
            "scapy" => {
                let class_name = dp.scapy_class.as_deref()?;
                let mut def = self.scapy_cache.as_ref()?.get(class_name)?.clone();
                def.name = dp.canonical.clone();
                Some(def)
            }
            _ => None,
        }
    }

    /// Look up a protocol from the tshark registry cache.
    fn get_from_registry(&self, dp: &DiscoveredProtocol) -> Option<ir::ProtocolDef> {
        let filter = dp.tshark_filter.as_deref()?;
        let mut def = self.tshark_registry_cache.as_ref()?.get(filter)?.clone();
        def.name = dp.canonical.clone();
        def.generation_source = Some("tshark-registry".to_string());
        Some(def)
    }
}

/// Shared helper: run audit across protocols and sources, return AuditResults.
/// Now tier-aware: includes discovered protocols when tier != "curated".
fn run_audit(
    protos: Option<&str>,
    sources: Option<&str>,
    tier: &str,
    discovery_state: &DiscoveryState,
    paths: &SourcePaths,
) -> Vec<ir::AuditResult> {
    let source_list = parse_source_list(sources);
    let tier_filter = TierFilter::from_str(tier);

    // Build the protocol list based on tier
    let proto_list: Vec<(String, Option<DiscoveredProtocol>)> = match protos {
        Some(p) => p
            .split(',')
            .map(|s| (s.trim().to_string(), None))
            .collect(),
        None => {
            if tier_filter == TierFilter::Curated {
                // Curated only: use the existing table
                name_mapping::protocol_table()
                    .iter()
                    .map(|p| (p.canonical.to_string(), None))
                    .collect()
            } else {
                // All or Discovered: merge curated + discovered
                let all_protos = discovery::all_protocols(discovery_state);
                all_protos
                    .into_iter()
                    .filter(|(_, dp)| tier_filter.matches(dp.tier))
                    .map(|(name, dp)| (name, Some(dp)))
                    .collect()
            }
        }
    };

    // For discovered-tier protocols, pre-load batch caches to avoid
    // N subprocess calls. Only load if we have discovered protocols.
    let has_discovered = proto_list
        .iter()
        .any(|(_, dp)| dp.as_ref().map(|d| d.tier == Tier::Discovered).unwrap_or(false));

    let batch = if has_discovered {
        Some(BatchCache::load(paths, discovery_state))
    } else {
        None
    };

    let mut results = Vec::new();
    for (proto, dp_opt) in &proto_list {
        let mut extracted: Vec<(String, ir::ProtocolDef)> = Vec::new();

        // Determine if this is a discovered protocol
        let is_discovered = dp_opt
            .as_ref()
            .map(|dp| dp.tier == Tier::Discovered)
            .unwrap_or(false);

        for source in &source_list {
            let def = if is_discovered {
                // For Tier 2, try batch cache first, then fallback to per-protocol
                let from_cache = dp_opt.as_ref().and_then(|dp| {
                    batch.as_ref().and_then(|b| b.get(source, dp))
                });
                from_cache.or_else(|| {
                    dp_opt
                        .as_ref()
                        .and_then(|dp| try_extract_discovered(source, dp, paths))
                })
            } else {
                // For Tier 1, use curated extraction path
                try_extract(source, proto, paths)
            };

            if let Some(d) = def {
                extracted.push((source.clone(), d));
            }
        }

        if extracted.is_empty() {
            continue;
        }

        let refs: Vec<(&str, &ir::ProtocolDef)> = extracted
            .iter()
            .map(|(name, def)| (name.as_str(), def))
            .collect();
        let mut result = comparator::audit_protocol(proto, &refs);

        // Tag the tier in the protocol name for display
        if is_discovered {
            result.protocol = format!("{} [D]", result.protocol);
        }

        results.push(result);
    }

    results
}

/// Apply --compact and --limit filters to audit results.
fn apply_filters(
    results: Vec<ir::AuditResult>,
    compact: bool,
    limit: Option<usize>,
) -> Vec<ir::AuditResult> {
    let mut results = if compact {
        results
            .into_iter()
            .filter(|r| r.total_fields > 0)
            .collect()
    } else {
        results
    };

    if let Some(n) = limit {
        results.truncate(n);
    }

    results
}

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
                "  {:<4}  {:<16}  {:<30}  {:<14}  {:<8}  {:<8}  {:<20}  {:<12}  {:>4}",
                "Tier", "Protocol", "XDP2", "Kernel", "Scapy", "tshark", "etherparse", "libpcap",
                "Bytes"
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

        let filtered: Vec<_> = all_protos
            .values()
            .filter(|dp| tier_filter.matches(dp.tier))
            .collect();

        if json_output {
            let json_list: Vec<_> = filtered
                .iter()
                .map(|dp| {
                    serde_json::json!({
                        "canonical": dp.canonical,
                        "tier": dp.tier.to_string(),
                        "tshark_filter": dp.tshark_filter,
                        "scapy_class": dp.scapy_class,
                        "kernel_struct": dp.kernel_struct,
                        "kernel_header": dp.kernel_header,
                        "estimated_field_count": dp.estimated_field_count,
                        "min_header_bytes": dp.min_header_bytes,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_list)?);
        } else {
            println!(
                "  {:<4}  {:<40}  {:<16}  {:<16}  {:<16}  {:>6}",
                "Tier", "Protocol", "tshark", "Scapy", "Kernel", "Fields"
            );
            println!(
                "  {}  {}  {}  {}  {}  {}",
                "-".repeat(4),
                "-".repeat(40),
                "-".repeat(16),
                "-".repeat(16),
                "-".repeat(16),
                "-".repeat(6)
            );
            for dp in &filtered {
                println!(
                    "  [{}]  {:<40}  {:<16}  {:<16}  {:<16}  {:>6}",
                    dp.tier,
                    truncate(&dp.canonical, 40),
                    dp.tshark_filter.as_deref().unwrap_or("-"),
                    dp.scapy_class.as_deref().unwrap_or("-"),
                    dp.kernel_struct.as_deref().unwrap_or("-"),
                    dp.estimated_field_count,
                );
            }
            println!(
                "\n  Total: {} protocols ({} curated, {} discovered)",
                filtered.len(),
                filtered.iter().filter(|dp| dp.tier == Tier::Curated).count(),
                filtered
                    .iter()
                    .filter(|dp| dp.tier == Tier::Discovered)
                    .count(),
            );
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
    // Reject targets that require curated metadata
    if target == "c" || target == "pcap" {
        anyhow::bail!(
            "generate-all does not support target '{}' — only 'etherparse' and 'scapy' are supported \
             for batch generation (C and PCAP targets require curated metadata).",
            target
        );
    }
    if target != "etherparse" && target != "scapy" {
        anyhow::bail!(
            "Unknown target '{}'. Valid targets for generate-all: etherparse, scapy",
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
                }));
            }
            continue;
        }

        // Generate code
        let generated = match target {
            "etherparse" => generator::generate_etherparse(&ir),
            "scapy" => generator::generate_scapy(&ir),
            _ => unreachable!(),
        };

        if let Some(ref dir) = output_dir {
            let ext = match target {
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

/// Truncate a string to max_len, appending "..." if truncated.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", &s[..max_len - 3])
    } else {
        s[..max_len].to_string()
    }
}
