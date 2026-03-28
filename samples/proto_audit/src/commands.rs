use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::{comparator, extractors, generator, ir, name_mapping, report, type_mapping, SourcePaths};

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
    paths: &SourcePaths,
    json_output: bool,
) -> Result<()> {
    let source_list = parse_source_list(sources);

    eprintln!(
        "Auditing {} protocols across sources: {}",
        match protos {
            Some(p) => p.split(',').count(),
            None => name_mapping::protocol_table().len(),
        },
        source_list.join(", ")
    );

    let results = run_audit(protos, sources, paths);

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

        let proto_map = build_proto_map(proto, paths);
        let pcap_output = generator::generate_pcap(&protocol_def, &proto_map)
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

    let protocol_def = if let Some(json_path) = from_json {
        let content = std::fs::read_to_string(&json_path)
            .with_context(|| format!("reading {}", json_path.display()))?;
        serde_json::from_str(&content).context("parsing IR JSON")?
    } else if target == "c" {
        // For C target, a minimal ProtocolDef from name mapping suffices
        let names = name_mapping::find_by_canonical(proto)
            .context(format!("Unknown protocol: {}. Use --from-json for custom protocols.", proto))?;

        {
            let mut def = ir::ProtocolDef::new(names.canonical, names.min_header_bytes * 8);
            if names.variable_length {
                def = def.with_variable_length();
            }
            def
        }
    } else {
        // For etherparse/scapy targets, try to extract a rich IR from available sources
        build_rich_ir(proto, paths)?
    };

    let generated = match target {
        "c" => generator::generate_proto_def(&protocol_def),
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
) -> std::collections::BTreeMap<String, ir::ProtocolDef> {
    let mut map = std::collections::BTreeMap::new();

    // Walk the route from target to root, collecting all protocol names on the path
    let mut protos_needed: Vec<String> = vec![target_proto.to_string()];
    let mut current = target_proto;
    for _ in 0..10 {
        if generator::is_root(current) {
            protos_needed.push(current.to_string());
            break;
        }
        if let Some((_, parent, _, _)) = generator::stack_route_for(current) {
            protos_needed.push(parent.to_string());
            current = parent;
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

pub(crate) fn cmd_validate(
    proto: &str,
    keep_pcap: Option<PathBuf>,
    json_output: bool,
    paths: &SourcePaths,
) -> Result<()> {
    // Step 1: Build rich IR for target protocol
    let protocol_def = build_rich_ir(proto, paths)?;
    eprintln!("  [1/5] Built IR for {} ({} fields)", proto, protocol_def.fields.len());

    // Step 2: Build proto map for stack construction
    let proto_map = build_proto_map(proto, paths);
    eprintln!("  [2/5] Built protocol map ({} entries)", proto_map.len());

    // Step 3: Generate PCAP
    let pcap_output = generator::generate_pcap(&protocol_def, &proto_map)
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
        let tmp = std::env::temp_dir().join(format!("proto-audit-{}.pcap", proto.to_lowercase()));
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
    let tshark_dissector = name_mapping::find_by_canonical(proto)
        .and_then(|n| n.tshark.map(|s| s.to_string()));

    let tshark_proto = tshark_dissector
        .as_deref()
        .and_then(|dissector| extractors::tshark::extract_protocol_from_pdml(&packets, dissector));

    let tshark_def = match tshark_proto {
        Some(pdml) => extractors::tshark::to_protocol_def(&pdml),
        None => {
            let msg = format!(
                "tshark did not produce a dissection for '{}'. The PCAP was generated \
                 but tshark could not parse the target protocol layer.",
                proto
            );
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "protocol": proto,
                        "status": "error",
                        "message": msg,
                    }))?
                );
            } else {
                eprintln!("  [5/5] {}", msg);
            }
            // Clean up temp file if not keeping
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
    let result = comparator::audit_protocol(proto, &refs);
    eprintln!("  [5/5] Comparison complete");

    if json_output {
        let output = serde_json::json!({
            "protocol": proto,
            "status": if result.fields_mismatch == 0 { "pass" } else { "fail" },
            "stack": pcap_output.stack,
            "pcap_bytes": pcap_output.pcap_bytes.len(),
            "ir_fields": protocol_def.fields.len(),
            "tshark_fields": tshark_def.fields.len(),
            "audit": result,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Round-trip validation: {}", proto);
        println!("  Stack: {}", pcap_output.stack.join(" → "));
        println!("  PCAP:  {} bytes", pcap_output.pcap_bytes.len());
        println!(
            "  IR fields:     {}",
            protocol_def.fields.len()
        );
        println!(
            "  tshark fields: {}",
            tshark_def.fields.len()
        );
        println!(
            "  Agreement:     {}/{} fields",
            result.fields_agree, result.total_fields
        );
        if result.fields_type_differ > 0 {
            println!(
                "  Type differ:   {} fields",
                result.fields_type_differ
            );
        }
        if result.fields_mismatch > 0 {
            println!(
                "  Mismatch:      {} fields",
                result.fields_mismatch
            );
        }
        if result.fields_missing > 0 {
            println!(
                "  Missing:       {} fields",
                result.fields_missing
            );
        }
        println!(
            "  Status:        {}",
            if result.fields_mismatch == 0 { "PASS" } else { "FAIL" }
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

/// Shared helper: run audit across protocols and sources, return AuditResults.
fn run_audit(
    protos: Option<&str>,
    sources: Option<&str>,
    paths: &SourcePaths,
) -> Vec<ir::AuditResult> {
    let source_list = parse_source_list(sources);

    let proto_names: Vec<String> = match protos {
        Some(p) => p.split(',').map(|s| s.trim().to_string()).collect(),
        None => name_mapping::protocol_table()
            .iter()
            .map(|p| p.canonical.to_string())
            .collect(),
    };

    let mut results = Vec::new();
    for proto in &proto_names {
        let mut extracted: Vec<(String, ir::ProtocolDef)> = Vec::new();
        for source in &source_list {
            if let Some(def) = try_extract(source, proto, paths) {
                extracted.push((source.clone(), def));
            }
        }
        if extracted.is_empty() {
            continue;
        }
        let refs: Vec<(&str, &ir::ProtocolDef)> = extracted
            .iter()
            .map(|(name, def)| (name.as_str(), def))
            .collect();
        results.push(comparator::audit_protocol(proto, &refs));
    }

    results
}

pub(crate) fn cmd_matrix(
    protos: Option<&str>,
    sources: Option<&str>,
    paths: &SourcePaths,
    json_output: bool,
) -> Result<()> {
    let results = run_audit(protos, sources, paths);

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
    paths: &SourcePaths,
    json_output: bool,
) -> Result<()> {
    let results = run_audit(protos, sources, paths);

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

pub(crate) fn cmd_list(json_output: bool) -> Result<()> {
    let table = name_mapping::protocol_table();

    if json_output {
        let json_list: Vec<_> = table
            .iter()
            .map(|p| {
                serde_json::json!({
                    "canonical": p.canonical,
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
            "  {:<16}  {:<30}  {:<14}  {:<8}  {:<8}  {:<20}  {:<12}  {:>4}",
            "Protocol", "XDP2", "Kernel", "Scapy", "tshark", "etherparse", "libpcap", "Bytes"
        );
        println!(
            "  {}  {}  {}  {}  {}  {}  {}  {}",
            "-".repeat(16), "-".repeat(30), "-".repeat(14), "-".repeat(8), "-".repeat(8), "-".repeat(20), "-".repeat(12), "-".repeat(4)
        );
        for p in &table {
            println!(
                "  {:<16}  {:<30}  {:<14}  {:<8}  {:<8}  {:<20}  {:<12}  {:>4}",
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

    Ok(())
}
