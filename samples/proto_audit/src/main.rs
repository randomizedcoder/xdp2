//! proto-audit: Multi-source protocol definition audit & generation tool.
//!
//! Compares protocol definitions across XDP2, Linux kernel, Scapy, and
//! tshark to audit correctness, find bugs, and auto-generate proto_defs.

mod comparator;
mod extractors;
mod generator;
mod ir;
mod name_mapping;
mod report;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "proto-audit")]
#[command(about = "Multi-source protocol definition audit & generation tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Common source path options shared by compare, audit, and extract.
#[derive(clap::Args, Clone)]
struct SourcePaths {
    /// Path to XDP2 proto_defs directory
    #[arg(long)]
    proto_defs_dir: Option<PathBuf>,

    /// Path to kernel source tree
    #[arg(long)]
    kernel_src: Option<PathBuf>,

    /// Path to pcap file (for tshark)
    #[arg(long)]
    pcap: Option<PathBuf>,

    /// Path to scapy_dump.py helper
    #[arg(long)]
    scapy_helper: Option<PathBuf>,

    /// Python binary
    #[arg(long, default_value = "python3")]
    python: String,

    /// tshark binary
    #[arg(long, default_value = "tshark")]
    tshark_bin: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Extract protocol definition from a single source
    Extract {
        /// Source to extract from: xdp2, kernel, scapy, tshark
        #[arg(long)]
        source: String,

        /// Protocol name (canonical: IPv4, TCP, etc.)
        #[arg(long)]
        proto: String,

        #[command(flatten)]
        paths: SourcePaths,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Compare a protocol across available sources
    Compare {
        /// Protocol name (canonical: IPv4, TCP, etc.)
        #[arg(long)]
        proto: String,

        /// Only use these sources (comma-separated: xdp2,kernel,scapy,tshark)
        #[arg(long)]
        sources: Option<String>,

        #[command(flatten)]
        paths: SourcePaths,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Audit all mapped protocols across available sources
    Audit {
        /// Only audit these protocols (comma-separated)
        #[arg(long)]
        protos: Option<String>,

        /// Only use these sources (comma-separated)
        #[arg(long)]
        sources: Option<String>,

        #[command(flatten)]
        paths: SourcePaths,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Scan XDP2 proto_defs directory
    Scan {
        /// Path to proto_defs directory
        #[arg(long)]
        proto_defs_dir: PathBuf,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Generate a proto_def C header from IR
    Generate {
        /// Protocol name or path to IR JSON
        #[arg(long)]
        proto: String,

        /// Path to IR JSON file (alternative to --proto)
        #[arg(long)]
        from_json: Option<PathBuf>,

        /// Print to stdout without writing
        #[arg(long)]
        dry_run: bool,

        /// Output file path
        #[arg(long, short)]
        output: Option<PathBuf>,
    },

    /// List known protocols from the name mapping table
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Extract {
            source,
            proto,
            paths,
            json,
        } => cmd_extract(&source, &proto, &paths, json),
        Commands::Compare {
            proto,
            sources,
            paths,
            json,
        } => cmd_compare(&proto, sources.as_deref(), &paths, json),
        Commands::Audit {
            protos,
            sources,
            paths,
            json,
        } => cmd_audit(protos.as_deref(), sources.as_deref(), &paths, json),
        Commands::Scan { proto_defs_dir, json } => cmd_scan(&proto_defs_dir, json),
        Commands::Generate {
            proto,
            from_json,
            dry_run,
            output,
        } => cmd_generate(&proto, from_json, dry_run, output),
        Commands::List { json } => cmd_list(json),
    }
}

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
            extractors::kernel::extract_protocol(&content, struct_name, header)
                .ok()
                .flatten()
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
        _ => None,
    }
}

fn cmd_extract(
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

const ALL_SOURCES: &[&str] = &["xdp2", "kernel", "scapy", "tshark"];

fn parse_source_list(sources: Option<&str>) -> Vec<String> {
    match sources {
        Some(s) => s.split(',').map(|s| s.trim().to_string()).collect(),
        None => ALL_SOURCES.iter().map(|s| s.to_string()).collect(),
    }
}

fn cmd_compare(
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

fn cmd_audit(
    protos: Option<&str>,
    sources: Option<&str>,
    paths: &SourcePaths,
    json_output: bool,
) -> Result<()> {
    let source_list = parse_source_list(sources);

    // Determine which protocols to audit
    let proto_names: Vec<String> = match protos {
        Some(p) => p.split(',').map(|s| s.trim().to_string()).collect(),
        None => {
            // Default: all protocols in the name mapping table
            name_mapping::protocol_table()
                .iter()
                .map(|p| p.canonical.to_string())
                .collect()
        }
    };

    eprintln!(
        "Auditing {} protocols across sources: {}",
        proto_names.len(),
        source_list.join(", ")
    );

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

        let result = comparator::audit_protocol(proto, &refs);
        results.push(result);
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        print!("{}", report::format_audit_summary(&results));

        // Print detailed results for protocols with mismatches
        let problematic: Vec<_> = results
            .iter()
            .filter(|r| r.fields_mismatch > 0 || r.fields_missing > 0)
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

fn cmd_scan(proto_defs_dir: &PathBuf, json_output: bool) -> Result<()> {
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

fn cmd_generate(
    proto: &str,
    from_json: Option<PathBuf>,
    dry_run: bool,
    output: Option<PathBuf>,
) -> Result<()> {
    let protocol_def = if let Some(json_path) = from_json {
        let content = std::fs::read_to_string(&json_path)
            .with_context(|| format!("reading {}", json_path.display()))?;
        serde_json::from_str(&content).context("parsing IR JSON")?
    } else {
        // Try to build a minimal ProtocolDef from the name mapping
        let names = name_mapping::find_by_canonical(proto)
            .context(format!("Unknown protocol: {}. Use --from-json for custom protocols.", proto))?;

        ir::ProtocolDef {
            name: names.canonical.to_string(),
            min_header_bits: names.min_header_bytes * 8,
            is_variable_length: names.variable_length,
            fields: vec![],
            dispatch_field: None,
            dispatch_table: vec![],
            identifiers: std::collections::BTreeMap::new(),
            sources: std::collections::BTreeMap::new(),
        }
    };

    let header = generator::generate_proto_def(&protocol_def);

    if dry_run {
        println!("{}", header);
    } else if let Some(path) = output {
        std::fs::write(&path, &header)
            .with_context(|| format!("writing {}", path.display()))?;
        eprintln!("Wrote: {}", path.display());
    } else {
        println!("{}", header);
    }

    Ok(())
}

fn cmd_list(json_output: bool) -> Result<()> {
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
                    "min_header_bytes": p.min_header_bytes,
                    "variable_length": p.variable_length,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json_list)?);
    } else {
        println!(
            "  {:<16}  {:<30}  {:<14}  {:<8}  {:<8}  {:>4}",
            "Protocol", "XDP2", "Kernel", "Scapy", "tshark", "Bytes"
        );
        println!(
            "  {}  {}  {}  {}  {}  {}",
            "-".repeat(16), "-".repeat(30), "-".repeat(14), "-".repeat(8), "-".repeat(8), "-".repeat(4)
        );
        for p in &table {
            println!(
                "  {:<16}  {:<30}  {:<14}  {:<8}  {:<8}  {:>4}",
                p.canonical,
                p.xdp2.unwrap_or("-"),
                p.kernel_struct.unwrap_or("-"),
                p.scapy.unwrap_or("-"),
                p.tshark.unwrap_or("-"),
                p.min_header_bytes,
            );
        }
        println!("\n  Total: {} protocols", table.len());
    }

    Ok(())
}
