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

        /// Path to XDP2 proto_defs directory (for xdp2 source)
        #[arg(long)]
        proto_defs_dir: Option<PathBuf>,

        /// Path to kernel source tree (for kernel source)
        #[arg(long)]
        kernel_src: Option<PathBuf>,

        /// Path to pcap file (for tshark source)
        #[arg(long)]
        pcap: Option<PathBuf>,

        /// Path to scapy_dump.py helper
        #[arg(long)]
        scapy_helper: Option<PathBuf>,

        /// Python binary (default: python3)
        #[arg(long, default_value = "python3")]
        python: String,

        /// tshark binary (default: tshark)
        #[arg(long, default_value = "tshark")]
        tshark_bin: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Compare a protocol across multiple sources
    Compare {
        /// Protocol name
        #[arg(long)]
        proto: String,

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
            proto_defs_dir,
            kernel_src,
            pcap,
            scapy_helper,
            python,
            tshark_bin,
            json,
        } => cmd_extract(
            &source,
            &proto,
            proto_defs_dir,
            kernel_src,
            pcap,
            scapy_helper,
            &python,
            &tshark_bin,
            json,
        ),
        Commands::Compare { proto, json } => cmd_compare(&proto, json),
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

fn cmd_extract(
    source: &str,
    proto: &str,
    proto_defs_dir: Option<PathBuf>,
    kernel_src: Option<PathBuf>,
    pcap: Option<PathBuf>,
    scapy_helper: Option<PathBuf>,
    python: &str,
    tshark_bin: &str,
    json_output: bool,
) -> Result<()> {
    let protocol_def = match source {
        "xdp2" => {
            let dir = proto_defs_dir.context(
                "--proto-defs-dir required for xdp2 source"
            )?;
            let all_defs = extractors::xdp2::scan_proto_defs_dir(&dir)?;
            let matching: Vec<_> = all_defs
                .iter()
                .filter(|d| {
                    d.display_name.to_lowercase() == proto.to_lowercase()
                        || d.var_name.to_lowercase().contains(&proto.to_lowercase())
                })
                .collect();

            match matching.first() {
                Some(def) => extractors::xdp2::to_protocol_def(def),
                None => anyhow::bail!("Protocol '{}' not found in XDP2 proto_defs", proto),
            }
        }
        "kernel" => {
            let src = kernel_src.context("--kernel-src required for kernel source")?;
            let names = name_mapping::find_by_canonical(proto)
                .context(format!("Unknown protocol: {}", proto))?;
            let struct_name = names
                .kernel_struct
                .context(format!("No kernel struct known for {}", proto))?;
            let header = names
                .kernel_header
                .context(format!("No kernel header known for {}", proto))?;

            let header_path = src.join(format!("include/uapi/{}", header));
            let content = std::fs::read_to_string(&header_path)
                .with_context(|| format!("reading {}", header_path.display()))?;

            extractors::kernel::extract_protocol(&content, struct_name, header)?
                .context(format!("Struct {} not found in {}", struct_name, header))?
        }
        "scapy" => {
            let helper = scapy_helper
                .unwrap_or_else(|| PathBuf::from("helpers/scapy_dump.py"));
            let names = name_mapping::find_by_canonical(proto);
            let scapy_name = names
                .as_ref()
                .and_then(|n| n.scapy)
                .unwrap_or(proto);

            let sp = extractors::scapy::run_scapy_helper(&helper, scapy_name, python)?;
            extractors::scapy::to_protocol_def(&sp)
        }
        "tshark" => {
            let pcap_path = pcap.context("--pcap required for tshark source")?;
            let names = name_mapping::find_by_canonical(proto);
            let dissector = names
                .as_ref()
                .and_then(|n| n.tshark)
                .unwrap_or(proto);

            let xml = extractors::tshark::run_tshark(&pcap_path, tshark_bin, 10)?;
            let packets = extractors::tshark::parse_pdml(&xml)?;
            let pdml = extractors::tshark::extract_protocol_from_pdml(&packets, dissector)
                .context(format!("Protocol '{}' not found in PDML output", dissector))?;
            extractors::tshark::to_protocol_def(&pdml)
        }
        _ => anyhow::bail!("Unknown source: {}. Use: xdp2, kernel, scapy, tshark", source),
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&protocol_def)?);
    } else {
        print!("{}", report::format_protocol_text(&protocol_def));
    }

    Ok(())
}

fn cmd_compare(_proto: &str, _json: bool) -> Result<()> {
    // Comparison requires extracting from multiple sources and comparing.
    // For now, show that the infrastructure is in place.
    eprintln!("Compare command requires multiple source configurations.");
    eprintln!("Use 'extract' to get individual sources, then compare the JSON outputs.");
    eprintln!("Full multi-source comparison will be implemented in Phase 5.");
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
