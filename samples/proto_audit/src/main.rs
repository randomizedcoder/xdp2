//! proto-audit: Multi-source protocol definition audit & generation tool.
//!
//! Compares protocol definitions across XDP2, Linux kernel, Scapy, and
//! tshark to audit correctness, find bugs, and auto-generate proto_defs.

mod commands;
mod comparator;
mod discovery;
mod extractors;
mod generator;
mod ir;
mod name_mapping;
mod report;
mod type_mapping;

#[cfg(test)]
mod test_data;
#[cfg(test)]
mod roundtrip_tests;

use anyhow::Result;
use clap::{Parser, Subcommand};
use commands::*;
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
pub(crate) struct SourcePaths {
    /// Path to XDP2 proto_defs directory
    #[arg(long, env = "PROTO_AUDIT_PROTO_DEFS_DIR")]
    pub(crate) proto_defs_dir: Option<PathBuf>,

    /// Path to kernel source tree
    #[arg(long, env = "PROTO_AUDIT_KERNEL_SRC")]
    pub(crate) kernel_src: Option<PathBuf>,

    /// Path to pcap file (for tshark)
    #[arg(long, env = "PROTO_AUDIT_PCAP")]
    pub(crate) pcap: Option<PathBuf>,

    /// Path to scapy_dump.py helper
    #[arg(long, env = "PROTO_AUDIT_SCAPY_HELPER")]
    pub(crate) scapy_helper: Option<PathBuf>,

    /// Python binary
    #[arg(long, env = "PROTO_AUDIT_PYTHON", default_value = "python3")]
    pub(crate) python: String,

    /// tshark binary
    #[arg(long, env = "PROTO_AUDIT_TSHARK_BIN", default_value = "tshark")]
    pub(crate) tshark_bin: String,

    /// Path to etherparse source tree
    #[arg(long, env = "PROTO_AUDIT_ETHERPARSE_SRC")]
    pub(crate) etherparse_src: Option<PathBuf>,

    /// Path to libpcap source tree
    #[arg(long, env = "PROTO_AUDIT_LIBPCAP_SRC")]
    pub(crate) libpcap_src: Option<PathBuf>,

    /// Path to Kaitai Struct formats directory
    #[arg(long, env = "PROTO_AUDIT_KAITAI_DIR")]
    pub(crate) kaitai_dir: Option<PathBuf>,

    /// Path to Suricata Rust source directory
    #[arg(long, env = "PROTO_AUDIT_SURICATA_DIR")]
    pub(crate) suricata_dir: Option<PathBuf>,
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

        /// Protocol tier: curated, discovered, or all
        #[arg(long, default_value = "curated")]
        tier: String,

        /// Omit protocols with no extracted fields (for large output)
        #[arg(long)]
        compact: bool,

        /// Limit output to first N protocols
        #[arg(long)]
        limit: Option<usize>,

        #[command(flatten)]
        paths: SourcePaths,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Scan XDP2 proto_defs directory
    Scan {
        /// Path to proto_defs directory
        #[arg(long, env = "PROTO_AUDIT_PROTO_DEFS_DIR")]
        proto_defs_dir: PathBuf,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Batch generate code for all discoverable protocols
    GenerateAll {
        /// Target output format: etherparse, scapy
        #[arg(long, default_value = "etherparse")]
        target: String,

        /// Protocol tier: curated, discovered, or all
        #[arg(long, default_value = "all")]
        tier: String,

        /// Output directory for generated files
        #[arg(long)]
        output_dir: Option<PathBuf>,

        /// Only count translatable protocols, don't generate code
        #[arg(long)]
        count_only: bool,

        /// Minimum number of fields to include a protocol
        #[arg(long)]
        min_fields: Option<usize>,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        #[command(flatten)]
        paths: SourcePaths,
    },

    /// Generate libpcap overlay patches from corpus PDML data
    #[command(name = "generate-libpcap-patches")]
    GenerateLibpcapPatches {
        /// Output directory for patch files (default: patches/libpcap)
        #[arg(long)]
        output_dir: Option<PathBuf>,

        /// Only generate for these protocols (comma-separated)
        #[arg(long)]
        protos: Option<String>,

        /// Minimum number of fields to include a protocol
        #[arg(long, default_value = "2")]
        min_fields: usize,

        /// Print to stdout without writing files
        #[arg(long)]
        dry_run: bool,

        #[command(flatten)]
        paths: SourcePaths,
    },

    /// Generate etherparse Rust struct patches from corpus PDML data
    #[command(name = "generate-etherparse-patches")]
    GenerateEtherparsePatches {
        /// Output directory for patch files (default: patches/etherparse)
        #[arg(long)]
        output_dir: Option<PathBuf>,

        /// Only generate for these protocols (comma-separated)
        #[arg(long)]
        protos: Option<String>,

        /// Minimum number of fields to include a protocol
        #[arg(long, default_value = "2")]
        min_fields: usize,

        /// Print to stdout without writing files
        #[arg(long)]
        dry_run: bool,

        #[command(flatten)]
        paths: SourcePaths,
    },

    /// Generate code from IR (C header, etherparse Rust struct, or Scapy class)
    Generate {
        /// Protocol name or path to IR JSON
        #[arg(long)]
        proto: String,

        /// Path to IR JSON file (alternative to --proto)
        #[arg(long)]
        from_json: Option<PathBuf>,

        /// Target output format: c, etherparse, scapy
        #[arg(long, default_value = "c")]
        target: String,

        /// Print to stdout without writing
        #[arg(long)]
        dry_run: bool,

        /// Output file path
        #[arg(long, short)]
        output: Option<PathBuf>,

        #[command(flatten)]
        paths: SourcePaths,
    },

    /// List known protocols from the name mapping table
    List {
        /// Protocol tier: curated, discovered, or all
        #[arg(long, default_value = "curated")]
        tier: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show source × protocol coverage matrix
    Matrix {
        /// Only audit these protocols (comma-separated)
        #[arg(long)]
        protos: Option<String>,

        /// Only use these sources (comma-separated)
        #[arg(long)]
        sources: Option<String>,

        /// Protocol tier: curated, discovered, or all
        #[arg(long, default_value = "curated")]
        tier: String,

        /// Omit protocols with no extracted fields
        #[arg(long)]
        compact: bool,

        /// Limit output to first N protocols
        #[arg(long)]
        limit: Option<usize>,

        #[command(flatten)]
        paths: SourcePaths,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show detailed cross-source disagreements and findings
    Findings {
        /// Only audit these protocols (comma-separated)
        #[arg(long)]
        protos: Option<String>,

        /// Only use these sources (comma-separated)
        #[arg(long)]
        sources: Option<String>,

        /// Protocol tier: curated, discovered, or all
        #[arg(long, default_value = "curated")]
        tier: String,

        /// Omit protocols with no findings
        #[arg(long)]
        compact: bool,

        /// Limit output to first N protocols
        #[arg(long)]
        limit: Option<usize>,

        #[command(flatten)]
        paths: SourcePaths,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Auto-match protocols across tshark, Scapy, and kernel registries
    AutoMatch {
        /// Minimum confidence threshold (0.0–1.0)
        #[arg(long, default_value = "0.8")]
        min_confidence: f32,

        /// Output file for auto_mappings.json (default: stdout)
        #[arg(long, short)]
        output: Option<PathBuf>,

        /// Output as JSON (always JSON, this controls pretty-print)
        #[arg(long)]
        json: bool,
    },

    /// Show PCAP corpus coverage (which protocols have PDML data)
    Corpus {
        /// Filter to show only protocols matching this name
        #[arg(long)]
        proto: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show cross-source coverage gaps and improvement opportunities
    Coverage {
        /// Protocol tier: curated, discovered, or all
        #[arg(long, default_value = "curated")]
        tier: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        #[command(flatten)]
        paths: SourcePaths,
    },

    /// Show comprehensive system statistics
    Stats {
        /// Output as JSON
        #[arg(long)]
        json: bool,

        #[command(flatten)]
        paths: SourcePaths,
    },

    /// Show RFC/IEEE/IANA standards references for protocols
    Standards {
        /// Protocol name (or "all" for summary)
        #[arg(long, default_value = "all")]
        proto: String,

        /// Validate dispatch tables against IANA registries
        #[arg(long)]
        validate: bool,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Rank protocols by XDP2 relevance, source coverage, and parseability
    Prioritize {
        /// Show top N protocols (default: 100)
        #[arg(long, default_value = "100")]
        top: usize,

        /// Protocol tier: curated, discovered, or all
        #[arg(long, default_value = "all")]
        tier: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        #[command(flatten)]
        paths: SourcePaths,
    },

    /// Show protocol quality breakdown (confidence, source coverage, categories)
    Quality {
        /// Protocol tier: curated, discovered, or all
        #[arg(long, default_value = "all")]
        tier: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Search protocols by keyword (name, tshark filter, description)
    Search {
        /// Search query (case-insensitive substring match)
        #[arg(long)]
        query: String,

        /// Protocol tier: curated, discovered, or all
        #[arg(long, default_value = "all")]
        tier: String,

        /// Limit output to first N results
        #[arg(long)]
        limit: Option<usize>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Generate PCAP, feed to tshark, compare IR vs tshark round-trip
    Validate {
        /// Protocol name (canonical: IPv4, TCP, etc.)
        #[arg(long)]
        proto: String,

        /// Protocol tier: curated, discovered, or all
        #[arg(long, default_value = "curated")]
        tier: String,

        /// Save generated PCAP to this path (otherwise uses a temp file)
        #[arg(long)]
        keep_pcap: Option<PathBuf>,

        #[command(flatten)]
        paths: SourcePaths,

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
            tier,
            compact,
            limit,
            paths,
            json,
        } => cmd_audit(protos.as_deref(), sources.as_deref(), &tier, compact, limit, &paths, json),
        Commands::Scan { proto_defs_dir, json } => cmd_scan(&proto_defs_dir, json),
        Commands::GenerateAll {
            target,
            tier,
            output_dir,
            count_only,
            min_fields,
            json,
            paths,
        } => cmd_generate_all(&target, &tier, output_dir, count_only, min_fields, json, &paths),
        Commands::GenerateLibpcapPatches {
            output_dir,
            protos,
            min_fields,
            dry_run,
            paths,
        } => cmd_generate_libpcap_patches(output_dir, protos.as_deref(), min_fields, dry_run, &paths),
        Commands::GenerateEtherparsePatches {
            output_dir,
            protos,
            min_fields,
            dry_run,
            paths,
        } => cmd_generate_etherparse_patches(output_dir, protos.as_deref(), min_fields, dry_run, &paths),
        Commands::Generate {
            proto,
            from_json,
            target,
            dry_run,
            output,
            paths,
        } => cmd_generate(&proto, from_json, &target, dry_run, output, &paths),
        Commands::List { tier, json } => cmd_list(&tier, json),
        Commands::Matrix {
            protos,
            sources,
            tier,
            compact,
            limit,
            paths,
            json,
        } => cmd_matrix(protos.as_deref(), sources.as_deref(), &tier, compact, limit, &paths, json),
        Commands::Findings {
            protos,
            sources,
            tier,
            compact,
            limit,
            paths,
            json,
        } => cmd_findings(protos.as_deref(), sources.as_deref(), &tier, compact, limit, &paths, json),
        Commands::AutoMatch {
            min_confidence,
            output,
            json,
        } => cmd_auto_match(min_confidence, output, json),
        Commands::Corpus { proto, json } => cmd_corpus(proto.as_deref(), json),
        Commands::Coverage { tier, json, paths } => cmd_coverage(&tier, json, &paths),
        Commands::Stats { json, paths } => cmd_stats(json, &paths),
        Commands::Standards {
            proto,
            validate,
            json,
        } => cmd_standards(&proto, validate, json),
        Commands::Prioritize {
            top,
            tier,
            json,
            paths,
        } => cmd_prioritize(top, &tier, json, &paths),
        Commands::Quality { tier, json } => cmd_quality(&tier, json),
        Commands::Search {
            query,
            tier,
            limit,
            json,
        } => cmd_search(&query, &tier, limit, json),
        Commands::Validate {
            proto,
            tier,
            keep_pcap,
            paths,
            json,
        } => cmd_validate(&proto, &tier, keep_pcap, json, &paths),
    }
}
