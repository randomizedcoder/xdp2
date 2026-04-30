//! proto-audit: Multi-source protocol definition audit & generation tool.
//!
//! Compares protocol definitions across XDP2, Linux kernel, Scapy, and
//! tshark to audit correctness, find bugs, and auto-generate proto_defs.

mod cli;
mod commands;
mod comparator;
mod discovery;
mod extractors;
mod generator;
mod ir;
mod name_mapping;
mod netlink;
mod report;
mod type_mapping;

#[cfg(test)]
mod test_data;
#[cfg(test)]
mod roundtrip_tests;
#[cfg(test)]
mod crossgen_tests;

use anyhow::Result;
use clap::Parser;
use cli::*;
use commands::*;

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
        Commands::CorpusParse {
            pcap,
            proto,
            paths,
            json,
        } => cmd_corpus_parse(&pcap, proto.as_deref(), json, &paths),
        Commands::CrossGen {
            proto,
            target,
            paths,
            json,
        } => cmd_crossgen(&proto, &target, json, &paths),
        Commands::GenPatches {
            target,
            source,
            protos,
            out,
            dry_run,
            paths,
        } => cmd_gen_patches(&target, &source, protos.as_deref(), out, dry_run, &paths),
        Commands::Pipeline {
            proto,
            target,
            input_pcap,
            keep_pcap: _,
            paths,
            json,
        } => cmd_pipeline(&proto, &target, input_pcap.as_deref(), json, &paths),
        Commands::PipelineMatrix {
            protos,
            targets,
            workers,
            paths,
            json,
        } => cmd_pipeline_matrix(protos.as_deref(), targets.as_deref(), json, workers, &paths),
        Commands::GenerateTemplates {
            protos,
            output_dir,
            dry_run,
            workers,
            paths,
        } => cmd_generate_templates(&protos, &output_dir, dry_run, workers, &paths),
        Commands::Validate {
            proto,
            tier,
            keep_pcap,
            paths,
            json,
        } => cmd_validate(&proto, &tier, keep_pcap, json, &paths),
        Commands::CheckRs {
            rs_src,
            paths,
            json,
        } => cmd_check_rs(&rs_src, json, &paths),
        Commands::ValidateNetlink {
            proto,
            keep_lua,
            paths,
            json,
        } => cmd_validate_netlink(&proto, keep_lua, json, &paths),
    }
}
