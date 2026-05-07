//! XDP2 Rust parse engine benchmark.
//!
//! Reads a PCAP file, filters to packets the Rust parse graph can handle,
//! and times the parse engine. Optionally writes a filtered PCAP for use
//! by the C benchmark so both parsers are measured on identical packets.
//!
//! ## Usage
//!
//! ```bash
//! # Benchmark with auto-filtering (default)
//! xdp2-bench --pcap test.pcap --iterations 100
//!
//! # Write filtered PCAP for C benchmark comparison
//! xdp2-bench --pcap test.pcap --output-pcap filtered.pcap --iterations 100
//! ```
//!
//! ## Filtering
//!
//! Before benchmarking, each packet is parsed once. Only packets that parse
//! successfully (ParseResult::Okay) are included in the timed benchmark.
//! This ensures a fair comparison with the C parser — both process only
//! packets that the Rust graph supports. As more protocols are added to
//! `graph.rs`, the filter automatically includes more packets.
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `main()` | `benchmark.c:590-726` | Performance benchmark loop |
//! | `graph::make_parser()` | `flow_dissector_parsers.h` | L2 parser definition |
//! | `pcap::load_pcap()` | `pcap_loader.h:load_pcap()` | PCAP file loading |

mod af_xdp;
#[cfg(target_os = "linux")]
mod af_xdp_template;
mod bench;
mod chain_histogram;
mod cli;
mod extractors;
mod flow_meta;
mod parity;
mod graph;
mod graph_compiled;
#[cfg(feature = "graph-enum")]
mod graph_enum;
mod graph_mono;
mod nodes;
mod pcap;
mod perf;
mod report;
mod runners;
mod simd_batch;
mod template;
mod template_classify;
mod template_gre;
mod template_ipip;
mod template_plain;
mod template_qinq;
mod template_simd;
mod template_vlan;

use std::process;

use clap::Parser;

use cli::{AfXdpTemplate, Cli, ParserMode};
use report::{af_xdp_error, print_af_xdp_stats, print_json_report, report, report_mt};
use runners::pin_to_core;

fn main() {
    let cli = Cli::parse();

    // Pin to a specific CPU core if requested (reduces jitter).
    if let Some(core) = cli.core_pin {
        pin_to_core(core);
    }

    // AF_XDP mode: live packet capture from NIC (exits after run).
    // af-xdp / af-xdp-mono / af-xdp-graph-enum all share the rx loop;
    // they differ only in the per-packet parser invoked by the
    // dispatch closure inside run_af_xdp.
    if matches!(cli.mode, ParserMode::AfXdp | ParserMode::AfXdpMono) {
        run_af_xdp(&cli);
        return;
    }
    #[cfg(feature = "graph-enum")]
    if matches!(cli.mode, ParserMode::AfXdpGraphEnum) {
        run_af_xdp(&cli);
        return;
    }

    // AF_XDP per-queue hardware-classified template mode (Linux only).
    #[cfg(target_os = "linux")]
    if matches!(cli.mode, ParserMode::AfXdpTemplateHw) {
        run_af_xdp_per_queue_template(&cli);
        return;
    }
    #[cfg(not(target_os = "linux"))]
    if matches!(cli.mode, ParserMode::AfXdpTemplateHw) {
        eprintln!("error: --mode af-xdp-template requires Linux");
        process::exit(1);
    }

    // All other modes require a PCAP file.
    let pcap_path = cli.pcap.as_deref().unwrap_or_else(|| {
        eprintln!("error: --pcap is required for mode {:?}", cli.mode);
        process::exit(1);
    });

    // Load packets
    let all_packets = match pcap::load_pcap(std::path::Path::new(pcap_path)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot load '{pcap_path}': {e}");
            process::exit(1);
        }
    };

    let total_loaded = all_packets.len();
    if total_loaded == 0 {
        eprintln!("error: no packets in '{pcap_path}'");
        process::exit(1);
    }

    eprintln!("Loaded {} packets from {pcap_path}", total_loaded);

    let parser = graph::make_parser();

    // ── Filter: keep only packets the Rust parser handles ──
    let packets: Vec<&pcap::StoredPacket> = all_packets
        .iter()
        .filter(|pkt| graph::parse_packet(&parser, &pkt.data).is_ok())
        .collect();

    let npkts = packets.len();
    eprintln!(
        "Filtered: {}/{} packets parseable ({:.1}%)",
        npkts,
        total_loaded,
        100.0 * npkts as f64 / total_loaded as f64
    );

    if npkts == 0 {
        eprintln!("error: no packets passed the parse filter");
        process::exit(1);
    }

    // ── Probe: chain-signature histogram (no benchmarking) ──
    if cli.chain_histogram {
        chain_histogram::run(&packets, cli.top);
        return;
    }

    // ── Write filtered PCAP if requested ──
    if let Some(ref path) = cli.output_pcap {
        let filtered: Vec<pcap::StoredPacket> = packets
            .iter()
            .map(|pkt| pcap::StoredPacket {
                data: pkt.data.clone(),
            })
            .collect();
        if let Err(e) = pcap::write_pcap(std::path::Path::new(path), &filtered) {
            eprintln!("error: cannot write '{}': {}", path, e);
            process::exit(1);
        }
        eprintln!("Wrote filtered PCAP: {} ({} packets)", path, npkts);
    }

    // Warmup
    for _ in 0..cli.warmup {
        for pkt in &packets {
            let _ = graph::parse_packet(&parser, &pkt.data);
        }
    }

    // Determine which perf passes to run.
    let perf_passes: Vec<perf::PerfPass> = if cli.perf {
        if cli.perf_pass.is_empty() {
            vec![perf::PerfPass::Basic]
        } else {
            cli.perf_pass.clone()
        }
    } else {
        vec![]
    };

    // Validate perf counter availability up front (fail-fast).
    if let Some(&first_pass) = perf_passes.first() {
        match perf::PerfCounters::new(first_pass) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("warning: could not initialize perf counters: {e}");
                eprintln!("         (try: sudo sysctl -w kernel.perf_event_paranoid=1)");
            }
        }
    }

    // Correctness & anti-DCE: count successful parses across one full sweep.
    let cc = bench::check_correctness(&packets, &parser);

    // ── Parity dump (Phase 17.B) ──
    // When --dump-meta <path> is set, run each enabled mode once per
    // packet and emit one ParityRecord per packet per mode. Done as a
    // separate pass before the timed benchmark so iteration count
    // doesn't multiply the JSONL line count.
    //
    // CRITICAL: dump-meta iterates `all_packets` (the unfiltered set),
    // NOT the graph-filtered `packets`. The parity comparator joins
    // records across parsers by (pcap, packet_index); using the filtered
    // set in Rust while C parsers use the unfiltered set breaks index
    // alignment across the JSONL tree and produces phantom disagreements.
    // Each parser handles its own rejections via accepted=false.
    if let Some(ref dump_path) = cli.dump_meta {
        let pcap_label = cli
            .dump_meta_pcap
            .clone()
            .unwrap_or_else(|| {
                std::path::Path::new(&pcap_path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("?")
                    .to_string()
            });
        let all_refs: Vec<&pcap::StoredPacket> = all_packets.iter().collect();
        if let Err(e) = bench::dump_meta_pass(
            &cli.mode,
            &all_refs,
            &parser,
            dump_path,
            &pcap_label,
        ) {
            eprintln!("error: dump-meta pass failed: {e}");
            process::exit(1);
        }
        eprintln!("[dump-meta] wrote {} ({} packets)", dump_path, all_packets.len());
        if cli.dump_meta_only {
            return;
        }
    }

    if !cli.report {
        println!(
            "--- Performance ({} packets x {} iterations, {} template-matched) ---",
            npkts, cli.iterations, cc.template_ok
        );
    }

    let results = bench::run_benchmarks(
        &cli.mode,
        &packets,
        &parser,
        cli.iterations,
        cli.threads,
        &perf_passes,
        cli.report,
    );

    // Output results
    if cli.report {
        print_json_report(
            pcap_path,
            npkts,
            cli.iterations,
            &results,
            cc.graph_ok,
            cc.mono_ok,
            cc.compiled_ok,
            cc.template_ok,
        );
    } else {
        for r in &results {
            if r.threads > 1 {
                report_mt(&r.mode, r.ns_pkt, r.mpps, r.threads);
            } else {
                report(r);
            }
        }
        println!(
            "Correctness: graph ok={}/{}, mono ok={}/{}, compiled ok={}/{}, template ok={}/{}",
            cc.graph_ok, npkts, cc.mono_ok, npkts, cc.compiled_ok, npkts, cc.template_ok, npkts
        );
    }
}

/// AF_XDP per-queue hardware-classified template benchmark.
///
/// Parses `--queue-template` flags into `PerQueueTemplate` bindings,
/// binds one AF_XDP socket per queue, and times template extraction
/// with no software classification. Emits a per-queue table to stdout.
#[cfg(target_os = "linux")]
fn run_af_xdp_per_queue_template(cli: &Cli) {
    let iface = match &cli.interface {
        Some(s) => s.as_str(),
        None => {
            eprintln!("error: --interface is required for --mode af-xdp-template");
            process::exit(1);
        }
    };
    if cli.queue_templates.is_empty() {
        eprintln!(
            "error: --mode af-xdp-template requires at least one \
             --queue-template <QID>=<NAME>"
        );
        process::exit(1);
    }

    let queues: Vec<af_xdp_template::PerQueueTemplate> = cli
        .queue_templates
        .iter()
        .map(|s| af_xdp_template::parse_queue_template(s))
        .collect::<Result<_, _>>()
        .unwrap_or_else(|e| {
            eprintln!("error: {e}");
            process::exit(1);
        });

    let mut bind_flags: u16 = 0;
    if cli.zero_copy {
        bind_flags |= xdp2_af_xdp::sys::XDP_ZEROCOPY;
    }
    let run_cfg = af_xdp::RunConfig {
        huge_pages: cli.huge_pages,
        busy_poll_us: cli.busy_poll,
        batch_size: cli.batch_size,
        bind_flags,
        need_wakeup: cli.need_wakeup,
        rx_ring_size: cli.rx_ring_size,
        fill_ring_size: cli.fill_ring_size,
        frame_count: cli.frame_count,
    };

    match af_xdp_template::run_af_xdp_template(
        iface,
        &queues,
        cli.duration,
        &run_cfg,
        cli.core_pin,
    ) {
        Ok(reports) => {
            println!(
                "--- AF_XDP per-queue template on {iface} ({}s) ---",
                cli.duration
            );
            println!(
                "{:<8} | {:<34} | {:>14} | {:>14} | {:>10} | {:>8}",
                "queue", "template", "packets", "bytes", "ns/pkt", "Mpps"
            );
            println!("{}", "-".repeat(103));
            for r in &reports {
                println!(
                    "{:<8} | {:<34} | {:>14} | {:>14} | {:>10} | {:>8.2}",
                    r.queue_id,
                    format!("{:?}", r.template_id),
                    r.packets,
                    r.bytes,
                    r.ns_per_pkt,
                    r.mpps
                );
            }
            let total: u64 = reports.iter().map(|r| r.packets).sum();
            if total == 0 {
                eprintln!(
                    "warning: 0 packets across all queues. Check Flow \
                     Director rules (ethtool -n {iface}) and that \
                     traffic is actually arriving."
                );
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    }
}

/// AF_XDP live capture benchmark.
fn run_af_xdp(cli: &Cli) {
    let iface = match &cli.interface {
        Some(s) => s.as_str(),
        None => {
            eprintln!("error: --interface is required for --mode af-xdp");
            process::exit(1);
        }
    };

    // Parser selection. The default is `--mode af-xdp`, which dispatches
    // through graph_compiled (or a template if --af-xdp-template is set).
    // Phase L2 modes (AfXdpMono, AfXdpGraphEnum) override the parser
    // unconditionally — the template selection is only honored on AfXdp.
    let mode = cli.mode;
    let tmpl = cli.af_xdp_template.clone();

    // Build the parser-selection enum once outside the closure so the
    // dispatch is a single match on a small enum (cheaper than re-checking
    // ParserMode every packet, and lets the compiler hoist the
    // graph_enum config setup ONCE).
    enum AfXdpDispatch {
        CompiledOrTemplate(Option<AfXdpTemplate>),
        Mono,
        #[cfg(feature = "graph-enum")]
        GraphEnum(std::sync::Arc<xdp2_core::ParserConfig<graph::FlowMeta>>),
    }
    let dispatch = match mode {
        ParserMode::AfXdpMono => AfXdpDispatch::Mono,
        #[cfg(feature = "graph-enum")]
        ParserMode::AfXdpGraphEnum => {
            AfXdpDispatch::GraphEnum(std::sync::Arc::new(graph_enum::make_config()))
        }
        // AfXdp (or anything else that gets here) honors --af-xdp-template.
        _ => AfXdpDispatch::CompiledOrTemplate(tmpl.clone()),
    };

    let process = move |pkt: &[u8]| {
        let mut meta = graph::FlowMeta::default();
        match &dispatch {
            AfXdpDispatch::CompiledOrTemplate(Some(AfXdpTemplate::EthIpv4Tcp)) => {
                let _ = template::extract_eth_ipv4_tcp(pkt, &mut meta);
            }
            AfXdpDispatch::CompiledOrTemplate(Some(AfXdpTemplate::EthIpv4Udp)) => {
                let _ = template::extract_eth_ipv4_udp(pkt, &mut meta);
            }
            AfXdpDispatch::CompiledOrTemplate(Some(AfXdpTemplate::EthIpv6Tcp)) => {
                let _ = template::extract_eth_ipv6_tcp(pkt, &mut meta);
            }
            AfXdpDispatch::CompiledOrTemplate(Some(AfXdpTemplate::Auto)) => {
                if let Some(id) = template::select_template_id(pkt) {
                    let _ = template::extract_by_id(pkt, id, &mut meta);
                } else {
                    let _ = graph_compiled::parse_packet(pkt, &mut meta);
                }
            }
            AfXdpDispatch::CompiledOrTemplate(None) => {
                let _ = graph_compiled::parse_packet(pkt, &mut meta);
            }
            AfXdpDispatch::Mono => {
                let _ = graph_mono::parse_packet_mono(pkt, &mut meta);
            }
            #[cfg(feature = "graph-enum")]
            AfXdpDispatch::GraphEnum(cfg) => {
                let _ = graph_enum::parse_packet(cfg, pkt);
            }
        }
        std::hint::black_box(&meta);
    };

    let parser_label = match mode {
        ParserMode::AfXdpMono => "mono".to_string(),
        #[cfg(feature = "graph-enum")]
        ParserMode::AfXdpGraphEnum => "graph-enum".to_string(),
        _ => match &tmpl {
            Some(t) => format!("template:{t:?}"),
            None => "compiled".to_string(),
        },
    };

    let mut bind_flags: u16 = 0;
    if cli.zero_copy {
        bind_flags |= xdp2_af_xdp::sys::XDP_ZEROCOPY;
    }

    let run_cfg = af_xdp::RunConfig {
        huge_pages: cli.huge_pages,
        busy_poll_us: cli.busy_poll,
        batch_size: cli.batch_size,
        bind_flags,
        need_wakeup: cli.need_wakeup,
        rx_ring_size: cli.rx_ring_size,
        fill_ring_size: cli.fill_ring_size,
        frame_count: cli.frame_count,
    };

    if cli.queues <= 1 {
        let result = af_xdp::run(iface, cli.queue, cli.duration, &run_cfg, process);
        match result {
            Ok(stats) => {
                print_af_xdp_stats(iface, cli.queue, &parser_label, &stats);
            }
            Err(e) => af_xdp_error(&e),
        }
    } else {
        let result = af_xdp::run_multi_queue(
            iface,
            cli.queue,
            cli.queues,
            cli.duration,
            &run_cfg,
            cli.core_pin,
            process,
        );
        match result {
            Ok(per_queue) => {
                for (i, stats) in per_queue.iter().enumerate() {
                    let qid = cli.queue + i as u32;
                    print_af_xdp_stats(iface, qid, &parser_label, stats);
                }
                if per_queue.len() > 1 {
                    let agg = af_xdp::aggregate_stats(&per_queue);
                    println!(
                        "\nAF_XDP Aggregate ({} queues, parser={parser_label}):",
                        per_queue.len()
                    );
                    println!("  Packets:  {}", agg.total_pkts);
                    println!("  Duration: {:.2}s", agg.elapsed.as_secs_f64());
                    if agg.total_pkts > 0 {
                        println!("  {} ns/pkt,  {:.1} Mpps", agg.ns_pkt(), agg.mpps());
                    }
                    println!("  {:.1} MB received", agg.total_bytes as f64 / 1_000_000.0);
                }
            }
            Err(e) => af_xdp_error(&e),
        }
    }
}
