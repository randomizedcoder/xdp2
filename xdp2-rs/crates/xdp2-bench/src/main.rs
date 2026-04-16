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
mod cli;
mod extractors;
mod flow_meta;
mod graph;
mod graph_compiled;
mod graph_mono;
mod nodes;
mod pcap;
mod perf;
mod report;
mod runners;
mod simd_batch;
mod template;
mod template_gre;
mod template_ipip;
mod template_plain;
mod template_qinq;
mod template_simd;
mod template_vlan;

use std::process;

use clap::Parser;

use cli::{AfXdpTemplate, BenchResult, Cli, ParserMode};
use report::{af_xdp_error, print_af_xdp_stats, print_json_report, report, report_mt};
use runners::{bench_mono_x4, pin_to_core, run_mt, time_run_passes};

fn main() {
    let cli = Cli::parse();

    // Pin to a specific CPU core if requested (reduces jitter).
    if let Some(core) = cli.core_pin {
        pin_to_core(core);
    }

    // AF_XDP mode: live packet capture from NIC (exits after run).
    if matches!(cli.mode, ParserMode::AfXdp) {
        run_af_xdp(&cli);
        return;
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

    let total_pkts = npkts as u64 * cli.iterations as u64;

    let run_graph = matches!(cli.mode, ParserMode::Graph | ParserMode::Both);
    let run_mono = matches!(cli.mode, ParserMode::Mono | ParserMode::Both);
    let run_monox4 = matches!(cli.mode, ParserMode::MonoX4 | ParserMode::Both);
    let run_compiled = matches!(cli.mode, ParserMode::Compiled | ParserMode::Both);
    let run_simd = matches!(cli.mode, ParserMode::Simd | ParserMode::Both);
    let run_template = matches!(cli.mode, ParserMode::Template | ParserMode::Both);
    let run_template_simd = matches!(cli.mode, ParserMode::TemplateSimd | ParserMode::Both);

    // Correctness & anti-DCE: count successful parses across one full sweep.
    let graph_ok = packets
        .iter()
        .filter(|pkt| graph::parse_packet(&parser, &pkt.data).is_ok())
        .count();
    let mono_ok = packets
        .iter()
        .filter(|pkt| {
            let mut meta = graph::FlowMeta::default();
            graph_mono::parse_packet_mono(&pkt.data, &mut meta).is_ok()
        })
        .count();
    let compiled_ok = packets
        .iter()
        .filter(|pkt| {
            let mut meta = graph::FlowMeta::default();
            graph_compiled::parse_packet(&pkt.data, &mut meta).is_ok()
        })
        .count();
    let template_ok = packets
        .iter()
        .filter(|pkt| {
            let mut meta = graph::FlowMeta::default();
            template::select_template_id(&pkt.data)
                .map(|id| template::extract_by_id(&pkt.data, id, &mut meta).is_ok())
                .unwrap_or(false)
        })
        .count();

    if !cli.report {
        println!(
            "--- Performance ({} packets x {} iterations, {} template-matched) ---",
            npkts, cli.iterations, template_ok
        );
    }

    let mut results: Vec<BenchResult> = Vec::new();

    if cli.threads <= 1 {
        if run_graph {
            let (ns, snap) = time_run_passes(&perf_passes, cli.iterations, || {
                let mut acc: u64 = 0;
                for pkt in &packets {
                    if graph::parse_packet(&parser, &pkt.data).is_ok() {
                        acc += 1;
                    }
                }
                std::hint::black_box(acc);
            });
            results.push(BenchResult::new("graph", ns, total_pkts, 1, snap));
        }

        if run_mono {
            let (ns, snap) = time_run_passes(&perf_passes, cli.iterations, || {
                let mut acc: u64 = 0;
                let mut meta = graph::FlowMeta::default();
                for pkt in &packets {
                    meta = graph::FlowMeta::default();
                    if graph_mono::parse_packet_mono(&pkt.data, &mut meta).is_ok() {
                        acc += 1;
                    }
                }
                std::hint::black_box(acc);
                std::hint::black_box(&meta);
            });
            results.push(BenchResult::new("mono", ns, total_pkts, 1, snap));
        }

        if run_monox4 {
            let (ns, snap) = time_run_passes(&perf_passes, cli.iterations, || {
                std::hint::black_box(bench_mono_x4(&packets));
            });
            results.push(BenchResult::new("mono-x4", ns, total_pkts, 1, snap));
        }

        if run_compiled {
            let (ns, snap) = time_run_passes(&perf_passes, cli.iterations, || {
                let mut acc: u64 = 0;
                let mut meta = graph::FlowMeta::default();
                for pkt in &packets {
                    meta = graph::FlowMeta::default();
                    if graph_compiled::parse_packet(&pkt.data, &mut meta).is_ok() {
                        acc += 1;
                    }
                }
                std::hint::black_box(acc);
                std::hint::black_box(&meta);
            });
            results.push(BenchResult::new("compiled", ns, total_pkts, 1, snap));
        }

        if run_simd && simd_batch::is_available() {
            let (ns, snap) = time_run_passes(&perf_passes, cli.iterations, || {
                let mut meta = graph::FlowMeta::default();
                std::hint::black_box(unsafe { simd_batch::parse_batch_avx2(&packets, &mut meta) });
                std::hint::black_box(&meta);
            });
            results.push(BenchResult::new("simd", ns, total_pkts, 1, snap));
        } else if run_simd {
            eprintln!("warning: AVX2 not available, skipping SIMD benchmark");
        }

        if run_template {
            let (ns, snap) = time_run_passes(&perf_passes, cli.iterations, || {
                let mut acc: u64 = 0;
                let mut meta = graph::FlowMeta::default();
                for pkt in &packets {
                    meta = graph::FlowMeta::default();
                    if let Some(id) = template::select_template_id(&pkt.data) {
                        if template::extract_by_id(&pkt.data, id, &mut meta).is_ok() {
                            acc += 1;
                        }
                    } else {
                        if graph_compiled::parse_packet(&pkt.data, &mut meta).is_ok() {
                            acc += 1;
                        }
                    }
                }
                std::hint::black_box(acc);
                std::hint::black_box(&meta);
            });
            results.push(BenchResult::new("template", ns, total_pkts, 1, snap));
        }

        if run_template_simd && template_simd::is_available() {
            let template_ids: Vec<Option<template::TemplateId>> = packets
                .iter()
                .map(|pkt| template::select_template_id(&pkt.data))
                .collect();
            let (ns, snap) = time_run_passes(&perf_passes, cli.iterations, || {
                let batch_acc =
                    template_simd::extract_batch(&packets, &template_ids);
                let mut meta = graph::FlowMeta::default();
                let mut fallback_acc: u64 = 0;
                for (pkt, tid) in packets.iter().zip(template_ids.iter()) {
                    if tid.is_none() {
                        meta = graph::FlowMeta::default();
                        if graph_compiled::parse_packet(&pkt.data, &mut meta).is_ok() {
                            fallback_acc += 1;
                        }
                    }
                }
                std::hint::black_box(batch_acc + fallback_acc);
                std::hint::black_box(&meta);
            });
            results.push(BenchResult::new("template-simd", ns, total_pkts, 1, snap));
        } else if run_template_simd {
            eprintln!("warning: AVX2 not available, skipping template-simd benchmark");
        }
    } else {
        if !cli.report {
            eprintln!(
                "Multi-threaded benchmark: {} threads (perf counters disabled)",
                cli.threads
            );
        }
        if run_graph {
            let ns = run_mt(&packets, cli.iterations, cli.threads, |slice| {
                let slice = std::hint::black_box(slice);
                let mut acc: u64 = 0;
                for pkt in slice {
                    if graph::parse_packet(&parser, &pkt.data).is_ok() {
                        acc += 1;
                    }
                }
                acc
            });
            results.push(BenchResult::new("graph-mt", ns, total_pkts, cli.threads, None));
        }

        if run_mono {
            let ns = run_mt(&packets, cli.iterations, cli.threads, |slice| {
                let slice = std::hint::black_box(slice);
                let mut acc: u64 = 0;
                let mut meta = graph::FlowMeta::default();
                for pkt in slice {
                    meta = graph::FlowMeta::default();
                    if graph_mono::parse_packet_mono(&pkt.data, &mut meta).is_ok() {
                        acc += 1;
                    }
                }
                std::hint::black_box(&meta);
                acc
            });
            results.push(BenchResult::new("mono-mt", ns, total_pkts, cli.threads, None));
        }

        if run_monox4 {
            let ns = run_mt(&packets, cli.iterations, cli.threads, |slice| {
                bench_mono_x4(slice)
            });
            results.push(BenchResult::new("mono-x4-mt", ns, total_pkts, cli.threads, None));
        }

        if run_compiled {
            let ns = run_mt(&packets, cli.iterations, cli.threads, |slice| {
                let slice = std::hint::black_box(slice);
                let mut acc: u64 = 0;
                let mut meta = graph::FlowMeta::default();
                for pkt in slice {
                    meta = graph::FlowMeta::default();
                    if graph_compiled::parse_packet(&pkt.data, &mut meta).is_ok() {
                        acc += 1;
                    }
                }
                std::hint::black_box(&meta);
                acc
            });
            results.push(BenchResult::new("compiled-mt", ns, total_pkts, cli.threads, None));
        }

        if run_simd && simd_batch::is_available() {
            let ns = run_mt(&packets, cli.iterations, cli.threads, |slice| {
                let mut meta = graph::FlowMeta::default();
                let r = unsafe { simd_batch::parse_batch_avx2(slice, &mut meta) };
                std::hint::black_box(&meta);
                r
            });
            results.push(BenchResult::new("simd-mt", ns, total_pkts, cli.threads, None));
        }

        if run_template {
            let ns = run_mt(&packets, cli.iterations, cli.threads, |slice| {
                let slice = std::hint::black_box(slice);
                let mut acc: u64 = 0;
                let mut meta = graph::FlowMeta::default();
                for pkt in slice {
                    meta = graph::FlowMeta::default();
                    if let Some(id) = template::select_template_id(&pkt.data) {
                        if template::extract_by_id(&pkt.data, id, &mut meta).is_ok() {
                            acc += 1;
                        }
                    } else {
                        if graph_compiled::parse_packet(&pkt.data, &mut meta).is_ok() {
                            acc += 1;
                        }
                    }
                }
                std::hint::black_box(&meta);
                acc
            });
            results.push(BenchResult::new("template-mt", ns, total_pkts, cli.threads, None));
        }

        if run_template_simd && template_simd::is_available() {
            let ns = run_mt(&packets, cli.iterations, cli.threads, |slice| {
                let tids: Vec<Option<template::TemplateId>> = slice
                    .iter()
                    .map(|pkt| template::select_template_id(&pkt.data))
                    .collect();
                let batch_acc = template_simd::extract_batch(slice, &tids);
                let mut meta = graph::FlowMeta::default();
                let mut fallback_acc: u64 = 0;
                for (pkt, tid) in slice.iter().zip(tids.iter()) {
                    if tid.is_none() {
                        meta = graph::FlowMeta::default();
                        if graph_compiled::parse_packet(&pkt.data, &mut meta).is_ok() {
                            fallback_acc += 1;
                        }
                    }
                }
                std::hint::black_box(&meta);
                batch_acc + fallback_acc
            });
            results.push(BenchResult::new("template-simd-mt", ns, total_pkts, cli.threads, None));
        }
    }

    // Output results
    if cli.report {
        print_json_report(
            pcap_path,
            npkts,
            cli.iterations,
            &results,
            graph_ok,
            mono_ok,
            compiled_ok,
            template_ok,
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
            graph_ok, npkts, mono_ok, npkts, compiled_ok, npkts, template_ok, npkts
        );
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

    let tmpl = &cli.af_xdp_template;
    let process = move |pkt: &[u8]| {
        let mut meta = graph::FlowMeta::default();
        match tmpl {
            Some(AfXdpTemplate::EthIpv4Tcp) => {
                let _ = template::extract_eth_ipv4_tcp(pkt, &mut meta);
            }
            Some(AfXdpTemplate::EthIpv4Udp) => {
                let _ = template::extract_eth_ipv4_udp(pkt, &mut meta);
            }
            Some(AfXdpTemplate::EthIpv6Tcp) => {
                let _ = template::extract_eth_ipv6_tcp(pkt, &mut meta);
            }
            Some(AfXdpTemplate::Auto) => {
                if let Some(id) = template::select_template_id(pkt) {
                    let _ = template::extract_by_id(pkt, id, &mut meta);
                } else {
                    let _ = graph_compiled::parse_packet(pkt, &mut meta);
                }
            }
            None => {
                let _ = graph_compiled::parse_packet(pkt, &mut meta);
            }
        }
        std::hint::black_box(&meta);
    };

    let parser_label = match &cli.af_xdp_template {
        Some(t) => format!("template:{t:?}"),
        None => "compiled".to_string(),
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
                    println!("\nAF_XDP Aggregate ({} queues, parser={parser_label}):", per_queue.len());
                    println!("  Packets:  {}", agg.total_pkts);
                    println!("  Duration: {:.2}s", agg.elapsed.as_secs_f64());
                    if agg.total_pkts > 0 {
                        println!("  {} ns/pkt,  {:.1} Mpps", agg.ns_pkt(), agg.mpps());
                    }
                    println!(
                        "  {:.1} MB received",
                        agg.total_bytes as f64 / 1_000_000.0
                    );
                }
            }
            Err(e) => af_xdp_error(&e),
        }
    }
}
