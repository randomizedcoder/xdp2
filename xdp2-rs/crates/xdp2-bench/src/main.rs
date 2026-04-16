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
mod graph;
mod graph_compiled;
mod graph_mono;
mod pcap;
mod perf;
mod simd_batch;
mod template;
mod template_simd;

use std::fmt::Write as _;
use std::process;
use std::time::Instant;

use clap::{Parser, ValueEnum};

/// Which parser implementation to exercise.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum ParserMode {
    /// Graph-dispatched engine (`&dyn ParseNodeDyn`), the default.
    Graph,
    /// Hand-rolled monomorphic parser (Step 2 proof-of-concept).
    Mono,
    /// Mono parser, outer loop software-pipelined 4 packets wide.
    /// Feeds the OoO engine 4 independent parse chains per iteration.
    MonoX4,
    /// Auto-generated monomorphic parser from xdp2-compiler codegen.
    Compiled,
    /// AVX2 batch SIMD parser (8 packets at a time, Eth/IPv4 fast path).
    Simd,
    /// Hardware-classified template extraction (fixed offsets, no branching).
    Template,
    /// Batch AVX2 template extraction (8 packets at a time, fixed offsets).
    TemplateSimd,
    /// Run graph + mono + mono-x4 + compiled + simd + template + template-simd back-to-back.
    Both,
    /// AF_XDP live capture: receive packets from a NIC via zero-copy kernel
    /// bypass and parse with the compiled parser. Requires --interface.
    AfXdp,
}

/// Template selection for AF_XDP template extraction mode.
#[derive(Clone, Debug, clap::ValueEnum)]
enum AfXdpTemplate {
    /// Eth / IPv4 (IHL=5) / TCP — 54 bytes minimum.
    EthIpv4Tcp,
    /// Eth / IPv4 (IHL=5) / UDP — 42 bytes minimum.
    EthIpv4Udp,
    /// Eth / IPv6 / TCP — 74 bytes minimum.
    EthIpv6Tcp,
    /// Auto-detect template from packet headers (adds classification overhead).
    Auto,
}

#[derive(Parser)]
#[command(
    name = "xdp2-bench",
    about = "XDP2 Rust parse engine benchmark",
    version
)]
struct Cli {
    /// Input PCAP file (required for all modes except af-xdp).
    #[arg(short, long)]
    pcap: Option<String>,

    /// Number of benchmark iterations.
    #[arg(short = 'n', long, default_value_t = 100)]
    iterations: u32,

    /// Number of warmup iterations (discarded).
    #[arg(short, long, default_value_t = 3)]
    warmup: u32,

    /// Write filtered PCAP (only parseable packets) for C benchmark.
    #[arg(long)]
    output_pcap: Option<String>,

    /// Collect CPU performance counters (Linux only, requires
    /// `kernel.perf_event_paranoid <= 2`).
    #[arg(long)]
    perf: bool,

    /// Which perf counter pass to run. Requires `--perf`.
    /// Use `basic` (default), `stalls`, `detail`, or pass the flag
    /// multiple times to run several passes and merge results.
    #[arg(long, value_enum)]
    perf_pass: Vec<perf::PerfPass>,

    /// Which parser implementation to benchmark.
    #[arg(long, value_enum, default_value_t = ParserMode::Graph)]
    mode: ParserMode,

    /// Number of worker threads for the multi-core benchmark.
    /// When > 1, perf counters are disabled (they are per-thread and
    /// not aggregated here). `--perf` still works with `--threads 1`.
    #[arg(long, default_value_t = 1)]
    threads: usize,

    /// Pin the benchmark thread to a specific CPU core (Linux only).
    /// Eliminates jitter from OS scheduler migration. Use with `isolcpus`
    /// for HFT-grade measurement consistency.
    #[arg(long)]
    core_pin: Option<usize>,

    /// Network interface for AF_XDP mode (e.g., "eth0", "veth1").
    #[arg(long)]
    interface: Option<String>,

    /// Starting RX queue number for AF_XDP mode.
    #[arg(long, default_value_t = 0)]
    queue: u32,

    /// Number of RX queues for AF_XDP mode (multi-queue).
    /// Spawns one thread per queue (queue, queue+1, ..., queue+N-1).
    #[arg(long, default_value_t = 1)]
    queues: u32,

    /// Duration in seconds for AF_XDP mode.
    #[arg(long, default_value_t = 10)]
    duration: u32,

    /// Use 2MB huge pages for AF_XDP UMEM (reduces TLB misses).
    /// Requires: echo 64 > /proc/sys/vm/nr_hugepages
    #[arg(long)]
    huge_pages: bool,

    /// Enable busy-polling for AF_XDP (lowest latency, burns CPU).
    /// Value is the busy-poll timeout in microseconds (e.g., 20).
    #[arg(long)]
    busy_poll: Option<u32>,

    /// Use template extraction in AF_XDP mode instead of the compiled parser.
    /// Simulates the production path where the NIC classifies packets and
    /// each queue uses fixed-offset extraction. "auto" classifies per-packet.
    #[arg(long, value_enum)]
    af_xdp_template: Option<AfXdpTemplate>,

    /// Emit machine-parseable JSON report to stdout instead of
    /// human-readable text. Suitable for automated collection.
    #[arg(long)]
    report: bool,
}

/// Collected result from one benchmark run.
struct BenchResult {
    mode: String,
    ns_pkt: u64,
    mpps: f64,
    threads: usize,
    total_pkts: u64,
    perf: Option<perf::PerfSnapshot>,
}

impl BenchResult {
    fn new(
        mode: &str,
        ns: u64,
        total_pkts: u64,
        threads: usize,
        perf: Option<perf::PerfSnapshot>,
    ) -> Self {
        let ns_pkt = if total_pkts > 0 { ns / total_pkts } else { 0 };
        let mpps = if ns > 0 {
            (total_pkts as f64 * 1000.0) / ns as f64
        } else {
            0.0
        };
        Self {
            mode: mode.to_string(),
            ns_pkt,
            mpps,
            threads,
            total_pkts,
            perf,
        }
    }
}

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
    //
    // Run each packet through the parser once. Keep packets where
    // parse returns Ok (any successful result). As protocols are added
    // to graph.rs, more packets will pass this filter automatically.
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

    // Warmup (always exercises the graph-dispatched path; good enough to
    // warm icache, TLB, and the branch predictor for both modes).
    for _ in 0..cli.warmup {
        for pkt in &packets {
            let _ = graph::parse_packet(&parser, &pkt.data);
        }
    }

    // Determine which perf passes to run.
    // Default to Basic if --perf is given without --perf-pass.
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
            Ok(_) => {} // counters work; they'll be created per-pass in time_run_passes
            Err(e) => {
                eprintln!("warning: could not initialize perf counters: {e}");
                eprintln!("         (try: sudo sysctl -w kernel.perf_event_paranoid=1)");
            }
        }
    }

    let total_pkts = npkts as u64 * cli.iterations as u64;

    if !cli.report {
        println!(
            "--- Performance ({} packets x {} iterations) ---",
            npkts, cli.iterations
        );
    }

    let run_graph = matches!(cli.mode, ParserMode::Graph | ParserMode::Both);
    let run_mono = matches!(cli.mode, ParserMode::Mono | ParserMode::Both);
    let run_monox4 = matches!(cli.mode, ParserMode::MonoX4 | ParserMode::Both);
    let run_compiled = matches!(cli.mode, ParserMode::Compiled | ParserMode::Both);
    let run_simd = matches!(cli.mode, ParserMode::Simd | ParserMode::Both);
    let run_template = matches!(cli.mode, ParserMode::Template | ParserMode::Both);
    let run_template_simd = matches!(cli.mode, ParserMode::TemplateSimd | ParserMode::Both);

    // Correctness & anti-DCE: count successful parses across one full sweep
    // and print the total. This prevents LLVM from eliding the parse body
    // and lets us sanity-check that both modes agree on which packets
    // parse. Counts printed after timing so they do not perturb it.
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
            template::select_template_id(&pkt.data)
                .map(|id| template::extract_by_id(&pkt.data, id).is_ok())
                .unwrap_or(false)
        })
        .count();

    // Pre-select templates for all packets (simulates NIC queue assignment).
    // Done once before timing so the benchmark measures extraction only.
    let template_ids: Vec<Option<template::TemplateId>> = packets
        .iter()
        .map(|pkt| template::select_template_id(&pkt.data))
        .collect();

    let mut results: Vec<BenchResult> = Vec::new();

    if cli.threads <= 1 {
        if run_graph {
            let (ns, snap) = time_run_passes(&perf_passes, cli.iterations, || {
                // Sum successes into a black_box-fed accumulator so the
                // compiler cannot elide the loop.
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
                // Safety: is_available() checked above.
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
                for (pkt, tid) in packets.iter().zip(template_ids.iter()) {
                    if let Some(id) = tid {
                        if let Ok(v) = template::extract_by_id(&pkt.data, *id) {
                            acc = acc.wrapping_add(v);
                        }
                    }
                }
                std::hint::black_box(acc);
            });
            results.push(BenchResult::new("template", ns, total_pkts, 1, snap));
        }

        if run_template_simd && template_simd::is_available() {
            let (ns, snap) = time_run_passes(&perf_passes, cli.iterations, || {
                std::hint::black_box(unsafe {
                    template_simd::extract_batch_avx2(&packets, &template_ids)
                });
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
                for pkt in slice {
                    // In MT mode, re-select per packet (cheap, and avoids
                    // needing to split the template_ids vec in sync with packets).
                    if let Some(id) = template::select_template_id(&pkt.data) {
                        if let Ok(v) = template::extract_by_id(&pkt.data, id) {
                            acc = acc.wrapping_add(v);
                        }
                    }
                }
                acc
            });
            results.push(BenchResult::new("template-mt", ns, total_pkts, cli.threads, None));
        }

        if run_template_simd && template_simd::is_available() {
            let ns = run_mt(&packets, cli.iterations, cli.threads, |slice| {
                // Re-select template IDs per slice (same as template-mt).
                let tids: Vec<Option<template::TemplateId>> = slice
                    .iter()
                    .map(|pkt| template::select_template_id(&pkt.data))
                    .collect();
                unsafe { template_simd::extract_batch_avx2(slice, &tids) }
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

/// AF_XDP live capture benchmark. Binds to a NIC via AF_XDP, receives
/// packets for `--duration` seconds, and parses each with the compiled parser.
///
/// With `--queues N`, spawns N threads, one per NIC queue, for multi-queue
/// receive. Each thread gets its own XskSocket, UMEM, and optional core pin.
fn run_af_xdp(cli: &Cli) {
    let iface = match &cli.interface {
        Some(s) => s.as_str(),
        None => {
            eprintln!("error: --interface is required for --mode af-xdp");
            process::exit(1);
        }
    };

    // Build the per-packet processing closure based on template selection.
    let tmpl = &cli.af_xdp_template;
    let process = move |pkt: &[u8]| {
        match tmpl {
            Some(AfXdpTemplate::EthIpv4Tcp) => {
                let _ = std::hint::black_box(template::extract_eth_ipv4_tcp(pkt));
            }
            Some(AfXdpTemplate::EthIpv4Udp) => {
                let _ = std::hint::black_box(template::extract_eth_ipv4_udp(pkt));
            }
            Some(AfXdpTemplate::EthIpv6Tcp) => {
                let _ = std::hint::black_box(template::extract_eth_ipv6_tcp(pkt));
            }
            Some(AfXdpTemplate::Auto) => {
                if let Some(id) = template::select_template_id(pkt) {
                    let _ = std::hint::black_box(template::extract_by_id(pkt, id));
                }
            }
            None => {
                let mut meta = graph::FlowMeta::default();
                let _ = graph_compiled::parse_packet(pkt, &mut meta);
                std::hint::black_box(&meta);
            }
        }
    };

    let parser_label = match &cli.af_xdp_template {
        Some(t) => format!("template:{t:?}"),
        None => "compiled".to_string(),
    };

    if cli.queues <= 1 {
        // Single-queue path.
        let result = af_xdp::run(
            iface, cli.queue, cli.duration, cli.huge_pages, cli.busy_poll, process,
        );
        match result {
            Ok(stats) => {
                print_af_xdp_stats(iface, cli.queue, &parser_label, &stats);
            }
            Err(e) => af_xdp_error(&e),
        }
    } else {
        // Multi-queue path.
        let result = af_xdp::run_multi_queue(
            iface,
            cli.queue,
            cli.queues,
            cli.duration,
            cli.huge_pages,
            cli.busy_poll,
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

fn print_af_xdp_stats(iface: &str, queue: u32, parser: &str, stats: &af_xdp::Stats) {
    println!("AF_XDP Results ({iface} queue {queue}, parser={parser}):");
    println!("  Packets:  {}", stats.total_pkts);
    println!("  Duration: {:.2}s", stats.elapsed.as_secs_f64());
    if stats.total_pkts > 0 {
        println!("  {} ns/pkt,  {:.1} Mpps", stats.ns_pkt(), stats.mpps());
    }
    println!(
        "  {:.1} MB received",
        stats.total_bytes as f64 / 1_000_000.0
    );
}

fn af_xdp_error(e: &str) -> ! {
    eprintln!("error: {e}");
    eprintln!("Hints:");
    eprintln!("  - AF_XDP requires root or CAP_NET_RAW + CAP_NET_ADMIN");
    eprintln!("  - An XDP program must be loaded on the interface");
    eprintln!("  - The XDP program must redirect to an XSKMAP");
    process::exit(1);
}

/// Multi-threaded benchmark: split packets across `threads` workers, each
/// processing its chunk `iterations` times. The work closure must be `Sync`
/// (each thread calls it with a disjoint slice). Returns wallclock nanos.
fn run_mt<F>(
    packets: &[&pcap::StoredPacket],
    iterations: u32,
    threads: usize,
    work: F,
) -> u64
where
    F: Fn(&[&pcap::StoredPacket]) -> u64 + Sync,
{
    let chunk = packets.len().div_ceil(threads);
    let slices: Vec<&[&pcap::StoredPacket]> = packets.chunks(chunk).collect();
    let work = &work;

    let t_start = Instant::now();
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(slices.len());
        for slice in slices {
            handles.push(s.spawn(move || {
                let mut acc: u64 = 0;
                for _ in 0..iterations {
                    acc = acc.wrapping_add(work(slice));
                }
                std::hint::black_box(acc)
            }));
        }
        for h in handles {
            let _ = h.join();
        }
    });
    t_start.elapsed().as_nanos() as u64
}

/// Software-pipelined scalar parser: process 4 packets per iteration with
/// 4 independent parse chains visible to the compiler and OoO engine.
///
/// The theory: a single mono parse is a serial dependent-load chain
/// (ethertype → protocol → ...) capped by the OoO window's ability to
/// overlap the next packet. By explicitly fanning out to 4 in-flight
/// packets per loop iteration, we give the scheduler 4x the independent
/// work and potentially hide the per-packet load-latency.
///
/// Returns the count of successful parses so the caller can black_box it.
#[inline(never)]
fn bench_mono_x4(packets: &[&pcap::StoredPacket]) -> u64 {
    use graph_mono::parse_packet_mono as mono;

    // `black_box` on the input prevents LLVM from inferring the call as
    // `readonly` + loop-invariant and hoisting it out of the caller's
    // `for _ in 0..iterations { work(slice) }` loop (which happened
    // initially and produced fake 10x multi-thread numbers).
    let packets = std::hint::black_box(packets);
    let mut acc: u64 = 0;
    let mut m0 = graph::FlowMeta::default();
    let mut m1;
    let mut m2;
    let mut m3;
    let mut chunks = packets.chunks_exact(4);
    for c in chunks.by_ref() {
        // Four independent parse chains. With `#[inline]` on mono's
        // internals and fat LTO, the compiler can interleave the loads
        // from all four packets across the OoO window.
        m0 = graph::FlowMeta::default();
        m1 = graph::FlowMeta::default();
        m2 = graph::FlowMeta::default();
        m3 = graph::FlowMeta::default();
        let r0 = mono(&c[0].data, &mut m0).is_ok() as u64;
        let r1 = mono(&c[1].data, &mut m1).is_ok() as u64;
        let r2 = mono(&c[2].data, &mut m2).is_ok() as u64;
        let r3 = mono(&c[3].data, &mut m3).is_ok() as u64;
        acc += r0 + r1 + r2 + r3;
    }
    // Tail.
    let mut mt;
    for pkt in chunks.remainder() {
        mt = graph::FlowMeta::default();
        acc += mono(&pkt.data, &mut mt).is_ok() as u64;
    }
    std::hint::black_box(&m0);
    acc
}

fn report_mt(mode: &str, ns_pkt: u64, mpps: f64, threads: usize) {
    println!(
        "Rust {:<11}: {} ns/pkt wall,  {:.1} Mpps  ({}T, {:.2} Mpps/thread)",
        mode,
        ns_pkt,
        mpps,
        threads,
        mpps / threads as f64
    );
}

/// Run `body` for `iterations` iterations under the given perf counter group
/// and return (elapsed nanos, optional perf snapshot).
fn time_run<F: FnMut()>(
    mut counters: Option<&mut perf::PerfCounters>,
    iterations: u32,
    mut body: F,
) -> (u64, Option<perf::PerfSnapshot>) {
    if let Some(c) = counters.as_deref_mut() {
        let _ = c.reset();
        let _ = c.start();
    }
    let t_start = Instant::now();
    for _ in 0..iterations {
        body();
    }
    let ns = t_start.elapsed().as_nanos() as u64;
    let snap = counters.and_then(|c| {
        let _ = c.stop();
        c.read().ok()
    });
    (ns, snap)
}

/// Run `body` across all perf passes, merging results.
///
/// Returns (elapsed_nanos from first pass, merged snapshot).
/// If `passes` is empty, runs once without counters.
fn time_run_passes<F: FnMut()>(
    passes: &[perf::PerfPass],
    iterations: u32,
    mut body: F,
) -> (u64, Option<perf::PerfSnapshot>) {
    if passes.is_empty() {
        // No perf — just time it once.
        let t_start = Instant::now();
        for _ in 0..iterations {
            body();
        }
        return (t_start.elapsed().as_nanos() as u64, None);
    }

    let mut merged = perf::PerfSnapshot::default();
    let mut first_ns = 0u64;

    for (i, &pass) in passes.iter().enumerate() {
        let mut counters = match perf::PerfCounters::new(pass) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("warning: perf pass {pass:?} failed: {e}");
                continue;
            }
        };
        let (ns, snap) = time_run(Some(&mut counters), iterations, &mut body);
        if i == 0 {
            first_ns = ns;
        }
        if let Some(s) = snap {
            merged.merge(&s);
        }
    }

    (first_ns, Some(merged))
}

/// Pin the calling thread to a specific CPU core via `sched_setaffinity`.
#[cfg(target_os = "linux")]
fn pin_to_core(core: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core, &mut set);
        let ret = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        if ret == 0 {
            eprintln!("Pinned to core {core}");
        } else {
            eprintln!(
                "warning: failed to pin to core {core}: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn pin_to_core(core: usize) {
    eprintln!("warning: --core-pin is only supported on Linux (requested core {core})");
}

fn report(r: &BenchResult) {
    print!("Rust {:<9}: {} ns/pkt", r.mode, r.ns_pkt);
    if r.mpps > 0.0 {
        print!(",  {:.0} Mpps", r.mpps);
    }
    println!();
    if let Some(ref s) = r.perf {
        s.report(r.total_pkts);
    }
}

fn print_json_report(
    pcap: &str,
    npkts: usize,
    iterations: u32,
    results: &[BenchResult],
    graph_ok: usize,
    mono_ok: usize,
    compiled_ok: usize,
    template_ok: usize,
) {
    let mut json = String::with_capacity(2048);
    writeln!(json, "{{").unwrap();
    writeln!(json, "  \"pcap\": \"{pcap}\",").unwrap();
    writeln!(json, "  \"packets\": {npkts},").unwrap();
    writeln!(json, "  \"iterations\": {iterations},").unwrap();
    writeln!(json, "  \"correctness\": {{").unwrap();
    writeln!(json, "    \"graph\": {graph_ok},").unwrap();
    writeln!(json, "    \"mono\": {mono_ok},").unwrap();
    writeln!(json, "    \"compiled\": {compiled_ok},").unwrap();
    writeln!(json, "    \"template\": {template_ok}").unwrap();
    writeln!(json, "  }},").unwrap();
    writeln!(json, "  \"results\": [").unwrap();
    for (i, r) in results.iter().enumerate() {
        let comma = if i + 1 < results.len() { "," } else { "" };
        write!(json, "    {{").unwrap();
        write!(json, "\"mode\": \"{}\", ", r.mode).unwrap();
        write!(json, "\"ns_pkt\": {}, ", r.ns_pkt).unwrap();
        write!(json, "\"mpps\": {:.1}, ", r.mpps).unwrap();
        write!(json, "\"threads\": {}, ", r.threads).unwrap();
        write!(json, "\"total_pkts\": {}", r.total_pkts).unwrap();
        if let Some(ref p) = r.perf {
            write!(json, ", \"perf\": {{").unwrap();
            write!(json, "\"cycles\": {}, ", p.cycles).unwrap();
            write!(json, "\"instructions\": {}, ", p.instructions).unwrap();
            write!(json, "\"branches\": {}, ", p.branches).unwrap();
            write!(json, "\"branch_misses\": {}, ", p.branch_misses).unwrap();
            write!(json, "\"cache_refs\": {}, ", p.cache_refs).unwrap();
            write!(json, "\"cache_misses\": {}", p.cache_misses).unwrap();
            // stalls pass fields (only if measured)
            if p.frontend_stalls > 0 || p.backend_stalls > 0 {
                write!(json, ", \"frontend_stalls\": {}", p.frontend_stalls).unwrap();
                write!(json, ", \"backend_stalls\": {}", p.backend_stalls).unwrap();
                write!(json, ", \"dtlb_misses\": {}", p.dtlb_misses).unwrap();
                write!(json, ", \"itlb_misses\": {}", p.itlb_misses).unwrap();
                write!(json, ", \"l1d_misses\": {}", p.l1d_misses).unwrap();
            }
            // detail pass fields (only if measured)
            if p.l1i_misses > 0 || p.ll_misses > 0 {
                write!(json, ", \"l1i_misses\": {}", p.l1i_misses).unwrap();
                write!(json, ", \"ll_misses\": {}", p.ll_misses).unwrap();
            }
            // zen pass fields (only if measured)
            if p.retired_uops > 0 || p.op_cache_hits > 0 {
                write!(json, ", \"op_cache_hits\": {}", p.op_cache_hits).unwrap();
                write!(json, ", \"retired_uops\": {}", p.retired_uops).unwrap();
                write!(json, ", \"dispatch_stalls\": {}", p.dispatch_stalls).unwrap();
                write!(json, ", \"mab_stalls\": {}", p.mab_stalls).unwrap();
            }
            write!(json, "}}").unwrap();
        }
        writeln!(json, "}}{comma}").unwrap();
    }
    writeln!(json, "  ]").unwrap();
    writeln!(json, "}}").unwrap();
    print!("{json}");
}
