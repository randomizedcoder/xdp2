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
}

#[derive(Parser)]
#[command(
    name = "xdp2-bench",
    about = "XDP2 Rust parse engine benchmark",
    version
)]
struct Cli {
    /// Input PCAP file.
    #[arg(short, long)]
    pcap: String,

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

    /// Which parser implementation to benchmark.
    #[arg(long, value_enum, default_value_t = ParserMode::Graph)]
    mode: ParserMode,

    /// Number of worker threads for the multi-core benchmark.
    /// When > 1, perf counters are disabled (they are per-thread and
    /// not aggregated here). `--perf` still works with `--threads 1`.
    #[arg(long, default_value_t = 1)]
    threads: usize,

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

    // Load packets
    let all_packets = match pcap::load_pcap(std::path::Path::new(&cli.pcap)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot load '{}': {}", cli.pcap, e);
            process::exit(1);
        }
    };

    let total_loaded = all_packets.len();
    if total_loaded == 0 {
        eprintln!("error: no packets in '{}'", cli.pcap);
        process::exit(1);
    }

    eprintln!("Loaded {} packets from {}", total_loaded, cli.pcap);

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

    // Optional: create perf counter group. Fails gracefully with a message
    // if unavailable (paranoid level too high, non-Linux, etc.).
    let mut perf_counters = if cli.perf {
        match perf::PerfCounters::new() {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("warning: could not initialize perf counters: {e}");
                eprintln!("         (try: sudo sysctl -w kernel.perf_event_paranoid=1)");
                None
            }
        }
    } else {
        None
    };

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
        .filter(|pkt| graph_mono::parse_packet_mono(&pkt.data).is_ok())
        .count();
    let compiled_ok = packets
        .iter()
        .filter(|pkt| graph_compiled::parse_packet(&pkt.data).is_ok())
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
            let (ns, snap) = time_run(perf_counters.as_mut(), cli.iterations, || {
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
            let (ns, snap) = time_run(perf_counters.as_mut(), cli.iterations, || {
                let mut acc: u64 = 0;
                for pkt in &packets {
                    if graph_mono::parse_packet_mono(&pkt.data).is_ok() {
                        acc += 1;
                    }
                }
                std::hint::black_box(acc);
            });
            results.push(BenchResult::new("mono", ns, total_pkts, 1, snap));
        }

        if run_monox4 {
            let (ns, snap) = time_run(perf_counters.as_mut(), cli.iterations, || {
                std::hint::black_box(bench_mono_x4(&packets));
            });
            results.push(BenchResult::new("mono-x4", ns, total_pkts, 1, snap));
        }

        if run_compiled {
            let (ns, snap) = time_run(perf_counters.as_mut(), cli.iterations, || {
                let mut acc: u64 = 0;
                for pkt in &packets {
                    if graph_compiled::parse_packet(&pkt.data).is_ok() {
                        acc += 1;
                    }
                }
                std::hint::black_box(acc);
            });
            results.push(BenchResult::new("compiled", ns, total_pkts, 1, snap));
        }

        if run_simd && simd_batch::is_available() {
            let (ns, snap) = time_run(perf_counters.as_mut(), cli.iterations, || {
                // Safety: is_available() checked above.
                std::hint::black_box(unsafe { simd_batch::parse_batch_avx2(&packets) });
            });
            results.push(BenchResult::new("simd", ns, total_pkts, 1, snap));
        } else if run_simd {
            eprintln!("warning: AVX2 not available, skipping SIMD benchmark");
        }

        if run_template {
            let (ns, snap) = time_run(perf_counters.as_mut(), cli.iterations, || {
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
            let (ns, snap) = time_run(perf_counters.as_mut(), cli.iterations, || {
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
                for pkt in slice {
                    if graph_mono::parse_packet_mono(&pkt.data).is_ok() {
                        acc += 1;
                    }
                }
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
                for pkt in slice {
                    if graph_compiled::parse_packet(&pkt.data).is_ok() {
                        acc += 1;
                    }
                }
                acc
            });
            results.push(BenchResult::new("compiled-mt", ns, total_pkts, cli.threads, None));
        }

        if run_simd && simd_batch::is_available() {
            let ns = run_mt(&packets, cli.iterations, cli.threads, |slice| {
                unsafe { simd_batch::parse_batch_avx2(slice) }
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
            &cli.pcap,
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
    let mut chunks = packets.chunks_exact(4);
    for c in chunks.by_ref() {
        // Four independent parse chains. With `#[inline]` on mono's
        // internals and fat LTO, the compiler can interleave the loads
        // from all four packets across the OoO window.
        let r0 = mono(&c[0].data).is_ok() as u64;
        let r1 = mono(&c[1].data).is_ok() as u64;
        let r2 = mono(&c[2].data).is_ok() as u64;
        let r3 = mono(&c[3].data).is_ok() as u64;
        acc += r0 + r1 + r2 + r3;
    }
    // Tail.
    for pkt in chunks.remainder() {
        acc += mono(&pkt.data).is_ok() as u64;
    }
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
            write!(json, "}}").unwrap();
        }
        writeln!(json, "}}{comma}").unwrap();
    }
    writeln!(json, "  ]").unwrap();
    writeln!(json, "}}").unwrap();
    print!("{json}");
}
