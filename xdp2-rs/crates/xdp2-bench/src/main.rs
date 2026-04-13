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
mod graph_mono;
mod pcap;
mod perf;

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
    /// Run both back-to-back for direct A/B comparison.
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

    println!(
        "--- Performance ({} packets x {} iterations) ---",
        npkts, cli.iterations
    );

    let run_graph = matches!(cli.mode, ParserMode::Graph | ParserMode::Both);
    let run_mono = matches!(cli.mode, ParserMode::Mono | ParserMode::Both);

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
            report("graph    ", ns, total_pkts, snap);
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
            report("mono     ", ns, total_pkts, snap);
        }
    } else {
        eprintln!(
            "Multi-threaded benchmark: {} threads (perf counters disabled)",
            cli.threads
        );
        if run_graph {
            let ns = run_mt(&packets, cli.iterations, cli.threads, |slice| {
                let mut acc: u64 = 0;
                for pkt in slice {
                    if graph::parse_packet(&parser, &pkt.data).is_ok() {
                        acc += 1;
                    }
                }
                acc
            });
            report_mt("graph-mt ", ns, total_pkts, cli.threads);
        }

        if run_mono {
            let ns = run_mt(&packets, cli.iterations, cli.threads, |slice| {
                let mut acc: u64 = 0;
                for pkt in slice {
                    if graph_mono::parse_packet_mono(&pkt.data).is_ok() {
                        acc += 1;
                    }
                }
                acc
            });
            report_mt("mono-mt  ", ns, total_pkts, cli.threads);
        }
    }

    println!(
        "Correctness: graph ok={}/{}, mono ok={}/{}",
        graph_ok, npkts, mono_ok, npkts
    );
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

fn report_mt(label: &str, ns: u64, total_pkts: u64, threads: usize) {
    let avg = ns / total_pkts;
    let mpps = if ns > 0 {
        (total_pkts as f64 * 1000.0) / ns as f64
    } else {
        0.0
    };
    println!(
        "Rust {}: {} ns/pkt wall,  {:.1} Mpps  ({}T, {:.2} Mpps/thread)",
        label,
        avg,
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

fn report(label: &str, ns: u64, total_pkts: u64, snap: Option<perf::PerfSnapshot>) {
    let avg = ns / total_pkts;
    print!("Rust {}: {} ns/pkt", label, avg);
    if avg > 0 {
        print!(",  {} Mpps", 1000 / avg);
    }
    println!();
    if let Some(s) = snap {
        s.report(total_pkts);
    }
}
