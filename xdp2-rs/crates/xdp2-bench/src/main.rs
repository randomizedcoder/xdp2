//! XDP2 Rust parse engine benchmark.
//!
//! Reads a PCAP file, loads all packets into memory, and times the Rust
//! parse engine processing each packet through a protocol parse graph
//! matching the C flow_dissector benchmark's coverage.
//!
//! ## Usage
//!
//! ```bash
//! xdp2-bench --pcap test.pcap --iterations 100
//! ```
//!
//! ## C/C++ Cross-Reference
//!
//! | Rust Item | C/C++ Source | C/C++ Item |
//! |-----------|-------------|------------|
//! | `main()` | `benchmark.c:590-726` | Performance benchmark loop |
//! | `graph::make_parser()` | `flow_dissector_parsers.h` | L2 parser definition |
//! | `pcap::load_pcap()` | `pcap_loader.h:load_pcap()` | PCAP file loading |
//!
//! ## Output
//!
//! Reports ns/pkt and Mpps in same format as C benchmark for comparison.

mod graph;
mod pcap;

use std::process;
use std::time::Instant;

use clap::Parser;

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
}

fn main() {
    let cli = Cli::parse();

    // Load packets
    let packets = match pcap::load_pcap(std::path::Path::new(&cli.pcap)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot load '{}': {}", cli.pcap, e);
            process::exit(1);
        }
    };

    let npkts = packets.len();
    if npkts == 0 {
        eprintln!("error: no packets in '{}'", cli.pcap);
        process::exit(1);
    }

    eprintln!("Loaded {} packets from {}", npkts, cli.pcap);

    let parser = graph::make_parser();

    // Warmup: run iterations to stabilize CPU caches
    for _ in 0..cli.warmup {
        for pkt in &packets {
            let _ = graph::parse_packet(&parser, &pkt.data);
        }
    }

    // ── Benchmark 1: Full parse (metadata re-initialized per packet) ──
    //
    // This matches the C "XDP2 parser (with memset)" measurement where
    // metadata is zeroed for each packet.
    let t_start = Instant::now();
    let mut ok_count: u64 = 0;
    let mut err_count: u64 = 0;
    for _ in 0..cli.iterations {
        for pkt in &packets {
            match graph::parse_packet(&parser, &pkt.data) {
                Ok(_) => ok_count += 1,
                Err(_) => err_count += 1,
            }
        }
    }
    let full_ns = t_start.elapsed().as_nanos() as u64;

    // ── Benchmark 2: Parse-only (reuse metadata) ──
    //
    // This matches the C "XDP2 parse-only" measurement. In Rust, parse()
    // always creates fresh metadata via Default::default(), so this is
    // functionally identical to benchmark 1. We keep it for output format
    // compatibility with the C benchmark.
    let t_start = Instant::now();
    for _ in 0..cli.iterations {
        for pkt in &packets {
            let _ = graph::parse_packet(&parser, &pkt.data);
        }
    }
    let parseonly_ns = t_start.elapsed().as_nanos() as u64;

    // ── Report ──
    let total_pkts = npkts as u64 * cli.iterations as u64;

    println!(
        "--- Performance ({} packets x {} iterations) ---",
        npkts, cli.iterations
    );

    let avg_full = full_ns / total_pkts;
    print!("Rust parser:     {} ns/pkt", avg_full);
    if avg_full > 0 {
        print!(",  {} Mpps", 1000 / avg_full);
    }
    println!();

    let avg_parseonly = parseonly_ns / total_pkts;
    print!("Rust parse-only: {} ns/pkt", avg_parseonly);
    if avg_parseonly > 0 {
        print!(",  {} Mpps", 1000 / avg_parseonly);
    }
    println!();

    println!();
    println!("Parse results: {} ok, {} err ({:.1}% success)",
        ok_count, err_count,
        100.0 * ok_count as f64 / total_pkts as f64
    );
}
