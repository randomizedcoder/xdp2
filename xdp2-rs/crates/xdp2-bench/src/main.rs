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

    /// Write filtered PCAP (only parseable packets) for C benchmark.
    #[arg(long)]
    output_pcap: Option<String>,
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

    // Warmup
    for _ in 0..cli.warmup {
        for pkt in &packets {
            let _ = graph::parse_packet(&parser, &pkt.data);
        }
    }

    // ── Benchmark 1: Full parse (metadata re-initialized per packet) ──
    let t_start = Instant::now();
    for _ in 0..cli.iterations {
        for pkt in &packets {
            let _ = graph::parse_packet(&parser, &pkt.data);
        }
    }
    let full_ns = t_start.elapsed().as_nanos() as u64;

    // ── Benchmark 2: Parse-only ──
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
}
