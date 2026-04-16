//! Benchmark result reporting: text and JSON output.

use std::fmt::Write as _;

use crate::af_xdp;
use crate::cli::BenchResult;

pub(crate) fn report(r: &BenchResult) {
    print!("Rust {:<9}: {} ns/pkt", r.mode, r.ns_pkt);
    if r.mpps > 0.0 {
        print!(",  {:.0} Mpps", r.mpps);
    }
    println!();
    if let Some(ref s) = r.perf {
        s.report(r.total_pkts);
    }
}

pub(crate) fn report_mt(mode: &str, ns_pkt: u64, mpps: f64, threads: usize) {
    println!(
        "Rust {:<11}: {} ns/pkt wall,  {:.1} Mpps  ({}T, {:.2} Mpps/thread)",
        mode,
        ns_pkt,
        mpps,
        threads,
        mpps / threads as f64
    );
}

pub(crate) fn print_af_xdp_stats(iface: &str, queue: u32, parser: &str, stats: &af_xdp::Stats) {
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

pub(crate) fn af_xdp_error(e: &str) -> ! {
    eprintln!("error: {e}");
    eprintln!("Hints:");
    eprintln!("  - AF_XDP requires root or CAP_NET_RAW + CAP_NET_ADMIN");
    eprintln!("  - An XDP program must be loaded on the interface");
    eprintln!("  - The XDP program must redirect to an XSKMAP");
    std::process::exit(1);
}

pub(crate) fn print_json_report(
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
            if p.frontend_stalls > 0 || p.backend_stalls > 0 {
                write!(json, ", \"frontend_stalls\": {}", p.frontend_stalls).unwrap();
                write!(json, ", \"backend_stalls\": {}", p.backend_stalls).unwrap();
                write!(json, ", \"dtlb_misses\": {}", p.dtlb_misses).unwrap();
                write!(json, ", \"itlb_misses\": {}", p.itlb_misses).unwrap();
                write!(json, ", \"l1d_misses\": {}", p.l1d_misses).unwrap();
            }
            if p.l1i_misses > 0 || p.ll_misses > 0 {
                write!(json, ", \"l1i_misses\": {}", p.l1i_misses).unwrap();
                write!(json, ", \"ll_misses\": {}", p.ll_misses).unwrap();
            }
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
