//! CLI types and benchmark result struct.

use crate::perf;
use clap::{Parser, ValueEnum};

/// Which parser implementation to exercise.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum ParserMode {
    /// Graph-dispatched engine (`&dyn ParseNodeDyn`), the default.
    Graph,
    /// Enum-dispatch graph engine (static `match` instead of vtable).
    /// Requires the `graph-enum` feature (default). Minimal graph
    /// (Ether/IPv4/{TCP,UDP,ICMP}) for A/B comparison with `Graph`.
    #[cfg(feature = "graph-enum")]
    GraphEnum,
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
    /// Per-queue hardware-classified template extraction. Pair with
    /// Flow Director ntuple rules that steer known packet shapes to
    /// known RX queues; each queue's AF_XDP socket then calls the
    /// pre-mapped fixed-offset extractor directly, no software
    /// classification. Requires --interface and one or more
    /// --queue-template <QID>=<NAME>. See docs/ntuple-template-bench.md.
    #[value(name = "af-xdp-template")]
    AfXdpTemplateHw,
}

/// Template selection for AF_XDP template extraction mode.
#[derive(Clone, Debug, clap::ValueEnum)]
pub(crate) enum AfXdpTemplate {
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
pub(crate) struct Cli {
    /// Input PCAP file (required for all modes except af-xdp).
    #[arg(short, long)]
    pub pcap: Option<String>,

    /// Number of benchmark iterations.
    #[arg(short = 'n', long, default_value_t = 100)]
    pub iterations: u32,

    /// Number of warmup iterations (discarded).
    #[arg(short, long, default_value_t = 3)]
    pub warmup: u32,

    /// Write filtered PCAP (only parseable packets) for C benchmark.
    #[arg(long)]
    pub output_pcap: Option<String>,

    /// Collect CPU performance counters (Linux only, requires
    /// `kernel.perf_event_paranoid <= 2`).
    #[arg(long)]
    pub perf: bool,

    /// Which perf counter pass to run. Requires `--perf`.
    /// Use `basic` (default), `stalls`, `detail`, or pass the flag
    /// multiple times to run several passes and merge results.
    #[arg(long, value_enum)]
    pub perf_pass: Vec<perf::PerfPass>,

    /// Which parser implementation to benchmark.
    #[arg(long, value_enum, default_value_t = ParserMode::Graph)]
    pub mode: ParserMode,

    /// Number of worker threads for the multi-core benchmark.
    /// When > 1, perf counters are disabled (they are per-thread and
    /// not aggregated here). `--perf` still works with `--threads 1`.
    #[arg(long, default_value_t = 1)]
    pub threads: usize,

    /// Pin the benchmark thread to a specific CPU core (Linux only).
    /// Eliminates jitter from OS scheduler migration. Use with `isolcpus`
    /// for HFT-grade measurement consistency.
    #[arg(long)]
    pub core_pin: Option<usize>,

    /// Network interface for AF_XDP mode (e.g., "eth0", "veth1").
    #[arg(long)]
    pub interface: Option<String>,

    /// Starting RX queue number for AF_XDP mode.
    #[arg(long, default_value_t = 0)]
    pub queue: u32,

    /// Number of RX queues for AF_XDP mode (multi-queue).
    /// Spawns one thread per queue (queue, queue+1, ..., queue+N-1).
    #[arg(long, default_value_t = 1)]
    pub queues: u32,

    /// Duration in seconds for AF_XDP mode.
    #[arg(long, default_value_t = 10)]
    pub duration: u32,

    /// Use 2MB huge pages for AF_XDP UMEM (reduces TLB misses).
    /// Requires: echo 64 > /proc/sys/vm/nr_hugepages
    #[arg(long)]
    pub huge_pages: bool,

    /// Enable busy-polling for AF_XDP (lowest latency, burns CPU).
    /// Value is the busy-poll timeout in microseconds (e.g., 20).
    #[arg(long)]
    pub busy_poll: Option<u32>,

    /// Use template extraction in AF_XDP mode instead of the compiled parser.
    /// Simulates the production path where the NIC classifies packets and
    /// each queue uses fixed-offset extraction. "auto" classifies per-packet.
    #[arg(long, value_enum)]
    pub af_xdp_template: Option<AfXdpTemplate>,

    /// Per-queue template mapping for `--mode af-xdp-template`.
    /// Format: `<QID>=<NAME>`. Repeat once per queue. NAME is a
    /// hyphen-case TemplateId (e.g. `eth-ipv4-tcp`, `eth-vlan-ipv6-udp`).
    /// See `src/af_xdp_template.rs::template_id_from_str` for the full
    /// set of 63 accepted names.
    #[arg(long = "queue-template", value_name = "QID=NAME")]
    pub queue_templates: Vec<String>,

    /// Request zero-copy mode for AF_XDP (NIC driver must support it).
    /// Falls back to copy mode if the driver doesn't support zero-copy.
    #[arg(long)]
    pub zero_copy: bool,

    /// Batch size for AF_XDP receive (number of descriptors per recv call).
    #[arg(long, default_value_t = 64)]
    pub batch_size: usize,

    /// Enable NEED_WAKEUP for AF_XDP fill ring. The kernel signals when
    /// it needs a wakeup, reducing unnecessary sendto() calls.
    #[arg(long)]
    pub need_wakeup: bool,

    /// Emit machine-parseable JSON report to stdout instead of
    /// human-readable text. Suitable for automated collection.
    #[arg(long)]
    pub report: bool,

    /// Probe mode: parse each packet once with the graph engine, bucket
    /// by protocol-chain signature, and print a top-N histogram. Used
    /// to characterize how skewed a PCAP's traffic is (see
    /// `docs/fast-path-dispatch.md`). No benchmarking is done.
    #[arg(long)]
    pub chain_histogram: bool,

    /// Top-N cutoff for `--chain-histogram`.
    #[arg(long, default_value_t = 20)]
    pub top: usize,
}

/// Collected result from one benchmark run.
pub(crate) struct BenchResult {
    pub mode: String,
    pub ns_pkt: u64,
    pub mpps: f64,
    pub threads: usize,
    pub total_pkts: u64,
    pub perf: Option<perf::PerfSnapshot>,
}

impl BenchResult {
    pub fn new(
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
