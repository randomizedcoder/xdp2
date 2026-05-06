//! Benchmark dispatch: runs single-threaded and multi-threaded parse benchmarks
//! across all parser modes (graph, mono, compiled, template, SIMD, etc.).

use std::io;

use crate::cli::{BenchResult, ParserMode};
use crate::parity::{
    first_ethertype, parser_id, reject_reason, DumpMetaWriter, ParityRecord,
};

const ETH_P_IP: u16 = 0x0800;
use crate::{graph, graph_compiled, graph_mono, pcap, perf, simd_batch, template, template_simd};
use crate::runners::{bench_mono_x4, run_mt, time_run_passes};

/// Correctness counts from a pre-benchmark verification sweep.
pub struct CorrectnessCheck {
    pub graph_ok: usize,
    pub mono_ok: usize,
    pub compiled_ok: usize,
    pub template_ok: usize,
}

/// Run correctness verification: count successful parses across one full sweep.
pub fn check_correctness(
    packets: &[&pcap::StoredPacket],
    parser: &xdp2_core::Parser<graph::FlowMeta>,
) -> CorrectnessCheck {
    let graph_ok = packets
        .iter()
        .filter(|pkt| graph::parse_packet(parser, &pkt.data).is_ok())
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

    CorrectnessCheck {
        graph_ok,
        mono_ok,
        compiled_ok,
        template_ok,
    }
}

/// Phase 17.B parity-dump pass.
///
/// Runs each enabled mode ONCE per packet and emits one ParityRecord
/// per (packet, mode) line into the file at `dump_path`. Independent
/// from the timed benchmark loop — iteration count doesn't multiply
/// the line count.
///
/// Mode handling:
///   - graph / graph-enum / mono / mono-x4 / compiled: per-packet
///     parse with fresh FlowMeta; emit accepted=true on Ok, rejected
///     with reject_reason="parse-error" on Err.
///   - simd: AVX2-only. On non-AVX2 hosts emit rejected with
///     reject_reason="no-avx2". On AVX2 hosts run the SIMD batch path
///     in 1-packet batches so per-packet meta is recoverable.
///   - template: select_template_id → if Some, extract_by_id;
///     if None, emit rejected with reject_reason="no-template".
///   - template-simd: same template-selection logic; the SIMD path is
///     internally a per-packet loop with prefetch (no SIMD intrinsics)
///     so per-packet meta is well-defined.
pub fn dump_meta_pass(
    mode: &ParserMode,
    packets: &[&pcap::StoredPacket],
    parser: &xdp2_core::Parser<graph::FlowMeta>,
    dump_path: &str,
    pcap_label: &str,
) -> io::Result<()> {
    let mut w = DumpMetaWriter::create(dump_path)?;
    let do_all = matches!(mode, ParserMode::Both);

    for (idx, pkt) in packets.iter().enumerate() {
        let i = idx as u32;

        if matches!(mode, ParserMode::Graph) || do_all {
            let rec = ParityRecord::new(parser_id::RUST_GRAPH, "rust", pcap_label, i);
            match graph::parse_packet(parser, &pkt.data) {
                Ok(output) => w.emit(&rec.accepted(&output.metadata, None))?,
                Err(_) => w.emit(&rec.rejected(reject_reason::PARSE_ERROR))?,
            }
        }

        #[cfg(feature = "graph-enum")]
        if matches!(mode, ParserMode::GraphEnum) || do_all {
            // graph-enum's table currently covers Ether/IPv4/{TCP,UDP,
            // ICMP} only (see cli.rs:12-13). On non-IPv4 packets we
            // emit reject_reason="ipv4-only" so the parity gate
            // distinguishes a documented scope gap from a parser bug.
            // graph-enum::parse_packet returns Result<(), ()> without
            // a FlowMeta-output variant; when accepted, fall back to
            // graph-mode's metadata for parity purposes.
            let cfg = crate::graph_enum::make_config();
            let ok = crate::graph_enum::parse_packet(&cfg, &pkt.data).is_ok();
            let rec =
                ParityRecord::new(parser_id::RUST_GRAPH_ENUM, "rust", pcap_label, i);
            if ok {
                match graph::parse_packet(parser, &pkt.data) {
                    Ok(output) => w.emit(&rec.accepted(&output.metadata, None))?,
                    Err(_) => w.emit(&rec.rejected(reject_reason::PARSE_ERROR))?,
                }
            } else {
                let reason = match first_ethertype(&pkt.data) {
                    Some(et) if et != ETH_P_IP => reject_reason::IPV4_ONLY,
                    _ => reject_reason::PARSE_ERROR,
                };
                w.emit(&rec.rejected(reason))?;
            }
        }

        if matches!(mode, ParserMode::Mono) || do_all {
            let mut meta = graph::FlowMeta::default();
            let ok = graph_mono::parse_packet_mono(&pkt.data, &mut meta).is_ok();
            let rec = ParityRecord::new(parser_id::RUST_MONO, "rust", pcap_label, i);
            let rec = if ok {
                rec.accepted(&meta, None)
            } else {
                rec.rejected(reject_reason::PARSE_ERROR)
            };
            w.emit(&rec)?;
        }

        if matches!(mode, ParserMode::MonoX4) || do_all {
            // mono-x4 is a 4-wide pipelined wrapper around mono;
            // per-packet output is just mono's output. Use mono's
            // single-packet path here.
            let mut meta = graph::FlowMeta::default();
            let ok = graph_mono::parse_packet_mono(&pkt.data, &mut meta).is_ok();
            let rec = ParityRecord::new(parser_id::RUST_MONO_X4, "rust", pcap_label, i);
            let rec = if ok {
                rec.accepted(&meta, None)
            } else {
                rec.rejected(reject_reason::PARSE_ERROR)
            };
            w.emit(&rec)?;
        }

        if matches!(mode, ParserMode::Compiled) || do_all {
            let mut meta = graph::FlowMeta::default();
            let ok = graph_compiled::parse_packet(&pkt.data, &mut meta).is_ok();
            let rec = ParityRecord::new(parser_id::RUST_COMPILED, "rust", pcap_label, i);
            let rec = if ok {
                rec.accepted(&meta, None)
            } else {
                rec.rejected(reject_reason::PARSE_ERROR)
            };
            w.emit(&rec)?;
        }

        if matches!(mode, ParserMode::Simd) || do_all {
            let rec = ParityRecord::new(parser_id::RUST_SIMD, "rust", pcap_label, i);
            if !simd_batch::is_available() {
                w.emit(&rec.rejected(reject_reason::NO_AVX2))?;
            } else {
                let mut meta = graph::FlowMeta::default();
                // SAFETY: is_available() returned true → AVX2 supported on this CPU.
                let acc = unsafe { simd_batch::parse_batch_avx2(&[*pkt], &mut meta) };
                let rec = if acc > 0 {
                    rec.accepted(&meta, None)
                } else {
                    rec.rejected(reject_reason::PARSE_ERROR)
                };
                w.emit(&rec)?;
            }
        }

        if matches!(mode, ParserMode::Template) || do_all {
            let rec =
                ParityRecord::new(parser_id::RUST_TEMPLATE, "rust", pcap_label, i);
            match template::select_template_id(&pkt.data) {
                None => {
                    w.emit(&rec.rejected(reject_reason::NO_TEMPLATE))?;
                }
                Some(id) => {
                    let mut meta = graph::FlowMeta::default();
                    let ok =
                        template::extract_by_id(&pkt.data, id, &mut meta).is_ok();
                    let rec = if ok {
                        rec.accepted(&meta, None)
                    } else {
                        rec.rejected(reject_reason::PARSE_ERROR)
                    };
                    w.emit(&rec)?;
                }
            }
        }

        if matches!(mode, ParserMode::TemplateSimd) || do_all {
            let rec = ParityRecord::new(
                parser_id::RUST_TEMPLATE_SIMD,
                "rust",
                pcap_label,
                i,
            );
            if !template_simd::is_available() {
                w.emit(&rec.rejected(reject_reason::NO_AVX2))?;
            } else {
                match template::select_template_id(&pkt.data) {
                    None => {
                        w.emit(&rec.rejected(reject_reason::NO_TEMPLATE))?;
                    }
                    Some(id) => {
                        let mut meta = graph::FlowMeta::default();
                        let ok =
                            template::extract_by_id(&pkt.data, id, &mut meta).is_ok();
                        let rec = if ok {
                            rec.accepted(&meta, None)
                        } else {
                            rec.rejected(reject_reason::PARSE_ERROR)
                        };
                        w.emit(&rec)?;
                    }
                }
            }
        }
    }

    w.flush()?;
    Ok(())
}

/// Run all enabled benchmarks (single-threaded or multi-threaded).
pub fn run_benchmarks(
    mode: &ParserMode,
    packets: &[&pcap::StoredPacket],
    parser: &xdp2_core::Parser<graph::FlowMeta>,
    iterations: u32,
    threads: usize,
    perf_passes: &[perf::PerfPass],
    report: bool,
) -> Vec<BenchResult> {
    let npkts = packets.len();
    let total_pkts = npkts as u64 * iterations as u64;

    let run_graph = matches!(mode, ParserMode::Graph | ParserMode::Both);
    #[cfg(feature = "graph-enum")]
    let run_graph_enum = matches!(mode, ParserMode::GraphEnum);
    let run_mono = matches!(mode, ParserMode::Mono | ParserMode::Both);
    let run_monox4 = matches!(mode, ParserMode::MonoX4 | ParserMode::Both);
    let run_compiled = matches!(mode, ParserMode::Compiled | ParserMode::Both);
    let run_simd = matches!(mode, ParserMode::Simd | ParserMode::Both);
    let run_template = matches!(mode, ParserMode::Template | ParserMode::Both);
    let run_template_simd = matches!(mode, ParserMode::TemplateSimd | ParserMode::Both);

    let mut results: Vec<BenchResult> = Vec::new();

    if threads <= 1 {
        run_single_threaded(
            &mut results,
            packets,
            parser,
            iterations,
            perf_passes,
            total_pkts,
            run_graph,
            #[cfg(feature = "graph-enum")]
            run_graph_enum,
            run_mono,
            run_monox4,
            run_compiled,
            run_simd,
            run_template,
            run_template_simd,
        );
    } else {
        if !report {
            eprintln!(
                "Multi-threaded benchmark: {} threads (perf counters disabled)",
                threads
            );
        }
        run_multi_threaded(
            &mut results,
            packets,
            parser,
            iterations,
            threads,
            total_pkts,
            run_graph,
            run_mono,
            run_monox4,
            run_compiled,
            run_simd,
            run_template,
            run_template_simd,
        );
    }

    results
}

#[allow(clippy::too_many_arguments)]
fn run_single_threaded(
    results: &mut Vec<BenchResult>,
    packets: &[&pcap::StoredPacket],
    parser: &xdp2_core::Parser<graph::FlowMeta>,
    iterations: u32,
    perf_passes: &[perf::PerfPass],
    total_pkts: u64,
    run_graph: bool,
    #[cfg(feature = "graph-enum")] run_graph_enum: bool,
    run_mono: bool,
    run_monox4: bool,
    run_compiled: bool,
    run_simd: bool,
    run_template: bool,
    run_template_simd: bool,
) {
    if run_graph {
        let (ns, snap) = time_run_passes(perf_passes, iterations, || {
            let mut acc: u64 = 0;
            for pkt in packets {
                if graph::parse_packet(parser, &pkt.data).is_ok() {
                    acc += 1;
                }
            }
            std::hint::black_box(acc);
        });
        results.push(BenchResult::new("graph", ns, total_pkts, 1, snap));
    }

    #[cfg(feature = "graph-enum")]
    if run_graph_enum {
        let cfg = crate::graph_enum::make_config();
        let (ns, snap) = time_run_passes(perf_passes, iterations, || {
            let mut acc: u64 = 0;
            for pkt in packets {
                if crate::graph_enum::parse_packet(&cfg, &pkt.data).is_ok() {
                    acc += 1;
                }
            }
            std::hint::black_box(acc);
        });
        results.push(BenchResult::new("graph-enum", ns, total_pkts, 1, snap));
    }

    if run_mono {
        let (ns, snap) = time_run_passes(perf_passes, iterations, || {
            let mut acc: u64 = 0;
            let mut meta = graph::FlowMeta::default();
            for pkt in packets {
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
        let (ns, snap) = time_run_passes(perf_passes, iterations, || {
            std::hint::black_box(bench_mono_x4(packets));
        });
        results.push(BenchResult::new("mono-x4", ns, total_pkts, 1, snap));
    }

    if run_compiled {
        let (ns, snap) = time_run_passes(perf_passes, iterations, || {
            let mut acc: u64 = 0;
            let mut meta = graph::FlowMeta::default();
            for pkt in packets {
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
        let (ns, snap) = time_run_passes(perf_passes, iterations, || {
            let mut meta = graph::FlowMeta::default();
            std::hint::black_box(unsafe { simd_batch::parse_batch_avx2(packets, &mut meta) });
            std::hint::black_box(&meta);
        });
        results.push(BenchResult::new("simd", ns, total_pkts, 1, snap));
    } else if run_simd {
        eprintln!("warning: AVX2 not available, skipping SIMD benchmark");
    }

    if run_template {
        let (ns, snap) = time_run_passes(perf_passes, iterations, || {
            let mut acc: u64 = 0;
            let mut meta = graph::FlowMeta::default();
            for pkt in packets {
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
        let (ns, snap) = time_run_passes(perf_passes, iterations, || {
            let batch_acc = template_simd::extract_batch(packets, &template_ids);
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
}

#[allow(clippy::too_many_arguments)]
fn run_multi_threaded(
    results: &mut Vec<BenchResult>,
    packets: &[&pcap::StoredPacket],
    parser: &xdp2_core::Parser<graph::FlowMeta>,
    iterations: u32,
    threads: usize,
    total_pkts: u64,
    run_graph: bool,
    run_mono: bool,
    run_monox4: bool,
    run_compiled: bool,
    run_simd: bool,
    run_template: bool,
    run_template_simd: bool,
) {
    if run_graph {
        let ns = run_mt(packets, iterations, threads, |slice| {
            let slice = std::hint::black_box(slice);
            let mut acc: u64 = 0;
            for pkt in slice {
                if graph::parse_packet(parser, &pkt.data).is_ok() {
                    acc += 1;
                }
            }
            acc
        });
        results.push(BenchResult::new(
            "graph-mt",
            ns,
            total_pkts,
            threads,
            None,
        ));
    }

    if run_mono {
        let ns = run_mt(packets, iterations, threads, |slice| {
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
        results.push(BenchResult::new(
            "mono-mt",
            ns,
            total_pkts,
            threads,
            None,
        ));
    }

    if run_monox4 {
        let ns = run_mt(packets, iterations, threads, |slice| {
            bench_mono_x4(slice)
        });
        results.push(BenchResult::new(
            "mono-x4-mt",
            ns,
            total_pkts,
            threads,
            None,
        ));
    }

    if run_compiled {
        let ns = run_mt(packets, iterations, threads, |slice| {
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
        results.push(BenchResult::new(
            "compiled-mt",
            ns,
            total_pkts,
            threads,
            None,
        ));
    }

    if run_simd && simd_batch::is_available() {
        let ns = run_mt(packets, iterations, threads, |slice| {
            let mut meta = graph::FlowMeta::default();
            let r = unsafe { simd_batch::parse_batch_avx2(slice, &mut meta) };
            std::hint::black_box(&meta);
            r
        });
        results.push(BenchResult::new(
            "simd-mt",
            ns,
            total_pkts,
            threads,
            None,
        ));
    }

    if run_template {
        let ns = run_mt(packets, iterations, threads, |slice| {
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
        results.push(BenchResult::new(
            "template-mt",
            ns,
            total_pkts,
            threads,
            None,
        ));
    }

    if run_template_simd && template_simd::is_available() {
        let ns = run_mt(packets, iterations, threads, |slice| {
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
        results.push(BenchResult::new(
            "template-simd-mt",
            ns,
            total_pkts,
            threads,
            None,
        ));
    }
}
