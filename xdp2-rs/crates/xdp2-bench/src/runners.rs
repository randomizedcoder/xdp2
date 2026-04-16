//! Benchmark runner functions: timing, multi-threaded dispatch, mono-x4.

use std::time::Instant;

use crate::graph;
use crate::graph_mono;
use crate::pcap;
use crate::perf;

/// Run `body` for `iterations` iterations under the given perf counter group
/// and return (elapsed nanos, optional perf snapshot).
pub(crate) fn time_run<F: FnMut()>(
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
pub(crate) fn time_run_passes<F: FnMut()>(
    passes: &[perf::PerfPass],
    iterations: u32,
    mut body: F,
) -> (u64, Option<perf::PerfSnapshot>) {
    if passes.is_empty() {
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

/// Multi-threaded benchmark: split packets across `threads` workers, each
/// processing its chunk `iterations` times. The work closure must be `Sync`
/// (each thread calls it with a disjoint slice). Returns wallclock nanos.
pub(crate) fn run_mt<F>(
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
/// Returns the count of successful parses so the caller can black_box it.
#[inline(never)]
pub(crate) fn bench_mono_x4(packets: &[&pcap::StoredPacket]) -> u64 {
    use graph_mono::parse_packet_mono as mono;

    let packets = std::hint::black_box(packets);
    let mut acc: u64 = 0;
    let mut m0 = graph::FlowMeta::default();
    let mut m1;
    let mut m2;
    let mut m3;
    let mut chunks = packets.chunks_exact(4);
    for c in chunks.by_ref() {
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
    let mut mt;
    for pkt in chunks.remainder() {
        mt = graph::FlowMeta::default();
        acc += mono(&pkt.data, &mut mt).is_ok() as u64;
    }
    std::hint::black_box(&m0);
    acc
}

/// Pin the calling thread to a specific CPU core via `sched_setaffinity`.
#[cfg(target_os = "linux")]
pub(crate) fn pin_to_core(core: usize) {
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
pub(crate) fn pin_to_core(core: usize) {
    eprintln!("warning: --core-pin is only supported on Linux (requested core {core})");
}
