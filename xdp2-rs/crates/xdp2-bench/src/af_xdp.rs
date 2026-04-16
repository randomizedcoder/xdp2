//! AF_XDP live packet capture benchmark.
//!
//! Receives packets from a NIC via AF_XDP (zero-copy kernel bypass) and
//! feeds them to the Rust parser. Measures end-to-end throughput including
//! the AF_XDP receive path.
//!
//! Requirements:
//! - Linux with AF_XDP support (kernel 4.18+)
//! - Root or CAP_NET_RAW + CAP_NET_ADMIN
//! - An XDP program loaded on the interface that redirects to XSKMAP
//! - Traffic arriving on the specified interface and queue

use std::time::{Duration, Instant};

/// Results from an AF_XDP benchmark run.
pub struct Stats {
    pub total_pkts: u64,
    pub total_bytes: u64,
    pub elapsed: Duration,
}

impl Stats {
    pub fn ns_pkt(&self) -> u64 {
        let ns = self.elapsed.as_nanos() as u64;
        if self.total_pkts > 0 {
            ns / self.total_pkts
        } else {
            0
        }
    }

    pub fn mpps(&self) -> f64 {
        let ns = self.elapsed.as_nanos() as u64;
        if ns > 0 {
            (self.total_pkts as f64 * 1000.0) / ns as f64
        } else {
            0.0
        }
    }
}

/// Default pinned path for the XSKMAP BPF map.
pub const DEFAULT_XSKMAP_PATH: &str = "/sys/fs/bpf/xsks_map";

/// AF_XDP socket configuration for the benchmark.
pub struct RunConfig {
    pub huge_pages: bool,
    pub busy_poll_us: Option<u32>,
    pub batch_size: usize,
    pub bind_flags: u16,
    pub need_wakeup: bool,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            huge_pages: false,
            busy_poll_us: None,
            batch_size: 64,
            bind_flags: 0,
            need_wakeup: false,
        }
    }
}

/// Run the AF_XDP receive + parse loop for `duration_secs` seconds.
///
/// Calls `process` for each received packet. The closure should parse
/// the packet and black_box the result to prevent dead-code elimination.
///
/// If an XSKMAP is pinned at `/sys/fs/bpf/xsks_map`, the socket FD
/// is automatically registered so the XDP program can redirect to it.
#[cfg(target_os = "linux")]
pub fn run<F>(
    ifname: &str,
    queue_id: u32,
    duration_secs: u32,
    cfg: &RunConfig,
    mut process: F,
) -> Result<Stats, String>
where
    F: FnMut(&[u8]),
{
    use xdp2_af_xdp::{Config, SocketConfig, UmemConfig, XdpDesc, XskSocket};

    let mut bind_flags = cfg.bind_flags;
    if cfg.need_wakeup {
        bind_flags |= xdp2_af_xdp::sys::XDP_USE_NEED_WAKEUP;
    }

    let config = Config {
        umem: UmemConfig {
            huge_pages: cfg.huge_pages,
            ..UmemConfig::default()
        },
        socket: SocketConfig {
            bind_flags,
            ..SocketConfig::default()
        },
    };
    let mut xsk = XskSocket::bind(ifname, queue_id, config)
        .map_err(|e| format!("AF_XDP bind failed: {e}"))?;

    // Try to register in the XSKMAP (non-fatal if not present).
    match xsk.register_xskmap(DEFAULT_XSKMAP_PATH, queue_id) {
        Ok(()) => eprintln!("AF_XDP: registered in XSKMAP at {DEFAULT_XSKMAP_PATH}"),
        Err(e) => eprintln!("AF_XDP: XSKMAP not found ({e}), assuming external setup"),
    }

    // Enable busy-polling if requested.
    if let Some(timeout_us) = cfg.busy_poll_us {
        match xsk.set_busy_poll(cfg.batch_size as u32, timeout_us) {
            Ok(()) => eprintln!("AF_XDP: busy-poll enabled ({timeout_us}us timeout)"),
            Err(e) => eprintln!("AF_XDP: busy-poll failed ({e}), using interrupt mode"),
        }
    }

    let batch_size = cfg.batch_size;
    let mut batch = vec![XdpDesc::default(); batch_size];
    let mut total_pkts = 0u64;
    let mut total_bytes = 0u64;
    let deadline = Duration::from_secs(duration_secs as u64);
    let t_start = Instant::now();
    let use_wakeup = cfg.need_wakeup;

    eprintln!(
        "AF_XDP: receiving on {ifname} queue {queue_id} for {duration_secs}s (batch={batch_size})..."
    );

    while t_start.elapsed() < deadline {
        let n = xsk.recv(&mut batch);
        if n == 0 {
            if use_wakeup && xsk.fill_needs_wakeup() {
                let _ = xsk.wakeup();
            }
            let _ = xsk.poll(10); // 10ms timeout
            continue;
        }

        for desc in &batch[..n] {
            // SAFETY: desc was received from recv() and not yet recycled.
            let pkt = unsafe { xsk.pkt(desc) };
            process(pkt);
            total_pkts += 1;
            total_bytes += desc.len as u64;
        }

        xsk.recycle(&batch[..n]);
    }

    Ok(Stats {
        total_pkts,
        total_bytes,
        elapsed: t_start.elapsed(),
    })
}

/// Run AF_XDP receive across multiple NIC queues in parallel.
///
/// Spawns one thread per queue, each with its own XskSocket and UMEM.
/// Returns per-queue stats (one entry per queue). The `process` closure
/// must be `Send + Sync` since it runs on multiple threads.
///
/// If `core_pin_start` is `Some(cpu)`, thread for queue N is pinned to
/// core `cpu + N` (round-robin across available cores).
#[cfg(target_os = "linux")]
pub fn run_multi_queue<F>(
    ifname: &str,
    queue_start: u32,
    num_queues: u32,
    duration_secs: u32,
    cfg: &RunConfig,
    core_pin_start: Option<usize>,
    process: F,
) -> Result<Vec<Stats>, String>
where
    F: Fn(&[u8]) + Send + Sync,
{
    use std::thread;

    if num_queues == 0 {
        return Err("num_queues must be >= 1".to_string());
    }

    let process = &process;

    thread::scope(|s| {
        let mut handles = Vec::with_capacity(num_queues as usize);

        for i in 0..num_queues {
            let queue_id = queue_start + i;
            let handle = s.spawn(move || {
                // Pin to core if requested.
                if let Some(base) = core_pin_start {
                    let cpu = base + i as usize;
                    pin_to_core(cpu);
                }

                run(ifname, queue_id, duration_secs, cfg, |pkt| {
                    process(pkt);
                })
            });
            handles.push(handle);
        }

        let mut results = Vec::with_capacity(handles.len());
        for (i, h) in handles.into_iter().enumerate() {
            match h.join() {
                Ok(Ok(stats)) => results.push(stats),
                Ok(Err(e)) => {
                    return Err(format!("queue {} failed: {}", queue_start + i as u32, e));
                }
                Err(_) => {
                    return Err(format!("queue {} thread panicked", queue_start + i as u32));
                }
            }
        }
        Ok(results)
    })
}

/// Aggregate stats from multiple queues into a single summary.
pub fn aggregate_stats(per_queue: &[Stats]) -> Stats {
    let total_pkts: u64 = per_queue.iter().map(|s| s.total_pkts).sum();
    let total_bytes: u64 = per_queue.iter().map(|s| s.total_bytes).sum();
    // Use the maximum elapsed time (all threads run concurrently).
    let elapsed = per_queue
        .iter()
        .map(|s| s.elapsed)
        .max()
        .unwrap_or_default();
    Stats {
        total_pkts,
        total_bytes,
        elapsed,
    }
}

/// Best-effort CPU pinning via sched_setaffinity.
#[cfg(target_os = "linux")]
fn pin_to_core(cpu: usize) {
    unsafe {
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut cpuset);
        libc::CPU_SET(cpu, &mut cpuset);
        let ret = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &cpuset);
        if ret == 0 {
            eprintln!("AF_XDP: pinned thread to core {cpu}");
        } else {
            eprintln!(
                "AF_XDP: failed to pin to core {cpu}: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn run<F>(
    _ifname: &str,
    _queue_id: u32,
    _duration_secs: u32,
    _cfg: &RunConfig,
    _process: F,
) -> Result<Stats, String>
where
    F: FnMut(&[u8]),
{
    Err("AF_XDP requires Linux".to_string())
}

#[cfg(not(target_os = "linux"))]
pub fn run_multi_queue<F>(
    _ifname: &str,
    _queue_start: u32,
    _num_queues: u32,
    _duration_secs: u32,
    _cfg: &RunConfig,
    _core_pin_start: Option<usize>,
    _process: F,
) -> Result<Vec<Stats>, String>
where
    F: Fn(&[u8]) + Send + Sync,
{
    Err("AF_XDP requires Linux".to_string())
}
