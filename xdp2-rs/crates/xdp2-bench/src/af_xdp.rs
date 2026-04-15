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
    mut process: F,
) -> Result<Stats, String>
where
    F: FnMut(&[u8]),
{
    use xdp2_af_xdp::{Config, XdpDesc, XskSocket};

    let config = Config::default();
    let mut xsk = XskSocket::bind(ifname, queue_id, config)
        .map_err(|e| format!("AF_XDP bind failed: {e}"))?;

    // Try to register in the XSKMAP (non-fatal if not present).
    match xsk.register_xskmap(DEFAULT_XSKMAP_PATH, queue_id) {
        Ok(()) => eprintln!("AF_XDP: registered in XSKMAP at {DEFAULT_XSKMAP_PATH}"),
        Err(e) => eprintln!("AF_XDP: XSKMAP not found ({e}), assuming external setup"),
    }

    let mut batch = vec![XdpDesc::default(); 64];
    let mut total_pkts = 0u64;
    let mut total_bytes = 0u64;
    let deadline = Duration::from_secs(duration_secs as u64);
    let t_start = Instant::now();

    eprintln!(
        "AF_XDP: receiving on {ifname} queue {queue_id} for {duration_secs}s..."
    );

    while t_start.elapsed() < deadline {
        let n = xsk.recv(&mut batch);
        if n == 0 {
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

#[cfg(not(target_os = "linux"))]
pub fn run<F>(
    _ifname: &str,
    _queue_id: u32,
    _duration_secs: u32,
    _process: F,
) -> Result<Stats, String>
where
    F: FnMut(&[u8]),
{
    Err("AF_XDP requires Linux".to_string())
}
