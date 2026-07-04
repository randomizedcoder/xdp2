// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
//
// Reference userspace agent for the flow_dissector fast-path gates (series4
// "Home A"). Kernel stays mechanism-only (per-shape counters + manual
// sysctls); this loop runs the identical policy the in-kernel `auto` worker
// would, so netdev can choose where the loop belongs.
//
// Run (needs CAP_NET_ADMIN to write the sysctls):
//   cargo run --example flowdis-auto-agent
//
// It polls /proc/net/flow_dissector_stats and, once a decision window's worth
// of packets has accumulated, enables/disables /proc/sys/net/flow_dissector/<shape>
// per the measured break-even + hysteresis/dwell/rate-cap policy.

use std::thread::sleep;
use std::time::{Duration, Instant};

use xdp2_fastpath_control::flowdis_auto::{apply, read_snapshot, Config, Policy};

fn main() {
    // Defaults match the in-kernel worker: 1,000,000-packet window, 1s flip cap.
    let cfg = Config::default();
    let mut policy = Policy::new(cfg);
    let start = Instant::now();
    let poll = Duration::from_secs(1);

    eprintln!(
        "flowdis-auto: window={} pkts, flip-cap={}ms — polling every {:?}",
        cfg.window_packets, cfg.flip_min_interval_ms, poll
    );

    loop {
        match read_snapshot() {
            Ok(snap) => {
                let now_ms = start.elapsed().as_millis() as u64;
                for a in policy.decide(&snap, now_ms) {
                    let verb = if a.enable { "enable" } else { "disable" };
                    match apply(&a) {
                        Ok(()) => eprintln!("flowdis-auto: {verb} {}", a.shape.sysctl_name()),
                        Err(e) => {
                            eprintln!("flowdis-auto: {verb} {} failed: {e}", a.shape.sysctl_name())
                        }
                    }
                }
            }
            Err(e) => eprintln!("flowdis-auto: read stats: {e}"),
        }
        sleep(poll);
    }
}
