// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
//
// Reference userspace agent for the flow_dissector fast-path gates
// (series4 "Home A"). This is the userspace half of the same policy the
// in-kernel `net.flow_dissector.auto` worker implements
// (net/core/flow_dissector.c): identical packet-window + measured-break-even
// + hysteresis/dwell/rate-cap policy, but the control loop lives here so the
// kernel can stay mechanism-only (per-shape counters + the manual per-shape
// sysctls).
//
//   read : /proc/net/flow_dissector_stats   (the counters patch's seq_file)
//   write: /proc/sys/net/flow_dissector/<shape>
//
// The policy core (`Policy::decide`) is a pure function of (previous snapshot,
// current snapshot, wall-clock) so it is unit-testable without a live kernel —
// the tests below feed a frac time-series and assert dwell/hysteresis/rate-cap
// behaviour, mirroring reconciler.rs's test style.
//
// The break-even thresholds, dwell, margins and rate cap are byte-for-byte the
// same constants as the kernel worker, so both homes make the same decision on
// the same input — the RFC presents both and lets the list choose where the
// loop belongs.

use std::fs;
use std::io;

/// Byte-identical shapes the controller may auto-manage. Descent shapes
/// (vxlan/geneve/gtpu) are never auto-managed — they change hashing behaviour —
/// so they are not in this set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Shape {
    EthIp,
    Vlan,
    Qinq,
    Pppoe,
    Mpls,
    Ipip,
    Gre,
}

pub const N_SHAPES: usize = 7;

impl Shape {
    pub const ALL: [Shape; N_SHAPES] = [
        Shape::EthIp,
        Shape::Vlan,
        Shape::Qinq,
        Shape::Pppoe,
        Shape::Mpls,
        Shape::Ipip,
        Shape::Gre,
    ];

    pub fn idx(self) -> usize {
        self as usize
    }

    /// The `/proc/sys/net/flow_dissector/<name>` leaf.
    pub fn sysctl_name(self) -> &'static str {
        match self {
            Shape::EthIp => "eth_ip",
            Shape::Vlan => "vlan",
            Shape::Qinq => "qinq",
            Shape::Pppoe => "pppoe",
            Shape::Mpls => "mpls",
            Shape::Ipip => "ipip",
            Shape::Gre => "gre",
        }
    }

    fn from_name(s: &str) -> Option<Shape> {
        Shape::ALL.into_iter().find(|sh| sh.sysctl_name() == s)
    }

    /// mpls is not auto-managed: its break-even is 60-70% on in-order cores
    /// (S ~ C), a net loss unless mpls is a large majority — leave that to a
    /// deliberate operator. Matches the kernel's `fd_auto_managed()`.
    pub fn auto_managed(self) -> bool {
        self != Shape::Mpls
    }
}

/// Measured break-even p_be = C/(S+C), in parts-per-10000, conservative
/// in-order row from perf-results/2026-07-02-fastpath-breakeven/BREAKEVEN.md.
/// Byte-identical to the kernel worker's `fd_auto_pbe[]`.
pub const P_BE: [u32; N_SHAPES] = [
    1920, // eth_ip
    1290, // vlan
    1100, // qinq
    1840, // pppoe
    6950, // mpls (excluded from auto)
    800,  // ipip
    1000, // gre (S not separately microbenched; ~ipip class)
];

/// Enable at break-even + 10.00pp, disable at break-even - 5.00pp; a flip
/// requires the condition to hold for DWELL consecutive windows. Same as the
/// kernel `FD_AUTO_*`.
pub const DWELL: u8 = 3;
pub const MARGIN_HI: u32 = 1000;
pub const MARGIN_LO: u32 = 500;

/// A per-shape traffic snapshot parsed from /proc/net/flow_dissector_stats.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// occurrences + fast_hits per shape (the gate-invariant shape total).
    pub total: [u64; N_SHAPES],
    pub dissects: u64,
    pub gate: [bool; N_SHAPES],
}

/// Parse the counters patch's seq_file. Format:
/// ```text
/// shape        occurrences   fast_hits   eligible%   gate
/// eth_ip          12345678      9012345      74.1%     on
/// ...
/// dissects: 16600000
/// ```
/// Malformed lines are skipped; returns None only if `dissects:` is absent.
pub fn parse_stats(text: &str) -> Option<Snapshot> {
    let mut snap = Snapshot::default();
    let mut saw_dissects = false;

    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("dissects:") {
            snap.dissects = rest.trim().parse().ok()?;
            saw_dissects = true;
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 5 {
            continue;
        }
        let shape = match Shape::from_name(f[0]) {
            Some(s) => s,
            None => continue, // header row or unknown
        };
        let occ: u64 = match f[1].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let fast: u64 = match f[2].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        snap.total[shape.idx()] = occ + fast;
        snap.gate[shape.idx()] = f[4] == "on";
    }

    saw_dissects.then_some(snap)
}

/// One gate flip the controller decided to make.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Action {
    pub shape: Shape,
    pub enable: bool,
}

/// Controller configuration. `window_packets` is the decision window (how fast
/// it adapts); `flip_min_interval_ms` is the global rate cap between any two
/// flips.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub window_packets: u64,
    pub flip_min_interval_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            window_packets: 1_000_000,
            flip_min_interval_ms: 1_000,
        }
    }
}

/// The policy core — identical decision logic to the kernel worker.
pub struct Policy {
    cfg: Config,
    prev: Option<Snapshot>,
    en_dwell: [u8; N_SHAPES],
    dis_dwell: [u8; N_SHAPES],
    last_flip_ms: Option<u64>,
}

impl Policy {
    pub fn new(cfg: Config) -> Self {
        Policy {
            cfg,
            prev: None,
            en_dwell: [0; N_SHAPES],
            dis_dwell: [0; N_SHAPES],
            last_flip_ms: None,
        }
    }

    /// Feed the latest snapshot and current monotonic time; return the flips to
    /// apply. Decisions are on the *delta* since the last decision (never
    /// cumulative — a since-boot ratio asymptotically freezes), and only once a
    /// window's worth of new packets has accumulated.
    pub fn decide(&mut self, cur: &Snapshot, now_ms: u64) -> Vec<Action> {
        let mut actions = Vec::new();

        let prev = match &self.prev {
            Some(p) => p.clone(),
            None => {
                self.prev = Some(cur.clone()); // baseline; decide next window
                return actions;
            }
        };

        let ddiss = cur.dissects.saturating_sub(prev.dissects);
        if ddiss < self.cfg.window_packets / 2 {
            return actions; // not a full-ish window yet
        }

        for s in Shape::ALL {
            let i = s.idx();
            if !s.auto_managed() {
                continue;
            }

            let dtot = cur.total[i].saturating_sub(prev.total[i]);
            let frac = if ddiss > 0 {
                (dtot.saturating_mul(10_000) / ddiss) as u32
            } else {
                0
            };
            let pbe = P_BE[i];
            let rate_ok = self
                .last_flip_ms
                .is_none_or(|t| now_ms.saturating_sub(t) >= self.cfg.flip_min_interval_ms);

            if !cur.gate[i] {
                self.en_dwell[i] = if frac > pbe + MARGIN_HI {
                    self.en_dwell[i] + 1
                } else {
                    0
                };
                self.dis_dwell[i] = 0;
                if self.en_dwell[i] >= DWELL && rate_ok {
                    actions.push(Action { shape: s, enable: true });
                    self.last_flip_ms = Some(now_ms);
                    self.en_dwell[i] = 0;
                }
            } else {
                let lo = pbe.saturating_sub(MARGIN_LO);
                self.dis_dwell[i] = if frac < lo { self.dis_dwell[i] + 1 } else { 0 };
                self.en_dwell[i] = 0;
                if self.dis_dwell[i] >= DWELL && rate_ok {
                    actions.push(Action { shape: s, enable: false });
                    self.last_flip_ms = Some(now_ms);
                    self.dis_dwell[i] = 0;
                }
            }
        }

        self.prev = Some(cur.clone());
        actions
    }
}

/// Apply a flip by writing the per-shape sysctl. The kernel-side handlers
/// enforce the vlan/qinq coupling (writing qinq=1 also enables vlan; vlan=0
/// also clears qinq), so the agent does not replicate it.
pub fn apply(action: &Action) -> io::Result<()> {
    let path = format!(
        "/proc/sys/net/flow_dissector/{}",
        action.shape.sysctl_name()
    );
    fs::write(path, if action.enable { "1\n" } else { "0\n" })
}

/// Read + parse the current stats snapshot from the live kernel.
pub fn read_snapshot() -> io::Result<Snapshot> {
    let text = fs::read_to_string("/proc/net/flow_dissector_stats")?;
    parse_stats(&text)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no dissects: line"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(totals: [u64; N_SHAPES], dissects: u64, gates: [bool; N_SHAPES]) -> Snapshot {
        Snapshot {
            total: totals,
            dissects,
            gate: gates,
        }
    }

    // A snapshot where only `shape` carries `frac_bp`/10000 of the window's
    // traffic, cumulative dissects = `d`, all gates as given.
    fn one_shape(shape: Shape, frac_bp: u64, d: u64, gates: [bool; N_SHAPES]) -> Snapshot {
        let mut t = [0u64; N_SHAPES];
        t[shape.idx()] = d * frac_bp / 10_000;
        snap(t, d, gates)
    }

    const OFF: [bool; N_SHAPES] = [false; N_SHAPES];

    #[test]
    fn enable_only_after_dwell() {
        let cfg = Config {
            window_packets: 1000,
            flip_min_interval_ms: 0,
        };
        let mut p = Policy::new(cfg);
        // eth_ip at 40% (well above p_be 19.2% + 10pp). window = 1000.
        // First call baselines, then one decision per window.
        let mut d = 0u64;
        let mut flips = 0;
        for round in 0..5 {
            d += 1000;
            let acts = p.decide(&one_shape(Shape::EthIp, 4000, d, OFF), round * 10);
            flips += acts.iter().filter(|a| a.enable).count();
        }
        // baseline(round0) + 3 dwell windows -> first enable on the 4th decision.
        assert_eq!(flips, 1);
    }

    #[test]
    fn no_flip_inside_hysteresis_band() {
        let cfg = Config {
            window_packets: 1000,
            flip_min_interval_ms: 0,
        };
        let mut p = Policy::new(cfg);
        // eth_ip at 22% — above p_be (19.2%) but below p_be+10pp (29.2%).
        let mut d = 0;
        let mut flips = 0;
        for round in 0..8 {
            d += 1000;
            flips += p
                .decide(&one_shape(Shape::EthIp, 2200, d, OFF), round)
                .len();
        }
        assert_eq!(flips, 0);
    }

    #[test]
    fn disable_after_dwell_below_low_margin() {
        let cfg = Config {
            window_packets: 1000,
            flip_min_interval_ms: 0,
        };
        let mut p = Policy::new(cfg);
        let mut on = OFF;
        on[Shape::Ipip.idx()] = true; // ipip gate currently on
                                      // ipip p_be 8% - 5pp = 3%; feed 1% -> below -> disable after dwell.
        let mut d = 0;
        let mut disables = 0;
        for round in 0..5 {
            d += 1000;
            let acts = p.decide(&one_shape(Shape::Ipip, 100, d, on), round);
            disables += acts.iter().filter(|a| !a.enable).count();
        }
        assert_eq!(disables, 1);
    }

    #[test]
    fn mpls_never_auto_managed() {
        let cfg = Config {
            window_packets: 1000,
            flip_min_interval_ms: 0,
        };
        let mut p = Policy::new(cfg);
        // mpls at 100% of traffic — still never touched.
        let mut d = 0;
        let mut acts_total = 0;
        for round in 0..6 {
            d += 1000;
            acts_total += p
                .decide(&one_shape(Shape::Mpls, 10_000, d, OFF), round)
                .iter()
                .filter(|a| a.shape == Shape::Mpls)
                .count();
        }
        assert_eq!(acts_total, 0);
    }

    #[test]
    fn rate_cap_limits_to_one_flip_per_interval() {
        let cfg = Config {
            window_packets: 1000,
            flip_min_interval_ms: 10_000, // 10s cap
        };
        let mut p = Policy::new(cfg);
        // Two shapes both eligible in the same window; only one may flip.
        let mut totals = [0u64; N_SHAPES];
        let make = |d: u64, totals: &mut [u64; N_SHAPES]| {
            totals[Shape::EthIp.idx()] = d * 4000 / 10_000;
            totals[Shape::Vlan.idx()] = d * 4000 / 10_000;
            snap(*totals, d, OFF)
        };
        let mut d = 0;
        let mut enables = 0;
        // Hold both above threshold; times all within the 10s cap window.
        for _ in 0..5 {
            d += 1000;
            let s = make(d, &mut totals);
            enables += p.decide(&s, 100).iter().filter(|a| a.enable).count();
        }
        assert_eq!(enables, 1, "rate cap should permit only one flip per interval");
    }

    #[test]
    fn window_gate_waits_for_enough_packets() {
        let cfg = Config {
            window_packets: 1_000_000,
            flip_min_interval_ms: 0,
        };
        let mut p = Policy::new(cfg);
        // Only 1000 packets accumulate — far below window/2 — so no decision.
        let mut d = 0;
        let mut acts = 0;
        for round in 0..10 {
            d += 1000;
            acts += p.decide(&one_shape(Shape::EthIp, 9000, d, OFF), round).len();
        }
        assert_eq!(acts, 0);
    }

    #[test]
    fn parse_roundtrip() {
        let text = "\
shape        occurrences   fast_hits   eligible%   gate
eth_ip          100      0      10.00%     off
vlan             50      50      10.00%     on
qinq              0       0       0.00%     off
pppoe             0       0       0.00%     off
mpls              0       0       0.00%     off
ipip              0       0       0.00%     off
gre               0       0       0.00%     off
dissects: 1000
";
        let s = parse_stats(text).expect("parse");
        assert_eq!(s.dissects, 1000);
        assert_eq!(s.total[Shape::EthIp.idx()], 100);
        assert_eq!(s.total[Shape::Vlan.idx()], 100); // 50 occ + 50 fast
        assert!(!s.gate[Shape::EthIp.idx()]);
        assert!(s.gate[Shape::Vlan.idx()]);
    }

    #[test]
    fn parse_rejects_missing_dissects() {
        assert!(parse_stats("eth_ip 1 2 3% on\n").is_none());
    }
}
