//! CPU performance counter instrumentation via Linux `perf_event_open`.
//!
//! Reports per-packet cycles, instructions (IPC), cache misses, branch
//! mispredicts, and microarchitectural stall breakdowns so we can attribute
//! benchmark time to specific causes rather than guess.
//!
//! ## Perf Passes
//!
//! Zen 2 (and most x86 CPUs) have only 6 general-purpose PMC registers.
//! We want more than 6 counters, so we split measurement into passes:
//!
//! - **basic** (default): cycles, instructions, branches, branch-misses,
//!   cache-refs, cache-misses — the classic 6.
//! - **stalls**: cycles, frontend stalls, backend stalls, DTLB misses,
//!   ITLB misses, L1D misses — answers "why is IPC low?"
//! - **detail**: cycles, L1I misses, LL misses — instruction cache and
//!   last-level cache pressure.
//!
//! Each pass reuses the same benchmark loop so results are directly
//! comparable.
//!
//! ## Requirements
//!
//! - Linux kernel with `perf_event_open` support (any recent kernel).
//! - `kernel.perf_event_paranoid <= 2` for user-space counter access
//!   (typical default). Check with:
//!   ```bash
//!   cat /proc/sys/kernel/perf_event_paranoid
//!   ```
//!   If higher, lower it with:
//!   ```bash
//!   sudo sysctl -w kernel.perf_event_paranoid=1
//!   ```
//!
//! ## Non-Linux Platforms
//!
//! Performance counters are only available on Linux. On other platforms,
//! this module compiles to a no-op shim that reports "not supported".

/// Which set of performance counters to measure.
///
/// See module-level docs for why we need multiple passes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum PerfPass {
    /// Classic 6: cycles, instructions, branches, branch-misses,
    /// cache-refs, cache-misses.
    Basic,
    /// Microarchitectural stalls: frontend stalls, backend stalls,
    /// DTLB misses, ITLB misses, L1D misses.
    Stalls,
    /// Cache hierarchy detail: L1I misses, LL (last-level) misses.
    Detail,
}

#[cfg(target_os = "linux")]
mod linux {
    use super::PerfPass;
    use perf_event::events::{Cache, CacheOp, CacheResult, Hardware, WhichCache};
    use perf_event::{Builder, Counter};
    use std::io;

    /// A bundle of hardware performance counters for one pass.
    ///
    /// Counters are read individually (not via a `Group`) because the
    /// `Group::read()` path was returning zero for every counter on our
    /// target kernels, while individual `Counter::read()` works reliably.
    /// We pay a small cost for N syscalls per read, but the measurement
    /// happens once per benchmark phase — not per packet — so the overhead
    /// is negligible.
    pub struct PerfCounters {
        pass: PerfPass,
        counters: Vec<Counter>,
        baseline: Vec<u64>,
    }

    impl PerfCounters {
        /// Create a new counter bundle for the given pass.
        pub fn new(pass: PerfPass) -> io::Result<Self> {
            let mut counters = Vec::new();
            match pass {
                PerfPass::Basic => {
                    counters.push(Builder::new().kind(Hardware::CPU_CYCLES).build()?);
                    counters.push(Builder::new().kind(Hardware::INSTRUCTIONS).build()?);
                    counters.push(Builder::new().kind(Hardware::BRANCH_INSTRUCTIONS).build()?);
                    counters.push(Builder::new().kind(Hardware::BRANCH_MISSES).build()?);
                    counters.push(Builder::new().kind(Hardware::CACHE_REFERENCES).build()?);
                    counters.push(Builder::new().kind(Hardware::CACHE_MISSES).build()?);
                }
                PerfPass::Stalls => {
                    counters.push(Builder::new().kind(Hardware::CPU_CYCLES).build()?);
                    counters
                        .push(Builder::new().kind(Hardware::STALLED_CYCLES_FRONTEND).build()?);
                    counters
                        .push(Builder::new().kind(Hardware::STALLED_CYCLES_BACKEND).build()?);
                    counters.push(
                        Builder::new()
                            .kind(Cache {
                                which: WhichCache::DTLB,
                                operation: CacheOp::READ,
                                result: CacheResult::MISS,
                            })
                            .build()?,
                    );
                    counters.push(
                        Builder::new()
                            .kind(Cache {
                                which: WhichCache::ITLB,
                                operation: CacheOp::READ,
                                result: CacheResult::MISS,
                            })
                            .build()?,
                    );
                    counters.push(
                        Builder::new()
                            .kind(Cache {
                                which: WhichCache::L1D,
                                operation: CacheOp::READ,
                                result: CacheResult::MISS,
                            })
                            .build()?,
                    );
                }
                PerfPass::Detail => {
                    counters.push(Builder::new().kind(Hardware::CPU_CYCLES).build()?);
                    counters.push(
                        Builder::new()
                            .kind(Cache {
                                which: WhichCache::L1I,
                                operation: CacheOp::READ,
                                result: CacheResult::MISS,
                            })
                            .build()?,
                    );
                    counters.push(
                        Builder::new()
                            .kind(Cache {
                                which: WhichCache::LL,
                                operation: CacheOp::READ,
                                result: CacheResult::MISS,
                            })
                            .build()?,
                    );
                }
            }
            let n = counters.len();
            Ok(Self {
                pass,
                counters,
                baseline: vec![0; n],
            })
        }

        /// Enable all counters and capture the baseline reading.
        pub fn start(&mut self) -> io::Result<()> {
            for c in &mut self.counters {
                c.enable()?;
            }
            self.baseline = self.read_raw()?;
            Ok(())
        }

        /// Disable all counters.
        pub fn stop(&mut self) -> io::Result<()> {
            for c in &mut self.counters {
                c.disable()?;
            }
            Ok(())
        }

        /// Read current counter values as a delta from the `start()` baseline.
        pub fn read(&mut self) -> io::Result<PerfSnapshot> {
            let now = self.read_raw()?;
            let deltas: Vec<u64> = now
                .iter()
                .zip(self.baseline.iter())
                .map(|(n, b)| n.saturating_sub(*b))
                .collect();
            Ok(PerfSnapshot::from_pass(self.pass, &deltas))
        }

        /// Reset the baseline to the current raw counter values.
        pub fn reset(&mut self) -> io::Result<()> {
            self.baseline = self.read_raw()?;
            Ok(())
        }

        fn read_raw(&mut self) -> io::Result<Vec<u64>> {
            self.counters.iter_mut().map(|c| c.read()).collect()
        }
    }

    /// Snapshot of counter values, covering all passes.
    ///
    /// Fields from passes that haven't been run remain zero.
    /// This lets us accumulate results from multiple passes into one
    /// report and one JSON object.
    #[derive(Default, Clone, Copy)]
    pub struct PerfSnapshot {
        // --- basic pass ---
        pub cycles: u64,
        pub instructions: u64,
        pub branches: u64,
        pub branch_misses: u64,
        pub cache_refs: u64,
        pub cache_misses: u64,
        // --- stalls pass ---
        pub frontend_stalls: u64,
        pub backend_stalls: u64,
        pub dtlb_misses: u64,
        pub itlb_misses: u64,
        pub l1d_misses: u64,
        // --- detail pass ---
        pub l1i_misses: u64,
        pub ll_misses: u64,
    }

    impl PerfSnapshot {
        /// Build a snapshot from raw counter deltas for a given pass.
        fn from_pass(pass: PerfPass, deltas: &[u64]) -> Self {
            let mut s = Self::default();
            match pass {
                PerfPass::Basic => {
                    s.cycles = deltas[0];
                    s.instructions = deltas[1];
                    s.branches = deltas[2];
                    s.branch_misses = deltas[3];
                    s.cache_refs = deltas[4];
                    s.cache_misses = deltas[5];
                }
                PerfPass::Stalls => {
                    s.cycles = deltas[0];
                    s.frontend_stalls = deltas[1];
                    s.backend_stalls = deltas[2];
                    s.dtlb_misses = deltas[3];
                    s.itlb_misses = deltas[4];
                    s.l1d_misses = deltas[5];
                }
                PerfPass::Detail => {
                    s.cycles = deltas[0];
                    s.l1i_misses = deltas[1];
                    s.ll_misses = deltas[2];
                }
            }
            s
        }

        /// Merge another snapshot into this one (for combining passes).
        pub fn merge(&mut self, other: &PerfSnapshot) {
            // For cycles, prefer the value from whichever pass set it
            // (all passes measure cycles, so take the max for consistency).
            if other.cycles > 0 && (self.cycles == 0 || other.cycles > self.cycles) {
                self.cycles = other.cycles;
            }
            // basic
            if other.instructions > 0 {
                self.instructions = other.instructions;
            }
            if other.branches > 0 {
                self.branches = other.branches;
            }
            if other.branch_misses > 0 {
                self.branch_misses = other.branch_misses;
            }
            if other.cache_refs > 0 {
                self.cache_refs = other.cache_refs;
            }
            if other.cache_misses > 0 {
                self.cache_misses = other.cache_misses;
            }
            // stalls
            if other.frontend_stalls > 0 {
                self.frontend_stalls = other.frontend_stalls;
            }
            if other.backend_stalls > 0 {
                self.backend_stalls = other.backend_stalls;
            }
            if other.dtlb_misses > 0 {
                self.dtlb_misses = other.dtlb_misses;
            }
            if other.itlb_misses > 0 {
                self.itlb_misses = other.itlb_misses;
            }
            if other.l1d_misses > 0 {
                self.l1d_misses = other.l1d_misses;
            }
            // detail
            if other.l1i_misses > 0 {
                self.l1i_misses = other.l1i_misses;
            }
            if other.ll_misses > 0 {
                self.ll_misses = other.ll_misses;
            }
        }

        /// Format a per-packet report. `total_pkts` is the number of packets
        /// observed across all iterations while the counters were running.
        pub fn report(&self, total_pkts: u64) {
            if total_pkts == 0 {
                println!("  (no packets — skipping perf report)");
                return;
            }

            let per = |n: u64| n as f64 / total_pkts as f64;
            let ipc = if self.cycles > 0 {
                self.instructions as f64 / self.cycles as f64
            } else {
                0.0
            };
            let branch_miss_rate = if self.branches > 0 {
                100.0 * self.branch_misses as f64 / self.branches as f64
            } else {
                0.0
            };
            let cache_miss_rate = if self.cache_refs > 0 {
                100.0 * self.cache_misses as f64 / self.cache_refs as f64
            } else {
                0.0
            };

            // --- basic pass ---
            if self.instructions > 0 {
                println!("  cycles/pkt:          {:>8.1}", per(self.cycles));
                println!(
                    "  instructions/pkt:    {:>8.1}   (IPC {:.2})",
                    per(self.instructions),
                    ipc
                );
                println!(
                    "  branches/pkt:        {:>8.1}   ({} total)",
                    per(self.branches),
                    self.branches
                );
                println!(
                    "  branch-misses/pkt:   {:>8.3}   ({:.2}% miss rate)",
                    per(self.branch_misses),
                    branch_miss_rate
                );
                println!("  cache-refs/pkt:      {:>8.3}", per(self.cache_refs));
                println!(
                    "  cache-misses/pkt:    {:>8.3}   ({:.2}% miss rate)",
                    per(self.cache_misses),
                    cache_miss_rate
                );
            }

            // --- stalls pass ---
            if self.frontend_stalls > 0 || self.backend_stalls > 0 {
                let stall_cycles = per(self.cycles);
                let fe = per(self.frontend_stalls);
                let be = per(self.backend_stalls);
                let fe_pct = if stall_cycles > 0.0 {
                    100.0 * fe / stall_cycles
                } else {
                    0.0
                };
                let be_pct = if stall_cycles > 0.0 {
                    100.0 * be / stall_cycles
                } else {
                    0.0
                };
                if self.instructions == 0 {
                    // Only print cycles here if basic pass didn't
                    println!("  cycles/pkt:          {:>8.1}", stall_cycles);
                }
                println!(
                    "  frontend-stalls/pkt: {:>8.1}   ({:.1}% of cycles)",
                    fe, fe_pct
                );
                println!(
                    "  backend-stalls/pkt:  {:>8.1}   ({:.1}% of cycles)",
                    be, be_pct
                );
                println!("  dtlb-misses/pkt:     {:>8.3}", per(self.dtlb_misses));
                println!("  itlb-misses/pkt:     {:>8.3}", per(self.itlb_misses));
                println!("  l1d-misses/pkt:      {:>8.3}", per(self.l1d_misses));
            }

            // --- detail pass ---
            if self.l1i_misses > 0 || self.ll_misses > 0 {
                if self.instructions == 0 && self.frontend_stalls == 0 {
                    println!("  cycles/pkt:          {:>8.1}", per(self.cycles));
                }
                println!("  l1i-misses/pkt:      {:>8.3}", per(self.l1i_misses));
                println!("  ll-misses/pkt:       {:>8.3}", per(self.ll_misses));
            }

            // --- TMA Level 1 summary (when basic + stalls passes available) ---
            if self.instructions > 0
                && (self.frontend_stalls > 0 || self.backend_stalls > 0)
                && self.cycles > 0
            {
                self.report_tma();
            }
        }

        /// Print TopDown Microarchitecture Analysis Level 1 summary.
        ///
        /// TMA decomposes pipeline utilization into four buckets:
        /// - **Retiring**: slots doing useful work (instructions / (cycles × pipeline_width))
        /// - **Bad Speculation**: wasted slots from branch mispredicts
        /// - **Frontend Bound**: stalls from instruction fetch/decode
        /// - **Backend Bound**: stalls from execution/memory
        ///
        /// This is a simplified model using generic perf events. For precise
        /// TMA, architecture-specific PMU events would be needed.
        fn report_tma(&self) {
            // Simplified TMA: estimate pipeline width from IPC ceiling.
            // Zen 2 can retire up to 5 µops/cycle; we use 4 as a conservative
            // estimate since generic perf events count instructions, not µops.
            const PIPELINE_WIDTH: f64 = 4.0;

            let total_slots = self.cycles as f64 * PIPELINE_WIDTH;
            if total_slots == 0.0 {
                return;
            }

            // Retiring: fraction of slots that did useful work
            let retiring = self.instructions as f64 / total_slots;

            // Bad Speculation: approximate from branch mispredicts.
            // Each mispredict wastes ~15-20 cycles on Zen 2; estimate
            // wasted slots as mispredicts × pipeline_width × penalty.
            let bad_spec = if self.branch_misses > 0 {
                // Conservative: assume 15 cycle penalty per mispredict
                (self.branch_misses as f64 * 15.0 * PIPELINE_WIDTH) / total_slots
            } else {
                0.0
            };

            // Frontend Bound: stalled cycles with no µops delivered
            let fe_bound = self.frontend_stalls as f64 / self.cycles as f64;

            // Backend Bound: stalled cycles where execution units are busy/waiting
            let be_bound = self.backend_stalls as f64 / self.cycles as f64;

            // Normalize: these are estimates that may not sum to 100%
            let total = retiring + bad_spec + fe_bound + be_bound;
            let norm = if total > 0.0 { 100.0 / total } else { 1.0 };

            println!("  --- TMA Level 1 (approximate) ---");
            println!(
                "  Retiring:         {:>5.1}%   (useful work)",
                retiring * norm
            );
            println!(
                "  Bad Speculation:  {:>5.1}%   (branch mispredicts)",
                bad_spec * norm
            );
            println!(
                "  Frontend Bound:   {:>5.1}%   (fetch/decode stalls)",
                fe_bound * norm
            );
            println!(
                "  Backend Bound:    {:>5.1}%   (memory/execution stalls)",
                be_bound * norm
            );

            // Level 2 hints
            if be_bound > fe_bound && be_bound > retiring {
                let dtlb_rate = if self.cache_refs > 0 {
                    self.dtlb_misses as f64 / self.cache_refs as f64
                } else {
                    0.0
                };
                if self.l1d_misses > 0 || self.ll_misses > 0 {
                    println!("    -> Memory Bound: L1D misses={}, LL misses={}, DTLB misses={}",
                        self.l1d_misses, self.ll_misses, self.dtlb_misses);
                }
                if dtlb_rate > 0.01 {
                    println!("    -> High DTLB miss rate — consider huge pages");
                }
            }
            if fe_bound > be_bound && fe_bound > retiring {
                if self.l1i_misses > 0 {
                    println!("    -> Instruction cache pressure: L1I misses={}, ITLB misses={}",
                        self.l1i_misses, self.itlb_misses);
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod stub {
    use super::PerfPass;
    use std::io;

    pub struct PerfCounters;

    #[derive(Default, Clone, Copy)]
    pub struct PerfSnapshot {
        pub cycles: u64,
        pub instructions: u64,
        pub branches: u64,
        pub branch_misses: u64,
        pub cache_refs: u64,
        pub cache_misses: u64,
        pub frontend_stalls: u64,
        pub backend_stalls: u64,
        pub dtlb_misses: u64,
        pub itlb_misses: u64,
        pub l1d_misses: u64,
        pub l1i_misses: u64,
        pub ll_misses: u64,
    }

    impl PerfCounters {
        pub fn new(_pass: PerfPass) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "perf counters are only available on Linux",
            ))
        }
        pub fn start(&mut self) -> io::Result<()> {
            Ok(())
        }
        pub fn stop(&mut self) -> io::Result<()> {
            Ok(())
        }
        pub fn read(&mut self) -> io::Result<PerfSnapshot> {
            Ok(PerfSnapshot::default())
        }
        pub fn reset(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl PerfSnapshot {
        pub fn merge(&mut self, _other: &PerfSnapshot) {}
        pub fn report(&self, _total_pkts: u64) {
            println!("  (perf counters not supported on this platform)");
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{PerfCounters, PerfSnapshot};

#[cfg(not(target_os = "linux"))]
pub use stub::{PerfCounters, PerfSnapshot};
