//! CPU performance counter instrumentation via Linux `perf_event_open`.
//!
//! Reports per-packet cycles, instructions (IPC), cache misses, and branch
//! mispredicts so we can attribute benchmark time to microarchitectural
//! causes rather than guess.
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

#[cfg(target_os = "linux")]
mod linux {
    use perf_event::events::Hardware;
    use perf_event::{Builder, Counter};
    use std::io;

    /// A bundle of hardware performance counters.
    ///
    /// Counters are read individually (not via a `Group`) because the
    /// `Group::read()` path was returning zero for every counter on our
    /// target kernels, while individual `Counter::read()` works reliably.
    /// We pay a small cost for N syscalls per read, but the measurement
    /// happens once per benchmark phase — not per packet — so the overhead
    /// is negligible.
    pub struct PerfCounters {
        cycles: Counter,
        instructions: Counter,
        branches: Counter,
        branch_misses: Counter,
        cache_refs: Counter,
        cache_misses: Counter,
        baseline: PerfSnapshot,
    }

    /// Snapshot of counter values.
    #[derive(Default, Clone, Copy)]
    pub struct PerfSnapshot {
        pub cycles: u64,
        pub instructions: u64,
        pub branches: u64,
        pub branch_misses: u64,
        pub cache_refs: u64,
        pub cache_misses: u64,
    }

    impl PerfCounters {
        /// Create a new counter bundle. Counters start disabled and must
        /// be enabled via `start()`.
        pub fn new() -> io::Result<Self> {
            let cycles = Builder::new().kind(Hardware::CPU_CYCLES).build()?;
            let instructions = Builder::new().kind(Hardware::INSTRUCTIONS).build()?;
            let branches = Builder::new().kind(Hardware::BRANCH_INSTRUCTIONS).build()?;
            let branch_misses = Builder::new().kind(Hardware::BRANCH_MISSES).build()?;
            let cache_refs = Builder::new().kind(Hardware::CACHE_REFERENCES).build()?;
            let cache_misses = Builder::new().kind(Hardware::CACHE_MISSES).build()?;

            Ok(Self {
                cycles,
                instructions,
                branches,
                branch_misses,
                cache_refs,
                cache_misses,
                baseline: PerfSnapshot::default(),
            })
        }

        /// Enable all counters and capture the baseline reading.
        /// Subsequent `read()` calls return values relative to this baseline.
        pub fn start(&mut self) -> io::Result<()> {
            self.cycles.enable()?;
            self.instructions.enable()?;
            self.branches.enable()?;
            self.branch_misses.enable()?;
            self.cache_refs.enable()?;
            self.cache_misses.enable()?;
            self.baseline = self.read_raw()?;
            Ok(())
        }

        /// Disable all counters.
        pub fn stop(&mut self) -> io::Result<()> {
            self.cycles.disable()?;
            self.instructions.disable()?;
            self.branches.disable()?;
            self.branch_misses.disable()?;
            self.cache_refs.disable()?;
            self.cache_misses.disable()?;
            Ok(())
        }

        /// Read current counter values as a delta from the `start()` baseline.
        pub fn read(&mut self) -> io::Result<PerfSnapshot> {
            let now = self.read_raw()?;
            Ok(PerfSnapshot {
                cycles: now.cycles.saturating_sub(self.baseline.cycles),
                instructions: now.instructions.saturating_sub(self.baseline.instructions),
                branches: now.branches.saturating_sub(self.baseline.branches),
                branch_misses: now.branch_misses.saturating_sub(self.baseline.branch_misses),
                cache_refs: now.cache_refs.saturating_sub(self.baseline.cache_refs),
                cache_misses: now.cache_misses.saturating_sub(self.baseline.cache_misses),
            })
        }

        /// Reset the baseline to the current raw counter values, so the
        /// next `read()` returns a delta relative to now.
        pub fn reset(&mut self) -> io::Result<()> {
            self.baseline = self.read_raw()?;
            Ok(())
        }

        fn read_raw(&mut self) -> io::Result<PerfSnapshot> {
            Ok(PerfSnapshot {
                cycles: self.cycles.read()?,
                instructions: self.instructions.read()?,
                branches: self.branches.read()?,
                branch_misses: self.branch_misses.read()?,
                cache_refs: self.cache_refs.read()?,
                cache_misses: self.cache_misses.read()?,
            })
        }
    }

    impl PerfSnapshot {
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
    }
}

#[cfg(not(target_os = "linux"))]
mod stub {
    use std::io;

    pub struct PerfCounters;

    #[derive(Default, Clone, Copy)]
    pub struct PerfSnapshot;

    impl PerfCounters {
        pub fn new() -> io::Result<Self> {
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
            Ok(PerfSnapshot)
        }
        pub fn reset(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl PerfSnapshot {
        pub fn report(&self, _total_pkts: u64) {
            println!("  (perf counters not supported on this platform)");
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::PerfCounters;

#[cfg(not(target_os = "linux"))]
pub use stub::PerfCounters;
