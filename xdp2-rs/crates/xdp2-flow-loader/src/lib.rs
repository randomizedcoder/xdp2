//! xdp2-flow-loader — userspace control plane for xdp2-flow-ebpf.
//!
//! This crate is the production counterpart of the test-only loader
//! embedded in `samples/flow_dissector/benchmark_bpf.c` and
//! `samples/flow_dissector/fast_bpf/parity_test.c`. It is responsible
//! for:
//!
//! 1. Opening the fast-path BPF object (`fast_flow.bpf.o`).
//! 2. Loading its programs and populating the `jmp_table` PROG_ARRAY
//!    with every non-entry program in declaration order (matching
//!    `CHAIN_*` indices in `fast_flow.bpf.c`).
//! 3. Optionally attaching the entry program to a network namespace's
//!    `flow_dissector` hook.
//! 4. (Future) Receiving template updates from the shared control
//!    plane (`xdp2-fastpath-control`, plan §5a) and installing a
//!    dynamic template into `CHAIN_DYNAMIC`.
//!
//! # Status
//!
//! **D7a skeleton** — this crate currently exposes the API surface but
//! every operation returns [`LoaderError::NotImplemented`]. D7b will
//! add the libbpf-backed implementation.
//!
//! The test-only C loaders remain the source of truth for how the
//! `jmp_table` is populated; see
//! `samples/flow_dissector/fast_bpf/parity_test.c` lines 76-95.

use std::fmt;
use std::path::PathBuf;

/// Configuration for loading `fast_flow.bpf.o`.
#[derive(Debug, Clone)]
pub struct LoaderConfig {
    /// Path to the fast-path BPF object (typically `fast_flow.bpf.o`).
    pub bpf_object: PathBuf,

    /// Optional path to a slow-path BPF object. When provided, the
    /// loader installs its entry program into the `CHAIN_DYNAMIC` slot
    /// so fast-path misses tail-call into a full xdp2-compiler-generated
    /// dissector instead of returning `BPF_FLOW_DISSECTOR_CONTINUE`
    /// (see D6 in the implementation log).
    pub slow_path_object: Option<PathBuf>,

    /// Network namespace to attach the flow_dissector hook to. `None`
    /// means load-only (the programs remain in the kernel but are
    /// unreachable until something attaches them).
    pub attach_netns: Option<PathBuf>,
}

impl LoaderConfig {
    /// Convenience constructor — load the given object, no slow path,
    /// no attach.
    pub fn new(bpf_object: impl Into<PathBuf>) -> Self {
        Self {
            bpf_object: bpf_object.into(),
            slow_path_object: None,
            attach_netns: None,
        }
    }
}

/// A loaded (but not necessarily attached) fast-path flow dissector.
///
/// Dropping this handle closes all file descriptors and detaches the
/// flow_dissector hook if one was installed.
#[derive(Debug)]
pub struct Loader {
    #[allow(dead_code)]
    config: LoaderConfig,
}

impl Loader {
    /// Open the BPF object, load its programs, and populate `jmp_table`.
    pub fn load(config: LoaderConfig) -> Result<Self, LoaderError> {
        // D7b will replace this with the libbpf-backed implementation.
        // Reference C code:
        //   samples/flow_dissector/fast_bpf/parity_test.c:42-100
        //   samples/flow_dissector/benchmark_bpf.c:67-160
        let _ = config;
        Err(LoaderError::NotImplemented {
            operation: "Loader::load",
        })
    }

    /// Attach the entry program to the flow_dissector hook in the
    /// configured network namespace.
    pub fn attach(&mut self) -> Result<(), LoaderError> {
        Err(LoaderError::NotImplemented {
            operation: "Loader::attach",
        })
    }
}

/// Errors produced by the loader.
#[derive(Debug)]
pub enum LoaderError {
    /// D7a placeholder — the operation is part of the planned API but
    /// has no implementation yet.
    NotImplemented {
        /// Name of the operation that isn't implemented.
        operation: &'static str,
    },
}

impl fmt::Display for LoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoaderError::NotImplemented { operation } => {
                write!(f, "{} is not implemented yet (D7a skeleton)", operation)
            }
        }
    }
}

impl std::error::Error for LoaderError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loader_load_returns_not_implemented() {
        let cfg = LoaderConfig::new("/nonexistent/fast_flow.bpf.o");
        let err = Loader::load(cfg).unwrap_err();
        assert!(matches!(err, LoaderError::NotImplemented { .. }));
    }

    #[test]
    fn loader_config_new_leaves_slow_path_empty() {
        let cfg = LoaderConfig::new("/tmp/fast.o");
        assert!(cfg.slow_path_object.is_none());
        assert!(cfg.attach_netns.is_none());
    }
}
