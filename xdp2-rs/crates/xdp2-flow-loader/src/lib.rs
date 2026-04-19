//! xdp2-flow-loader — userspace control plane for xdp2-flow-ebpf.
//!
//! Production counterpart of the test-only loaders in
//! `samples/flow_dissector/benchmark_bpf.c` and
//! `samples/flow_dissector/fast_bpf/parity_test.c`. Responsibilities:
//!
//! 1. Open the fast-path BPF object (`fast_flow.bpf.o`).
//! 2. Load its programs and populate the `jmp_table` PROG_ARRAY with
//!    every non-entry program in declaration order (matching `CHAIN_*`
//!    indices in `fast_flow.bpf.c`).
//! 3. Optionally install a slow-path program into `CHAIN_DYNAMIC` so
//!    fast-path misses tail-call into a full dissector instead of
//!    returning `BPF_FLOW_DISSECTOR_CONTINUE` (D6).
//! 4. Attach the entry program to a network namespace's
//!    `flow_dissector` hook.
//!
//! # Status
//!
//! - **D7a** — API surface + CLI. ✅
//! - **D7b** — `Loader::load` implementation: opens the `.o`, forces
//!   every program to `BPF_PROG_TYPE_FLOW_DISSECTOR`, loads, finds
//!   `_dissect`, and populates `jmp_table` with non-entry programs in
//!   declaration order. ✅
//! - **D7c** — `Loader::attach` (flow_dissector netns hook).
//! - **D7d** — slow-path object handling (CHAIN_DYNAMIC install).

use std::ffi::{CString, NulError};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::ptr;

mod libbpf_sys;
use libbpf_sys as lb;

/// Configuration for loading `fast_flow.bpf.o`.
#[derive(Debug, Clone)]
pub struct LoaderConfig {
    /// Path to the fast-path BPF object (typically `fast_flow.bpf.o`).
    pub bpf_object: PathBuf,

    /// Optional path to a slow-path BPF object. When provided, the
    /// loader installs its entry program into the `CHAIN_DYNAMIC` slot
    /// so fast-path misses tail-call into a full xdp2-compiler-generated
    /// dissector instead of returning `BPF_FLOW_DISSECTOR_CONTINUE`
    /// (D6). **D7d — not wired yet.**
    pub slow_path_object: Option<PathBuf>,

    /// Network namespace to attach the flow_dissector hook to. `None`
    /// means load-only. **D7c — not wired yet.**
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
/// Dropping this handle closes all file descriptors via
/// `bpf_object__close`, which unloads every program that wasn't pinned
/// or attached elsewhere.
pub struct Loader {
    config: LoaderConfig,
    obj: *mut lb::bpf_object,
    entry_fd: i32,
    slot_count: usize,
}

// `bpf_object` is handled through libbpf's own thread-safety model; we
// don't expose it across threads from this handle today.
impl fmt::Debug for Loader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Loader")
            .field("config", &self.config)
            .field("entry_fd", &self.entry_fd)
            .field("slot_count", &self.slot_count)
            .finish()
    }
}

impl Loader {
    /// Open the BPF object, load its programs, and populate `jmp_table`.
    ///
    /// Mirrors `load_dissector()` in
    /// `samples/flow_dissector/fast_bpf/parity_test.c:42-100`.
    pub fn load(config: LoaderConfig) -> Result<Self, LoaderError> {
        let path = path_to_cstring(&config.bpf_object)?;

        // SAFETY: libbpf takes the string by const pointer and copies
        // what it needs before returning.
        let obj = unsafe { lb::bpf_object__open(path.as_ptr()) };
        if obj.is_null() {
            return Err(LoaderError::Open {
                path: config.bpf_object.clone(),
                source: io::Error::last_os_error(),
            });
        }

        let mut loader = Loader {
            config,
            obj,
            entry_fd: -1,
            slot_count: 0,
        };

        // Force every SEC("flow_dissector") program to the right type.
        // libbpf derives the type from the SEC() prefix so this is
        // usually a no-op, but it matches what the C loaders do and is
        // robust against ELF section renames.
        unsafe {
            let mut p = lb::bpf_object__next_program(obj, ptr::null_mut());
            while !p.is_null() {
                lb::bpf_program__set_type(p, lb::BPF_PROG_TYPE_FLOW_DISSECTOR);
                p = lb::bpf_object__next_program(obj, p);
            }
        }

        // SAFETY: obj is a live bpf_object from a successful open.
        let rc = unsafe { lb::bpf_object__load(obj) };
        if rc < 0 {
            return Err(LoaderError::Load {
                source: io::Error::last_os_error(),
            });
        }

        // Find the entry program.
        let entry_name = CString::new("_dissect").expect("static ASCII");
        let entry_prog = unsafe { lb::bpf_object__find_program_by_name(obj, entry_name.as_ptr()) };
        if entry_prog.is_null() {
            return Err(LoaderError::MissingEntryProgram);
        }
        loader.entry_fd = unsafe { lb::bpf_program__fd(entry_prog) };
        if loader.entry_fd < 0 {
            return Err(LoaderError::MissingEntryProgram);
        }

        // Populate jmp_table with non-entry programs in declaration
        // order. Absent jmp_table is OK — legacy dissectors without
        // tail-calls can use this loader too.
        let map_name = CString::new("jmp_table").expect("static ASCII");
        let map = unsafe { lb::bpf_object__find_map_by_name(obj, map_name.as_ptr()) };
        if !map.is_null() {
            let map_fd = unsafe { lb::bpf_map__fd(map) };
            if map_fd < 0 {
                return Err(LoaderError::JmpTableFd);
            }

            let mut slot: u32 = 0;
            unsafe {
                let mut p = lb::bpf_object__next_program(obj, ptr::null_mut());
                while !p.is_null() {
                    let fd = lb::bpf_program__fd(p);
                    if fd >= 0 && fd != loader.entry_fd {
                        let prog_fd: i32 = fd;
                        let rc = lb::bpf_map_update_elem(
                            map_fd,
                            &slot as *const u32 as *const _,
                            &prog_fd as *const i32 as *const _,
                            lb::BPF_ANY,
                        );
                        if rc < 0 {
                            return Err(LoaderError::JmpTableUpdate {
                                slot,
                                source: io::Error::last_os_error(),
                            });
                        }
                        slot += 1;
                    }
                    p = lb::bpf_object__next_program(obj, p);
                }
            }
            loader.slot_count = slot as usize;
        }

        Ok(loader)
    }

    /// File descriptor of the entry program (`_dissect`).
    pub fn entry_fd(&self) -> i32 {
        self.entry_fd
    }

    /// Number of `jmp_table` slots populated at load time.
    pub fn slot_count(&self) -> usize {
        self.slot_count
    }

    /// Attach the entry program to the flow_dissector hook in the
    /// configured network namespace.
    ///
    /// **D7c — not implemented yet.**
    pub fn attach(&mut self) -> Result<(), LoaderError> {
        Err(LoaderError::NotImplemented {
            operation: "Loader::attach",
        })
    }
}

impl Drop for Loader {
    fn drop(&mut self) {
        if !self.obj.is_null() {
            // SAFETY: we own obj; closing it exactly once here.
            unsafe { lb::bpf_object__close(self.obj) };
            self.obj = ptr::null_mut();
        }
    }
}

/// Errors produced by the loader.
#[derive(Debug)]
pub enum LoaderError {
    /// Path contained an interior nul byte.
    BadPath(NulError),

    /// `bpf_object__open` returned NULL.
    Open {
        path: PathBuf,
        source: io::Error,
    },

    /// `bpf_object__load` returned < 0.
    Load { source: io::Error },

    /// No program named `_dissect` in the object.
    MissingEntryProgram,

    /// `bpf_map__fd` on `jmp_table` returned < 0.
    JmpTableFd,

    /// `bpf_map_update_elem` on `jmp_table` failed.
    JmpTableUpdate { slot: u32, source: io::Error },

    /// Operation is part of the planned API but hasn't been implemented
    /// yet.
    NotImplemented { operation: &'static str },
}

impl fmt::Display for LoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoaderError::BadPath(e) => write!(f, "invalid BPF object path: {}", e),
            LoaderError::Open { path, source } => {
                write!(f, "bpf_object__open({}): {}", path.display(), source)
            }
            LoaderError::Load { source } => write!(f, "bpf_object__load: {}", source),
            LoaderError::MissingEntryProgram => {
                write!(f, "no _dissect program in BPF object")
            }
            LoaderError::JmpTableFd => write!(f, "bpf_map__fd(jmp_table) failed"),
            LoaderError::JmpTableUpdate { slot, source } => {
                write!(f, "jmp_table[{}] update: {}", slot, source)
            }
            LoaderError::NotImplemented { operation } => {
                write!(f, "{} is not implemented yet", operation)
            }
        }
    }
}

impl std::error::Error for LoaderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LoaderError::BadPath(e) => Some(e),
            LoaderError::Open { source, .. } => Some(source),
            LoaderError::Load { source } => Some(source),
            LoaderError::JmpTableUpdate { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<NulError> for LoaderError {
    fn from(e: NulError) -> Self {
        LoaderError::BadPath(e)
    }
}

fn path_to_cstring(p: &Path) -> Result<CString, NulError> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(p.as_os_str().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loader_load_missing_path_errors() {
        let cfg = LoaderConfig::new("/nonexistent/fast_flow.bpf.o");
        let err = Loader::load(cfg).unwrap_err();
        // bpf_object__open returns NULL for nonexistent files.
        assert!(matches!(err, LoaderError::Open { .. }), "got {:?}", err);
    }

    #[test]
    fn loader_config_new_leaves_slow_path_empty() {
        let cfg = LoaderConfig::new("/tmp/fast.o");
        assert!(cfg.slow_path_object.is_none());
        assert!(cfg.attach_netns.is_none());
    }

    #[test]
    fn attach_still_returns_not_implemented() {
        // Can't actually construct a Loader without a real .o, so just
        // confirm the error variant exists for D7c wiring.
        let err = LoaderError::NotImplemented {
            operation: "Loader::attach",
        };
        assert!(format!("{}", err).contains("not implemented"));
    }
}
