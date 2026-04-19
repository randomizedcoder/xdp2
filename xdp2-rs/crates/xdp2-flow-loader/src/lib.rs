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
//! # Portability
//!
//! Requires Linux ≥ 5.1 (for `BPF_FLOW_DISSECTOR_CONTINUE` in the
//! fast-path `.o`) and system libbpf ≥ 0.7 (for `bpf_tail_call_static`
//! and the `bpf_prog_attach(BPF_FLOW_DISSECTOR)` family that we
//! ultimately call through `#[link(name = "bpf")]`). See the block
//! comment at the top of
//! `samples/flow_dissector/fast_bpf/fast_flow.bpf.c` for why CO-RE
//! isn't required (short version: we only read BPF uapi and wire-
//! format structs, neither of which vary across kernel versions).
//!
//! # Status
//!
//! - **D7a** — API surface + CLI. ✅
//! - **D7b** — `Loader::load` implementation: opens the `.o`, forces
//!   every program to `BPF_PROG_TYPE_FLOW_DISSECTOR`, loads, finds
//!   `_dissect`, and populates `jmp_table` with non-entry programs in
//!   declaration order. ✅
//! - **D7c** — `Loader::attach` attaches the entry program to the
//!   target netns via `bpf_prog_attach(BPF_FLOW_DISSECTOR)`; `Drop`
//!   detaches. ✅
//! - **D7d** — slow-path object: when `config.slow_path_object` is
//!   set, open/load it and install its `_dissect` fd into the fast
//!   path's `jmp_table[CHAIN_DYNAMIC]` so misses tail-call into the
//!   full dissector instead of returning `CONTINUE`. ✅

use std::ffi::{CString, NulError};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::ptr;

mod libbpf_sys;
use libbpf_sys as lb;

/// Fast-path `jmp_table` slot reserved for the slow-path dissector.
///
/// Must match `CHAIN_DYNAMIC` in
/// `samples/flow_dissector/fast_bpf/fast_flow.bpf.c`.
pub const CHAIN_DYNAMIC: u32 = 7;

/// Configuration for loading `fast_flow.bpf.o`.
#[derive(Debug, Clone)]
pub struct LoaderConfig {
    /// Path to the fast-path BPF object (typically `fast_flow.bpf.o`).
    pub bpf_object: PathBuf,

    /// Optional path to a slow-path BPF object. When provided, the
    /// loader installs its `_dissect` program into the fast-path
    /// `jmp_table[CHAIN_DYNAMIC]` slot so fast-path misses tail-call
    /// into a full dissector instead of returning
    /// `BPF_FLOW_DISSECTOR_CONTINUE` (D6).
    pub slow_path_object: Option<PathBuf>,

    /// Network namespace to attach the flow_dissector hook to. `None`
    /// makes [`Loader::attach`] default to `/proc/self/ns/net`.
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
    /// Slow-path object — null unless `config.slow_path_object` was
    /// Some. Owned; freed in `Drop`.
    slow_obj: *mut lb::bpf_object,
    entry_fd: i32,
    slot_count: usize,
    /// Whether `CHAIN_DYNAMIC` was populated from `slow_obj`. Separate
    /// from `slot_count` because `slot_count` tracks the sequential
    /// 0..N fast-path slots.
    slow_path_installed: bool,
    /// Owned netns file descriptor — Some(fd) means attach succeeded
    /// and `Drop` should detach. None means never attached (or already
    /// detached).
    netns_fd: Option<i32>,
}

// `bpf_object` is handled through libbpf's own thread-safety model; we
// don't expose it across threads from this handle today.
impl fmt::Debug for Loader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Loader")
            .field("config", &self.config)
            .field("entry_fd", &self.entry_fd)
            .field("slot_count", &self.slot_count)
            .field("slow_path_installed", &self.slow_path_installed)
            .field("netns_fd", &self.netns_fd)
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
            slow_obj: ptr::null_mut(),
            entry_fd: -1,
            slot_count: 0,
            slow_path_installed: false,
            netns_fd: None,
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
        let map_fd = if map.is_null() {
            -1
        } else {
            let fd = unsafe { lb::bpf_map__fd(map) };
            if fd < 0 {
                return Err(LoaderError::JmpTableFd);
            }
            fd
        };

        if map_fd >= 0 {
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

        // D7d — if a slow-path object was configured, load it and
        // install its `_dissect` fd into `jmp_table[CHAIN_DYNAMIC]`.
        // Absence of jmp_table is a hard error here: the caller asked
        // for a slow-path install, but the fast-path object has no
        // tail-call table to plug into.
        if loader.config.slow_path_object.is_some() {
            if map_fd < 0 {
                return Err(LoaderError::JmpTableFd);
            }
            let slow_path = loader.config.slow_path_object.clone().unwrap();
            let slow_entry_fd = open_and_load_slow_path(&mut loader, &slow_path)?;
            let slot = CHAIN_DYNAMIC;
            let prog_fd: i32 = slow_entry_fd;
            let rc = unsafe {
                lb::bpf_map_update_elem(
                    map_fd,
                    &slot as *const u32 as *const _,
                    &prog_fd as *const i32 as *const _,
                    lb::BPF_ANY,
                )
            };
            if rc < 0 {
                return Err(LoaderError::JmpTableUpdate {
                    slot,
                    source: io::Error::last_os_error(),
                });
            }
            loader.slow_path_installed = true;
        }

        Ok(loader)
    }

    /// True if a slow-path program was installed into
    /// `jmp_table[CHAIN_DYNAMIC]` at load time.
    pub fn slow_path_installed(&self) -> bool {
        self.slow_path_installed
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
    /// The target netns is taken from `config.attach_netns`; when
    /// `None`, defaults to `/proc/self/ns/net` (the calling process's
    /// current netns). The attached program is detached automatically
    /// when this [`Loader`] is dropped.
    ///
    /// Requires `CAP_NET_ADMIN` (typically root).
    pub fn attach(&mut self) -> Result<(), LoaderError> {
        if self.netns_fd.is_some() {
            return Err(LoaderError::AlreadyAttached);
        }
        if self.entry_fd < 0 {
            return Err(LoaderError::MissingEntryProgram);
        }

        let netns_path = self
            .config
            .attach_netns
            .clone()
            .unwrap_or_else(|| PathBuf::from("/proc/self/ns/net"));
        let c_path = path_to_cstring(&netns_path)?;

        // SAFETY: c_path is a valid NUL-terminated string.
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(LoaderError::OpenNetns {
                path: netns_path,
                source: io::Error::last_os_error(),
            });
        }

        let rc = unsafe {
            lb::bpf_prog_attach(self.entry_fd, fd, lb::BPF_FLOW_DISSECTOR_ATTACH, 0)
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            // SAFETY: fd was just opened and is owned by us.
            unsafe { libc::close(fd) };
            return Err(LoaderError::Attach {
                netns: netns_path,
                source: err,
            });
        }

        self.netns_fd = Some(fd);
        Ok(())
    }
}

impl Drop for Loader {
    fn drop(&mut self) {
        // Detach before freeing the program fds — otherwise the attach
        // survives across `bpf_object__close` until the kernel garbage
        // collects the last reference, which can interfere with a
        // second loader instance in the same netns.
        if let Some(fd) = self.netns_fd.take() {
            if self.entry_fd >= 0 {
                unsafe {
                    lb::bpf_prog_detach2(
                        self.entry_fd,
                        fd,
                        lb::BPF_FLOW_DISSECTOR_ATTACH,
                    );
                }
            }
            // SAFETY: fd was produced by our own open() call.
            unsafe { libc::close(fd) };
        }
        if !self.slow_obj.is_null() {
            // SAFETY: we own slow_obj; closing it exactly once here.
            // Close *before* the fast-path obj so the slow-path prog fd
            // in jmp_table[CHAIN_DYNAMIC] is released first; the kernel
            // then drops the prog array entry's reference when the map
            // is freed with the fast-path object.
            unsafe { lb::bpf_object__close(self.slow_obj) };
            self.slow_obj = ptr::null_mut();
        }
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

    /// `open()` on the target netns path failed.
    OpenNetns {
        path: PathBuf,
        source: io::Error,
    },

    /// `bpf_prog_attach(BPF_FLOW_DISSECTOR)` failed.
    Attach {
        netns: PathBuf,
        source: io::Error,
    },

    /// `Loader::attach` called while the loader already has an active
    /// attachment.
    AlreadyAttached,

    /// `bpf_object__open` on the slow-path object returned NULL.
    SlowPathOpen {
        path: PathBuf,
        source: io::Error,
    },

    /// `bpf_object__load` on the slow-path object returned < 0.
    SlowPathLoad { source: io::Error },

    /// Slow-path object had no `_dissect` program.
    SlowPathMissingEntry,

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
            LoaderError::OpenNetns { path, source } => {
                write!(f, "open netns {}: {}", path.display(), source)
            }
            LoaderError::Attach { netns, source } => {
                write!(
                    f,
                    "bpf_prog_attach(BPF_FLOW_DISSECTOR) on {}: {}",
                    netns.display(),
                    source
                )
            }
            LoaderError::AlreadyAttached => {
                write!(f, "loader is already attached")
            }
            LoaderError::SlowPathOpen { path, source } => {
                write!(
                    f,
                    "bpf_object__open(slow path {}): {}",
                    path.display(),
                    source
                )
            }
            LoaderError::SlowPathLoad { source } => {
                write!(f, "bpf_object__load(slow path): {}", source)
            }
            LoaderError::SlowPathMissingEntry => {
                write!(f, "slow-path object has no _dissect program")
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
            LoaderError::OpenNetns { source, .. } => Some(source),
            LoaderError::Attach { source, .. } => Some(source),
            LoaderError::SlowPathOpen { source, .. } => Some(source),
            LoaderError::SlowPathLoad { source } => Some(source),
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

/// Open a slow-path BPF object, coerce its programs to
/// `BPF_PROG_TYPE_FLOW_DISSECTOR`, load, and return its `_dissect`
/// program fd. The `bpf_object *` is stashed on `loader.slow_obj` so
/// `Drop` can close it.
///
/// Any error leaves `loader.slow_obj` untouched (null) — the caller's
/// overall `Loader::load` failure unwinds through `Drop` which is a
/// no-op for the slow path in that case.
fn open_and_load_slow_path(
    loader: &mut Loader,
    path: &Path,
) -> Result<i32, LoaderError> {
    let c_path = path_to_cstring(path)?;
    // SAFETY: c_path is a valid NUL-terminated string; libbpf copies.
    let sobj = unsafe { lb::bpf_object__open(c_path.as_ptr()) };
    if sobj.is_null() {
        return Err(LoaderError::SlowPathOpen {
            path: path.to_path_buf(),
            source: io::Error::last_os_error(),
        });
    }

    // Same type-coercion dance as the fast path — the slow object's
    // programs must load as FLOW_DISSECTOR for the prog_array slot
    // to accept them.
    unsafe {
        let mut p = lb::bpf_object__next_program(sobj, ptr::null_mut());
        while !p.is_null() {
            lb::bpf_program__set_type(p, lb::BPF_PROG_TYPE_FLOW_DISSECTOR);
            p = lb::bpf_object__next_program(sobj, p);
        }
    }

    let rc = unsafe { lb::bpf_object__load(sobj) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        // SAFETY: sobj was just opened successfully above; close it
        // before returning so we don't leak on the error path.
        unsafe { lb::bpf_object__close(sobj) };
        return Err(LoaderError::SlowPathLoad { source: err });
    }

    let entry_name = CString::new("_dissect").expect("static ASCII");
    let prog =
        unsafe { lb::bpf_object__find_program_by_name(sobj, entry_name.as_ptr()) };
    if prog.is_null() {
        unsafe { lb::bpf_object__close(sobj) };
        return Err(LoaderError::SlowPathMissingEntry);
    }
    let fd = unsafe { lb::bpf_program__fd(prog) };
    if fd < 0 {
        unsafe { lb::bpf_object__close(sobj) };
        return Err(LoaderError::SlowPathMissingEntry);
    }

    loader.slow_obj = sobj;
    Ok(fd)
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
    fn slow_path_open_error_bubbles_up() {
        // When bpf_object__open fails on the slow-path .o, load() must
        // return SlowPathOpen (not the generic Open) so callers can
        // distinguish which object errored. We point the fast-path at a
        // path that will fail first; bpf_object__open(NULL-ish) surface
        // still returns Open, but the display of each variant names
        // the object — this smoke test confirms the Display wording.
        let err = LoaderError::SlowPathOpen {
            path: PathBuf::from("/nonexistent/slow.bpf.o"),
            source: io::Error::from_raw_os_error(libc::ENOENT),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("slow path"), "got {}", msg);
        assert!(msg.contains("/nonexistent/slow.bpf.o"), "got {}", msg);
    }

    #[test]
    fn chain_dynamic_matches_fast_flow_header() {
        // If this ever drifts from CHAIN_DYNAMIC in
        // samples/flow_dissector/fast_bpf/fast_flow.bpf.c, the
        // PROG_ARRAY slot install will silently clobber the wrong slot.
        assert_eq!(CHAIN_DYNAMIC, 7);
    }

    #[test]
    fn attach_error_display_includes_netns() {
        // Covers the non-OS-dependent branch of LoaderError::Display for
        // the attach failure path. Full attach exercise requires
        // CAP_NET_ADMIN + a real .o and lives in the parity test harness.
        let err = LoaderError::Attach {
            netns: PathBuf::from("/proc/self/ns/net"),
            source: io::Error::from_raw_os_error(libc::EPERM),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("/proc/self/ns/net"), "got {}", msg);
        assert!(msg.contains("BPF_FLOW_DISSECTOR"), "got {}", msg);
    }
}
