//! Minimal FFI bindings to the subset of libbpf we use.
//!
//! The full `libbpf-sys` crate covers the whole library; we need ~10
//! entry points and prefer to link against the system libbpf without a
//! crates.io dependency (this crate must build offline). Signatures
//! mirror `<bpf/libbpf.h>` from libbpf 1.x.

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use libc::{c_char, c_int, c_uint};

// Opaque handles — we only manipulate them through libbpf entry points.
pub enum bpf_object {}
pub enum bpf_program {}
pub enum bpf_map {}

/// BPF program types we care about. Full enum is in `<linux/bpf.h>`.
pub const BPF_PROG_TYPE_FLOW_DISSECTOR: c_uint = 22;

/// `bpf_map_update_elem` flag — "any" (insert or update).
pub const BPF_ANY: u64 = 0;

#[link(name = "bpf")]
unsafe extern "C" {
    pub fn bpf_object__open(path: *const c_char) -> *mut bpf_object;
    pub fn bpf_object__load(obj: *mut bpf_object) -> c_int;
    pub fn bpf_object__close(obj: *mut bpf_object);

    pub fn bpf_object__find_program_by_name(
        obj: *const bpf_object,
        name: *const c_char,
    ) -> *mut bpf_program;

    pub fn bpf_object__find_map_by_name(
        obj: *const bpf_object,
        name: *const c_char,
    ) -> *mut bpf_map;

    /// Iterate programs. Pass NULL for `prog` to get the first.
    pub fn bpf_object__next_program(
        obj: *const bpf_object,
        prog: *mut bpf_program,
    ) -> *mut bpf_program;

    pub fn bpf_program__fd(prog: *const bpf_program) -> c_int;
    pub fn bpf_program__name(prog: *const bpf_program) -> *const c_char;
    pub fn bpf_program__set_type(prog: *mut bpf_program, prog_type: c_uint);

    pub fn bpf_map__fd(map: *const bpf_map) -> c_int;

    pub fn bpf_map_update_elem(
        fd: c_int,
        key: *const core::ffi::c_void,
        value: *const core::ffi::c_void,
        flags: u64,
    ) -> c_int;
}
