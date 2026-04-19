// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
//
// Minimal raw-syscall BPF map-op wrappers.
//
// This crate deliberately avoids linking against libbpf — a
// listen-socket enumerator + slot-management API shouldn't drag in
// elfutils + zlib + libbpf just to update a PROG_ARRAY entry. The
// three map ops we need (update/delete/lookup) are thin wrappers
// around the `bpf(2)` syscall and fit in ~50 lines. The signatures
// mirror `<linux/bpf.h>` verbatim; see `bpf_attr.map_elem` in the
// kernel uapi headers.

use std::io;

// bpf(2) command numbers from <linux/bpf.h>. Stable uapi.
pub const BPF_MAP_LOOKUP_ELEM: u32 = 1;
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
pub const BPF_MAP_DELETE_ELEM: u32 = 3;

// bpf_map_update_elem flags. `BPF_ANY` = "insert or update".
pub const BPF_ANY: u64 = 0;

// `union bpf_attr` for map ops. The kernel expects the full union
// sized to the largest variant, but for the three ops we need the
// layout below (map_elem sub-struct) is what the kernel reads. We
// zero-init the whole `BpfAttr` before each call so any bytes the
// kernel treats as the "wrong" variant stay zero — safe across
// kernel versions that may grow the union later.
#[repr(C)]
#[derive(Default)]
pub struct BpfAttrMapElem {
    pub map_fd: u32,
    pub _pad0: u32, // ensures next field is 8-byte aligned
    pub key: u64,
    pub value_or_next_key: u64,
    pub flags: u64,
}

/// Call `bpf(cmd, &attr, sizeof(attr))`. Returns the raw return value
/// on success; `Err(io::Error::last_os_error())` on failure (the
/// kernel sets errno via the usual -1 path).
///
/// SAFETY: caller must pass an `attr` whose layout matches what the
/// kernel expects for `cmd`. We only use this with `BpfAttrMapElem`,
/// so that contract is enforced at the call site.
pub unsafe fn bpf_syscall<T>(cmd: u32, attr: *const T, size: usize) -> io::Result<i64> {
    // SAFETY: SYS_bpf takes `(cmd, ptr, size)`; caller-provided cmd
    // and size bound the read. libc::syscall is a variadic i32
    // wrapper returning i64.
    let rc = unsafe { libc::syscall(libc::SYS_bpf, cmd as i32, attr, size) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// Write `value` to `map[key]`. For a PROG_ARRAY (`map_fd` of a
/// `BPF_MAP_TYPE_PROG_ARRAY`), `value` is a *program fd*.
pub fn map_update_elem(map_fd: i32, key: u32, value: u32, flags: u64) -> io::Result<()> {
    let mut attr = BpfAttrMapElem::default();
    attr.map_fd = map_fd as u32;
    attr.key = &key as *const u32 as u64;
    attr.value_or_next_key = &value as *const u32 as u64;
    attr.flags = flags;
    unsafe { bpf_syscall(BPF_MAP_UPDATE_ELEM, &attr, std::mem::size_of_val(&attr)) }?;
    Ok(())
}

/// Remove `map[key]`. Succeeds even if the slot was already empty
/// — the kernel returns ENOENT which we translate into `Ok(())` so
/// the operation is idempotent from the caller's perspective. A
/// genuine failure (EBADF, EINVAL, …) still surfaces.
pub fn map_delete_elem(map_fd: i32, key: u32) -> io::Result<()> {
    let mut attr = BpfAttrMapElem::default();
    attr.map_fd = map_fd as u32;
    attr.key = &key as *const u32 as u64;
    match unsafe { bpf_syscall(BPF_MAP_DELETE_ELEM, &attr, std::mem::size_of_val(&attr)) } {
        Ok(_) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Read `map[key]` into `value` (4 bytes for a PROG_ARRAY — the
/// stored program fd). `Ok(Some(v))` on hit, `Ok(None)` on miss
/// (ENOENT), `Err` for anything else.
pub fn map_lookup_elem_u32(map_fd: i32, key: u32) -> io::Result<Option<u32>> {
    let mut value: u32 = 0;
    let mut attr = BpfAttrMapElem::default();
    attr.map_fd = map_fd as u32;
    attr.key = &key as *const u32 as u64;
    attr.value_or_next_key = &mut value as *mut u32 as u64;
    match unsafe { bpf_syscall(BPF_MAP_LOOKUP_ELEM, &attr, std::mem::size_of_val(&attr)) } {
        Ok(_) => Ok(Some(value)),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}
