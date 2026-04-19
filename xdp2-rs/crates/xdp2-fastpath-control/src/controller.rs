// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
//
// TemplateController — slot management API for the fast-path
// PROG_ARRAY (`jmp_table`) that xdp2-flow-loader creates.
//
// This is §5a milestone S6 in
// `samples/flow_dissector/docs/super-flow-dissector-implementation.md`.
//
// The controller is deliberately decoupled from the loader: Track D's
// `xdp2-flow-loader` and Track E's future `xdp2-flow-afxdp` both
// populate a PROG_ARRAY jmp table; both can consume this controller
// by passing in the fd they own. Borrowing, not owning, the fd keeps
// lifecycle clear — the owner (loader) closes it on Drop.
//
// Slot layout contract (§5a of the plan):
//   0..=6  static specialised extractors (eth/ipv4/tcp, ...) — do not touch
//   7      CHAIN_DYNAMIC: slow-path dissector (installed by loader)
//   8..    §5a dynamic per-port templates — this is what the controller manages
//
// The controller refuses to install into slots < `FIRST_DYNAMIC_SLOT`
// to prevent an §5a control-plane bug from clobbering the static
// fast-path programs or the slow-path hook.

use std::collections::BTreeMap;
use std::io;

use crate::bpf;

/// Mirror of `CHAIN_DYNAMIC` in `fast_flow.bpf.c` and in
/// `xdp2_flow_loader::CHAIN_DYNAMIC`. Anything < this is reserved for
/// the static fast path. §5a templates live at `FIRST_DYNAMIC_SLOT`
/// and above.
pub const CHAIN_DYNAMIC: u32 = 7;

/// First slot the controller is willing to write to. The slow-path
/// dissector lives at `CHAIN_DYNAMIC`; §5a templates start after it.
pub const FIRST_DYNAMIC_SLOT: u32 = CHAIN_DYNAMIC + 1;

#[derive(Debug)]
pub enum ControllerError {
    /// Caller asked the controller to touch a slot reserved for the
    /// static fast path or the slow-path dissector.
    ReservedSlot { slot: u32 },
    /// `bpf_map_update_elem` failed.
    Update { slot: u32, source: io::Error },
    /// `bpf_map_delete_elem` failed with something other than ENOENT.
    Delete { slot: u32, source: io::Error },
    /// `bpf_map_lookup_elem` failed with something other than ENOENT.
    Lookup { slot: u32, source: io::Error },
}

impl std::fmt::Display for ControllerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControllerError::ReservedSlot { slot } => write!(
                f,
                "slot {slot} is reserved (static fast path or CHAIN_DYNAMIC); \
                 only slots >= {FIRST_DYNAMIC_SLOT} are writable by the controller"
            ),
            ControllerError::Update { slot, source } => {
                write!(f, "bpf_map_update_elem slot {slot}: {source}")
            }
            ControllerError::Delete { slot, source } => {
                write!(f, "bpf_map_delete_elem slot {slot}: {source}")
            }
            ControllerError::Lookup { slot, source } => {
                write!(f, "bpf_map_lookup_elem slot {slot}: {source}")
            }
        }
    }
}

impl std::error::Error for ControllerError {}

/// Thin, non-owning wrapper around a PROG_ARRAY jmp_table fd.
///
/// Clone is a raw copy of the fd — *not* a dup(2). Callers must not
/// outlive the fd owner (typically `xdp2_flow_loader::Loader`).
#[derive(Debug, Clone, Copy)]
pub struct TemplateController {
    jmp_table_fd: i32,
}

impl TemplateController {
    /// Build a controller over an already-open PROG_ARRAY fd. The
    /// caller retains ownership of the fd.
    pub fn new(jmp_table_fd: i32) -> Self {
        Self { jmp_table_fd }
    }

    /// Install `prog_fd` at `slot`. Fails if `slot < FIRST_DYNAMIC_SLOT`.
    pub fn install(&self, slot: u32, prog_fd: i32) -> Result<(), ControllerError> {
        if slot < FIRST_DYNAMIC_SLOT {
            return Err(ControllerError::ReservedSlot { slot });
        }
        // PROG_ARRAY stores 4-byte program fds. `prog_fd` is i32 but
        // the kernel treats the 4 bytes as the fd directly.
        bpf::map_update_elem(self.jmp_table_fd, slot, prog_fd as u32, bpf::BPF_ANY)
            .map_err(|source| ControllerError::Update { slot, source })
    }

    /// Remove `slot`. Idempotent — an already-empty slot returns
    /// `Ok(())`. Fails on `slot < FIRST_DYNAMIC_SLOT` so a control
    /// plane bug can't inadvertently detach the slow-path dissector
    /// or a static extractor.
    pub fn remove(&self, slot: u32) -> Result<(), ControllerError> {
        if slot < FIRST_DYNAMIC_SLOT {
            return Err(ControllerError::ReservedSlot { slot });
        }
        bpf::map_delete_elem(self.jmp_table_fd, slot)
            .map_err(|source| ControllerError::Delete { slot, source })
    }

    /// Return the fd currently installed at `slot`, if any.
    /// `Ok(None)` for an empty slot; `Err` for anything else.
    /// Does *not* enforce the FIRST_DYNAMIC_SLOT boundary — read-only
    /// lookups on static slots are fine and useful for debugging.
    pub fn lookup(&self, slot: u32) -> Result<Option<i32>, ControllerError> {
        bpf::map_lookup_elem_u32(self.jmp_table_fd, slot)
            .map(|o| o.map(|v| v as i32))
            .map_err(|source| ControllerError::Lookup { slot, source })
    }

    /// Reconcile the dynamic-slot range `[FIRST_DYNAMIC_SLOT, max_slot)`
    /// with a desired map: install/update every (slot, prog_fd) in
    /// `desired`, and delete any dynamic slot not in `desired`.
    ///
    /// `max_slot` is the exclusive upper bound (typically the
    /// jmp_table's `max_entries`). Only slots in
    /// `FIRST_DYNAMIC_SLOT..max_slot` are touched; static slots are
    /// never read or written by reconcile.
    ///
    /// This is the "one-shot sync" entry point control planes use
    /// after enumerate_all(); incremental updates can call
    /// install/remove directly.
    pub fn reconcile(
        &self,
        desired: &BTreeMap<u32, i32>,
        max_slot: u32,
    ) -> Result<(), ControllerError> {
        // Install or update everything the caller wants.
        for (&slot, &prog_fd) in desired.iter() {
            if slot < FIRST_DYNAMIC_SLOT || slot >= max_slot {
                return Err(ControllerError::ReservedSlot { slot });
            }
            self.install(slot, prog_fd)?;
        }
        // Remove anything populated in the dynamic range that isn't
        // in `desired`. `remove` is idempotent so we can blanket-walk
        // without first probing with lookup — but probing first saves
        // syscalls on sparse maps. Pick probing; at 16 dynamic slots
        // the syscall count is the same either way, but with 1024+
        // slots it's a meaningful difference.
        for slot in FIRST_DYNAMIC_SLOT..max_slot {
            if desired.contains_key(&slot) {
                continue;
            }
            if self.lookup(slot)?.is_some() {
                self.remove(slot)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_slots_rejected_by_install() {
        // Use fd = -1 so we'd hit EBADF if the slot check didn't fire
        // first. The error from the slot-check path is what we want
        // to see.
        let c = TemplateController::new(-1);
        for slot in 0..FIRST_DYNAMIC_SLOT {
            let err = c.install(slot, 0).unwrap_err();
            match err {
                ControllerError::ReservedSlot { slot: s } => assert_eq!(s, slot),
                other => panic!("expected ReservedSlot, got {other:?}"),
            }
        }
    }

    #[test]
    fn reserved_slots_rejected_by_remove() {
        let c = TemplateController::new(-1);
        for slot in 0..FIRST_DYNAMIC_SLOT {
            let err = c.remove(slot).unwrap_err();
            matches!(err, ControllerError::ReservedSlot { .. });
        }
    }

    #[test]
    fn first_dynamic_slot_matches_chain_dynamic_plus_one() {
        // Guardrail: if someone bumps CHAIN_DYNAMIC without updating
        // FIRST_DYNAMIC_SLOT (or vice versa), the dynamic range would
        // overlap the slow-path slot. Catch that at compile + test
        // time.
        assert_eq!(FIRST_DYNAMIC_SLOT, CHAIN_DYNAMIC + 1);
        assert_eq!(CHAIN_DYNAMIC, 7);
    }

    #[test]
    fn chain_dynamic_matches_loader_constant() {
        // xdp2_flow_loader::CHAIN_DYNAMIC is 7 by its own assertion
        // test; we can't depend on that crate from here without a
        // cycle (loader may eventually depend on us). A manual equals
        // is the lightest-weight drift guard.
        assert_eq!(CHAIN_DYNAMIC, 7);
    }

    #[test]
    fn reconcile_rejects_out_of_range_desired() {
        let c = TemplateController::new(-1);
        let mut desired = BTreeMap::new();
        desired.insert(CHAIN_DYNAMIC, 42); // reserved
        let err = c.reconcile(&desired, 16).unwrap_err();
        matches!(err, ControllerError::ReservedSlot { .. });
    }
}
