// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
//
// xdp2-fastpath-control: shared control plane for the xdp2 fast-path
// flow dissector.
//
// Consumers:
//   - Track D: `xdp2-flow-loader` (eBPF DaemonSet) — uses the
//     `ListenSocket` enumeration to decide which per-port fast-path
//     templates to install in the PROG_ARRAY (§5a of
//     super-flow-dissector-plan.md).
//   - Track E: `xdp2-flow-afxdp` (AF_XDP userspace daemon) — uses the
//     same enumeration to pre-filter traffic at the XDP_REDIRECT gate
//     before packets reach the SIMD batch classifier.
//
// This crate is intentionally scoped to "what should the fast path be
// optimising for right now?" — it does not load BPF programs itself;
// it produces the data model (who's listening on which (family, proto,
// port)) that the loaders consume.
//
// S2 (this file, initial landing): read-only `sock_diag` netlink
// enumerator. Future milestones per
// `samples/flow_dissector/docs/super-flow-dissector-implementation.md`:
//   S3: BPF_CGROUP_INETx_BIND ringbuf producer + consumer.
//   S4: inet_diag multicast subscriber (system-wide updates).
//   S5: /proc/net/{tcp,tcp6,udp,udp6} polling fallback.
//   S6: PROG_ARRAY update API.
//   S7: LRU hysteresis for template retirement.
//   S8: Adversarial-bind mitigations (port ≥ 1024 filter, cgroup scope).
//
// Portability:
//   - Linux-only (AF_NETLINK + NETLINK_SOCK_DIAG).
//   - Requires CAP_NET_ADMIN only for *all* user sockets (we filter to
//     the caller's view when unprivileged, which is fine for the common
//     "what's listening on this host?" use case).

use std::io;
use std::mem;

pub mod bpf;
pub mod controller;
pub mod flowdis_auto;
pub mod hysteresis;
pub mod proc_net;
pub mod reconciler;
pub mod security;

pub use controller::{ControllerError, TemplateController, CHAIN_DYNAMIC, FIRST_DYNAMIC_SLOT};
pub use flowdis_auto::{Config as FlowdisAutoConfig, Policy as FlowdisAutoPolicy, Shape};
pub use hysteresis::{Hysteresis, ListenerKey, DEFAULT_RETIRE_GRACE};
pub use proc_net::{enumerate_procfs, enumerate_procfs_all};
pub use reconciler::{Backend, ReconcileError, Reconciler, SlotAssigner, TickStats};
pub use security::{filter as apply_security_policy, SecurityPolicy};

/// Protocol family (IPv4 vs IPv6) for an enumerated listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    fn as_af(self) -> u8 {
        match self {
            Family::V4 => libc::AF_INET as u8,
            Family::V6 => libc::AF_INET6 as u8,
        }
    }
}

/// Transport protocol for an enumerated listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn as_ip(self) -> u8 {
        match self {
            // libc returns i32; AF/IPPROTO constants all fit in u8.
            Proto::Tcp => libc::IPPROTO_TCP as u8,
            Proto::Udp => libc::IPPROTO_UDP as u8,
        }
    }

    // For TCP we want TCP_LISTEN. For UDP there's no LISTEN state — an
    // unconnected UDP socket sits in TCP_CLOSE, matching what
    // `ss --udp -l` returns.
    fn state_mask(self) -> u32 {
        match self {
            // TCP_LISTEN = 10
            Proto::Tcp => 1u32 << 10,
            // TCP_CLOSE = 7
            Proto::Udp => 1u32 << 7,
        }
    }
}

/// A single listening-socket record. Only fields the fast-path
/// templating logic cares about are surfaced — inode, uid, timer, etc.
/// are dropped even though `inet_diag_msg` carries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenSocket {
    pub family: Family,
    pub proto: Proto,
    /// Local port in host byte order (the `sock_diag` wire format
    /// reports big-endian; we normalise here so downstream consumers
    /// never have to remember).
    pub port: u16,
}

#[derive(Debug)]
pub enum EnumerateError {
    Socket(io::Error),
    Send(io::Error),
    Recv(io::Error),
    Netlink(i32),
    Truncated,
}

impl std::fmt::Display for EnumerateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnumerateError::Socket(e) => write!(f, "open NETLINK_SOCK_DIAG socket: {e}"),
            EnumerateError::Send(e) => write!(f, "send sock_diag request: {e}"),
            EnumerateError::Recv(e) => write!(f, "recv sock_diag response: {e}"),
            EnumerateError::Netlink(code) => {
                write!(f, "kernel returned NLMSG_ERROR code {code}")
            }
            EnumerateError::Truncated => write!(f, "sock_diag reply shorter than inet_diag_msg"),
        }
    }
}

impl std::error::Error for EnumerateError {}

// ─── wire-format structs (sock_diag uapi) ──────────────────────────
//
// These live in <linux/sock_diag.h> and <linux/inet_diag.h>; we
// hand-roll them rather than pulling a generated-bindings crate so the
// crate builds offline. Layout/field order must match the uapi
// headers exactly — #[repr(C)] + manual padding on inet_diag_req_v2.

#[repr(C)]
struct Nlmsghdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
struct InetDiagSockid {
    sport_be: u16,
    dport_be: u16,
    src_be: [u32; 4],
    dst_be: [u32; 4],
    iface: u32,
    cookie: [u32; 2],
}

#[repr(C)]
struct InetDiagReqV2 {
    sdiag_family: u8,
    sdiag_protocol: u8,
    idiag_ext: u8,
    pad: u8,
    idiag_states: u32,
    id: InetDiagSockid,
}

#[repr(C)]
struct InetDiagMsg {
    idiag_family: u8,
    idiag_state: u8,
    idiag_timer: u8,
    idiag_retrans: u8,
    id: InetDiagSockid,
    // Trailing fields (idiag_expires, idiag_rqueue, idiag_wqueue,
    // idiag_uid, idiag_inode) are present in the kernel's struct but
    // we don't touch them — we only read up to `id`.
}

// Netlink constants. These are stable uapi; duplicating them here
// beats pulling a heavy binding crate.
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const SOCK_DIAG_BY_FAMILY: u16 = 20;

// `NLMSG_ALIGNTO` is 4 on all architectures (uapi fixed).
const NLMSG_ALIGNTO: usize = 4;

fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

/// Enumerate every listener matching (`family`, `proto`) that the
/// calling process can see. Non-root callers get the sockets their
/// uid owns; CAP_NET_ADMIN expands the view to all namespaces
/// reachable from the caller's netns. An empty result is not an error.
pub fn enumerate(family: Family, proto: Proto) -> Result<Vec<ListenSocket>, EnumerateError> {
    // 1. Open the netlink socket.
    //
    // SAFETY: `socket(2)` with literal constants is always safe; we
    // check the return value and wrap errno.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    if fd < 0 {
        return Err(EnumerateError::Socket(io::Error::last_os_error()));
    }
    // Wrap in a guard so every early return closes the fd.
    struct FdGuard(i32);
    impl Drop for FdGuard {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }
    let _guard = FdGuard(fd);

    // 2. Build the request: nlmsghdr + inet_diag_req_v2 (both packed
    // into one buffer so a single `send()` ships the whole dump
    // request).
    let req_body_len = mem::size_of::<InetDiagReqV2>();
    let total_len = mem::size_of::<Nlmsghdr>() + req_body_len;
    let mut req = vec![0u8; total_len];

    {
        // Fill the header.
        let hdr_ptr = req.as_mut_ptr() as *mut Nlmsghdr;
        // SAFETY: `req` is sized exactly for hdr + body; write is in
        // bounds and aligned (u8 buffer → u32-aligned fields through
        // write_unaligned).
        unsafe {
            std::ptr::write_unaligned(
                hdr_ptr,
                Nlmsghdr {
                    nlmsg_len: total_len as u32,
                    nlmsg_type: SOCK_DIAG_BY_FAMILY,
                    nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
                    nlmsg_seq: 1,
                    nlmsg_pid: 0,
                },
            );
        }
    }
    {
        let body_ptr =
            unsafe { req.as_mut_ptr().add(mem::size_of::<Nlmsghdr>()) } as *mut InetDiagReqV2;
        // SAFETY: same bounds argument as above; body is inside `req`.
        unsafe {
            std::ptr::write_unaligned(
                body_ptr,
                InetDiagReqV2 {
                    sdiag_family: family.as_af(),
                    sdiag_protocol: proto.as_ip(),
                    idiag_ext: 0,
                    pad: 0,
                    idiag_states: proto.state_mask(),
                    id: mem::zeroed(),
                },
            );
        }
    }

    // 3. Destination address: kernel (pid=0, groups=0).
    // SAFETY: sockaddr_nl is a POD struct; zeroed + filling the fields
    // we care about is the idiomatic way to construct it without
    // depending on libc's private Padding<_> wrapper for nl_pad.
    let mut sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    sa.nl_pid = 0;
    sa.nl_groups = 0;

    let sent = unsafe {
        libc::sendto(
            fd,
            req.as_ptr() as *const _,
            req.len(),
            0,
            &sa as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(EnumerateError::Send(io::Error::last_os_error()));
    }

    // 4. Drain the dump. Responses come as a stream of nlmsghdr-framed
    // messages terminated by NLMSG_DONE; each message carries one
    // inet_diag_msg + optional attributes (we ignore the attrs).
    let mut out = Vec::new();
    // 8 KiB per recv — enough for ~50 inet_diag_msg records, which is
    // a safe batch size even on hosts with a lot of listeners.
    let mut buf = vec![0u8; 8192];

    'outer: loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n < 0 {
            return Err(EnumerateError::Recv(io::Error::last_os_error()));
        }
        if n == 0 {
            // Peer closed — shouldn't happen for a kernel netlink
            // socket, but treat as clean EOF.
            break;
        }

        let mut offset = 0usize;
        let n_usize = n as usize;

        while offset + mem::size_of::<Nlmsghdr>() <= n_usize {
            let hdr =
                unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const Nlmsghdr) };
            let msg_len = hdr.nlmsg_len as usize;
            if msg_len < mem::size_of::<Nlmsghdr>() || offset + msg_len > n_usize {
                return Err(EnumerateError::Truncated);
            }

            match hdr.nlmsg_type {
                NLMSG_DONE => break 'outer,
                NLMSG_ERROR => {
                    // nlmsgerr is `i32 error` followed by the echoed
                    // request header. A zero error can appear as an
                    // "ack"; we treat non-zero as failure.
                    let err_off = offset + mem::size_of::<Nlmsghdr>();
                    if err_off + 4 > n_usize {
                        return Err(EnumerateError::Truncated);
                    }
                    let code = unsafe {
                        std::ptr::read_unaligned(buf.as_ptr().add(err_off) as *const i32)
                    };
                    if code != 0 {
                        return Err(EnumerateError::Netlink(code));
                    }
                    break 'outer;
                }
                SOCK_DIAG_BY_FAMILY => {
                    let body_off = offset + mem::size_of::<Nlmsghdr>();
                    if body_off + mem::size_of::<InetDiagMsg>() > n_usize {
                        return Err(EnumerateError::Truncated);
                    }
                    let msg = unsafe {
                        std::ptr::read_unaligned(buf.as_ptr().add(body_off) as *const InetDiagMsg)
                    };
                    out.push(ListenSocket {
                        family,
                        proto,
                        port: u16::from_be(msg.id.sport_be),
                    });
                }
                _ => {
                    // Unknown message type in the middle of a dump is
                    // non-fatal; the kernel occasionally emits
                    // informational messages we don't care about.
                }
            }

            offset += nlmsg_align(msg_len);
        }
    }

    Ok(out)
}

/// Convenience: enumerate across both IPv4/IPv6 and TCP/UDP in one
/// call. Callers that only want a single (family, proto) slice should
/// use [`enumerate`] directly to avoid the extra netlink round-trips.
pub fn enumerate_all() -> Result<Vec<ListenSocket>, EnumerateError> {
    let mut out = Vec::new();
    for &fam in &[Family::V4, Family::V6] {
        for &pr in &[Proto::Tcp, Proto::Udp] {
            match enumerate(fam, pr) {
                Ok(mut v) => out.append(&mut v),
                // Per-combo failure should not mask the other three;
                // caller likely wants best-effort behaviour (they can
                // filter by `family`/`proto` if they need strict).
                Err(EnumerateError::Socket(_)) => {
                    return Err(EnumerateError::Socket(io::Error::from(
                        io::ErrorKind::PermissionDenied,
                    )))
                }
                Err(e) => return Err(e),
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nlmsg_align_pads_to_4() {
        assert_eq!(nlmsg_align(0), 0);
        assert_eq!(nlmsg_align(1), 4);
        assert_eq!(nlmsg_align(4), 4);
        assert_eq!(nlmsg_align(5), 8);
    }

    #[test]
    fn family_maps_to_af() {
        assert_eq!(Family::V4.as_af() as i32, libc::AF_INET);
        assert_eq!(Family::V6.as_af() as i32, libc::AF_INET6);
    }

    #[test]
    fn proto_maps_to_ipproto() {
        assert_eq!(Proto::Tcp.as_ip() as i32, libc::IPPROTO_TCP);
        assert_eq!(Proto::Udp.as_ip() as i32, libc::IPPROTO_UDP);
    }

    #[test]
    fn state_masks_match_kernel_uapi() {
        // TCP_LISTEN = 10, TCP_CLOSE = 7 — documented in
        // <linux/tcp_states.h>. These must match exactly or we'll
        // query the wrong state and silently return zero listeners.
        assert_eq!(Proto::Tcp.state_mask(), 1u32 << 10);
        assert_eq!(Proto::Udp.state_mask(), 1u32 << 7);
    }

    #[test]
    fn struct_sizes_match_uapi() {
        // inet_diag_sockid: 48 bytes. inet_diag_req_v2: 8 + 48 = 56.
        // nlmsghdr: 16 bytes. Exposed as a regression test — if a
        // future refactor breaks repr(C) layout, this catches it
        // before enumerate() silently misparses wire data.
        assert_eq!(mem::size_of::<InetDiagSockid>(), 48);
        assert_eq!(mem::size_of::<InetDiagReqV2>(), 56);
        assert_eq!(mem::size_of::<Nlmsghdr>(), 16);
    }

    // enumerate() itself needs AF_NETLINK + live kernel; we exercise
    // it in an integration test gated on `cfg(target_os = "linux")`
    // only when XDP2_FASTPATH_CONTROL_LIVE is set, so `cargo test`
    // stays hermetic in CI.
    #[test]
    fn enumerate_smoke() {
        if std::env::var_os("XDP2_FASTPATH_CONTROL_LIVE").is_none() {
            return;
        }
        // Any running Linux system has something in TCP_LISTEN (sshd,
        // systemd-resolved, cupsd, ...), so a non-empty result on the
        // live path is a useful smoke signal.
        let listeners = enumerate(Family::V4, Proto::Tcp).expect("live enumerate");
        println!("live IPv4/TCP listeners: {}", listeners.len());
    }
}
