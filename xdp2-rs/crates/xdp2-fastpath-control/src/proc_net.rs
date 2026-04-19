// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
//
// /proc/net/{tcp,tcp6,udp,udp6} polling fallback for listening-socket
// enumeration — §5a milestone S5 in
// `samples/flow_dissector/docs/super-flow-dissector-implementation.md`.
//
// When to use this instead of the `sock_diag` netlink path
// (`crate::enumerate`):
//   - The caller can't open an `AF_NETLINK` socket (locked-down
//     container, seccomp policy, user namespace without CAP_NET_ADMIN
//     on an old-kernel host where SOCK_DIAG needs it).
//   - Debugging / test harnesses that want to feed fixture data in —
//     `parse` takes a `&str`, so tests can assert parsing without a
//     live kernel.
//
// When NOT to use it:
//   - On a busy host /proc/net/tcp can be many MB and snapshotting it
//     takes tens of ms; the netlink path is O(listeners) not O(all
//     sockets). Prefer `enumerate()` on the hot path, fall back to
//     this only if netlink fails.
//
// Format (kernel's `sock.c::tcp4_seq_show` / `tcp6_seq_show` /
// `udp4_seq_show` / `udp6_seq_show`):
//
//   /proc/net/tcp:
//      sl  local_address rem_address   st tx_queue rx_queue ...
//      0: 0100007F:0277 00000000:0000 0A ...
//
//   /proc/net/tcp6:
//      sl  local_address                         remote_address    st ...
//      0: 00000000000000000000000001000000:0277 00000000...:0000 0A ...
//
// We only care about:
//   - the port (4 hex digits after the first `:`),
//   - the state (first two hex digits of the 5th whitespace-delimited
//     field — "0A" = TCP_LISTEN, "07" = TCP_CLOSE for unconnected UDP).
//
// Everything else in the row (remote address, queues, timer, uid,
// inode) is irrelevant to template selection.

use std::fs;
use std::io;

use crate::{Family, ListenSocket, Proto};

/// TCP_LISTEN = 10 = 0x0A — the only TCP state we want to surface.
const TCP_LISTEN_HEX: &str = "0A";
/// TCP_CLOSE = 7 = 0x07 — UDP uses this for unconnected/listen
/// sockets, matching `ss --udp -l`.
const TCP_CLOSE_HEX: &str = "07";

/// Read the procfs file for (`family`, `proto`) and return the
/// filtered list of listeners. Path selection:
///   V4 + Tcp → /proc/net/tcp
///   V4 + Udp → /proc/net/udp
///   V6 + Tcp → /proc/net/tcp6
///   V6 + Udp → /proc/net/udp6
///
/// An empty result is not an error. Read failures propagate as
/// `io::Error`; malformed lines are silently skipped so a stray
/// kernel-debug addition to the format doesn't break enumeration.
pub fn enumerate_procfs(family: Family, proto: Proto) -> io::Result<Vec<ListenSocket>> {
    let path = procfs_path(family, proto);
    let contents = fs::read_to_string(path)?;
    Ok(parse(&contents, family, proto))
}

/// Convenience mirror of [`crate::enumerate_all`] but using the
/// procfs backend. Propagates the first read error encountered.
pub fn enumerate_procfs_all() -> io::Result<Vec<ListenSocket>> {
    let mut out = Vec::new();
    for &fam in &[Family::V4, Family::V6] {
        for &pr in &[Proto::Tcp, Proto::Udp] {
            let mut v = enumerate_procfs(fam, pr)?;
            out.append(&mut v);
        }
    }
    Ok(out)
}

fn procfs_path(family: Family, proto: Proto) -> &'static str {
    match (family, proto) {
        (Family::V4, Proto::Tcp) => "/proc/net/tcp",
        (Family::V4, Proto::Udp) => "/proc/net/udp",
        (Family::V6, Proto::Tcp) => "/proc/net/tcp6",
        (Family::V6, Proto::Udp) => "/proc/net/udp6",
    }
}

/// Parse procfs contents, returning only rows whose state matches the
/// listen filter for `proto`. Separated from file I/O so fixtures can
/// drive the parser directly in tests.
pub fn parse(contents: &str, family: Family, proto: Proto) -> Vec<ListenSocket> {
    let want_state = match proto {
        Proto::Tcp => TCP_LISTEN_HEX,
        Proto::Udp => TCP_CLOSE_HEX,
    };

    let mut out = Vec::new();
    // First line is the header — skip by predicate (starts with "sl")
    // rather than a fixed skip(1), so a kernel that ever drops the
    // header or adds a banner line still parses correctly.
    for line in contents.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("sl") || trimmed.is_empty() {
            continue;
        }
        if let Some(port) = parse_row(trimmed, want_state) {
            out.push(ListenSocket {
                family,
                proto,
                port,
            });
        }
    }
    out
}

/// Parse one data row. Returns `Some(port)` if the state matches
/// `want_state`, `None` otherwise (wrong state or malformed).
///
/// Row shape (whitespace-separated):
///   <sl>: <local_addr>:<port_hex> <rem_addr>:<port_hex> <st> <...rest>
///
/// We parse by field index so format drift (extra trailing columns,
/// which happens) doesn't break us.
fn parse_row(row: &str, want_state: &str) -> Option<u16> {
    let mut fields = row.split_whitespace();
    // Field 0: "NNN:" — the sl index. Discard.
    fields.next()?;
    // Field 1: local_address (IP:PORT in hex). Split on ':'.
    let local = fields.next()?;
    let port_hex = local.rsplit(':').next()?;
    if port_hex.len() != 4 {
        // Ports are always 4 hex digits (u16). Anything else means
        // the row doesn't match the format we expect.
        return None;
    }
    // Field 2: rem_address. Discard.
    fields.next()?;
    // Field 3: state. Should be exactly two hex digits.
    let state = fields.next()?;
    if state != want_state {
        return None;
    }
    // Port is in hex, big-endian-agnostic (procfs prints it as host-
    // byte-order u16 already).
    u16::from_str_radix(port_hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP4_FIXTURE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 40878 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000   196        0 40560 2 0000000000000000 100 0 0 10 0
   2: 0100007F:8C20 0100007F:0277 01 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000 100 0 0 10 0
";

    const UDP4_FIXTURE: &str = "\
   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
22473: 00000000:96D7 00000000:0000 07 00000000:00000000 00:00000000 00000000   995        0 9200 2 0000000000000000 0
49461: 00000000:0043 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12881 2 0000000000000000 0
49462: DB3210AC:0044 013210AC:0043 01 00000000:00000000 00:00000000 00000000     0        0 5974 2 0000000000000000 0
";

    const TCP6_FIXTURE: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:4A38 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   991        0 32739867 2 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 13911 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn parses_tcp4_listen_only() {
        // Expected: the two 0A rows produce listeners at 0x0277=631
        // and 0x0BB8=3000. The ESTABLISHED row (state 01) is dropped.
        let listeners = parse(TCP4_FIXTURE, Family::V4, Proto::Tcp);
        assert_eq!(listeners.len(), 2);
        let ports: Vec<u16> = listeners.iter().map(|l| l.port).collect();
        assert!(ports.contains(&0x0277));
        assert!(ports.contains(&0x0BB8));
        assert!(!ports.contains(&0x8C20));
        // All produced entries carry the requested family/proto.
        assert!(listeners.iter().all(|l| l.family == Family::V4));
        assert!(listeners.iter().all(|l| l.proto == Proto::Tcp));
    }

    #[test]
    fn parses_udp4_close_state_as_listen() {
        // UDP listeners sit in TCP_CLOSE (0x07). The 0x01 (connected)
        // row must be dropped.
        let listeners = parse(UDP4_FIXTURE, Family::V4, Proto::Udp);
        assert_eq!(listeners.len(), 2);
        let ports: Vec<u16> = listeners.iter().map(|l| l.port).collect();
        assert!(ports.contains(&0x96D7));
        assert!(ports.contains(&0x0043));
        assert!(!ports.contains(&0x0044));
    }

    #[test]
    fn parses_tcp6_wide_address() {
        // IPv6 row has a 32-hex-digit local address, not 8. The parser
        // must still extract the 4-hex-digit port via rsplit(':').
        let listeners = parse(TCP6_FIXTURE, Family::V6, Proto::Tcp);
        assert_eq!(listeners.len(), 2);
        let ports: Vec<u16> = listeners.iter().map(|l| l.port).collect();
        assert!(ports.contains(&0x4A38));
        assert!(ports.contains(&0x0016)); // SSH
        assert!(listeners.iter().all(|l| l.family == Family::V6));
    }

    #[test]
    fn udp_filter_rejects_tcp_listen_state() {
        // If someone asks for UDP but the file somehow has a 0A row
        // (shouldn't happen for a real /proc/net/udp, but parser must
        // be paranoid), we drop it rather than misclassify.
        let listeners = parse(TCP4_FIXTURE, Family::V4, Proto::Udp);
        assert!(listeners.is_empty());
    }

    #[test]
    fn header_and_blank_lines_ignored() {
        // Empty lines, and a header where "sl" is the first non-
        // whitespace token, must be skipped without error.
        let input = "\n  \n  sl  local_address ... header\n\n";
        let listeners = parse(input, Family::V4, Proto::Tcp);
        assert!(listeners.is_empty());
    }

    #[test]
    fn malformed_rows_are_dropped_not_errored() {
        // A garbage row in the middle shouldn't kill the whole parse —
        // we keep the good rows and skip the bad one.
        let input = "\
  sl  local_address rem_address   st
   0: 0100007F:0277 00000000:0000 0A ...
garbage row with no colons
   1: 0100007F:0BB8 00000000:0000 0A ...
";
        let listeners = parse(input, Family::V4, Proto::Tcp);
        assert_eq!(listeners.len(), 2);
    }

    #[test]
    fn path_map_matches_kernel_conventions() {
        // Pin path selection so a later refactor can't silently swap
        // tcp6 for tcp or vice versa.
        assert_eq!(procfs_path(Family::V4, Proto::Tcp), "/proc/net/tcp");
        assert_eq!(procfs_path(Family::V4, Proto::Udp), "/proc/net/udp");
        assert_eq!(procfs_path(Family::V6, Proto::Tcp), "/proc/net/tcp6");
        assert_eq!(procfs_path(Family::V6, Proto::Udp), "/proc/net/udp6");
    }

    #[test]
    fn live_smoke() {
        // Gated on the same env var the netlink path uses, so CI stays
        // hermetic. Any running Linux dev host should have at least
        // one TCP listener.
        if std::env::var_os("XDP2_FASTPATH_CONTROL_LIVE").is_none() {
            return;
        }
        let listeners = enumerate_procfs(Family::V4, Proto::Tcp)
            .expect("procfs enumerate should succeed on Linux");
        println!("live /proc/net/tcp listeners: {}", listeners.len());
    }
}
