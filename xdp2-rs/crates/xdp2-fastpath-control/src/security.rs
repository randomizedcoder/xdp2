// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
//
// Adversarial-bind mitigations — §5a milestone S8 in
// `samples/flow_dissector/docs/super-flow-dissector-implementation.md`.
//
// Threat model: an unprivileged local user binds a listen socket on a
// high port (say, 8443) specifically to displace a legitimate
// service's fast-path template, or to get their own (family, proto,
// port) tuple into the PROG_ARRAY. They can't modify the BPF program
// attached at that slot — `TemplateController` only installs
// pre-loaded fds — but they *can* cause a legitimate template to be
// evicted by the hysteresis layer, because the reconciler's desired
// map only has room for N entries.
//
// This module doesn't prevent the bind (the kernel already restricts
// ports < 1024 to CAP_NET_BIND_SERVICE). It filters the output of
// `enumerate` / `enumerate_procfs` before the hysteresis layer sees
// it, so attacker-bound sockets never enter the PROG_ARRAY population
// pipeline.
//
// Policies available:
//   - `Permissive`: identity filter. Default for test harnesses and
//     for operators who know their threat model doesn't include
//     local-unprivileged-user adversaries.
//   - `PrivilegedPortsOnly`: only ports < 1024 survive. Strongest
//     default for privilege-segregated hosts (one user per service,
//     well-known ports). Rejects nginx on 8080, ES on 9200, etc. —
//     operator must opt out or use an allow-list.
//   - `PortAllowList`: explicit set of permitted ports. Preferred
//     policy for production — operator names exactly which services
//     get fast-path acceleration, no matter who binds to what.
//
// Cgroup-scoped enumeration (the third bullet of §5a S8) is not in
// this module. It's a sock_diag request shape — setting the netns
// fd the enumerate() call reads from, or running the loader in a
// cgroup — not a post-hoc filter. Documented in the loader's
// LoaderConfig::netns path and enforceable by the systemd unit that
// runs the loader.

use std::collections::BTreeSet;

use crate::ListenSocket;

/// Policy governing which listening sockets are eligible to become
/// fast-path templates. The `Default` impl is `Permissive` to avoid
/// behaviour changes for callers who don't explicitly pick a policy,
/// but production deployments should pick `PortAllowList` or
/// `PrivilegedPortsOnly`.
#[derive(Debug, Clone, Default)]
pub enum SecurityPolicy {
    /// Identity filter — every listener survives. Use for tests and
    /// single-user hosts.
    #[default]
    Permissive,

    /// Only listeners with `port < 1024` (the privileged-port range
    /// an unprivileged user cannot bind without CAP_NET_BIND_SERVICE)
    /// survive. Strongest default safety; most restrictive.
    PrivilegedPortsOnly,

    /// Only listeners whose port is in the allow-list survive. The
    /// production-recommended choice: operator names exactly the
    /// services they want accelerated.
    PortAllowList(BTreeSet<u16>),
}

impl SecurityPolicy {
    /// Build a `PortAllowList` from an iterator of ports. Convenience
    /// for `SecurityPolicy::PortAllowList([80, 443, 22].into_iter().collect())`.
    pub fn allow_ports<I>(ports: I) -> Self
    where
        I: IntoIterator<Item = u16>,
    {
        SecurityPolicy::PortAllowList(ports.into_iter().collect())
    }

    /// Predicate form: does `listener` satisfy this policy? Used by
    /// `filter` below; exposed publicly so callers can compose it
    /// with other predicates (e.g. "allow-list AND < 1024").
    pub fn admits(&self, listener: &ListenSocket) -> bool {
        match self {
            SecurityPolicy::Permissive => true,
            SecurityPolicy::PrivilegedPortsOnly => listener.port < 1024,
            SecurityPolicy::PortAllowList(allowed) => allowed.contains(&listener.port),
        }
    }
}

/// Apply `policy` to `observed`, returning a new Vec containing only
/// the admitted listeners. Ordering is preserved.
///
/// Typical call-site in the reconciler:
/// ```ignore
/// let observed = enumerate_procfs_all()?;
/// let safe = filter(&policy, observed);
/// let (active, evicted) = hysteresis.tick(&safe, Instant::now());
/// ```
pub fn filter(policy: &SecurityPolicy, observed: Vec<ListenSocket>) -> Vec<ListenSocket> {
    observed.into_iter().filter(|l| policy.admits(l)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Family, Proto};

    fn sock(port: u16) -> ListenSocket {
        ListenSocket {
            family: Family::V4,
            proto: Proto::Tcp,
            port,
        }
    }

    #[test]
    fn permissive_admits_everything() {
        let policy = SecurityPolicy::Permissive;
        let observed = vec![sock(22), sock(443), sock(8443), sock(65535)];
        let out = filter(&policy, observed.clone());
        assert_eq!(out.len(), 4);
        // Ordering preserved.
        assert_eq!(
            out.iter().map(|l| l.port).collect::<Vec<_>>(),
            vec![22, 443, 8443, 65535]
        );
    }

    #[test]
    fn default_is_permissive() {
        // If the caller doesn't pick a policy, they keep their prior
        // behaviour. Surfacing policy changes as explicit code edits
        // rather than accidental Default::default() shifts.
        let policy = SecurityPolicy::default();
        assert!(policy.admits(&sock(8080)));
    }

    #[test]
    fn privileged_ports_admits_below_1024() {
        let policy = SecurityPolicy::PrivilegedPortsOnly;
        assert!(policy.admits(&sock(22)));
        assert!(policy.admits(&sock(80)));
        assert!(policy.admits(&sock(443)));
        assert!(policy.admits(&sock(1023)));
    }

    #[test]
    fn privileged_ports_rejects_1024_and_above() {
        let policy = SecurityPolicy::PrivilegedPortsOnly;
        // 1024 is the first un-privileged port — unprivileged users
        // can bind here without CAP_NET_BIND_SERVICE.
        assert!(!policy.admits(&sock(1024)));
        assert!(!policy.admits(&sock(8080)));
        assert!(!policy.admits(&sock(8443)));
        assert!(!policy.admits(&sock(65535)));
    }

    #[test]
    fn allow_list_admits_only_listed_ports() {
        let policy = SecurityPolicy::allow_ports([80, 443, 8080]);
        assert!(policy.admits(&sock(80)));
        assert!(policy.admits(&sock(443)));
        assert!(policy.admits(&sock(8080)));
        assert!(!policy.admits(&sock(22)));
        assert!(!policy.admits(&sock(8443)));
        assert!(!policy.admits(&sock(0)));
    }

    #[test]
    fn allow_list_empty_admits_nothing() {
        // A production caller that builds the allow-list from a
        // config file and mis-configures it (empty list) gets "no
        // fast path" not "fast path for everything" — fail closed.
        let policy = SecurityPolicy::PortAllowList(BTreeSet::new());
        assert!(!policy.admits(&sock(80)));
        assert!(!policy.admits(&sock(443)));
    }

    #[test]
    fn filter_preserves_proto_and_family() {
        // Policies act on port only; family and proto pass through so
        // downstream templates see the full tuple.
        let policy = SecurityPolicy::allow_ports([443]);
        let tcp_v4 = ListenSocket {
            family: Family::V4,
            proto: Proto::Tcp,
            port: 443,
        };
        let tcp_v6 = ListenSocket {
            family: Family::V6,
            proto: Proto::Tcp,
            port: 443,
        };
        let udp_v4 = ListenSocket {
            family: Family::V4,
            proto: Proto::Udp,
            port: 443,
        };
        let udp_v6 = ListenSocket {
            family: Family::V6,
            proto: Proto::Udp,
            port: 443,
        };
        let out = filter(&policy, vec![tcp_v4, tcp_v6, udp_v4, udp_v6]);
        // All four :443 variants survive and keep their original
        // family/proto — the fast path wants all four for the QUIC +
        // HTTPS dual-stack case.
        assert_eq!(out.len(), 4);
    }

    #[test]
    fn adversarial_scenario_allow_list_defeats_unprivileged_squat() {
        // Scenario: legitimate nginx on :443 + attacker on :8443. The
        // hysteresis layer has room for 4 templates. With no policy,
        // both get tracked. With an allow-list naming only the real
        // services, the attacker's listener is dropped before the
        // hysteresis layer sees it.
        let legit_443 = sock(443);
        let legit_80 = sock(80);
        let attacker_8443 = sock(8443);
        let observed = vec![legit_443, legit_80, attacker_8443];
        let policy = SecurityPolicy::allow_ports([80, 443]);
        let safe = filter(&policy, observed);
        assert_eq!(safe.len(), 2);
        assert!(safe.iter().all(|l| l.port == 80 || l.port == 443));
    }
}
