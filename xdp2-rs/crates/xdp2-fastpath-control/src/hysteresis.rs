// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
//
// LRU hysteresis for template retirement — §5a milestone S7 in
// `samples/flow_dissector/docs/super-flow-dissector-implementation.md`.
//
// Problem: if we drive template install/remove straight off the output
// of `enumerate_procfs` or `enumerate`, then any transient disappearance
// of a listener (process restart, socket migration across SO_REUSEPORT
// workers, a sampling race) would immediately retire its fast-path
// template. On the next tick the template would be reinstalled. That's
// churn; each reinstall is a bpf(2) syscall and a PROG_ARRAY slot slot
// re-population that races the data path.
//
// Fix: a policy that remembers every listener it's seen for a grace
// period after it was last observed. A tick() callback takes the
// current observation and wall time, and returns the set of listeners
// that should currently have templates. The caller wires that into
// `TemplateController` via a slot-assignment policy of their choice.
//
// This module is deliberately backend-agnostic — it doesn't care
// whether the caller sampled via netlink (S2), procfs (S5), or some
// future multicast subscriber (S4): whatever yields a
// `Vec<ListenSocket>` feeds in.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::ListenSocket;

/// Default grace window: one minute of absence before retiring a
/// template. Chosen to be comfortably larger than typical service-
/// restart downtime (10–30s for systemd-managed daemons) but short
/// enough that a genuinely-departed service doesn't squat on a slot
/// for hours. Callers with stricter SLAs override this.
pub const DEFAULT_RETIRE_GRACE: Duration = Duration::from_secs(60);

/// Key used for the last-seen map. We key on (family, proto, port)
/// because that's what the fast path branches on — two listeners with
/// the same tuple but different uids / inodes are indistinguishable
/// from the dissector's perspective, so the hysteresis policy treats
/// them as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ListenerKey {
    pub family: crate::Family,
    pub proto: crate::Proto,
    pub port: u16,
}

impl From<&ListenSocket> for ListenerKey {
    fn from(l: &ListenSocket) -> Self {
        Self {
            family: l.family,
            proto: l.proto,
            port: l.port,
        }
    }
}

/// In-memory LRU with grace-window expiry.
///
/// Not thread-safe by design — callers that share it across threads
/// wrap it in their own `Mutex` / `RwLock`. The common case is a
/// single reconciler thread ticking every poll interval, which does
/// not warrant internal locking.
#[derive(Debug, Default)]
pub struct Hysteresis {
    retire_grace: Duration,
    // Separately tracked because the policy can emit a "this listener
    // is still alive" decision even on a tick where the underlying
    // sampler didn't include it (within grace window).
    last_seen: HashMap<ListenerKey, Instant>,
}

impl Hysteresis {
    /// Build a policy with the default one-minute grace window.
    pub fn new() -> Self {
        Self::with_grace(DEFAULT_RETIRE_GRACE)
    }

    /// Build a policy with a caller-chosen grace window. Zero-duration
    /// is valid (degenerates to no-hysteresis, which is useful for
    /// tests and for the "aggressive churn" edge of the SLA spectrum).
    pub fn with_grace(retire_grace: Duration) -> Self {
        Self {
            retire_grace,
            last_seen: HashMap::new(),
        }
    }

    /// Grace window this policy was configured with.
    pub fn grace(&self) -> Duration {
        self.retire_grace
    }

    /// Number of listeners currently tracked (either just observed or
    /// still inside their grace window).
    pub fn len(&self) -> usize {
        self.last_seen.len()
    }

    /// Feed an observation: every entry in `observed` has its
    /// `last_seen` updated to `now`. Already-tracked entries not in
    /// `observed` keep their prior timestamp (they may still be inside
    /// the grace window).
    ///
    /// Does not prune expired entries — that happens in
    /// [`active_at`] / [`prune`]. Separating "record" from "prune"
    /// lets the caller run them on different cadences (record every
    /// tick, prune less often).
    pub fn record(&mut self, observed: &[ListenSocket], now: Instant) {
        for l in observed {
            self.last_seen.insert(ListenerKey::from(l), now);
        }
    }

    /// Return the set of listeners currently considered alive at time
    /// `now` — everything seen within the last `retire_grace`.
    ///
    /// Does NOT mutate `self.last_seen`. Callers that want expired
    /// entries removed from the working set should call
    /// [`prune`] after they're done computing the active set.
    pub fn active_at(&self, now: Instant) -> Vec<ListenerKey> {
        let mut out: Vec<ListenerKey> = self
            .last_seen
            .iter()
            .filter(|(_, &ts)| now.duration_since(ts) <= self.retire_grace)
            .map(|(k, _)| *k)
            .collect();
        // Deterministic ordering so the caller's slot-assignment
        // policy can build a stable PROG_ARRAY mapping — two ticks
        // with identical observations produce identical assignments,
        // which matters for debugging and for avoiding spurious
        // install/remove churn.
        out.sort_by_key(|k| (k.family as u8, k.proto as u8, k.port));
        out
    }

    /// Drop every entry whose `last_seen` is older than
    /// `retire_grace` at time `now`, returning the evicted keys so
    /// the caller can issue matching `TemplateController::remove`
    /// calls.
    pub fn prune(&mut self, now: Instant) -> Vec<ListenerKey> {
        let grace = self.retire_grace;
        let mut evicted = Vec::new();
        self.last_seen.retain(|k, &mut ts| {
            if now.duration_since(ts) > grace {
                evicted.push(*k);
                false
            } else {
                true
            }
        });
        // Same deterministic ordering as active_at — callers that
        // iterate evictions shouldn't see jitter from HashMap's
        // randomisation.
        evicted.sort_by_key(|k| (k.family as u8, k.proto as u8, k.port));
        evicted
    }

    /// One-shot helper that does the common "record + prune + return
    /// active" sequence. Returns `(active, evicted)`. Most callers
    /// want this; the granular API is there for testing and for
    /// callers that want to drive the steps independently.
    pub fn tick(
        &mut self,
        observed: &[ListenSocket],
        now: Instant,
    ) -> (Vec<ListenerKey>, Vec<ListenerKey>) {
        self.record(observed, now);
        let evicted = self.prune(now);
        let active = self.active_at(now);
        (active, evicted)
    }
}

// Make the field layouts `u8`-castable for the sort key above.
// `Family` and `Proto` are defined in lib.rs as simple C-like enums;
// casting them to `u8` relies on their `#[derive(Clone, Copy)]`
// representation. The two cases both have ≤2 variants so the numeric
// value is implementation-defined but stable within a build.
// We lean on `as u8` only for ordering, not correctness.

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

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn default_grace_is_one_minute() {
        let h = Hysteresis::new();
        assert_eq!(h.grace(), Duration::from_secs(60));
    }

    #[test]
    fn record_then_active_returns_observed() {
        let now = t0();
        let mut h = Hysteresis::new();
        h.record(&[sock(443), sock(80)], now);
        let active = h.active_at(now);
        assert_eq!(active.len(), 2);
        let ports: Vec<u16> = active.iter().map(|k| k.port).collect();
        assert!(ports.contains(&443));
        assert!(ports.contains(&80));
    }

    #[test]
    fn active_is_deterministically_ordered() {
        // Sort key is (family, proto, port) so insertion order is
        // irrelevant. A caller that builds slot mappings off the
        // active vec gets the same slot-for-port assignment every
        // tick.
        let now = t0();
        let mut h = Hysteresis::new();
        h.record(&[sock(443), sock(22), sock(80)], now);
        let active = h.active_at(now);
        let ports: Vec<u16> = active.iter().map(|k| k.port).collect();
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn entry_inside_grace_window_survives_a_missed_sample() {
        // Observed at t0; not observed at t0+30s; grace is 60s, so
        // it should still be active at t0+30s.
        let now = t0();
        let mut h = Hysteresis::with_grace(Duration::from_secs(60));
        h.record(&[sock(443)], now);
        let later = now + Duration::from_secs(30);
        // No observation on this tick.
        h.record(&[], later);
        assert_eq!(h.active_at(later).len(), 1);
    }

    #[test]
    fn entry_outside_grace_window_is_pruned() {
        let now = t0();
        let mut h = Hysteresis::with_grace(Duration::from_secs(10));
        h.record(&[sock(443)], now);
        let later = now + Duration::from_secs(11); // > grace
        let evicted = h.prune(later);
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].port, 443);
        assert_eq!(h.len(), 0);
        assert_eq!(h.active_at(later).len(), 0);
    }

    #[test]
    fn zero_grace_retires_on_same_tick_it_disappears() {
        // Grace == 0 means "any sample where the listener isn't
        // present retires it". Useful for aggressive-churn SLAs and
        // for tests.
        let now = t0();
        let mut h = Hysteresis::with_grace(Duration::from_secs(0));
        h.record(&[sock(443)], now);
        // next tick: listener gone
        let later = now + Duration::from_millis(1);
        let evicted = h.prune(later);
        assert_eq!(evicted.len(), 1);
    }

    #[test]
    fn tick_returns_active_and_evicted() {
        let now = t0();
        let mut h = Hysteresis::with_grace(Duration::from_secs(10));
        h.record(&[sock(443), sock(80)], now);

        // Jump past grace and observe only :443.
        let later = now + Duration::from_secs(11);
        let (active, evicted) = h.tick(&[sock(443)], later);
        // :80 fell outside grace *before* :443 was re-observed, so
        // it should be evicted. :443 is active (just re-observed).
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].port, 80);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].port, 443);
    }

    #[test]
    fn re_observation_refreshes_timestamp() {
        // If a listener is re-observed inside its grace window, its
        // deadline should extend, not expire at the original time.
        let now = t0();
        let mut h = Hysteresis::with_grace(Duration::from_secs(10));
        h.record(&[sock(443)], now);
        let t1 = now + Duration::from_secs(5);
        h.record(&[sock(443)], t1);
        // At t1 + 9s we're 14s past the *first* observation but only
        // 9s past the refresh, so the listener should still be alive.
        let t2 = t1 + Duration::from_secs(9);
        assert_eq!(h.active_at(t2).len(), 1);
    }

    #[test]
    fn different_proto_same_port_are_distinct_entries() {
        let now = t0();
        let mut h = Hysteresis::new();
        let tcp_443 = ListenSocket {
            family: Family::V4,
            proto: Proto::Tcp,
            port: 443,
        };
        let udp_443 = ListenSocket {
            family: Family::V4,
            proto: Proto::Udp,
            port: 443,
        };
        h.record(&[tcp_443, udp_443], now);
        assert_eq!(h.len(), 2, "TCP/443 and UDP/443 must track separately");
    }

    #[test]
    fn different_family_same_port_are_distinct_entries() {
        // Matters for QUIC / HTTP-3 where a host commonly listens on
        // both IPv4 and IPv6 UDP/443 and the fast path needs separate
        // templates.
        let now = t0();
        let mut h = Hysteresis::new();
        let v4 = ListenSocket {
            family: Family::V4,
            proto: Proto::Udp,
            port: 443,
        };
        let v6 = ListenSocket {
            family: Family::V6,
            proto: Proto::Udp,
            port: 443,
        };
        h.record(&[v4, v6], now);
        assert_eq!(h.len(), 2);
    }
}
