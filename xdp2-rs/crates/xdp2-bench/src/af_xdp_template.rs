//! Per-queue hardware-classified template extraction.
//!
//! This mode pairs with a NIC Flow Director rule (e.g., `ethtool -N
//! enp1s0f0np0 flow-type tcp4 dst-port 443 action 2`) that steers a
//! known packet shape to a known RX queue. We bind one AF_XDP socket
//! per queue; because the queue itself implies the template, we skip
//! `select_template_id` entirely and call the fixed-offset extractor
//! directly.
//!
//! This is the "what does the testbed enable" headline: purely parsing
//! a pre-classified stream with no software classification cost.
//!
//! ## CLI
//!
//! ```text
//! xdp2-bench --mode af-xdp-template \
//!   --interface enp1s0f0np0 \
//!   --queue-template 1=eth-ipv4-tcp \
//!   --queue-template 2=eth-ipv4-tcp \
//!   --duration 30
//! ```
//!
//! Repeat `--queue-template <QID>=<NAME>` once per queue. Valid NAMEs
//! match the `TemplateId` variant names in hyphen-case (e.g.
//! `eth-ipv4-tcp`, `eth-vlan-ipv6-udp`, `eth-ipv4-gre-ipv4-tcp`). The
//! mapping is maintained in `template_id_from_str` below.

use crate::af_xdp;
use crate::flow_meta::FlowMeta;
use crate::template::{self, TemplateId};

/// One (queue, template) binding derived from a `--queue-template` flag.
#[derive(Debug)]
pub struct PerQueueTemplate {
    pub queue_id: u32,
    pub template_id: TemplateId,
}

/// Per-queue result emitted by `run_af_xdp_template`.
#[derive(Debug)]
pub struct QueueReport {
    pub queue_id: u32,
    pub template_id: TemplateId,
    pub packets: u64,
    pub bytes: u64,
    pub ns_per_pkt: u64,
    pub mpps: f64,
}

/// Parse one `--queue-template` argument, formatted as `QID=NAME`.
pub fn parse_queue_template(spec: &str) -> Result<PerQueueTemplate, String> {
    let (qid_s, name) = spec
        .split_once('=')
        .ok_or_else(|| format!("expected 'QID=NAME', got '{spec}'"))?;
    let queue_id: u32 = qid_s
        .trim()
        .parse()
        .map_err(|e| format!("invalid queue id '{qid_s}': {e}"))?;
    let template_id = template_id_from_str(name.trim())?;
    Ok(PerQueueTemplate {
        queue_id,
        template_id,
    })
}

/// Map a hyphen-case name to a `TemplateId`. Kept in the same order as
/// the enum declaration in `template.rs` so a quick grep stays honest
/// if new variants land.
pub fn template_id_from_str(name: &str) -> Result<TemplateId, String> {
    use TemplateId::*;
    let id = match name {
        // ── Plain ──
        "eth-ipv4-tcp" => EthIpv4Tcp,
        "eth-ipv4-udp" => EthIpv4Udp,
        "eth-ipv4-icmp" => EthIpv4Icmp,
        "eth-ipv4-sctp" => EthIpv4Sctp,
        "eth-ipv4-other" => EthIpv4Other,
        "eth-ipv6-tcp" => EthIpv6Tcp,
        "eth-ipv6-udp" => EthIpv6Udp,
        "eth-ipv6-icmpv6" => EthIpv6Icmpv6,
        "eth-ipv6-sctp" => EthIpv6Sctp,
        "eth-ipv6-other" => EthIpv6Other,
        "eth-arp" => EthArp,
        // ── Single VLAN ──
        "eth-vlan-ipv4-tcp" => EthVlanIpv4Tcp,
        "eth-vlan-ipv4-udp" => EthVlanIpv4Udp,
        "eth-vlan-ipv4-icmp" => EthVlanIpv4Icmp,
        "eth-vlan-ipv4-sctp" => EthVlanIpv4Sctp,
        "eth-vlan-ipv4-other" => EthVlanIpv4Other,
        "eth-vlan-ipv6-tcp" => EthVlanIpv6Tcp,
        "eth-vlan-ipv6-udp" => EthVlanIpv6Udp,
        "eth-vlan-ipv6-icmpv6" => EthVlanIpv6Icmpv6,
        "eth-vlan-ipv6-sctp" => EthVlanIpv6Sctp,
        "eth-vlan-ipv6-other" => EthVlanIpv6Other,
        "eth-vlan-arp" => EthVlanArp,
        // ── QinQ ──
        "eth-qinq-ipv4-tcp" => EthQinQIpv4Tcp,
        "eth-qinq-ipv4-udp" => EthQinQIpv4Udp,
        "eth-qinq-ipv4-icmp" => EthQinQIpv4Icmp,
        "eth-qinq-ipv4-sctp" => EthQinQIpv4Sctp,
        "eth-qinq-ipv4-other" => EthQinQIpv4Other,
        "eth-qinq-ipv6-tcp" => EthQinQIpv6Tcp,
        "eth-qinq-ipv6-udp" => EthQinQIpv6Udp,
        "eth-qinq-ipv6-icmpv6" => EthQinQIpv6Icmpv6,
        "eth-qinq-ipv6-sctp" => EthQinQIpv6Sctp,
        "eth-qinq-ipv6-other" => EthQinQIpv6Other,
        "eth-qinq-arp" => EthQinQArp,
        // ── GRE ──
        "eth-ipv4-gre-ipv4-tcp" => EthIpv4GreIpv4Tcp,
        "eth-ipv4-gre-ipv4-udp" => EthIpv4GreIpv4Udp,
        "eth-ipv4-gre-ipv4-icmp" => EthIpv4GreIpv4Icmp,
        "eth-ipv4-gre-ipv6-tcp" => EthIpv4GreIpv6Tcp,
        "eth-ipv4-gre-ipv6-udp" => EthIpv4GreIpv6Udp,
        "eth-ipv4-gre-ipv6-icmpv6" => EthIpv4GreIpv6Icmpv6,
        // ── Double GRE ──
        "eth-ipv4-gre-ipv4-gre-ipv4-tcp" => EthIpv4GreIpv4GreIpv4Tcp,
        "eth-ipv4-gre-ipv4-gre-ipv4-udp" => EthIpv4GreIpv4GreIpv4Udp,
        "eth-ipv4-gre-ipv4-gre-ipv4-icmp" => EthIpv4GreIpv4GreIpv4Icmp,
        // ── VLAN + GRE ──
        "eth-vlan-ipv4-gre-ipv4-tcp" => EthVlanIpv4GreIpv4Tcp,
        "eth-vlan-ipv4-gre-ipv4-udp" => EthVlanIpv4GreIpv4Udp,
        "eth-vlan-ipv4-gre-ipv4-icmp" => EthVlanIpv4GreIpv4Icmp,
        "eth-vlan-ipv4-gre-ipv6-tcp" => EthVlanIpv4GreIpv6Tcp,
        "eth-vlan-ipv4-gre-ipv6-udp" => EthVlanIpv4GreIpv6Udp,
        "eth-vlan-ipv4-gre-ipv6-icmpv6" => EthVlanIpv4GreIpv6Icmpv6,
        // ── QinQ + GRE ──
        "eth-qinq-ipv4-gre-ipv4-tcp" => EthQinQIpv4GreIpv4Tcp,
        "eth-qinq-ipv4-gre-ipv4-udp" => EthQinQIpv4GreIpv4Udp,
        "eth-qinq-ipv4-gre-ipv4-icmp" => EthQinQIpv4GreIpv4Icmp,
        "eth-qinq-ipv4-gre-ipv6-tcp" => EthQinQIpv4GreIpv6Tcp,
        "eth-qinq-ipv4-gre-ipv6-udp" => EthQinQIpv4GreIpv6Udp,
        "eth-qinq-ipv4-gre-ipv6-icmpv6" => EthQinQIpv4GreIpv6Icmpv6,
        // ── IP-in-IP ──
        "eth-ipv4-ipv4-tcp" => EthIpv4Ipv4Tcp,
        "eth-ipv4-ipv4-udp" => EthIpv4Ipv4Udp,
        "eth-ipv4-ipv4-icmp" => EthIpv4Ipv4Icmp,
        "eth-vlan-ipv4-ipv4-tcp" => EthVlanIpv4Ipv4Tcp,
        "eth-vlan-ipv4-ipv4-udp" => EthVlanIpv4Ipv4Udp,
        "eth-vlan-ipv4-ipv4-icmp" => EthVlanIpv4Ipv4Icmp,
        "eth-qinq-ipv4-ipv4-tcp" => EthQinQIpv4Ipv4Tcp,
        "eth-qinq-ipv4-ipv4-udp" => EthQinQIpv4Ipv4Udp,
        "eth-qinq-ipv4-ipv4-icmp" => EthQinQIpv4Ipv4Icmp,
        _ => {
            return Err(format!(
                "unknown template '{name}'. See src/af_xdp_template.rs \
                 template_id_from_str for the full list (63 variants)."
            ))
        }
    };
    Ok(id)
}

/// Spawn one AF_XDP thread per `(queue_id, template_id)` and run for
/// `duration_secs`. Each thread uses the pre-mapped template directly
/// — no per-packet `select_template_id`.
///
/// Returns one `QueueReport` per input entry, in the same order.
#[cfg(target_os = "linux")]
pub fn run_af_xdp_template(
    ifname: &str,
    queues: &[PerQueueTemplate],
    duration_secs: u32,
    cfg: &af_xdp::RunConfig,
    core_pin_start: Option<usize>,
) -> Result<Vec<QueueReport>, String> {
    use std::thread;

    if queues.is_empty() {
        return Err("at least one --queue-template is required".to_string());
    }

    thread::scope(|s| {
        let mut handles = Vec::with_capacity(queues.len());
        for (i, q) in queues.iter().enumerate() {
            let qid = q.queue_id;
            let tid = q.template_id;
            let handle = s.spawn(move || {
                if let Some(base) = core_pin_start {
                    // Best-effort pinning; af_xdp::pin_to_core is private,
                    // but the same sched_setaffinity pattern works here.
                    pin_to_core(base + i);
                }
                let process = move |pkt: &[u8]| {
                    let mut meta = FlowMeta::default();
                    let _ = template::extract_by_id(pkt, tid, &mut meta);
                    std::hint::black_box(&meta);
                };
                af_xdp::run(ifname, qid, duration_secs, cfg, process)
            });
            handles.push((qid, tid, handle));
        }

        let mut reports = Vec::with_capacity(handles.len());
        for (qid, tid, h) in handles {
            match h.join() {
                Ok(Ok(stats)) => reports.push(QueueReport {
                    queue_id: qid,
                    template_id: tid,
                    packets: stats.total_pkts,
                    bytes: stats.total_bytes,
                    ns_per_pkt: stats.ns_pkt(),
                    mpps: stats.mpps(),
                }),
                Ok(Err(e)) => return Err(format!("queue {qid} failed: {e}")),
                Err(_) => return Err(format!("queue {qid} thread panicked")),
            }
        }
        Ok(reports)
    })
}

#[cfg(not(target_os = "linux"))]
pub fn run_af_xdp_template(
    _ifname: &str,
    _queues: &[PerQueueTemplate],
    _duration_secs: u32,
    _cfg: &af_xdp::RunConfig,
    _core_pin_start: Option<usize>,
) -> Result<Vec<QueueReport>, String> {
    Err("AF_XDP requires Linux".to_string())
}

#[cfg(target_os = "linux")]
fn pin_to_core(cpu: usize) {
    unsafe {
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut cpuset);
        libc::CPU_SET(cpu, &mut cpuset);
        let _ = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &cpuset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let pq = parse_queue_template("1=eth-ipv4-tcp").unwrap();
        assert_eq!(pq.queue_id, 1);
        assert!(matches!(pq.template_id, TemplateId::EthIpv4Tcp));
    }

    #[test]
    fn parse_ipv6_vlan() {
        let pq = parse_queue_template("7=eth-vlan-ipv6-udp").unwrap();
        assert_eq!(pq.queue_id, 7);
        assert!(matches!(pq.template_id, TemplateId::EthVlanIpv6Udp));
    }

    #[test]
    fn parse_missing_equals() {
        let e = parse_queue_template("42eth-ipv4-tcp").unwrap_err();
        assert!(e.contains("expected 'QID=NAME'"));
    }

    #[test]
    fn parse_bad_qid() {
        let e = parse_queue_template("abc=eth-ipv4-tcp").unwrap_err();
        assert!(e.contains("invalid queue id"));
    }

    #[test]
    fn parse_unknown_template() {
        let e = parse_queue_template("0=eth-quinoa-udp").unwrap_err();
        assert!(e.contains("unknown template"));
    }
}
