//! parity.rs — Rust-side ParityRecord for the cross-parser parity gate
//! (Phase 17.A; see `samples/flow_dissector/parity_scope.json` for schema).
//!
//! Used by `xdp2-bench` when `--dump-meta <jsonl>` is set. Every
//! per-packet parser invocation (graph / graph-enum / mono / mono-x4 /
//! compiled / simd / template / template-simd) builds one ParityRecord
//! and appends a JSONL line to the dump path.
//!
//! The serialised line schema must agree byte-for-byte (modulo field
//! order) with what `samples/flow_dissector/parity_schema.h` emits from
//! the C and BPF benchmark binaries. The Python comparator at
//! `nix/scripts/parity-compare.py` is the source of truth: a
//! parser-side bug that produces a non-conforming line is caught at
//! the comparator's JSON-Schema validation step.

use std::fs::File;
use std::io::{self, BufWriter, Write};

use crate::flow_meta::{AddrType, FlowMeta};

pub const SCHEMA_VERSION: u32 = 1;

/// Parser identifier strings — must match `parity_scope.json`'s `scopes` keys.
pub mod parser_id {
    pub const RUST_GRAPH: &str = "rust-graph";
    pub const RUST_GRAPH_ENUM: &str = "rust-graph-enum";
    pub const RUST_MONO: &str = "rust-mono";
    pub const RUST_MONO_X4: &str = "rust-mono-x4";
    pub const RUST_COMPILED: &str = "rust-compiled";
    pub const RUST_SIMD: &str = "rust-simd";
    pub const RUST_TEMPLATE: &str = "rust-template";
    pub const RUST_TEMPLATE_SIMD: &str = "rust-template-simd";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Fast/Slow/Fallback wired up by Phase 17.B.BPF for c-bpf-fast.
pub enum AcceptPath {
    Fast,
    Slow,
    Fallback,
}

impl AcceptPath {
    fn as_str(&self) -> &'static str {
        match self {
            AcceptPath::Fast => "fast",
            AcceptPath::Slow => "slow",
            AcceptPath::Fallback => "fallback",
        }
    }
}

/// Reasons the schema documents for accepted=false. Keep in sync with
/// `parity_scope.json:expected_divergences`.
#[allow(dead_code)] // VERIFIER and NO_FAST_PATH_CHAIN wired up by Phase 17.B.BPF.
pub mod reject_reason {
    pub const VERIFIER: &str = "verifier";
    pub const NO_AVX2: &str = "no-avx2";
    pub const NO_TEMPLATE: &str = "no-template";
    pub const NO_FAST_PATH_CHAIN: &str = "no-fast-path-chain";
    pub const PARSE_ERROR: &str = "parse-error";
    /// Used by rust-graph-enum on non-IPv4 packets — its current
    /// table covers Ether/IPv4/{TCP,UDP,ICMP} only. Documented in
    /// parity_scope.json:expected_divergences/rust-graph-enum-ipv4-only.
    pub const IPV4_ONLY: &str = "ipv4-only";
}

/// Pull the first non-VLAN ethertype out of a packet header. Returns
/// `None` if the packet is too short. Previously used by graph-enum's
/// dump-meta path; superseded 2026-05-18 when graph-enum's reject
/// reason was unified to "ipv4-only" for every rejection (see
/// bench.rs and parity_scope.json:expected_divergences/
/// rust-graph-enum-ipv4-only). Kept as a public helper since future
/// per-parser scope checks may want a fast Ethernet/VLAN walker.
#[allow(dead_code)]
pub fn first_ethertype(data: &[u8]) -> Option<u16> {
    if data.len() < 14 {
        return None;
    }
    let mut etype = u16::from_be_bytes([data[12], data[13]]);
    let mut off = 14usize;
    // Peel up to two VLAN tags (802.1Q = 0x8100, 802.1AD = 0x88a8).
    for _ in 0..2 {
        if etype == 0x8100 || etype == 0x88a8 {
            if data.len() < off + 4 {
                return Some(etype);
            }
            etype = u16::from_be_bytes([data[off + 2], data[off + 3]]);
            off += 4;
        } else {
            break;
        }
    }
    Some(etype)
}

/// One JSONL record per (parser, pcap, packet).
///
/// Emit order: header fields (always), then `fields` block (only fields
/// the parser populated). Out-of-scope fields are simply omitted from
/// `fields`; the comparator distinguishes "present-and-different" from
/// "absent" via the per-parser scope declaration in `parity_scope.json`.
pub struct ParityRecord<'a> {
    pub parser_id: &'static str,
    pub parser_kind: &'static str,
    pub pcap: &'a str,
    pub packet_index: u32,
    pub accepted: bool,
    pub accept_path: Option<AcceptPath>,
    pub reject_reason: Option<&'static str>,
    pub meta: Option<&'a FlowMeta>,
}

impl<'a> ParityRecord<'a> {
    pub fn new(
        parser_id: &'static str,
        parser_kind: &'static str,
        pcap: &'a str,
        packet_index: u32,
    ) -> Self {
        Self {
            parser_id,
            parser_kind,
            pcap,
            packet_index,
            accepted: false,
            accept_path: None,
            reject_reason: None,
            meta: None,
        }
    }

    pub fn accepted(mut self, meta: &'a FlowMeta, path: Option<AcceptPath>) -> Self {
        self.accepted = true;
        self.accept_path = path;
        self.meta = Some(meta);
        self
    }

    pub fn rejected(mut self, reason: &'static str) -> Self {
        self.accepted = false;
        self.reject_reason = Some(reason);
        self.meta = None;
        self
    }
}

/// Streaming JSONL emitter. Owns the file handle so per-packet writes
/// are buffered; flushes on drop.
pub struct DumpMetaWriter {
    inner: BufWriter<File>,
}

impl DumpMetaWriter {
    pub fn create(path: &str) -> io::Result<Self> {
        let f = File::create(path)?;
        Ok(Self {
            inner: BufWriter::with_capacity(64 * 1024, f),
        })
    }

    /// Append one JSONL record. Flushes on the underlying buffered writer
    /// implicitly when full or when `flush()` is called explicitly.
    pub fn emit(&mut self, rec: &ParityRecord<'_>) -> io::Result<()> {
        write!(
            self.inner,
            "{{\"schema_version\":{},\"pcap\":\"{}\",\"packet_index\":{}",
            SCHEMA_VERSION,
            json_escape(rec.pcap),
            rec.packet_index
        )?;
        write!(
            self.inner,
            ",\"parser_id\":\"{}\",\"parser_kind\":\"{}\"",
            rec.parser_id, rec.parser_kind
        )?;
        write!(self.inner, ",\"accepted\":{}", rec.accepted)?;
        if let Some(path) = rec.accept_path {
            write!(self.inner, ",\"accept_path\":\"{}\"", path.as_str())?;
        }
        if let Some(reason) = rec.reject_reason {
            write!(self.inner, ",\"reject_reason\":\"{}\"", reason)?;
        }

        write!(self.inner, ",\"fields\":{{")?;
        if let Some(meta) = rec.meta {
            self.emit_fields(meta)?;
        }
        writeln!(self.inner, "}}}}")?;
        Ok(())
    }

    #[allow(unused_assignments)]
    fn emit_fields(&mut self, m: &FlowMeta) -> io::Result<()> {
        // `first` toggles after the first field is emitted; the final
        // assignment in a `comma!()` macro expansion is technically
        // unused (no field follows it) but keeping it consistent makes
        // the macro safe to extend.
        let mut first = true;
        macro_rules! comma {
            () => {
                if !first {
                    write!(self.inner, ",")?;
                }
                first = false;
            };
        }

        // addr_type — only emit when non-Invalid (Invalid = "field not set").
        let addr = match m.addr_type {
            AddrType::Ipv4 => Some("ipv4"),
            AddrType::Ipv6 => Some("ipv6"),
            AddrType::Tipc => Some("tipc"),
            AddrType::Sunh => Some("sunh"),
            AddrType::Invalid => None,
        };
        if let Some(s) = addr {
            comma!();
            write!(self.inner, "\"addr_type\":\"{}\"", s)?;
        }

        if m.ip_proto != 0 {
            comma!();
            write!(self.inner, "\"ip_proto\":{}", m.ip_proto)?;
        }

        match m.addr_type {
            AddrType::Ipv4 if m.addrs.v4_src != 0 || m.addrs.v4_dst != 0 => {
                comma!();
                write!(
                    self.inner,
                    "\"ipv4_src\":\"{}\",\"ipv4_dst\":\"{}\"",
                    fmt_ipv4_be(m.addrs.v4_src),
                    fmt_ipv4_be(m.addrs.v4_dst)
                )?;
            }
            AddrType::Ipv6 if m.addrs.v6_src != [0u8; 16] || m.addrs.v6_dst != [0u8; 16] => {
                comma!();
                write!(
                    self.inner,
                    "\"ipv6_src\":\"{}\",\"ipv6_dst\":\"{}\"",
                    fmt_ipv6(&m.addrs.v6_src),
                    fmt_ipv6(&m.addrs.v6_dst)
                )?;
            }
            AddrType::Tipc if m.addrs.tipc_key != 0 => {
                comma!();
                write!(self.inner, "\"tipc_key\":{}", m.addrs.tipc_key)?;
            }
            _ => {}
        }

        if m.ports.src_port != 0 || m.ports.dst_port != 0 {
            comma!();
            write!(
                self.inner,
                "\"sport\":{},\"dport\":{}",
                m.ports.src_port, m.ports.dst_port
            )?;
        }
        if m.l4_off != 0 {
            comma!();
            write!(self.inner, "\"thoff\":{}", m.l4_off)?;
        }
        if m.is_fragment {
            comma!();
            write!(
                self.inner,
                "\"is_frag\":true,\"is_first_frag\":{}",
                m.first_frag
            )?;
        }
        if m.flow_label != 0 {
            comma!();
            write!(self.inner, "\"flow_label\":{}", m.flow_label)?;
        }
        if m.eth_proto != 0 {
            comma!();
            write!(self.inner, "\"eth_proto\":{}", m.eth_proto)?;
        }
        // eth_addrs is [u8; 12] = dst[6]+src[6] in struct order.
        if m.eth_addrs != [0u8; 12] {
            comma!();
            write!(
                self.inner,
                "\"eth_dst\":\"{}\",\"eth_src\":\"{}\"",
                fmt_mac(&m.eth_addrs[0..6]),
                fmt_mac(&m.eth_addrs[6..12])
            )?;
        }
        if m.ip_tos != 0 {
            comma!();
            write!(self.inner, "\"ip_tos\":{}", m.ip_tos)?;
        }
        if m.ip_ttl != 0 {
            comma!();
            write!(self.inner, "\"ip_ttl\":{}", m.ip_ttl)?;
        }
        if m.tcp_flags != 0 {
            comma!();
            write!(self.inner, "\"tcp_flags\":{}", m.tcp_flags)?;
        }
        if m.vlan_count > 0 {
            comma!();
            write!(self.inner, "\"vlan\":[")?;
            for i in 0..(m.vlan_count as usize).min(2) {
                if i > 0 {
                    write!(self.inner, ",")?;
                }
                let v = &m.vlan[i];
                // VlanMeta has tci/tpid; vid is the lower 12 bits of tci.
                write!(
                    self.inner,
                    "{{\"tci\":{},\"tpid\":{},\"vid\":{}}}",
                    v.tci,
                    v.tpid,
                    v.tci & 0x0FFF
                )?;
            }
            write!(self.inner, "]")?;
        }
        if m.mpls.label != 0 {
            comma!();
            // Single-label MPLS in the current FlowMeta; emit as 1-element array
            // so the schema is forward-compatible with multi-label stacks.
            write!(
                self.inner,
                "\"mpls\":[{{\"label\":{},\"tc\":{},\"s\":{},\"ttl\":{}}}]",
                m.mpls.label, m.mpls.tc, m.mpls.bos, m.mpls.ttl
            )?;
        }
        if m.arp.op != 0 || m.arp.spa != 0 || m.arp.tpa != 0 {
            comma!();
            write!(
                self.inner,
                "\"arp_sip\":\"{}\",\"arp_tip\":\"{}\",\"arp_op\":{}",
                fmt_ipv4_be(m.arp.spa),
                fmt_ipv4_be(m.arp.tpa),
                m.arp.op
            )?;
        }
        if m.gre.keyid != 0 {
            comma!();
            write!(self.inner, "\"gre_keyid\":{}", m.gre.keyid)?;
        }
        if m.esp_spi != 0 {
            comma!();
            write!(self.inner, "\"esp_spi\":{}", m.esp_spi)?;
        }
        if m.ah_spi != 0 {
            comma!();
            write!(self.inner, "\"ah_spi\":{}", m.ah_spi)?;
        }
        if m.l2tp_session_id != 0 {
            comma!();
            write!(self.inner, "\"l2tp_session_id\":{}", m.l2tp_session_id)?;
        }
        if m.icmp.icmp_type != 0 || m.icmp.code != 0 || m.icmp.id != 0 {
            comma!();
            write!(
                self.inner,
                "\"icmp_type\":{},\"icmp_code\":{},\"icmp_id\":{}",
                m.icmp.icmp_type, m.icmp.code, m.icmp.id
            )?;
        }
        if m.l2_off != 0 {
            comma!();
            write!(self.inner, "\"l2_off\":{}", m.l2_off)?;
        }
        if m.l3_off != 0 {
            comma!();
            write!(self.inner, "\"l3_off\":{}", m.l3_off)?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Drop for DumpMetaWriter {
    fn drop(&mut self) {
        let _ = self.inner.flush();
    }
}

// ── formatters ────────────────────────────────────────────────────

/// IPv4 formatter for u32 in network byte order (matches the C
/// emitter's interpretation of the addrs field). The wire-form bytes
/// are read MSB first, so use `to_be_bytes` to preserve dotted-quad
/// order regardless of host endianness.
fn fmt_ipv4_be(addr_be: u32) -> String {
    let b = addr_be.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn fmt_ipv6(b: &[u8; 16]) -> String {
    let groups: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    // Find longest run of zeros for :: compression.
    let (mut best_start, mut best_len) = (usize::MAX, 0);
    let (mut cur_start, mut cur_len) = (0usize, 0usize);
    for (i, &g) in groups.iter().enumerate() {
        if g == 0 {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
            if cur_len > best_len {
                best_start = cur_start;
                best_len = cur_len;
            }
        } else {
            cur_len = 0;
        }
    }
    if best_len < 2 {
        return groups
            .iter()
            .map(|g| format!("{:x}", g))
            .collect::<Vec<_>>()
            .join(":");
    }
    let head: Vec<String> = groups[..best_start].iter().map(|g| format!("{:x}", g)).collect();
    let tail: Vec<String> = groups[best_start + best_len..]
        .iter()
        .map(|g| format!("{:x}", g))
        .collect();
    format!("{}::{}", head.join(":"), tail.join(":"))
}

fn fmt_mac(b: &[u8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_meta::{AddrType, FlowMeta};

    #[test]
    fn ipv4_formatter() {
        // 0x0a000001 in little-endian = [0x01, 0x00, 0x00, 0x0a] which prints
        // as 10.0.0.1 only if we read it as a network-byte-order u32. Our
        // C-side stores the IPv4 address in network byte order in a u32, so
        // when we read it back as a u32 and feed to to_le_bytes we get the
        // four octets in print order. Test the round-trip:
        let addr: u32 = u32::from_be_bytes([10, 0, 0, 1]);
        // After u32::to_le_bytes(addr), bytes are [1, 0, 0, 10] — wrong order.
        // Use to_be_bytes for correct print.
        let b = addr.to_be_bytes();
        assert_eq!(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]), "10.0.0.1");
    }

    #[test]
    fn ipv6_compression() {
        let mut a = [0u8; 16];
        // 2001:db8::1
        a[0] = 0x20;
        a[1] = 0x01;
        a[2] = 0x0d;
        a[3] = 0xb8;
        a[15] = 0x01;
        assert_eq!(fmt_ipv6(&a), "2001:db8::1");

        // ::1
        let mut b = [0u8; 16];
        b[15] = 0x01;
        assert_eq!(fmt_ipv6(&b), "::1");

        // No compression when no run
        let c = [
            0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07,
            0x00, 0x08,
        ];
        assert_eq!(fmt_ipv6(&c), "1:2:3:4:5:6:7:8");
    }

    #[test]
    fn record_emit_smoke() {
        let mut meta = FlowMeta::default();
        meta.addr_type = AddrType::Ipv4;
        meta.ip_proto = 6;
        meta.addrs.v4_src = u32::from_be_bytes([10, 0, 0, 1]);
        meta.addrs.v4_dst = u32::from_be_bytes([10, 0, 0, 2]);
        meta.ports.src_port = 12345;
        meta.ports.dst_port = 80;
        meta.l4_off = 34;

        let tmpdir = std::env::temp_dir();
        let path = tmpdir.join("parity-rs-smoke.jsonl");
        let path_str = path.to_string_lossy().to_string();
        {
            let mut w = DumpMetaWriter::create(&path_str).expect("create");
            let rec = ParityRecord::new(parser_id::RUST_GRAPH_ENUM, "rust", "tcp_ipv4.pcap", 0)
                .accepted(&meta, Some(AcceptPath::Fast));
            w.emit(&rec).expect("emit");
            w.flush().expect("flush");
        }
        let s = std::fs::read_to_string(&path_str).expect("read");
        assert!(s.contains("\"parser_id\":\"rust-graph-enum\""), "{}", s);
        assert!(s.contains("\"accepted\":true"), "{}", s);
        assert!(s.contains("\"accept_path\":\"fast\""), "{}", s);
        assert!(s.contains("\"addr_type\":\"ipv4\""), "{}", s);
        assert!(s.contains("\"ipv4_src\":\"10.0.0.1\""), "{}", s);
        assert!(s.contains("\"ipv4_dst\":\"10.0.0.2\""), "{}", s);
        assert!(s.contains("\"ip_proto\":6"), "{}", s);
        assert!(s.contains("\"sport\":12345"), "{}", s);
        assert!(s.contains("\"dport\":80"), "{}", s);
        assert!(s.contains("\"thoff\":34"), "{}", s);
    }

    #[test]
    fn record_rejected() {
        let tmpdir = std::env::temp_dir();
        let path = tmpdir.join("parity-rs-reject.jsonl");
        let path_str = path.to_string_lossy().to_string();
        {
            let mut w = DumpMetaWriter::create(&path_str).expect("create");
            let rec = ParityRecord::new(parser_id::RUST_SIMD, "rust", "combo.pcap", 42)
                .rejected(reject_reason::NO_AVX2);
            w.emit(&rec).expect("emit");
            w.flush().expect("flush");
        }
        let s = std::fs::read_to_string(&path_str).expect("read");
        assert!(s.contains("\"accepted\":false"));
        assert!(s.contains("\"reject_reason\":\"no-avx2\""));
        assert!(s.contains("\"fields\":{}"));
    }
}
