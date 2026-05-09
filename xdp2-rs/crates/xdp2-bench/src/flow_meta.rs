// FlowMeta fields and some variants are populated by later phases (metadata extraction, tunnel dispatch).
#![allow(dead_code)]

// ── Flow metadata ────────────────────────────────────────────────
//
// Matches C's `struct xdp2_metadata_all` from parser_metadata.h.
// Each field group corresponds to a C metadata macro (XDP2_METADATA_*).

/// Address type — matches `enum xdp2_addr_types` in parser_metadata.h.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum AddrType {
    #[default]
    Invalid = 0,
    Ipv4 = 1,
    Ipv6 = 2,
    Tipc = 3,
    Sunh = 4,
}

/// IPv4 or IPv6 addresses — matches `XDP2_METADATA_addrs` union.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct AddrsMeta {
    pub v4_src: u32,
    pub v4_dst: u32,
    pub v6_src: [u8; 16],
    pub v6_dst: [u8; 16],
    pub tipc_key: u32,
}

/// Transport ports — matches `XDP2_METADATA_ports` union.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PortsMeta {
    pub src_port: u16,
    pub dst_port: u16,
}

/// ICMP metadata — matches `XDP2_METADATA_icmp`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct IcmpMeta {
    pub icmp_type: u8,
    pub code: u8,
    pub id: u16,
}

/// VLAN tag metadata — matches `XDP2_METADATA_vlan` array element.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct VlanMeta {
    pub tci: u16,
    pub tpid: u16,
}

/// MPLS label metadata — matches `XDP2_METADATA_mpls`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MplsMeta {
    pub label: u32,
    pub tc: u8,
    pub bos: bool,
    pub ttl: u8,
}

/// ARP metadata — matches `XDP2_METADATA_arp`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ArpMeta {
    pub op: u8,
    pub sha: [u8; 6],
    pub spa: u32,
    pub tha: [u8; 6],
    pub tpa: u32,
}

/// GRE v0 metadata — matches `XDP2_METADATA_gre`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct GreMeta {
    pub flags: u32,
    pub csum: u16,
    pub keyid: u32,
    pub seq: u32,
    pub routing: u32,
}

/// GRE v1/PPTP metadata — matches `XDP2_METADATA_gre_pptp`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct GrePptpMeta {
    pub flags: u32,
    pub length: u16,
    pub callid: u16,
    pub seq: u32,
    pub ack: u32,
}

/// Flow metadata — Rust equivalent of C's `struct xdp2_metadata_all`.
///
/// Populated by `extract_metadata` callbacks at each protocol layer.
/// Fields ordered to match the C struct for easy cross-reference.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FlowMeta {
    pub addr_type: AddrType,
    pub is_fragment: bool,
    pub first_frag: bool,
    pub vlan_count: u8,
    pub eth_addrs: [u8; 12], // dst[6] + src[6] MACs
    pub mpls: MplsMeta,
    pub arp: ArpMeta,
    pub gre: GreMeta,
    pub gre_pptp: GrePptpMeta,
    pub l2_off: u16,
    pub l3_off: u16,
    pub l4_off: u16,
    pub eth_proto: u16,
    pub ip_proto: u8,
    pub ip_tos: u8,     // IPv4 TOS / IPv6 traffic class
    pub ip_ttl: u8,     // IPv4 TTL / IPv6 hop limit
    pub tcp_flags: u8,  // TCP flags byte (SYN/ACK/FIN/RST/PSH/URG)
    pub flow_label: u32,
    pub vlan: [VlanMeta; 2],
    pub keyid: u32,
    pub esp_spi: u32,
    pub ah_spi: u32,
    pub l2tp_session_id: u32,
    pub ports: PortsMeta,
    pub icmp: IcmpMeta,
    pub addrs: AddrsMeta,
}

impl FlowMeta {
    /// Reset only the accumulator fields (counts and bool flags) to
    /// their zero state, leaving the larger byte-arrays / address /
    /// protocol-tag fields untouched.
    ///
    /// **Phase O5 optimisation (2026-05-08):** the bench inner loops
    /// previously did `meta = FlowMeta::default()` per packet — a
    /// full ~176 B zero. Most of that struct is unconditionally
    /// overwritten by the parser when it sees the relevant protocol
    /// (eth_addrs by eth, addrs/ports/ip_proto by ip+l4, etc.) so
    /// pre-zeroing isn't strictly required.
    ///
    /// The fields that DO need per-packet reset are the accumulator
    /// counters and conditional-write flags — `vlan_count`,
    /// `is_fragment`, `first_frag`, plus the conditional structs
    /// (mpls, arp, gre, icmp) that the parser only touches for those
    /// specific protocols. Reset just those; let the rest carry stale
    /// values that the parser will overwrite if it cares.
    ///
    /// Saves ~5-10 ins/pkt on Zen 1 vs the full-default approach.
    /// Documented in
    /// `perf-results/asm/2026-05-08/asm-comparison-baseline.md`
    /// Phase O5.
    #[inline(always)]
    pub fn reset_for_parse(&mut self) {
        self.vlan_count = 0;
        self.is_fragment = false;
        self.first_frag = false;
        // Conditional-write substructs the parser only touches for
        // their specific protocols. Zero them so a packet without
        // (e.g.) MPLS doesn't see a previous packet's MPLS data.
        self.mpls = MplsMeta::default();
        self.arp = ArpMeta::default();
        self.gre = GreMeta::default();
        self.gre_pptp = GrePptpMeta::default();
        self.icmp = IcmpMeta::default();
        // Other fields (eth_addrs, addrs, ports, eth_proto, ip_proto,
        // l*_off, flow_label, vlan, keyid, esp_spi, ah_spi,
        // l2tp_session_id, addr_type) are unconditionally overwritten
        // by the parser when their protocol is reached, so leaving
        // stale values is safe.
    }
}
