//! Step 12a/b: Hardware-classified template extraction.
//!
//! When the NIC has already classified a packet (via ntuple/Flow Director),
//! all header field offsets are compile-time constants.  No branches, no
//! graph walk — just one bounds check and fixed-offset reads.
//!
//! Two APIs:
//! - **Generic** (`extract_template`): iterates a `PacketTemplate` struct.
//!   Useful for code generation and testing, but LLVM cannot unroll the
//!   loop because the template is selected at runtime.
//! - **Specialized** (`extract_eth_ipv4_tcp`, etc.): hand-written per
//!   template with all offsets as integer literals.  These compile to the
//!   ideal code: one bounds check, fixed-offset loads, zero branches.
//!   The benchmark uses these.
//!
//! See `docs/hardware-classified-extraction.md` for the full concept.

// The generic PacketTemplate API is kept for future codegen and testing.
#![allow(dead_code)]

/// A field within a packet template.
pub struct FieldDef {
    pub name: &'static str,
    pub offset: usize,
    pub length: usize,
}

/// A packet template: compile-time-constant offsets for a known header stack.
pub struct PacketTemplate {
    pub name: &'static str,
    pub min_length: usize,
    pub fields: &'static [FieldDef],
}

// ── Compile-time template definitions ──

pub const ETH_IPV4_TCP: PacketTemplate = PacketTemplate {
    name: "eth_ipv4_tcp",
    min_length: 54,
    fields: &[
        FieldDef { name: "dst_mac",      offset: 0,  length: 6 },
        FieldDef { name: "src_mac",      offset: 6,  length: 6 },
        FieldDef { name: "ethertype",    offset: 12, length: 2 },
        FieldDef { name: "ip_src",       offset: 26, length: 4 },
        FieldDef { name: "ip_dst",       offset: 30, length: 4 },
        FieldDef { name: "ip_proto",     offset: 23, length: 1 },
        FieldDef { name: "tcp_src_port", offset: 34, length: 2 },
        FieldDef { name: "tcp_dst_port", offset: 36, length: 2 },
        FieldDef { name: "tcp_flags",    offset: 47, length: 1 },
    ],
};

pub const ETH_IPV4_UDP: PacketTemplate = PacketTemplate {
    name: "eth_ipv4_udp",
    min_length: 42,
    fields: &[
        FieldDef { name: "dst_mac",      offset: 0,  length: 6 },
        FieldDef { name: "src_mac",      offset: 6,  length: 6 },
        FieldDef { name: "ethertype",    offset: 12, length: 2 },
        FieldDef { name: "ip_src",       offset: 26, length: 4 },
        FieldDef { name: "ip_dst",       offset: 30, length: 4 },
        FieldDef { name: "ip_proto",     offset: 23, length: 1 },
        FieldDef { name: "udp_src_port", offset: 34, length: 2 },
        FieldDef { name: "udp_dst_port", offset: 36, length: 2 },
    ],
};

pub const ETH_IPV6_TCP: PacketTemplate = PacketTemplate {
    name: "eth_ipv6_tcp",
    min_length: 74,
    fields: &[
        FieldDef { name: "dst_mac",      offset: 0,  length: 6 },
        FieldDef { name: "src_mac",      offset: 6,  length: 6 },
        FieldDef { name: "ethertype",    offset: 12, length: 2 },
        FieldDef { name: "ipv6_src",     offset: 22, length: 16 },
        FieldDef { name: "ipv6_dst",     offset: 38, length: 16 },
        FieldDef { name: "ipv6_next_hdr", offset: 20, length: 1 },
        FieldDef { name: "tcp_src_port", offset: 54, length: 2 },
        FieldDef { name: "tcp_dst_port", offset: 56, length: 2 },
        FieldDef { name: "tcp_flags",    offset: 67, length: 1 },
    ],
};

// ── Generic extraction (for testing / codegen) ──

/// Extract fields from a packet using a template.  Single bounds check,
/// then read all field bytes at fixed offsets.  Returns Ok(checksum)
/// where checksum is a u64 XOR of all extracted bytes — this prevents
/// the compiler from eliding reads and serves as correctness verification.
#[inline]
pub fn extract_template(pkt: &[u8], tmpl: &PacketTemplate) -> Result<u64, ()> {
    if pkt.len() < tmpl.min_length {
        return Err(());
    }
    let mut acc: u64 = 0;
    for field in tmpl.fields {
        for i in 0..field.length {
            acc ^= pkt[field.offset + i] as u64;
        }
    }
    Ok(acc)
}

// ── Specialized extractors (compile to ideal code) ──
//
// Each function below reads fields at literal offsets.  LLVM compiles
// these to a single bounds check + a series of `movzx` / `mov`
// instructions with no loops or branches.  This is what template
// extraction actually is — the "loop over FieldDefs" version above
// is just a convenience for code generation and testing.

/// Template ID for pre-selected packets.  Avoids re-classifying
/// packets inside the timed benchmark loop.
#[derive(Clone, Copy)]
pub enum TemplateId {
    EthIpv4Tcp,
    EthIpv4Udp,
    EthIpv6Tcp,
}

/// Eth/IPv4(IHL=5)/TCP — 54 bytes, 28 bytes of key fields.
#[inline]
pub fn extract_eth_ipv4_tcp(pkt: &[u8]) -> Result<u64, ()> {
    if pkt.len() < 54 {
        return Err(());
    }
    // Read key fields at compile-time-constant offsets.
    // XOR into accumulator to prevent DCE.
    let acc = read_u32(pkt, 0)    // dst_mac[0..4]
        ^ read_u16(pkt, 4) as u64 // dst_mac[4..6]
        ^ read_u32(pkt, 6)        // src_mac[0..4]
        ^ read_u16(pkt, 10) as u64 // src_mac[4..6]
        ^ read_u16(pkt, 12) as u64 // ethertype
        ^ pkt[23] as u64           // ip_proto
        ^ read_u32(pkt, 26)        // ip_src
        ^ read_u32(pkt, 30)        // ip_dst
        ^ read_u16(pkt, 34) as u64 // tcp_src_port
        ^ read_u16(pkt, 36) as u64 // tcp_dst_port
        ^ pkt[47] as u64;          // tcp_flags
    Ok(acc)
}

/// Eth/IPv4(IHL=5)/UDP — 42 bytes, 26 bytes of key fields.
#[inline]
pub fn extract_eth_ipv4_udp(pkt: &[u8]) -> Result<u64, ()> {
    if pkt.len() < 42 {
        return Err(());
    }
    let acc = read_u32(pkt, 0)
        ^ read_u16(pkt, 4) as u64
        ^ read_u32(pkt, 6)
        ^ read_u16(pkt, 10) as u64
        ^ read_u16(pkt, 12) as u64
        ^ pkt[23] as u64
        ^ read_u32(pkt, 26)
        ^ read_u32(pkt, 30)
        ^ read_u16(pkt, 34) as u64
        ^ read_u16(pkt, 36) as u64;
    Ok(acc)
}

/// Eth/IPv6/TCP — 74 bytes, 52 bytes of key fields.
#[inline]
pub fn extract_eth_ipv6_tcp(pkt: &[u8]) -> Result<u64, ()> {
    if pkt.len() < 74 {
        return Err(());
    }
    let acc = read_u32(pkt, 0)
        ^ read_u16(pkt, 4) as u64
        ^ read_u32(pkt, 6)
        ^ read_u16(pkt, 10) as u64
        ^ read_u16(pkt, 12) as u64
        ^ pkt[20] as u64            // ipv6_next_hdr
        ^ read_u32(pkt, 22)         // ipv6_src[0..4]
        ^ read_u32(pkt, 26)         // ipv6_src[4..8]
        ^ read_u32(pkt, 30)         // ipv6_src[8..12]
        ^ read_u32(pkt, 34)         // ipv6_src[12..16]
        ^ read_u32(pkt, 38)         // ipv6_dst[0..4]
        ^ read_u32(pkt, 42)         // ipv6_dst[4..8]
        ^ read_u32(pkt, 46)         // ipv6_dst[8..12]
        ^ read_u32(pkt, 50)         // ipv6_dst[12..16]
        ^ read_u16(pkt, 54) as u64  // tcp_src_port
        ^ read_u16(pkt, 56) as u64  // tcp_dst_port
        ^ pkt[67] as u64;           // tcp_flags
    Ok(acc)
}

/// Dispatch to the specialized extractor for a pre-selected template.
#[inline]
pub fn extract_by_id(pkt: &[u8], id: TemplateId) -> Result<u64, ()> {
    match id {
        TemplateId::EthIpv4Tcp => extract_eth_ipv4_tcp(pkt),
        TemplateId::EthIpv4Udp => extract_eth_ipv4_udp(pkt),
        TemplateId::EthIpv6Tcp => extract_eth_ipv6_tcp(pkt),
    }
}

/// Select template ID for a packet.  In production, this is the NIC
/// queue number — zero runtime cost.  Here we sniff for benchmarking.
pub fn select_template_id(pkt: &[u8]) -> Option<TemplateId> {
    if pkt.len() < 34 {
        return None;
    }
    let ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
    match ethertype {
        0x0800 => {
            if pkt[14] & 0x0F != 5 {
                return None;
            }
            match pkt[23] {
                6 => Some(TemplateId::EthIpv4Tcp),
                17 => Some(TemplateId::EthIpv4Udp),
                _ => None,
            }
        }
        0x86DD => {
            if pkt.len() < 54 {
                return None;
            }
            match pkt[20] {
                6 => Some(TemplateId::EthIpv6Tcp),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Select the appropriate template for a packet, or None if no template
/// matches.  In production this would be driven by NIC queue assignment;
/// here we sniff ethertype + protocol for benchmark purposes.
pub fn select_template(pkt: &[u8]) -> Option<&'static PacketTemplate> {
    if pkt.len() < 34 {
        return None;
    }
    let ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
    match ethertype {
        0x0800 => {
            if pkt[14] & 0x0F != 5 {
                return None;
            }
            match pkt[23] {
                6 => Some(&ETH_IPV4_TCP),
                17 => Some(&ETH_IPV4_UDP),
                _ => None,
            }
        }
        0x86DD => {
            if pkt.len() < 54 {
                return None;
            }
            match pkt[20] {
                6 => Some(&ETH_IPV6_TCP),
                _ => None,
            }
        }
        _ => None,
    }
}

// ── Helpers ──

/// Read a u32 from a byte slice at a known offset, XOR-folded to u64.
#[inline(always)]
fn read_u32(pkt: &[u8], off: usize) -> u64 {
    u32::from_ne_bytes([pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]]) as u64
}

/// Read a u16 from a byte slice at a known offset.
#[inline(always)]
fn read_u16(pkt: &[u8], off: usize) -> u16 {
    u16::from_ne_bytes([pkt[off], pkt[off + 1]])
}
