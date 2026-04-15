# Hardware-Classified Template Extraction

When the NIC has already classified a packet — via ntuple filters, Flow Director,
or `rte_flow` — the entire header stack layout is known before software touches a
single byte.  Every field offset becomes a compile-time constant.  There are no
branches, no dependent-load chains, no graph walk.  The parser collapses from a
multi-stage state machine to a single fixed-offset extraction: one load, one
shuffle, done.

## At a Glance

All parser modes now perform identical metadata extraction (full parse + FlowMeta).
Template is field extraction, not parsing — shown separately.

| Engine | cycles/pkt | ins/pkt | IPC | branches | status |
|--------|-----------|---------|-----|----------|--------|
| Rust graph (`&dyn` dispatch + metadata) | 584 | 1066 | 1.83 | ~268 | measured (174 ns/pkt) |
| Rust compiled (inline byte reads + metadata) | 123 | 160 | 1.31 | ~30 | measured (36 ns/pkt) |
| AVX2 batch SIMD (8-wide + metadata) | 149 | 187 | 1.25 | ~33 | measured (44 ns/pkt) |
| Template scalar (field extraction) | 9 | 7 | 0.71 | ~2 | **measured (2 ns/pkt)** |
| Template + batch AVX2 (field extraction) | 7 | 6 | 0.87 | ~2 | **measured (2 ns/pkt)** |
| Template + batch AVX-512 (projected) | 1–2 | 2–3 | — | 0 | target |

All "measured" numbers from AMD Ryzen Threadripper 3945WX (Zen 2), 2026-04-14
(post feature-parity: 28 ethertypes, 31 metadata extractors, 445K mixed packets).
See [performance-maximization-plan.md](./performance-maximization-plan.md) for
methodology and full results.

---

## 1. Why Graph Walks Are Still Serial

Even the compiled parser — which eliminated vtable dispatch and cut instructions
from 542 to 48 — still has a **dependent-load chain**:

```
  read pkt[12..14]         ethertype
        │
        ▼
  branch on 0x0800         is it IPv4?
        │
        ▼
  read pkt[14] & 0x0F      IHL (variable header length)
        │
        ▼
  compute hlen = IHL × 4   offset to L4
        │
        ▼
  read pkt[23]             protocol byte
        │
        ▼
  branch on 6/17/1/132     TCP? UDP? ICMP? SCTP?
        │
        ▼
  bounds-check rest        leaf validation
```

Each load feeds the next branch, and each branch determines the next load
offset.  The CPU's out-of-order engine cannot start reading the protocol
byte until it knows the IHL, and it cannot know the IHL until it has
checked the ethertype.

At IPC 4.04 and 12 cycles per packet, the compiled parser is at the Zen 2
superscalar ceiling.  **You cannot make this chain faster — only eliminate it.**

Template extraction eliminates it:

```
  Template: Eth/IPv4(IHL=5)/TCP

  Offsets known at compile time:
    ethertype  = pkt[12..14]   (always 0x0800, verified by NIC)
    IHL        = 5             (constrained by NIC filter)
    protocol   = pkt[23]       (always 6, verified by NIC)
    src_ip     = pkt[26..30]
    dst_ip     = pkt[30..34]
    src_port   = pkt[34..36]
    dst_port   = pkt[36..38]
    ...

  No branches.  No dependent loads.  One bounds check: len >= 54.
```

---

## 2. Template Extraction Concept

### The Idea

When the NIC guarantees the packet type (e.g., "IPv4/TCP, IHL=5, no VLAN"),
every header field is at a **compile-time-constant byte offset**.  The parser
becomes a single bounds check followed by fixed-offset reads — or, with SIMD,
a single vector load and shuffle.

This is not "using SIMD for speed."  The problem itself shrinks: there are
**zero decisions** to make.  The NIC already made them in hardware.

### Concrete Offset Tables

**Eth/IPv4(IHL=5)/TCP (54 bytes):**

| Field | Offset | Size | Notes |
|-------|--------|------|-------|
| dst_mac | 0 | 6 | |
| src_mac | 6 | 6 | |
| ethertype | 12 | 2 | 0x0800 (known) |
| ip_version | 14 | 1 | 0x45 (known: v4, IHL=5) |
| ip_tos | 15 | 1 | |
| ip_total_len | 16 | 2 | |
| ip_id | 18 | 2 | |
| ip_flags_frag | 20 | 2 | |
| ip_ttl | 22 | 1 | |
| ip_proto | 23 | 1 | 6 (known) |
| ip_checksum | 24 | 2 | |
| ip_src | 26 | 4 | |
| ip_dst | 30 | 4 | |
| tcp_src_port | 34 | 2 | |
| tcp_dst_port | 36 | 2 | |
| tcp_seq | 38 | 4 | |
| tcp_ack | 42 | 4 | |
| tcp_data_off | 46 | 1 | |
| tcp_flags | 47 | 1 | |
| tcp_window | 48 | 2 | |
| tcp_checksum | 50 | 2 | |
| tcp_urgent | 52 | 2 | |

**Eth/IPv4(IHL=5)/UDP (42 bytes):**

Same as above through offset 33, then:

| Field | Offset | Size |
|-------|--------|------|
| udp_src_port | 34 | 2 |
| udp_dst_port | 36 | 2 |
| udp_length | 38 | 2 |
| udp_checksum | 40 | 2 |

**Eth/IPv6/TCP (74 bytes):**

| Field | Offset | Size |
|-------|--------|------|
| dst_mac | 0 | 6 |
| src_mac | 6 | 6 |
| ethertype | 12 | 2 |
| ipv6_ver_tc_fl | 14 | 4 |
| ipv6_payload_len | 18 | 2 |
| ipv6_next_hdr | 20 | 1 |
| ipv6_hop_limit | 21 | 1 |
| ipv6_src | 22 | 16 |
| ipv6_dst | 38 | 16 |
| tcp_src_port | 54 | 2 |
| tcp_dst_port | 56 | 2 |
| tcp_seq | 58 | 4 |
| tcp_ack | 62 | 4 |
| tcp_data_off | 66 | 1 |
| tcp_flags | 67 | 1 |
| tcp_window | 68 | 2 |
| tcp_checksum | 70 | 2 |
| tcp_urgent | 72 | 2 |

### AVX-512 Two-Instruction Extraction

The Eth/IPv4/UDP template is 42 bytes — fits in a single 64-byte ZMM register:

```asm
; Load first 64 bytes of packet (includes full Eth+IPv4+UDP + 22 bytes padding)
vmovdqu8  zmm0, [rdi]

; Shuffle to extract fields into a compact metadata struct
; The shuffle mask is a compile-time constant derived from the template offsets
vpermb    zmm1, zmm_shuffle_mask, zmm0
```

Two instructions.  ~5 cycles.  Zero branches.

For Eth/IPv4/TCP (54 bytes), the same approach works — 54 < 64, still one
ZMM load.  For Eth/IPv6/TCP (74 bytes), we need two loads and a merge,
but the shuffle mask is still compile-time constant.

### AVX2 Variant

AVX2 has 32-byte YMM registers and `vpshufb` (per-lane byte shuffle):

```asm
; Load two halves of the packet
vmovdqu   ymm0, [rdi]       ; bytes 0..31
vmovdqu   ymm1, [rdi + 32]  ; bytes 32..63

; Shuffle each half independently
vpshufb   ymm2, ymm0, ymm_shuffle_lo
vpshufb   ymm3, ymm1, ymm_shuffle_hi

; OR/blend the results
vpor      ymm4, ymm2, ymm3
```

Four instructions, ~8 cycles.  Still zero branches.  `vpshufb` only shuffles
within 16-byte lanes, so the shuffle masks require lane-crossing fixups — but
they are still compile-time constants.

---

## 3. Prior Art

| System | Mechanism | Relevance |
|--------|-----------|-----------|
| **P4 `extract()`** | Declarative fixed-offset extraction in programmable switch/NIC pipelines. The programmer declares the header layout; the compiler generates a single extraction step per header. | Direct analogue — P4's `extract()` IS template extraction, running on switch ASICs rather than host CPUs. |
| **DPDK `rte_flow` + `rte_flow_action_mark`** | NIC classifies packets into flows and stamps a 32-bit `mark` into the mbuf. Userspace dispatches on mark → known layout. | Production-deployed pattern. The mark selects the template; extraction uses fixed offsets. |
| **Intel FlowAPI / ADQ** | Application Device Queues: NIC steers classified traffic to per-application queues with dedicated resources. | Queue = template selector. ADQ + template extraction = zero-copy classified parse. |
| **Linux `ethtool -N` / ntuple** | Kernel-level n-tuple filter rules that steer packets to specific RX queues. Simplest deployment path — no DPDK required. | Works with AF_XDP. Queue N → template N. Available on Intel i40e/ice, Mellanox mlx5, Broadcom bnxt. |
| **PacketShader (SIGCOMM 2010)** | GPU-accelerated packet processing with batch extraction at known offsets. | Early demonstration that batch + known offsets = massive throughput gains. |
| **simdjson (Langdale & Lemire)** | JSON parser that exploits structural predictability (quotes, colons, braces at known positions) for SIMD acceleration. | Same insight: when structure is predictable, SIMD moves from "nice to have" to "fundamentally different algorithm." |

---

## 4. NIC Hardware Support

### Steering Capabilities

| NIC Family | Driver | Steering Mechanism | Max Rules | IHL=5 Filter | Queue Steering |
|-----------|--------|-------------------|-----------|-------------|----------------|
| Intel X710/XL710 | i40e | Flow Director, ntuple, cloud filters | 8K FD rules | Yes (byte match on IP[0]) | Yes, per-rule queue assignment |
| Intel E810 | ice | ntuple, switchdev, ADQ | 16K+ | Yes | Yes, including ADQ TC queues |
| Mellanox ConnectX-5/6 | mlx5 | `ethtool -N`, TC flower offload, DPDK `rte_flow` | Hardware dependent (~64K) | Yes (via raw byte match) | Yes |
| Broadcom NetXtreme | bnxt_en | ntuple, TC flower offload | ~8K | Partial (ethertype + proto, not IHL directly) | Yes |
| Intel i225/i226 (2.5G) | igc | Basic ntuple | ~128 | Limited | Yes |

### Configuration Examples

**Steer all IPv4/TCP to queue 0, IPv4/UDP to queue 1:**

```bash
# Intel i40e / ice
ethtool -N eth0 flow-type tcp4 action 0
ethtool -N eth0 flow-type udp4 action 1

# Verify
ethtool -n eth0
```

**Steer VXLAN traffic to queue 2:**

```bash
# Match UDP dst port 4789 (VXLAN)
ethtool -N eth0 flow-type udp4 dst-port 4789 action 2
```

**DPDK `rte_flow` (more expressive):**

```c
// Match IPv4/TCP with IHL=5 → queue 0 with mark 1
struct rte_flow_attr attr = { .ingress = 1 };
struct rte_flow_item pattern[] = {
    { .type = RTE_FLOW_ITEM_TYPE_ETH },
    { .type = RTE_FLOW_ITEM_TYPE_IPV4,
      .spec = &(struct rte_ipv4_hdr){ .version_ihl = 0x45 },
      .mask = &(struct rte_ipv4_hdr){ .version_ihl = 0xFF } },
    { .type = RTE_FLOW_ITEM_TYPE_TCP },
    { .type = RTE_FLOW_ITEM_TYPE_END },
};
struct rte_flow_action actions[] = {
    { .type = RTE_FLOW_ACTION_TYPE_MARK, .conf = &(struct rte_flow_action_mark){ .id = 1 } },
    { .type = RTE_FLOW_ACTION_TYPE_QUEUE, .conf = &(struct rte_flow_action_queue){ .index = 0 } },
    { .type = RTE_FLOW_ACTION_TYPE_END },
};
```

---

## 5. Performance Analysis

### Theoretical Lower Bound

For a 42-byte Eth/IPv4/UDP extraction:

- **1 cache-line load** (64 bytes covers the full header): ~4 cycles (L1 hit)
- **1 shuffle** (AVX-512 `vpermb`): ~1 cycle throughput
- **1 bounds check** (`cmp len, 42; jb err`): ~0 cycles (fused with branch)

**Total: ~5 cycles, 3 instructions, 0 data-dependent branches.**

### Instruction Count Comparison (Measured)

| Parser | Instructions/pkt | Branches/pkt | Dependent loads |
|--------|-----------------|-------------|-----------------|
| Graph (`&dyn` dispatch + metadata) | 1066 | ~268 | 5+ (vtable + proto chain) |
| Compiled (full parse + metadata) | 160 | ~30 | 3 (ethertype → IHL → proto) |
| Template scalar (field extraction) | 7 | ~2 | 0 (all offsets constant) |
| Template AVX-512 (projected) | 2–3 | 0 | 0 |

### Measured Performance

| Configuration | ns/pkt | Mpps | Speedup vs compiled |
|--------------|--------|------|-------------------|
| Compiled (full parse + metadata) | 36 | 27 | 1.0x |
| Template scalar (field extraction) | 2 | 364 | **13.5x** |
| Template + batch AVX2 (8-wide) | 2 | 493 | **18.3x** |
| Template + batch AVX-512 (projected) | 1–2 | 2000–4000 | 74–148x |

**Important:** Template is not a parser — it performs fixed-offset field
extraction on NIC-pre-classified packets (7 ins/pkt vs 160 ins/pkt for
compiled parsing). The speedup reflects the elimination of all protocol
walking, not a parser optimization. Measured on 445K mixed-protocol packets.

The key advantage is not just fewer cycles — it is the **elimination of the
dependent-load chain**.  With no serial dependencies, the out-of-order engine
can overlap many packets simultaneously, and batch SIMD can process 8–16
packets per instruction.

---

## 6. Complementing the Existing AVX2 Batch Parser

The current `simd_batch.rs` (Step 11) processes 8 packets at a time, but it
still **walks the graph** — it gathers ethertypes, compares, gathers protocols,
compares, checks IHL, and falls back to scalar for divergent packets:

```
simd_batch.rs stages (lines 89–168):
  Stage 2: Gather ethertypes from 8 packets
  Stage 3: Compare ethertypes == 0x0800 (IPv4)
  Stage 4: Check IHL == 5 for each
  Stage 5: Check protocol is TCP/UDP/ICMP + leaf length
  Stage 6: Count successes + scalar fallback
```

This multi-stage gather-compare pipeline is the SIMD analogue of the scalar
graph walk — it just runs 8 copies in parallel.  It achieved 4 ns/pkt
(~2x slower than the compiled parser) because the gather overhead outweighs
the parallelism benefit for packets this small.

Template extraction **collapses stages 2–5 into nothing**.  When the NIC has
already classified the packet, there is no ethertype to check, no IHL to
validate, no protocol to branch on.  The entire pipeline reduces to:

```
Template + batch extraction:
  Stage 1: Bounds check (8 lengths vs template minimum, SIMD compare)
  Stage 2: Gather fields at fixed offsets (one vpgatherdd per field)
  Done.
```

The two techniques are **complementary**:

- **Template extraction** answers WHAT to extract (which offsets, which fields)
- **Batch SIMD** answers HOW to extract (vector operations across N packets)

Together:

```
  ┌──────────┐     ┌──────────────────┐     ┌───────────────────┐
  │ RX Queue │────▶│ Template Selector │────▶│ Batch Template    │
  │ (NIC)    │     │ (queue → offsets) │     │ Extractor (AVX2)  │
  └──────────┘     └──────────────────┘     └───────────────────┘
       │                    │                         │
  NIC classifies      Compile-time           8 packets × fixed
  and steers          offset table           offsets = 1 gather
                      selected               per field
```

---

## 7. Protocol Coverage Analysis

XDP2 defines 218 protocol implementations.  Template extraction applies to
**complete header stacks**, not individual protocols — the question is how
many distinct stack combinations have all-fixed-length headers where the
NIC can guarantee the type.

### Tier 1: Direct Template Extraction (~20 templates, ~90%+ of real traffic)

Stacks where every header is fixed-length and mainstream NICs can classify:

| Template | Bytes | Traffic share |
|----------|-------|--------------|
| Eth / IPv4(IHL=5) / TCP | 54 | Dominant (web, APIs, databases) |
| Eth / IPv4(IHL=5) / UDP | 42 | DNS, QUIC, gaming, video, syslog |
| Eth / IPv4(IHL=5) / ICMP | 42 | Monitoring, traceroute |
| Eth / IPv4(IHL=5) / SCTP | 46 | Telecom signaling (SS7-over-IP) |
| Eth / IPv6 / TCP | 74 | Growing — ~40% of internet traffic |
| Eth / IPv6 / UDP | 62 | DNS over IPv6, QUIC |
| Eth / IPv6 / ICMPv6 | 62 | Neighbor Discovery, MLD |
| Eth / VLAN / IPv4 / TCP | 58 | Enterprise, data center |
| Eth / VLAN / IPv4 / UDP | 46 | |
| Eth / VLAN / IPv6 / TCP | 78 | |
| Eth / VLAN / IPv6 / UDP | 66 | |
| Eth / QinQ / IPv4 / TCP | 62 | Service provider |
| Eth / QinQ / IPv4 / UDP | 50 | |
| Eth / ARP | 42 | Control plane |
| Eth / LACP | 124 | Link aggregation (fixed TLV) |
| Eth / LLDP (fixed subset) | 14 + fixed TLVs | Discovery |
| Eth / IPv4 / UDP-Lite | 42 | Streaming media |
| Eth / IPv6 / SCTP | 66 | Telecom over IPv6 |

These ~20 templates cover the vast majority of packets in virtually any
deployment: enterprise, data center, ISP, mobile core, cloud.

### Tier 2: Fixed-Length Tunnels (~15 templates)

When the NIC classifies both the outer tunnel type and inner packet type.
All offsets remain compile-time constants because the tunnel headers are
fixed-length:

| Template | Bytes | Use case |
|----------|-------|----------|
| Eth / IPv4 / UDP / VXLAN / Eth / IPv4 / TCP | 108 | Data center overlay |
| Eth / IPv4 / UDP / VXLAN / Eth / IPv4 / UDP | 96 | DC overlay (DNS, QUIC) |
| Eth / IPv4 / UDP / VXLAN / Eth / IPv6 / TCP | 128 | DC overlay (IPv6 inner) |
| Eth / IPv4 / GRE(no flags) / IPv4 / TCP | 78 | Site-to-site VPN |
| Eth / IPv4 / GRE(no flags) / IPv4 / UDP | 66 | |
| Eth / IPv4 / IP-in-IP / TCP | 74 | Encapsulation |
| Eth / IPv4 / IP-in-IP / UDP | 62 | |
| Eth / IPv4 / UDP / MPLS / IPv4 / TCP | ~112 | MPLS-over-UDP |
| Eth / IPv4 / UDP / GTP-U / IPv4 / TCP | ~100 | 5G mobile core |
| Eth / IPv4 / UDP / GTP-U / IPv4 / UDP | ~88 | 5G mobile core (QUIC) |
| Eth / IPv4 / UDP / GTP-U / IPv6 / TCP | ~120 | 5G dual-stack |
| Eth / IPv4 / UDP / Geneve(no opts) / Eth / IPv4 / TCP | ~116 | Geneve overlay |
| Eth / IPv4 / ESP / IPv4 / TCP | ~82 | IPsec tunnel mode |

Maximum depth: **L2 → L3 → L4 → Tunnel → inner L2 → inner L3 → inner L4**
(7 layers, up to ~128 bytes = 2 cache lines).

NIC classification for tunnels varies:
- Intel E810 (ice): native VXLAN, Geneve, GTP-U inner flow steering
- Mellanox ConnectX-5/6: VXLAN, GRE, Geneve via `rte_flow`
- Intel X710: VXLAN, GRE/NVGRE (limited inner field matching)

### Tier 3: Constrained Variable Headers (~5–10 additional)

Variable-length protocols that the NIC filter can constrain to a fixed layout:

| Constraint | NIC support | Notes |
|-----------|-------------|-------|
| IPv4 IHL=5 (no options) | Intel i40e/ice, mlx5 (byte match on IP[0] = 0x45) | Covers ~99% of IPv4 traffic |
| GRE with key but no checksum/seq | Some NICs match GRE flags byte | Common in cloud (NVGRE uses key) |
| MPLS 1 label (bottom-of-stack = 1) | Limited NIC support | Single-label MPLS |

### Not Feasible (~180 protocols)

| Category | Count | Why |
|----------|-------|-----|
| **Variable-length headers** | ~17 | IPv4 options, IPv6 extension header chains, TCP options, Geneve with TLV options, GRE with variable flags, AH (variable auth data), DCCP — offsets depend on runtime field values |
| **Application-layer** | ~30 | HTTP, DNS records, TLS, QUIC frames, RADIUS, Diameter — content-dependent parsing; NICs do not classify at this layer |
| **Management / control** | ~78 | LLDP TLV chains, BFD, CFM, OAM, spanning tree, PTP with TLVs — variable-length TLV structures |
| **Non-Ethernet link layers** | ~30 | Bluetooth (HCI, L2CAP, BNEP), InfiniBand (LRH, BTH, RDETH), CAN bus, IEEE 802.11 — different physical/link layer, not delivered via NIC ntuple classification |
| **Deeply nested tunnels** | ~25 | Tunnel-in-tunnel, SRv6 with multiple segments, GTP-U with extension headers — combinatorial explosion of possible layouts; NIC classification impractical beyond 1 tunnel layer |

### Coverage Summary

```
  ┌─────────────────────────────────────────────────────┐
  │              XDP2 Protocol Universe (218)            │
  │                                                     │
  │   ┌───────────────────────────────────────┐         │
  │   │  Template-feasible (~35-40 templates) │ ◀── 90%+│
  │   │                                       │   of    │
  │   │   Tier 1: L2+L3+L4 (~20)            │   real  │
  │   │   Tier 2: Tunnels  (~15)            │   pkts  │
  │   │   Tier 3: Constrained (~5-10)       │         │
  │   └───────────────────────────────────────┘         │
  │                                                     │
  │   Remaining ~180: graph-walk fallback       ◀── <10%│
  │   (variable headers, app-layer, non-Eth)     of pkts│
  └─────────────────────────────────────────────────────┘
```

**Key insight:** ~35 templates cover >90% of real-world traffic by volume.
The remaining 180 protocols are long-tail — they matter for completeness
(and XDP2 parses them all via the graph engine) but represent a small
fraction of packets in most deployments.

### How Deep Can We Go?

| Depth | Example | Template feasibility |
|-------|---------|---------------------|
| L2 → L3 → L4 | Eth/IPv4/TCP | Full coverage (Tier 1) |
| L2 → VLAN → L3 → L4 | Eth/VLAN/IPv4/UDP | Full coverage (Tier 1) |
| L2 → L3 → L4 → Tunnel → L2 → L3 → L4 | Eth/IPv4/UDP/VXLAN/Eth/IPv4/TCP | Feasible for fixed-length tunnels (Tier 2) |
| Beyond 1 tunnel layer | Tunnel-in-tunnel | Diminishing returns — NIC classification impractical, template > 2 cache lines |
| Application layer | HTTP, TLS, DNS records | Not feasible — content-dependent, no NIC classification |

---

## 8. Implementation Plan

Proposed as **Step 12a–f** in the
[performance tracking table](./performance-maximization-plan.md#tracking-table).

| Step | Description | Deliverable | Depends on |
|------|------------|-------------|------------|
| **12a** | `PacketTemplate` struct + compile-time offset tables | `template.rs` in xdp2-core | — |
| **12b** | Scalar template extractor — single bounds check + fixed-offset reads | `template_extract.rs` | 12a |
| **12c** | `--mode template` in xdp2-bench, benchmark vs compiled | bench integration | 12b |
| **12d** | Batch template extractor (AVX2 / AVX-512) | `template_simd.rs` | 12a, 12c |
| **12e** | Queue-template binding for AF_XDP integration | AF_XDP config | 12b, Step 7 |
| **12f** | NIC configuration helper | `scripts/setup-queue-templates.sh` | 12e |

### 12a: PacketTemplate Struct

```rust
/// A packet template: compile-time-constant field offsets for a known
/// header stack.  No branches, no graph walk — just a flat offset table.
pub struct PacketTemplate {
    pub name: &'static str,         // e.g., "eth_ipv4_tcp"
    pub min_length: usize,          // single bounds check
    pub fields: &'static [FieldDef],
}

pub struct FieldDef {
    pub name: &'static str,
    pub offset: usize,
    pub length: usize,
}

/// Compile-time templates for common stacks.
pub const ETH_IPV4_TCP: PacketTemplate = PacketTemplate {
    name: "eth_ipv4_tcp",
    min_length: 54,
    fields: &[
        FieldDef { name: "dst_mac",      offset: 0,  length: 6 },
        FieldDef { name: "src_mac",      offset: 6,  length: 6 },
        FieldDef { name: "ethertype",    offset: 12, length: 2 },
        FieldDef { name: "ip_src",       offset: 26, length: 4 },
        FieldDef { name: "ip_dst",       offset: 30, length: 4 },
        FieldDef { name: "tcp_src_port", offset: 34, length: 2 },
        FieldDef { name: "tcp_dst_port", offset: 36, length: 2 },
        // ...
    ],
};
```

### 12b: Scalar Template Extractor

```rust
/// Extract fields using a template.  One bounds check, then fixed-offset reads.
#[inline]
pub fn extract_template(pkt: &[u8], tmpl: &PacketTemplate) -> Result<(), ParseError> {
    if pkt.len() < tmpl.min_length {
        return Err(ParseError::Length);
    }
    // At this point, all field reads are within bounds — no further checks needed.
    // The caller can read any field at its known offset.
    Ok(())
}
```

### 12d: Batch Template Extractor (sketch)

```rust
/// Extract a specific field from 8 packets at a known offset using AVX2 gather.
#[target_feature(enable = "avx2")]
unsafe fn gather_field_u32(
    ptrs: &[*const u8; 8],
    offset: usize,
) -> __m256i {
    // Build index vector: each lane points to ptr[i] + offset
    let indices = _mm256_set_epi32(
        ptrs[7].add(offset) as i32,
        ptrs[6].add(offset) as i32,
        ptrs[5].add(offset) as i32,
        ptrs[4].add(offset) as i32,
        ptrs[3].add(offset) as i32,
        ptrs[2].add(offset) as i32,
        ptrs[1].add(offset) as i32,
        ptrs[0].add(offset) as i32,
    );
    // Gather 8 × 32-bit values from scattered addresses
    let mask = _mm256_set1_epi32(-1);
    _mm256_mask_i32gather_epi32::<1>(_mm256_setzero_si256(), std::ptr::null(), indices, mask)
}
```

With AF_XDP's contiguous UMEM, the gather indices become simple arithmetic
(base + packet_index × frame_size + field_offset), enabling true hardware
gather with scale factors — far more efficient than the scattered-pointer
approach above.

---

## 9. Testing Approach

### Unit Tests
- Template extractor produces identical field values to the compiled parser
  (`graph_compiled.rs`) for every matching packet in the test PCAPs.
- Templates cover: Eth/IPv4/TCP, Eth/IPv4/UDP, Eth/IPv6/TCP, Eth/VLAN/IPv4/TCP,
  Eth/ARP, and at least one tunnel template (VXLAN).

### Edge Cases
- Minimum-length packet for each template (exactly `min_length` bytes)
- One byte short (must return `ParseError::Length`)
- Trailing garbage (extra bytes after valid headers — must still parse correctly)
- Wrong-type packet on a classified queue (optional: 2-instruction ethertype/proto
  safety check, not required for correctness if NIC is configured correctly)

### Benchmarks
- `--mode template`: scalar template vs compiled parser (expect 1.7–2.4x speedup)
- `--mode template-simd`: batch AVX2 template vs batch SIMD walk (expect 4–8x speedup)
- Perf counters: verify 0 branch misses, reduced instruction count
- Synthetic PCAPs: per-template homogeneous traffic for clean A/B comparison

### Integration Tests (hardware, when AF_XDP is available)
- Configure ntuple rules → verify packets arrive on expected queues
- Template extraction on classified queue → verify field correctness vs tcpdump
- Traffic generator (e.g., TRex, pktgen) at line rate → measure real throughput

---

## 10. Open Questions and Risks

| Risk | Impact | Mitigation |
|------|--------|-----------|
| **IPv4 options (IHL != 5)** | Template offsets wrong for L4+ fields | NIC filter constrains IHL=5; optional 1-instruction check (`if pkt[14] != 0x45 { fallback }`) |
| **VLAN tags shift all offsets** | IPv4 starts at 18 instead of 14 | Separate templates for tagged vs untagged; NIC steers each to different queues |
| **TCP options (data offset > 5)** | Template works for TCP header itself; payload offset varies | Template extracts TCP header at fixed offset; payload start derived from data_offset if needed |
| **Variable-length tunnels** | GRE with flags, Geneve with options, GTP-U with extensions | Constrain to fixed-length variants (GRE no flags = 4B, Geneve no opts = 8B, GTP-U basic = 8B); fallback for others |
| **AVX-512 availability** | AMD Zen 2/3 lack AVX-512; Zen 4+ has it | AVX2 as primary target, AVX-512 as optional fast path; scalar always available |
| **AVX-512 frequency throttling** | Some Intel CPUs (Skylake-SP era) throttle core frequency when executing heavy AVX-512 | Profile with `perf stat` to detect throttling; benchmark with and without AVX-512 to confirm net benefit |
| **NIC filter limitations** | Not all NICs can match on all fields; Broadcom lacks direct IHL filter | Document per-NIC capabilities; degrade gracefully to compiled parser when NIC cannot guarantee classification |
| **Wrong-type packet on classified queue** | NIC misclassification, late rule update, or configuration error | Optional 2-instruction safety check (ethertype + proto); log and fallback to graph parser |

---

## 11. Relationship to Performance Plan

This is proposed as **Step 12** in the
[performance maximization plan](./performance-maximization-plan.md).

**Dependencies:**
- Step 9 (compiled parser) — the baseline to beat (2 ns/pkt, 12 cycles)
- Step 11 (batch SIMD prototype) — provides the SIMD infrastructure and
  batch processing patterns that template extraction builds on
- Step 7 (AF_XDP) — required for queue-template binding in production;
  not required for benchmarking

**Relationship to existing steps:**
- Template extraction is the logical successor to the compiled parser (Step 9):
  the compiler generated optimal code for the graph walk; templates eliminate
  the walk itself.
- The AVX2 batch SIMD (Step 11) demonstrated that batch processing works but
  is bottlenecked by the multi-stage gather-compare pipeline.  Templates
  remove that bottleneck.
- Together, Steps 9 + 11 + 12 form a performance hierarchy:
  1. **Graph parser** — universal, handles all protocols with metadata extraction (~174 ns/pkt at scale)
  2. **Compiled parser** — auto-generated, same work as graph, no vtable overhead (~36 ns/pkt)
  3. **Template extraction** — hardware-classified field extraction, not parsing (~2 ns/pkt measured, ~0.5–1 ns/pkt projected with AVX-512)
