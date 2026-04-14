# Source Patching

proto-audit extends two third-party sources (etherparse and libpcap) with
**overlay struct patches** — small, per-protocol patch files that add struct
definitions for protocols not natively covered. This enables cross-source
comparison for hundreds of additional protocols beyond what each library
defines, including 27 trading protocols (ITCH v5, PITCH v2, SBE MDP3, EOBI,
SoupBinTCP) generated from OMI IR via the `gen-patches` pipeline.

## Why Patch?

etherparse natively defines 9 protocols (Ethernet, IPv4, IPv6, ARP, TCP,
UDP, VLAN, ICMPv4, ICMPv6). libpcap natively defines ~6 (SLL, SLL2, VLAN,
plus gencode offsets for IPv4/IPv6/TCP/UDP/ARP/SCTP). To compare these
sources against kernel, Scapy, and tshark for protocols like GRE, VXLAN,
MPLS, or NTP, we add overlay structs that define the wire format in each
source's native language (Rust for etherparse, C for libpcap).

Each overlay struct is a standalone file — one per protocol — applied as a
patch to the upstream source via Nix's `pkgs.applyPatches`. This keeps
patches small, reviewable, and suitable for upstream PRs where each protocol
typically has its own maintainer.

## Patch Architecture

```
patches/
  gen_fine_grained.py         # Legacy batch generator (PDML corpus → overlay structs)
  etherparse/                 # 332 Rust overlay struct patches
    gre.patch                 # → src/proto_audit/gre.rs
    vxlan.patch               # → src/proto_audit/vxlan.rs
    ...
    trading_itch_v5_addorder.patch     # → src/proto_audit/itch_v5_addorder.rs (from OMI IR)
    trading_eobi_v3_orderadd.patch     # → src/proto_audit/eobi_v3_orderadd.rs
    ...                                # 27 trading_*.patch files total
  libpcap/                    # 332 C header overlay struct patches
    gre.patch                 # → pcap/proto_audit/gre.h
    vxlan.patch               # → pcap/proto_audit/vxlan.h
    ...
    trading_itch_v5_addorder.patch     # → pcap/proto_audit/itch_v5_addorder.h
    trading_eobi_v3_orderadd.patch     # → pcap/proto_audit/eobi_v3_orderadd.h
    ...                                # 27 trading_*.patch files total
```

Each patch creates a single new file (`--- /dev/null` → `+++ b/path`),
making them order-independent and conflict-free. The Nix helper `patchesIn`
dynamically reads all `.patch` files from a directory:

```nix
patchesIn = dir:
  map (f: dir + "/${f}")
    (builtins.filter (f: pkgs.lib.hasSuffix ".patch" f)
      (builtins.attrNames (builtins.readDir dir)));

etherparseSrc = pkgs.applyPatches {
  src = pkgs.fetchFromGitHub { ... };
  patches = patchesIn ../samples/proto_audit/patches/etherparse;
};
```

Adding a new protocol is just adding a new `.patch` file — no Nix changes needed.

## Fine-Grained Field Analysis

The overlay structs use **RFC-level field granularity**, splitting coarse
combined fields into individual sub-fields. This was driven by an analysis
that found 22 coarse fields across 16 protocols where a single struct field
combined multiple distinct wire sub-fields.

### Before vs After

**GRE (RFC 2784) — etherparse overlay:**
```rust
// Before: 2 fields, coarse
pub struct GreHeader {
    pub flags_version: u16,     // ← 16 bits combining 6 distinct sub-fields
    pub protocol_type: u16,
}

// After: 7 fields, RFC-level
pub struct GreHeader {
    pub checksum_present: bool,   // bit 0
    pub reserved0: bool,          // bit 1
    pub key_present: bool,        // bit 2
    pub sequence_present: bool,   // bit 3
    pub reserved1: Bits9,         // bits 4-12
    pub version: Bits3,           // bits 13-15
    pub protocol_type: u16,       // bits 16-31
}
```

**MPLS (RFC 3032) — libpcap overlay:**
```c
// Before: coarse
struct mpls_header {
    uint32_t mpls_label_tc_s_ttl;   // ← 32 bits combining 4 sub-fields
};

// After: RFC-level with C bitfields
struct mpls_header {
    uint32_t mpls_label:20;
    uint32_t mpls_traffic_class:3;
    uint32_t mpls_bottom_of_stack:1;
    uint32_t mpls_ttl:8;
};
```

### Sub-Byte Type System

etherparse overlay structs use generic sub-byte Rust types for fields
smaller than 8 bits. These are mapped to wire bit widths in
`mappings/etherparse.toml`:

| Type | Wire Bits | Used By |
|------|-----------|---------|
| `bool` | 1 | GRE checksum_present, VXLAN vni_valid, L2TP msg_type, ... |
| `Bits2` | 2 | Geneve version, NTP leap_indicator, MACsec association_number |
| `Bits3` | 3 | GRE version, MPLS traffic_class, BFD version, VXLAN reserved |
| `Bits4` | 4 | PPPoE version/type, ERSPAN version, VXLAN reserved, PTP fields |
| `Bits5` | 5 | BFD diagnostic |
| `Bits6` | 6 | Geneve options_length, NSH ttl/length |
| `Bits7` | 7 | RTP payload_type |
| `Bits9` | 9 | GRE reserved1 |
| `Bits10` | 10 | ERSPAN session_id |
| `Bits12` | 12 | ERSPAN vlan/reserved, HSR lsdu_size |
| `Bits20` | 20 | MPLS label, ERSPAN index, CAN can_id (partial) |
| `Bits29` | 29 | CAN/CAN_FD can_id |

libpcap overlay structs use C bitfield syntax (`uint16_t field:N;`),
supported by the libpcap extractor's extended regex parser.

### Complete Coarse-to-Fine Summary

| Protocol | Source | Coarse Field | Fine-Grained Split | RFC |
|----------|--------|-------------|-------------------|-----|
| GRE | both | `flags_version` (16b) | checksum_present + reserved0 + key_present + sequence_present + reserved1 + version (1+1+1+1+9+3) | 2784 |
| VXLAN | both | `flags` (8b) | reserved_flags0 + vni_valid + reserved_flags1 (4+1+3) | 7348 |
| Geneve | both | `ver_opt_len` (8b) | version + options_length (2+6) | 8926 |
| Geneve | both | `flags_reserved` (8b) | oam + critical + reserved0 (1+1+6) | 8926 |
| MPLS | both | `label_tc_s_ttl` (32b) | label + traffic_class + bottom_of_stack + ttl (20+3+1+8) | 3032 |
| NVGRE | ep | `flags_version` (16b) | checksum_present + reserved0 + key_present + sequence_present + reserved1 + version (1+1+1+1+9+3) | 7637 |
| PPPoE | both | `ver_type` (8b) | version + pppoe_type (4+4) | 2516 |
| L2TP | both | `flags_version` (16b) | msg_type + length_present + reserved0 + sequence_present + reserved1 + offset_present + priority + reserved2 + version (1+1+2+1+1+1+1+4+4) | 2661 |
| ERSPAN | both | `ver_vlan` (16b), `cos_bso_t_session` (16b), `reserved_index` (32b) | version + vlan + cos + bso + truncated + session_id + reserved + index (4+12+3+2+1+10+12+20) | — |
| NSH | both | `ver_oam_ttl_len` (16b), `md_type_reserved` (8b) | version + oam + unused0 + ttl + length + unused1 + md_type (2+1+1+6+6+4+4) | 8300 |
| HSR | both | `path_lsdu` (16b) | path + lsdu_size (4+12) | IEC 62439-3 |
| NTP | both | `li_vn_mode` (8b) | leap_indicator + version + mode (2+3+3) | 5905 |
| RTP | ep | `vpxcc` (8b), `mpt` (8b) | version + padding + extension + csrc_count + marker + payload_type (2+1+1+4+1+7) | 3550 |
| BFD | ep | `ver_diag` (8b), `flags` (8b) | version + diagnostic + state + poll + final_flag + control_plane_independent + authentication_present + demand + multipoint (3+5+2+1+1+1+1+1+1) | 5880 |
| PTP | ep | fields (8b) | transport_specific + message_type + version_ptp + minor_version (4+4+4+4) | IEEE 1588 |
| DCCP | ep | `ccval_cscov` (8b), `type_x_res` (8b) | ccval + cscov + reserved + dccp_type + x (4+4+3+4+1) | 4340 |
| CAN | ep | `can_id` (32b) | can_id + err_flag + rtr_flag + eff_flag (29+1+1+1) | socketcan |
| CAN_FD | ep | `can_id` (32b) | can_id + err_flag + rtr_flag + eff_flag (29+1+1+1) | socketcan |
| MACsec | ep | `tci_an` (8b) | version + end_station + sci_present + scb + encryption + changed_text + association_number (1+1+1+1+1+1+2) | IEEE 802.1AE |

*ep = etherparse only, both = etherparse + libpcap*

## Generators

proto-audit has two patch generation paths:

### `gen-patches` — IR-driven (current)

The `gen-patches` subcommand walks the name-mapping table, extracts each
entry with the requested source, and pipes the IR through the existing
`generate_libpcap_patch` / `generate_etherparse_patch` generators.

```bash
nix run .#proto-audit -- gen-patches --target libpcap --source omi \
    --out samples/proto_audit/patches/libpcap/
nix run .#proto-audit -- gen-patches --target etherparse --source omi \
    --out samples/proto_audit/patches/etherparse/
```

Supported targets: `libpcap`, `etherparse`. Supported source: `omi` (the
only source currently wired for round-trip patch generation). Filter with
`--protos P1,P2` or preview with `--dry-run`. This is the pipeline that
produced the 27 `trading_*.patch` files.

### `gen_fine_grained.py` — legacy batch

`patches/gen_fine_grained.py` contains hand-curated struct definitions for
the older non-trading overlay set and generates their patches from a
Python dict source of truth:

```bash
cd samples/proto_audit/patches
python3 gen_fine_grained.py
```

Edit the `ETHERPARSE` / `LIBPCAP` lists in the script, then regenerate —
don't edit those `.patch` files directly.

## Relationship to Other Sources

### Why Not Patch the Kernel?

The Linux kernel UAPI headers are the **authoritative** upstream definitions.
Fields like `frag_off` (combining 3-bit flags + 13-bit offset) are deliberate
design choices for fast BPF access. proto-audit parses kernel headers as-is
and documents granularity differences as findings, rather than patching them.

### Why XDP2 Shows 0 Fields

XDP2 is an eBPF/XDP packet processing framework. Its `xdp2_proto_def` structs
define only metadata — protocol name, minimum length (via `sizeof(struct ...)`),
dispatch function, and length function. They reference kernel structs directly
via `#include <linux/ip.h>` and provide type-safe accessor functions for
packet parsing. Field-level definitions live in the kernel UAPI headers,
which proto-audit extracts separately via the kernel extractor.

In the matrix output, XDP2 shows `0*` (metadata present, zero fields) for
all protocols. This is by design — XDP2's role is protocol graph traversal
and BPF program generation, not field-level reflection.

## Upstream PR Workflow

The per-protocol patch architecture is designed for upstream contributions:

1. Each patch is a single self-contained file (one struct per protocol)
2. Patches target the correct subdirectory (`src/proto_audit/` for etherparse,
   `pcap/proto_audit/` for libpcap) to avoid conflicts with existing code
3. Each patch can be submitted independently to the upstream project
4. The proto-audit test suite validates that each overlay struct extracts
   correctly and matches other sources' field definitions

## Further Reading

- [Architecture](architecture.md) — system overview and data flow
- [Extractors](extractors.md) — per-source extractor details and TOML mappings
- [Nix Packaging](nix-packaging.md) — `patchesIn` helper and `applyPatches`
- [Adding a Source](adding-a-source.md) — how to add a new source
