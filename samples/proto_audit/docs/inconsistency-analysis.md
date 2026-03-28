# Inconsistency Analysis

proto-audit detects two types of cross-source disagreements: **field splits**
(different granularity) and **type differences** (same layout, different
classification). This document explains *why* these disagreements exist by
walking through concrete protocols.

## Root-Cause Taxonomy

Every disagreement falls into one of five categories:

### 1. Granularity Choice (22 protocols)

One source represents a header region as a single field while another breaks
it into sub-fields. Neither is wrong — they reflect different design goals.
Kernels optimize for fast access to the combined value; dissectors optimize
for human-readable display of each sub-field.

*Example:* kernel's `frag_off` (16 bits) vs Scapy's `flags` (3) + `frag` (13).

### 2. Semantic Classification (11 protocols)

Sources agree on a field's bit position and size but classify it differently.
This usually means one source treats the field as an IANA-registered
enumeration (`Enum`) while another treats it as a plain integer (`Uint`).

*Example:* kernel classifies `nexthdr` as `Enum` (via TOML override); Scapy
uses `ByteField` which maps to `Uint`.

### 3. Extraction Limitation

The source's native format lacks information that other sources provide.
This is a tooling constraint, not a disagreement about the protocol.

*Example:* tshark's PDML output is byte-aligned — it cannot represent
sub-byte fields like IPv4's 4-bit version. etherparse's Rust structs omit
`version` and `ihl` because they're implicit in the parsing logic.

### 4. Protocol Design Ambiguity

The RFC itself allows multiple valid interpretations. Different codebases
chose different valid readings.

*Example:* ARP (RFC 826) defines hardware and protocol addresses as
variable-length fields. Kernel's `struct arphdr` only includes the 5 fixed
fields before the addresses. Scapy and tshark include the address fields
with Ethernet/IPv4-specific sizes hardcoded.

### 5. Missing IETF Specification

No machine-readable format for protocol headers exists. Each codebase
independently translates RFC prose into code, inevitably making different
decisions about naming, typing, and granularity. This is the underlying
cause that proto-audit exists to measure. See
[IR as Standard](ir-as-standard.md) for a proposed solution.

## Showcase Protocols

### IPv4 — Best-Covered (6 sources, 12 IR fields)

IPv4 is the most cross-referenced protocol, with definitions in all six
sources. Of its 12 canonical fields, only 3 achieve full agreement.

**Granularity splits:**

| Region | kernel | scapy | tshark | etherparse |
|--------|--------|-------|--------|------------|
| offset 0–7 | `version` (4) + `ihl` (4) | `version` (4) + `ihl` (4) | merged (8) | implicit (skipped) |
| offset 48–63 | `frag_off` (16) | `flags` (3) + `frag` (13) | `flags` (3) + `frag_offset` (13) | `dont_fragment` (1) + `more_fragments` (1) + `fragment_offset` (13) |

Root cause: The kernel stores flags and fragment offset as a single `__be16`
because that's how the wire format packs them. Dissectors and packet
libraries split them for usability. etherparse goes further, exposing
individual flag bits as `bool` fields.

**Naming divergence (not a split, but illustrative):**

| Field | kernel | scapy | tshark | etherparse |
|-------|--------|-------|--------|------------|
| Total length | `tot_len` | `len` | `ip.len` | `total_len` |
| Source address | `saddr` | `src` | `ip.src` | `source` |
| Checksum | `check` | `chksum` | `ip.checksum` | `header_checksum` |

The IR preserves all four names in `source_names` and matches fields by
(offset, size), making naming irrelevant for comparison.

### TCP — Most Splits (15 disagreements)

TCP's 20-byte header has the widest split count, driven by flag representation:

| Region | kernel | scapy | tshark |
|--------|--------|-------|--------|
| offset 96–99 | `doff` (4) | `dataofs` (4) | merged with reserved (8) |
| offset 100–103 | `res1` (4) | `reserved` (3) | (merged above) |
| offset 103 | — | — | — |
| offset 104–111 | 8 individual bitfields: `cwr`, `ece`, `urg`, `ack`, `psh`, `rst`, `syn`, `fin` | `flags` (8) | `flags` (8) |

Root cause: Kernel exposes each TCP flag as a 1-bit bitfield in `struct
tcphdr` for efficient `if (th->syn)` checks. Scapy packs all flags into one
8-bit `FlagsField` with named bits. tshark goes further, merging
data_offset + reserved + flags into fewer PDML fields.

### ARP — Protocol Design Ambiguity (9 splits)

ARP (RFC 826) is unusual: its header contains variable-length address fields
whose size is determined by earlier fields (`ar_hln`, `ar_pln`).

| Source | Fields | How it handles addresses |
|--------|--------|------------------------|
| kernel | 5 | `struct arphdr` ends before addresses (variable-length) |
| scapy | 9 | Hardcodes Ethernet (6-byte) + IPv4 (4-byte) addresses |
| tshark | 9 | Same as Scapy — assumes Ethernet/IPv4 |
| etherparse | 3 | Only fixed fields (hw_addr_type, proto_addr_type, operation) |
| libpcap | 2 | BPF gencode only needs src_addr + dst_addr offsets |

Root cause: The kernel is *correct* — ARP addresses are genuinely
variable-length. But in practice, ARP is used almost exclusively with
Ethernet/IPv4, so Scapy and tshark hardcode those sizes. This is a valid
engineering trade-off, not a bug.

### VLAN — All Three Root Causes

VLAN (IEEE 802.1Q) is a compact 4-byte header that triggers granularity,
type, and extraction-limitation disagreements simultaneously:

| Region | kernel | scapy | tshark | libpcap |
|--------|--------|-------|--------|---------|
| TCI (16 bits) | `h_vlan_TCI`: Flags | `prio` (3) + `id` (1) + `vlan` (12): Uint | `tci` (16): Uint | `vlan_tci`: Flags |
| EtherType (16 bits) | — | `type`: Uint | `type`: Uint | `vlan_tpid`: Enum |

- **Granularity**: Scapy splits TCI into priority + DEI + VID; kernel and
  libpcap keep it as one 16-bit field.
- **Semantic classification**: Kernel and libpcap classify TCI as `Flags`;
  Scapy classifies its sub-fields as `Uint`.
- **Type difference**: libpcap classifies the TPID as `Enum` (it selects
  from a small set of values); Scapy uses `Uint`.

## Statistics by Root Cause

Aggregated from all 22 split and 11 type-difference protocols:

| Root Cause | Split Protocols | Type-Diff Protocols | Total |
|-----------|----------------|-------------------|-------|
| Granularity choice | 22 | — | 22 |
| Semantic classification | — | 11 | 11 |
| Extraction limitation | (contributes to splits) | — | — |
| Protocol design ambiguity | 3 (ARP, AH, SRv6) | — | 3 |
| Missing IETF spec | (underlying cause of all) | (underlying cause of all) | — |

Note: Categories overlap. ARP's 9 splits are caused by *both* protocol
design ambiguity (variable-length addresses) and granularity choice (how
many fields to expose). The missing-IETF-spec category is the root cause
of all disagreements — if a machine-readable format existed, codebases
would converge on it rather than independently interpreting RFC prose.

## Further Reading

- [Mapping Pipeline](mapping-pipeline.md) — how sources are extracted and
  how the TOML rules that drive type inference work
- [IR as Standard](ir-as-standard.md) — positioning the IR as the
  machine-readable format that could reduce these inconsistencies
- [Coverage](proto-audit-coverage.md) — full per-protocol source coverage
  matrix and field split/type difference details
- [Field Matching](field-matching.md) — how the comparator detects splits
  and type differences
