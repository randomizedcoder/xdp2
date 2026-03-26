# Field Matching & Comparison

## Matching Strategy

Fields from different sources are matched by **bit offset + size**, not by name.
Names vary across sources (kernel's `saddr` vs scapy's `src` vs tshark's `ip.src`),
but the wire layout is ground truth.

### Match Types

1. **Exact structural match**: Same `offset_bits` AND `size_bits` in both sources.
   The field occupies the same position in the header — this is the primary agreement metric.

2. **Overlap match**: Bit ranges overlap but sizes differ. This indicates different
   field-splitting choices (e.g., kernel's single `frag_off` u16 vs scapy's separate
   `flags` 3-bit + `frag` 13-bit fields). Reported as "SPLIT".

3. **Missing**: A field exists in one source but has no counterpart (exact or overlapping)
   in the other. Reported as a presence mismatch.

## Structural vs Semantic Agreement

The comparator distinguishes two levels of agreement:

### Structural Agreement (`sources_structural`)

Sources agree on **where the field is** — same bit offset and size. This means the
wire format is consistent. Even if one source calls a port field `Uint` and another
calls it `Enum`, they agree on the bytes.

### Semantic Agreement (`sources_agree`)

Sources agree on **everything** — offset, size, type, AND endianness. This is full
consensus including type annotations.

### Why the Distinction Matters

Type inference is inherently subjective. Different sources may classify the same
field differently — for example, one might call a protocol number field `Uint`
while another calls it `Enum`. Both are correct descriptions of the same bytes
at the same offset. Conflating this with a genuine layout disagreement (different
offsets or sizes) would make the audit useless.

The TOML-based type mapping system (`mappings/*.toml`) reduces these false
differences by aligning type inference across sources. For example, kernel field
name overrides (like `protocol` → Enum) and Scapy's deliberate non-mapping of
`ShortEnumField` (ports are Uint, not Enum) eliminate most type-diff findings
for core protocols.

The matrix and findings reports use structural agreement as the primary metric:
- **Agree**: All sources structurally and semantically match
- **TYPE_DIFF**: Structural match, but type/endian annotations differ (informational)
- **SPLIT**: Sources disagree on field boundaries (genuine structural difference)
- **PARTIAL**: Some sources lack the field entirely

## Zero-Field Source Handling

Some sources (notably XDP2) reference a protocol without defining fields — they
store a kernel struct name but don't parse the struct's fields themselves. These
sources are:

- **Included** in `sources_present` (shown in the matrix as `0*`)
- **Excluded** from field-level comparison (the unified field map)

Without this filtering, a zero-field source would cause every field to generate
a `presence:missing` mismatch, making Agree=0 for all protocols XDP2 references.

## Audit Algorithm

The `audit_protocol` function uses a **unified field map** rather than a single
reference source:

1. **Index all fields** from all sources into `BTreeMap<(offset, size), Vec<(source, field)>>`
2. **For each slot**: compare type/endian across all sources present at that position
3. **Detect overlaps**: find fields from other sources whose bit ranges overlap this slot
4. **Missing fields**: sources that have no field (exact or overlapping) at this position

This avoids reference-source bias. If sources B and C both define a field that source A
lacks, they are compared against each other directly — not reported as two separate
"missing from A" entries.

## Report Columns

### Matrix (`matrix` command)

| Column | Meaning |
|---|---|
| kernel/scapy/tshark/xdp2 | Number of fields this source structurally matches |
| Agree | Fields where all present sources fully agree (structural + semantic) |
| TDiff | Fields with structural match but type/endian annotation differences |
| Split | Fields where sources disagree on boundaries |
| Miss. | Fields present in some sources but absent in others |

### Findings (`findings` command)

The findings report has five sections:

1. **XDP2 Coverage** — which protocols XDP2 supports
2. **Field Layout Disagreements** — different field sizes at the same offset
3. **Coverage Gaps** — protocols with only one external source
4. **Type/Endian Annotation Differences** — informational, not bugs
5. **Field Boundary Disagreements** — genuine structural splits

## Environment Variables

The Nix wrapper sets defaults via `PROTO_AUDIT_*` env vars. Override any source path:

```bash
PROTO_AUDIT_KERNEL_SRC=/custom/linux nix run .#proto-audit -- extract --source kernel --proto IPv4
```

| Variable | Description |
|---|---|
| `PROTO_AUDIT_PROTO_DEFS_DIR` | XDP2 proto_defs directory |
| `PROTO_AUDIT_KERNEL_SRC` | Linux kernel source tree |
| `PROTO_AUDIT_PCAP` | PCAP file for tshark |
| `PROTO_AUDIT_SCAPY_HELPER` | Path to scapy_dump.py |
| `PROTO_AUDIT_PYTHON` | Python binary (with scapy) |
| `PROTO_AUDIT_TSHARK_BIN` | tshark binary |
| `PROTO_AUDIT_MAPPINGS_DIR` | Directory with override TOML mapping files |
