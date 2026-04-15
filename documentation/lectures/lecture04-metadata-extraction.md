# Lecture 4: Metadata Extraction and Advanced Node Types

## 4.1 Metadata Architecture

XDP2 uses a structured metadata buffer that the programmer defines. The buffer
has two regions:

```
+--------------------------------------------------+
| Metadata Buffer                                   |
+--------------------+-----------------------------+
| MetaMeta Data      | Common to all layers         |
| (metameta_size)    | (e.g., packet hash, flags)   |
+--------------------+-----------------------------+
| Frame 0            | Outermost headers' data      |
| (frame_size)       | (Eth, IPv4, TCP fields)      |
+--------------------+-----------------------------+
| Frame 1            | First encapsulation          |
| (frame_size)       | (inner headers' data)        |
+--------------------+-----------------------------+
| Frame 2            | Second encapsulation         |
| (frame_size)       | (if present)                 |
+--------------------+-----------------------------+
| ...                | Up to max_frames              |
+--------------------------------------------------+
```

<img src="../images/Metadata-frames.jpg" alt="Metadata frames"/>

*A metadata buffer with metameta data followed by three frames.*

The parser engine maintains a `frame` pointer that starts at
`metadata + metameta_size` and advances by `frame_size` each time an
encapsulation protocol is encountered.

## 4.2 The `extract_metadata` Callback

Each parse node can define an `extract_metadata` callback that copies protocol
fields from the packet header into the current metadata frame. The signature
([parser_types.h:222--224](../src/include/xdp2/parser_types.h)):

```c
void (*extract_metadata)(const void *hdr,        /* Header pointer */
                         size_t hdr_len,          /* Header length */
                         void *metadata,          /* MetaMeta pointer */
                         void *frame,             /* Current frame */
                         const struct xdp2_ctrl_data *ctrl);
```

A typical implementation (from
[samples/parser/ports_parser/parser.c:58--66](../samples/parser/ports_parser/parser.c)):

```c
static void ipv4_metadata(const void *v, size_t hdr_len, void *_meta,
                           void *frame, const struct xdp2_ctrl_data *ctrl)
{
    struct my_metadata *metadata = _meta;
    const struct iphdr *iph = v;

    metadata->src_addr = iph->saddr;
    metadata->dst_addr = iph->daddr;
}
```

## 4.3 Canned Metadata Templates

Writing metadata extraction callbacks by hand for every protocol is tedious.
XDP2 provides **canned templates** in
[src/include/xdp2/parser_metadata.h](../src/include/xdp2/parser_metadata.h)
that generate standard extraction functions:

```c
/* Generate an Ethernet metadata extraction function */
XDP2_METADATA_TEMP_ether(func_name, metadata_struct_type)

/* Generate an IPv4 metadata extraction function */
XDP2_METADATA_TEMP_ipv4(func_name, metadata_struct_type)

/* Generate an IPv6 metadata extraction function */
XDP2_METADATA_TEMP_ipv6(func_name, metadata_struct_type)

/* Generate a ports (TCP/UDP) metadata extraction function */
XDP2_METADATA_TEMP_ports(func_name, metadata_struct_type)
```

These templates expect the metadata structure to have specific field names
(e.g., `addr_type`, `addrs`, `src_port`, `dst_port`). The built-in
`struct xdp2_metadata_all` provides all required fields and is used by most
samples.

## 4.4 TLV Parsing

*Type-Length-Value* (TLV) tuples are a common networking construct for
variable-length optional data. Examples include TCP options, IPv4 options, and
IPv6 extension headers.

<img src="../images/TLVs parsing.png" alt="TLVs parsing logic flow"/>

*Logic flow for parsing a list of TLVs.*

### TLV Data Structures

TLV parsing introduces three new structures (defined in
[src/include/xdp2/tlvs.h](../src/include/xdp2/tlvs.h)):

**1. TLVs protocol definition** (`struct xdp2_proto_tlvs_def`): Extends the
base protocol definition with TLV-specific operations:
- `tlv_len(tlv)` -- returns the length of one TLV
- `tlv_type(tlv)` -- returns the type code of one TLV
- `tlv_data_offset(tlv)` -- returns the offset to the TLV's data
- `pad1_val`, `eol_val` -- special padding and end-of-list values

**2. TLVs parse node** (`struct xdp2_parse_tlvs_node`): Extends the base
parse node with:
- A TLV table for looking up TLV types
- A wildcard TLV node for unknown types
- Maximum TLV count and length limits

**3. TLV parse node** (`struct xdp2_parse_tlv_node`): Describes processing for
one TLV type, with optional `extract_metadata` and `handle_tlv` callbacks.

### The TLV Parsing Loop

The TLV parsing function `xdp2_parse_tlvs` in
[parser.c:97](../src/lib/xdp2/parser.c) iterates through TLV data within a
protocol header:

```
for each TLV in the options area:
    1. Check for padding (pad1_val) -- skip single-byte padding
    2. Check for end-of-list (eol_val) -- stop processing
    3. Read TLV type via tlv_type()
    4. Read TLV length via tlv_len()
    5. Validate length against remaining data
    6. Look up TLV type in the TLV table
    7. If found: call extract_metadata and handle_tlv on the TLV node
    8. Advance by TLV length
```

<img src="../images/TLVs parser example.png" alt="TLV nodes example"/>

*Example nodes for parsing TCP options as TLVs.*

### Creating TLV Nodes

```c
/* A leaf parse node with TLVs (e.g., TCP with options) */
XDP2_MAKE_LEAF_TLVS_PARSE_NODE(tcp_node, xdp2_parse_tcp_tlvs, tcp_tlv_table,
    (.ops.extract_metadata = extract_ports), ());

/* A TLV parse node for one specific option */
XDP2_MAKE_TLV_PARSE_NODE(tcp_opt_timestamp_node,
    xdp2_parse_tcp_option_timestamp,
    (.tlv_ops.extract_metadata = extract_tcp_timestamp));

/* TLV table mapping option types to TLV nodes */
XDP2_MAKE_TLV_TABLE(tcp_tlv_table,
    ( TCPOPT_TIMESTAMP, tcp_opt_timestamp_node )
);
```

## 4.5 Flag-Fields Parsing

*Flag-fields* encode optional data using a set of flags and corresponding
data fields. The flags indicate which fields are present; fields are fixed-size
and ordered by flag position. Examples: GRE, GUE.

<img src="../images/Flag-fields parsing.png" alt="Flag-fields parsing"/>

*Logic flow for parsing a set of flag-fields.*

### Flag-Fields Data Structures

Defined in [src/include/xdp2/flag_fields.h](../src/include/xdp2/flag_fields.h):

**`struct xdp2_flag_field`**: Describes one possible flag:
- `flag` -- the flag bit value
- `mask` -- mask to apply when testing
- `size` -- byte size of the corresponding data field

**`struct xdp2_flag_fields`**: An array of `xdp2_flag_field` entries for one
protocol.

A flag-field is matched when `(flags & entry->mask) == entry->flag`. The
parsing loop scans entries in order, and when a match is found, the
corresponding data field is processed through a flag-field node.

<img src="../images/Flag-fields parser example.png" alt="Flag-fields example"/>

*Flag-field nodes for parsing GRE flag-fields.*

## 4.6 Array Parsing

*Arrays* encode repeated fixed-size elements. Examples: SRv6 segment lists,
where each segment is a 128-bit IPv6 address.

Defined in [src/include/xdp2/arrays.h](../src/include/xdp2/arrays.h):

**`struct xdp2_proto_array_def`**: Extends the base protocol definition with:
- `num_els(hdr)` -- returns the number of array elements
- `start_offset(hdr)` -- returns the offset to the first element
- `el_type(element)` -- returns the type of an element
- `el_length` -- fixed size of each element

The parsing loop iterates through elements, looks up each element's type in an
array table, and processes matching nodes.

<img src="../images/Array parser example.png" alt="Array parsing example"/>

*Array parse nodes for SRv6 segment list.*

## 4.7 Exercise

Write a parser that handles TCP with timestamp and MSS options. You will need:
1. A `tcp_node` using `XDP2_MAKE_LEAF_TLVS_PARSE_NODE`
2. TLV nodes for timestamps and MSS
3. Metadata structure fields for both options
4. A TLV table mapping `TCPOPT_TIMESTAMP` and `TCPOPT_MSS`

Refer to
[samples/xdp/flow_tracker_tlvs/parser.c](../samples/xdp/flow_tracker_tlvs/parser.c)
for a complete example.

---

[< Lecture 3: The Runtime Parsing Engine -- Walking the Graph](lecture03-runtime-engine.md) | [Table of Contents](README.md) | [Lecture 5: The Optimizing Compiler -- From Graph to Linear Code >](lecture05-compiler.md)
