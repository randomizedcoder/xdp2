# Lecture 7: Worked Examples -- Packets Walking the Parse Graph

This lecture traces real packets through XDP2 parsers step by step, showing
exactly which bytes are read, which callbacks fire, and what ends up in the
metadata buffer.

## 7.1 Example 1: IPv4/TCP through `ports_parser`

We use the simplest parser from
[samples/parser/ports_parser/parser.c](../samples/parser/ports_parser/parser.c).

### The Parser

```c
struct my_metadata {
    __be32 src_addr, dst_addr;
    __be16 src_port, dst_port;
};

XDP2_MAKE_PARSE_NODE(ether_node, xdp2_parse_ether, ether_table, ());
XDP2_MAKE_PARSE_NODE(ipv4_node, xdp2_parse_ipv4, ip_table,
                     (.ops.extract_metadata = ipv4_metadata));
XDP2_MAKE_LEAF_PARSE_NODE(tcp_node, xdp2_parse_tcp_notlvs,
                          (.ops.extract_metadata = ports_metadata));

XDP2_MAKE_PROTO_TABLE(ether_table, ( ETH_P_IP, ipv4_node ));
XDP2_MAKE_PROTO_TABLE(ip_table, ( IPPROTO_TCP, tcp_node ),
                                ( IPPROTO_UDP, udp_node ));
```

### The Packet (74 bytes)

Consider a standard TCP SYN packet from 10.0.2.15:44188 to 10.0.2.15:80:

```
Offset  Hex                                              ASCII
------  -----------------------------------------------  ----------------
0x0000  08 00 27 8a 8d 14 52 54  00 12 35 02 08 00 45 00  ..'...RT..5...E.
0x0010  00 3c 1a 2b 40 00 40 06  1c 89 0a 00 02 0f 0a 00  .<.+@.@.........
0x0020  02 0f ac 8c 00 50 00 00  00 00 00 00 00 00 a0 02  .....P..........
0x0030  fa f0 b0 fe 00 00 02 04  05 b4 04 02 08 0a 70 7c  ..............p|
0x0040  e0 fd 00 00 00 00 01 03  03 07                    ..........
```

### Step-by-Step Trace

**Step 1: `ether_node`** (Ethernet, offset 0x0000)

```
Bytes 0x0000-0x000D: Ethernet header (14 bytes)
+--------+--------+--------+--------+--------+--------+
| Dst MAC: 08:00:27:8a:8d:14                           |
+--------+--------+--------+--------+--------+--------+
| Src MAC: 52:54:00:12:35:02                           |
+--------+--------+--------+--------+--------+--------+
| EtherType: 08 00 (0x0800 = IPv4)                     |
+--------+--------+--------+--------+--------+--------+
```

- `proto_def = xdp2_parse_ether`
- `min_len = 14`, `len = 74` -- OK
- `ops.len = NULL` -- use `min_len` (14 bytes)
- `extract_metadata = NULL` -- no metadata extracted
- `ops.next_proto = ether_proto(hdr)` -- reads bytes 12-13 (`08 00`)
  -- returns `0x0800` (network byte order)
- Lookup `0x0800` in `ether_table` -- **found: `ipv4_node`**
- Advance: `hdr += 14`, `len = 60`

**Step 2: `ipv4_node`** (IPv4, offset 0x000E)

```
Bytes 0x000E-0x0021: IPv4 header (20 bytes, IHL=5)
+--------+
| 45     | Version=4, IHL=5 (20 bytes)
+--------+--------+
| 00 3c  | Total length = 60
+--------+--------+
| ...    | ID, flags, fragment offset, TTL
+--------+
| 06     | Protocol = 6 (TCP)  ← next_proto reads this
+--------+--------+
| ...    | Header checksum
+--------+--------+--------+--------+
| 0a 00 02 0f                       | Src IP: 10.0.2.15
+--------+--------+--------+--------+
| 0a 00 02 0f                       | Dst IP: 10.0.2.15
+--------+--------+--------+--------+
```

- `proto_def = xdp2_parse_ipv4`
- `min_len = 20`, `len = 60` -- OK
- `ops.len = ipv4_length(hdr)` -- reads IHL field (5), returns `5 * 4 = 20`
- `20 >= 20` (min_len check) -- OK
- **`extract_metadata = ipv4_metadata(hdr, 20, metadata, frame, ctrl)`**
  - `metadata->src_addr = iph->saddr` -- copies `0a 00 02 0f` (10.0.2.15)
  - `metadata->dst_addr = iph->daddr` -- copies `0a 00 02 0f` (10.0.2.15)
- `ops.next_proto = ipv4_proto(hdr)` -- reads protocol byte (`06`)
  - Not a fragment, returns `6` (IPPROTO_TCP)
- Lookup `6` in `ip_table` -- **found: `tcp_node`**
- Advance: `hdr += 20`, `len = 40`

**Step 3: `tcp_node`** (TCP, offset 0x0022) -- **LEAF NODE**

```
Bytes 0x0022-0x0025: First 4 bytes of TCP header
+--------+--------+
| ac 8c  | Src port: 44172  ← ports_metadata reads this
+--------+--------+
| 00 50  | Dst port: 80     ← ports_metadata reads this
+--------+--------+
```

- `proto_def = xdp2_parse_tcp_notlvs`
- `min_len = 20`, `len = 40` -- OK
- **`extract_metadata = ports_metadata(hdr, 20, metadata, frame, ctrl)`**
  - `metadata->src_port = ports[0]` -- copies `ac 8c` (44172 in host order)
  - `metadata->dst_port = ports[1]` -- copies `00 50` (80 in host order)
- `proto_table = NULL`, `wildcard_node = NULL` -- **LEAF NODE**
- Return `XDP2_STOP_OKAY`

### Final Metadata State

```
struct my_metadata {
    src_addr = 0x0a00020f   (10.0.2.15)
    dst_addr = 0x0a00020f   (10.0.2.15)
    src_port = 0xac8c       (44172)
    dst_port = 0x0050       (80)
};
```

Output: `Packet 0: 10.0.2.15:44172 -> 10.0.2.15:80`

## 7.2 Example 2: IPv6/TCP with TLV Options through `simple_parser`

We use the parser from
[samples/parser/simple_parser/parser_notmpl.c](../samples/parser/simple_parser/parser_notmpl.c)
which handles dual-stack and TCP timestamp options.

### The Parser

```c
XDP2_MAKE_PARSE_NODE(ether_node, xdp2_parse_ether, ether_table, ());
XDP2_MAKE_PARSE_NODE(ipv4_node, xdp2_parse_ipv4, ip_table,
                     (.ops.extract_metadata = extract_ipv4));
XDP2_MAKE_PARSE_NODE(ipv6_node, xdp2_parse_ipv6, ip_table,
                     (.ops.extract_metadata = extract_ipv6));
XDP2_MAKE_LEAF_PARSE_NODE(ports_node, xdp2_parse_ports,
                          (.ops.extract_metadata = extract_ports));
XDP2_MAKE_LEAF_TLVS_PARSE_NODE(tcp_node, xdp2_parse_tcp_tlvs, tcp_tlv_table,
                               (.ops.extract_metadata = extract_ports), ());

XDP2_MAKE_TLV_PARSE_NODE(tcp_opt_timestamp_node,
                         xdp2_parse_tcp_option_timestamp,
                         (.tlv_ops.extract_metadata = extract_tcp_timestamp));

XDP2_MAKE_PROTO_TABLE(ether_table,
    ( ETH_P_IP, ipv4_node ),
    ( ETH_P_IPV6, ipv6_node )
);
XDP2_MAKE_PROTO_TABLE(ip_table,
    ( IPPROTO_TCP, tcp_node ),
    ( IPPROTO_UDP, ports_node )
);
XDP2_MAKE_TLV_TABLE(tcp_tlv_table,
    ( TCPOPT_TIMESTAMP, tcp_opt_timestamp_node )
);
```

### The Packet (94 bytes)

An IPv6/TCP packet from `::1` port 51648 to `::1` port 631, with TCP
timestamp option:

```
Offset  Hex
------  -----------------------------------------------
0x0000  00 00 00 00 00 00 00 00  00 00 00 00 86 dd 60 00  Ethernet (EtherType 0x86dd = IPv6)
0x0010  00 00 00 28 06 40 00 00  00 00 00 00 00 00 00 00  IPv6 (next=6/TCP, payload=40)
0x0020  00 00 00 00 00 01 00 00  00 00 00 00 00 00 00 00  IPv6 src/dst = ::1
0x0030  00 00 00 00 00 01 c9 c0  02 77 00 00 00 00 00 00  TCP (src=51648, dst=631)
0x0040  00 00 a0 12 ff ff fe 34  00 00 02 04 ff d7 04 02  TCP hdr (doff=10 → 40 bytes)
0x0050  08 0a 70 7c e0 fd 00 00  00 00 01 03 03 07        TCP options
```

### Step-by-Step Trace

**Step 1: `ether_node`** (offset 0x0000, len=94)

- `min_len = 14`, OK
- `ether_proto(hdr)` reads bytes 12-13: `86 dd` = `0x86DD` (IPv6)
- Lookup `0x86DD` in `ether_table` -- **found: `ipv6_node`**
- Advance: `hdr += 14`, `len = 80`

**Step 2: `ipv6_node`** (offset 0x000E, len=80)

- `min_len = 40` (sizeof(struct ipv6hdr)), `len = 80` -- OK
- `ops.len = NULL` -- fixed 40-byte header
- **`extract_ipv6(hdr, 40, metadata, frame, ctrl)`**
  - `metadata->ip_proto = nexthdr` = `6` (TCP)
  - `metadata->addr_type = XDP2_ADDR_TYPE_IPV6`
  - `metadata->addrs.v6.saddr = ::1`
  - `metadata->addrs.v6.daddr = ::1`
- `ipv6_proto(hdr)` returns `6` (IPPROTO_TCP)
- Lookup `6` in `ip_table` -- **found: `tcp_node`**
- Advance: `hdr += 40`, `len = 40`

**Step 3: `tcp_node`** (offset 0x0036, len=40) -- **TLVs LEAF NODE**

- `min_len = 20`, `len = 40` -- OK
- TCP data offset field (byte 12, upper nibble) = `0xa` = 10, so
  header length = `10 * 4 = 40` bytes
- **`extract_ports(hdr, 40, metadata, frame, ctrl)`**
  - `metadata->port_pair.sport = ports[0]` = `0xc9c0` (51648)
  - `metadata->port_pair.dport = ports[1]` = `0x0277` (631)

Now the TLV sub-loop begins, processing TCP options from byte 20 to byte 40
(20 bytes of options):

```
TCP Options area (offsets relative to TCP header start):
Offset  Hex     Meaning
------  ------  ---------------------------------
20      02 04   MSS option: kind=2, len=4
22      ff d7   MSS value = 65495
24      04 02   SACK Permitted: kind=4, len=2
26      08 0a   Timestamp: kind=8, len=10
28-2f   70 7c e0 fd 00 00 00 00  TSval, TSecr
30      01      NOP (padding, kind=1 = pad1)
31      03 03   Window Scale: kind=3, len=3
33      07      Shift count = 7
```

**TLV iteration:**

1. **TLV at offset 20**: `kind = 2` (MSS), `len = 4`
   - Lookup `2` in `tcp_tlv_table` -- **not found** (only timestamp is mapped)
   - Skip by length (4 bytes)

2. **TLV at offset 24**: `kind = 4` (SACK Permitted), `len = 2`
   - Lookup `4` in `tcp_tlv_table` -- **not found**
   - Skip by length (2 bytes)

3. **TLV at offset 26**: `kind = 8` (Timestamp), `len = 10`
   - Lookup `8` in `tcp_tlv_table` -- **found: `tcp_opt_timestamp_node`**
   - **`extract_tcp_timestamp(opt, 10, metadata, frame, ctrl)`**
     - `metadata->tcp_options.timestamp.value = ntohl(0x707ce0fd)` = 1887469821
     - `metadata->tcp_options.timestamp.echo = ntohl(0x00000000)` = 0
   - Skip by length (10 bytes)

4. **TLV at offset 36**: `kind = 1` (NOP)
   - This is `pad1_val` -- single byte padding, skip 1 byte

5. **TLV at offset 37**: `kind = 3` (Window Scale), `len = 3`
   - Lookup `3` in `tcp_tlv_table` -- **not found**
   - Skip by length (3 bytes)

6. **Offset 40**: Reached end of options area. TLV loop complete.

- `tcp_node` is a leaf -- return `XDP2_STOP_OKAY`

### Final Metadata State

```
struct metadata {
    tcp_options.timestamp.value = 1887469821
    tcp_options.timestamp.echo  = 0
    addr_type   = XDP2_ADDR_TYPE_IPV6
    ip_proto    = 6
    port_pair   = { sport: 51648, dport: 631 }
    addrs.v6    = { saddr: ::1, daddr: ::1 }
};
```

### Metadata Buffer Filling (Step by Step)

```
After ether_node:   [ all zeros -- no extract_metadata ]
After ipv6_node:    [ addr_type=IPv6, ip_proto=6, addrs=::1/::1 ]
After tcp_node:     [ + sport=51648, dport=631 ]
After TLV loop:     [ + timestamp.value=1887469821, timestamp.echo=0 ]
```

## 7.3 Comparing: Canned Templates vs Hand-Written

The `flow_tracker_combo` sample
([samples/xdp/flow_tracker_combo/parser.c](../samples/xdp/flow_tracker_combo/parser.c))
achieves the same dual-stack parsing as `simple_parser` but uses canned
metadata templates instead of hand-written extract functions:

```c
/* Hand-written (simple_parser) */
static void extract_ipv4(const void *viph, size_t hdr_len, void *_meta,
                         void *frame, const struct xdp2_ctrl_data *ctrl)
{
    struct metadata *metadata = _meta;
    const struct iphdr *iph = viph;
    metadata->ip_proto = iph->protocol;
    metadata->addr_type = XDP2_ADDR_TYPE_IPV4;
    metadata->addrs.v4.saddr = iph->saddr;
    metadata->addrs.v4.daddr = iph->daddr;
}

/* Canned template (flow_tracker_combo) -- generates equivalent code */
XDP2_METADATA_TEMP_ipv4(ipv4_metadata, xdp2_metadata_all)
```

The canned template generates the same operations but requires using the
standard `xdp2_metadata_all` structure. Hand-written callbacks give you
complete control over the metadata layout.

---

[< Lecture 6: The XDP/eBPF Target -- Kernel-Space Parsing](lecture06-xdp-ebpf.md) | [Table of Contents](README.md) | [Lecture 8: Testing and Clean-Room Reimplementation Guide >](lecture08-testing.md)
