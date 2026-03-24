[Back to Summary](../SUMMARY.md)

## Code Comparison

### Lines of Code

| Component | Kernel | xdp2 |
|---|---|---|
| Core flow dissector logic | 2,101 ([flow_dissector.c](https://github.com/torvalds/linux/blob/master/net/core/flow_dissector.c)) | 895 (parser.c + 11 header fragments — 14 parsers, ~65 protocol types) |
| BPF program | 437 ([bpf_flow.c](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_flow.c)) | 266 (flow_dissector.bpf.c) |
| **Total parsing code** | **2,538** | **1,161** |
| Reduction | -- | **~2.2x fewer lines** |

> **Note:** The xdp2 parser definition totals 895 lines across parser.c
> (116-line orchestrator) and 11 `#include`'d header fragments. The multi-graph
> expansion added 12 new parse graphs for non-Ethernet protocol families
> (WiFi 802.11, Bluetooth HCI, InfiniBand, CAN bus, Netlink, IEEE 802.15.4,
> Phonet, MCTP, ATM, X.25), plus 7 flow dissector parity gap closures and
> 15 new L2 ethertype entries. The Ethernet/IP flow dissector portion alone
> remains ~400 lines — the additional lines are entirely non-Ethernet
> protocol coverage that the kernel flow dissector does not attempt.

### What the xdp2 parser.c Looks Like

The entire parser definition is a set of declarations. No control flow, no
pointer arithmetic, no bounds checking:

```c
/* Metadata extractors: one line per protocol */
XDP2_METADATA_TEMP_ipv4(ipv4_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_ipv6(ipv6_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_ports(ports_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_icmp(icmp_metadata, xdp2_metadata_all)
/* ... 13 extractors total */

/* Parse nodes: bind protocol parsers to metadata extractors */
XDP2_MAKE_PARSE_NODE(ipv4_node, xdp2_parse_ipv4, ipv4_table,
                     (.ops.extract_metadata = ipv4_metadata));

/* Protocol tables: declarative dispatch */
XDP2_MAKE_PROTO_TABLE(ipv4_table,
    ( IPPROTO_TCP,  ports_node ),
    ( IPPROTO_UDP,  ports_node ),
    ( IPPROTO_ICMP, icmpv4_node ),
    ( IPPROTO_GRE,  gre_base_node ),
    /* ... */
);

/* Parser definition: one line */
XDP2_PARSER(xdp2_parser_flow_dissector, "XDP2 BPF flow dissector",
    ip_check_node,
    (.metameta_size = 0,
     .frame_size = sizeof(struct xdp2_metadata_all),
     .max_frames = 0));
```

All bounds checking, header length validation, protocol dispatch logic, and
pointer advancement are handled by the xdp2 framework and the pre-existing
protocol definitions in `xdp2/proto_defs/`.

### What the kernel's bpf_flow.c Looks Like

The kernel's BPF selftest
([bpf_flow.c](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_flow.c))
is hand-written BPF code with manual pointer arithmetic, bounds checking,
and tail calls for every protocol. Its `parse_ip_proto()` function (lines
[165--254](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_flow.c#L165))
handles each transport protocol with individual parsing code:

```c
/* From kernel bpf_flow.c lines 165-254 */
static __always_inline int parse_ip_proto(struct __sk_buff *skb, __u8 proto)
{
    struct bpf_flow_keys *keys = skb->flow_keys;
    void *data_end = (void *)(long)skb->data_end;
    struct icmphdr *icmp, _icmp;
    struct gre_hdr *gre, _gre;
    struct tcphdr *tcp, _tcp;
    struct udphdr *udp, _udp;

    switch (proto) {
    case IPPROTO_ICMP:
        icmp = bpf_flow_dissect_get_header(skb, sizeof(*icmp), &_icmp);
        if (!icmp)
            return export_flow_keys(keys, BPF_DROP);
        return export_flow_keys(keys, BPF_OK);
    case IPPROTO_IPIP:
        keys->is_encap = true;
        if (keys->flags & BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP)
            return export_flow_keys(keys, BPF_OK);
        return parse_eth_proto(skb, bpf_htons(ETH_P_IP));
    case IPPROTO_GRE:
        gre = bpf_flow_dissect_get_header(skb, sizeof(*gre), &_gre);
        if (!gre)
            return export_flow_keys(keys, BPF_DROP);
        if (bpf_htons(gre->flags & GRE_VERSION))
            return export_flow_keys(keys, BPF_OK);
        keys->thoff += sizeof(*gre);
        if (GRE_IS_CSUM(gre->flags))
            keys->thoff += 4;
        if (GRE_IS_KEY(gre->flags))
            keys->thoff += 4;
        if (GRE_IS_SEQ(gre->flags))
            keys->thoff += 4;
        keys->is_encap = true;
        /* ... dispatch on gre->proto ... */
    case IPPROTO_TCP:
        tcp = bpf_flow_dissect_get_header(skb, sizeof(*tcp), &_tcp);
        if (!tcp)
            return export_flow_keys(keys, BPF_DROP);
        if (tcp->doff < 5)
            return export_flow_keys(keys, BPF_DROP);
        keys->sport = tcp->source;
        keys->dport = tcp->dest;
        return export_flow_keys(keys, BPF_OK);
    case IPPROTO_UDP:
        udp = bpf_flow_dissect_get_header(skb, sizeof(*udp), &_udp);
        if (!udp)
            return export_flow_keys(keys, BPF_DROP);
        keys->sport = udp->source;
        keys->dport = udp->dest;
        return export_flow_keys(keys, BPF_OK);
    }
}
```

Every new protocol requires adding manual parsing code, bounds checks, and
dispatch logic. In xdp2, adding a protocol is a one-line table entry if the
protocol definition already exists.

### Protocol-by-Protocol Comparison

For each protocol, below is the kernel's hand-written code alongside xdp2's
declarative approach. The xdp2 framework provides reusable protocol definitions
(`xdp2_parse_*`) and metadata templates (`XDP2_METADATA_TEMP_*`) that
eliminate manual parsing entirely.

#### IPv4

**Kernel** ([bpf_flow.c lines 275--322](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_flow.c#L275)):
46 lines of manual parsing -- header pointer retrieval, IHL validation,
address extraction, fragment flag checking, thoff advancement:

```c
PROG(IP)(struct __sk_buff *skb)
{
    struct bpf_flow_keys *keys = skb->flow_keys;
    struct iphdr *iph, _iph;

    iph = bpf_flow_dissect_get_header(skb, sizeof(*iph), &_iph);
    if (!iph)
        return export_flow_keys(keys, BPF_DROP);
    if (iph->ihl < 5)
        return export_flow_keys(keys, BPF_DROP);

    keys->addr_proto = ETH_P_IP;
    keys->ipv4_src = iph->saddr;
    keys->ipv4_dst = iph->daddr;
    keys->ip_proto = iph->protocol;
    keys->thoff += iph->ihl << 2;

    if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
        keys->is_frag = true;
        if (iph->frag_off & bpf_htons(IP_OFFSET))
            done = true;
        else {
            keys->is_first_frag = true;
            if (!(keys->flags & BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG))
                done = true;
        }
    }
    /* ... */
}
```

**xdp2**: Zero lines of parsing code. The protocol definition and metadata
template handle everything:

```c
/* Protocol definition (proto_defs/proto_ipv4.h): */
static const struct xdp2_proto_def xdp2_parse_ipv4 = {
    .name = "IPv4",
    .min_len = sizeof(struct iphdr),    /* Automatic bounds check */
    .ops.len = ipv4_length,             /* IHL-based length */
    .ops.next_proto = ipv4_proto,       /* Extract protocol field */
};

/* Metadata template (parser_metadata.h) -- expands to a static function: */
XDP2_METADATA_TEMP_ipv4(ipv4_metadata, xdp2_metadata_all)
/* Automatically extracts: addr_type, saddr/daddr, ip_proto,
 * is_fragment, first_frag, l3_off */

/* User writes only this in parser.c: */
XDP2_MAKE_PARSE_NODE(ipv4_node, xdp2_parse_ipv4, ipv4_table,
                     (.ops.extract_metadata = ipv4_metadata));
```

**Why xdp2 is faster:** The framework performs a single bounds check
(`len < min_len`) and a single variable-length check via `ops.len`. The
kernel code does multiple separate checks (null pointer, IHL validation,
data bounds). The xdp2-compiler inlines the metadata extractor and
eliminates the function pointer overhead entirely in the optimized parser.

#### IPv6

**Kernel** ([bpf_flow.c lines 324--344](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_flow.c#L324)):
20 lines -- header access, address copy, flow label extraction, nexthdr dispatch:

```c
PROG(IPV6)(struct __sk_buff *skb)
{
    struct bpf_flow_keys *keys = skb->flow_keys;
    struct ipv6hdr *ip6h, _ip6h;

    ip6h = bpf_flow_dissect_get_header(skb, sizeof(*ip6h), &_ip6h);
    if (!ip6h)
        return export_flow_keys(keys, BPF_DROP);

    keys->addr_proto = ETH_P_IPV6;
    memcpy(&keys->ipv6_src, &ip6h->saddr, 2*sizeof(ip6h->saddr));
    keys->thoff += sizeof(struct ipv6hdr);
    keys->ip_proto = ip6h->nexthdr;
    keys->flow_label = ip6_flowlabel(ip6h);

    if (keys->flow_label && keys->flags & BPF_FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL)
        return export_flow_keys(keys, BPF_OK);

    return parse_ipv6_proto(skb, ip6h->nexthdr);
}
```

**xdp2**:

```c
/* Protocol definition (proto_defs/proto_ipv6.h): */
static const struct xdp2_proto_def xdp2_parse_ipv6 = {
    .name = "IPv6",
    .min_len = sizeof(struct ipv6hdr),  /* Fixed 40-byte header */
    .ops.next_proto = ipv6_proto,       /* Returns nexthdr */
};

/* Metadata template -- extracts addr_type, saddr/daddr, ip_proto,
 * flow_label, l3_off in a single function: */
XDP2_METADATA_TEMP_ipv6(ipv6_metadata, xdp2_metadata_all)

/* User writes: */
XDP2_MAKE_PARSE_NODE(ipv6_node, xdp2_parse_ipv6, ipv6_table,
                     (.ops.extract_metadata = ipv6_metadata));
```

**Why xdp2 is faster:** Fixed-length header means no `ops.len` call -- just
a single `len < 40` check. The `ipv6_proto()` helper is a trivial field
read. The optimized parser inlines both the bounds check and the 32-byte
`memcpy` for addresses.

#### TCP/UDP Ports

**Kernel** ([bpf_flow.c lines 226--248](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_flow.c#L226)):
Separate cases for TCP and UDP, with TCP-specific validation:

```c
case IPPROTO_TCP:
    tcp = bpf_flow_dissect_get_header(skb, sizeof(*tcp), &_tcp);
    if (!tcp)
        return export_flow_keys(keys, BPF_DROP);
    if (tcp->doff < 5)
        return export_flow_keys(keys, BPF_DROP);
    if ((__u8 *)tcp + (tcp->doff << 2) > data_end)
        return export_flow_keys(keys, BPF_DROP);
    keys->sport = tcp->source;
    keys->dport = tcp->dest;
    return export_flow_keys(keys, BPF_OK);
case IPPROTO_UDP:
case IPPROTO_UDPLITE:
    udp = bpf_flow_dissect_get_header(skb, sizeof(*udp), &_udp);
    if (!udp)
        return export_flow_keys(keys, BPF_DROP);
    keys->sport = udp->source;
    keys->dport = udp->dest;
    return export_flow_keys(keys, BPF_OK);
```

**xdp2**:

```c
/* Protocol definition: a single unified port reader for TCP/UDP/SCTP/DCCP */
static const struct xdp2_proto_def xdp2_parse_ports = {
    .name = "Transport with ports",
    .min_len = sizeof(struct port_hdr),  /* 4 bytes: src_port + dst_port */
};

/* Metadata: single 4-byte copy of the port pair */
XDP2_METADATA_TEMP_ports(ports_metadata, xdp2_metadata_all)
/* Expands to: frame->ports = ((struct port_hdr *)vhdr)->ports; */

/* All four protocols share one leaf node: */
XDP2_MAKE_LEAF_PARSE_NODE(ports_node, xdp2_parse_ports,
                          (.ops.extract_metadata = ports_metadata));
```

**Why xdp2 is faster:** TCP and UDP source/dest ports are at the same offset
in both headers. xdp2 reads them as a single 4-byte load. The kernel treats
TCP and UDP as separate cases with different struct types and validation.
xdp2 also avoids TCP `doff` validation here -- it's a leaf node that just
reads ports.

#### IPv6 Extension Headers

**Kernel** ([bpf_flow.c lines 346--361](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_flow.c#L346)):
Separate BPF tail-call program for hop-by-hop/destination/routing headers:

```c
PROG(IPV6OP)(struct __sk_buff *skb)
{
    struct bpf_flow_keys *keys = skb->flow_keys;
    struct ipv6_opt_hdr *ip6h, _ip6h;

    ip6h = bpf_flow_dissect_get_header(skb, sizeof(*ip6h), &_ip6h);
    if (!ip6h)
        return export_flow_keys(keys, BPF_DROP);

    keys->thoff += (1 + ip6h->hdrlen) << 3;
    keys->ip_proto = ip6h->nexthdr;

    return parse_ipv6_proto(skb, ip6h->nexthdr);
}
```

**xdp2**:

```c
/* Protocol definition (proto_defs/proto_ipv6_eh.h): */
static const struct xdp2_proto_def xdp2_parse_ipv6_eh = {
    .name = "IPv6 EH",
    .min_len = sizeof(struct ipv6_opt_hdr),
    .ops.next_proto = ipv6_eh_proto,     /* Returns nexthdr */
    .ops.len = ipv6_eh_len,              /* (1 + hdrlen) << 3 */
};

/* Metadata: just updates ip_proto to the next header value */
XDP2_METADATA_TEMP_ipv6_eh(ipv6_eh_metadata, xdp2_metadata_all)

/* Three protocols share one node (all chain back to ipv6_table): */
XDP2_MAKE_PARSE_NODE(ipv6_eh_node, xdp2_parse_ipv6_eh, ipv6_table,
                     (.ops.extract_metadata = ipv6_eh_metadata));
```

**Why xdp2 is faster:** The kernel uses a BPF tail call for each extension
header (context switch overhead). xdp2 chains extension headers through the
same dispatch table with zero-cost looping in the optimized parser.

#### IPv6 Fragment Header

**Kernel** ([bpf_flow.c lines 364--390](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_flow.c#L364)):
Another separate BPF tail-call program:

```c
PROG(IPV6FR)(struct __sk_buff *skb)
{
    struct bpf_flow_keys *keys = skb->flow_keys;
    struct frag_hdr *fragh, _fragh;

    fragh = bpf_flow_dissect_get_header(skb, sizeof(*fragh), &_fragh);
    if (!fragh)
        return export_flow_keys(keys, BPF_DROP);

    keys->thoff += sizeof(*fragh);
    keys->is_frag = true;
    keys->ip_proto = fragh->nexthdr;

    if (!(fragh->frag_off & bpf_htons(IP6_OFFSET))) {
        keys->is_first_frag = true;
        if (!(keys->flags & BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG))
            return export_flow_keys(keys, BPF_OK);
    } else {
        return export_flow_keys(keys, BPF_OK);
    }

    return parse_ipv6_proto(skb, fragh->nexthdr);
}
```

**xdp2**:

```c
/* Protocol definition: */
static const struct xdp2_proto_def xdp2_parse_ipv6_frag_eh = {
    .name = "IPv6 Frag EH",
    .min_len = sizeof(struct ipv6_frag_hdr),
    .ops.next_proto = ipv6_frag_proto,  /* Stops at non-first frags */
};

/* Metadata: sets ip_proto, is_fragment, first_frag */
XDP2_METADATA_TEMP_ipv6_frag(ipv6_frag_metadata, xdp2_metadata_all)

/* Separate node from regular EH because it needs different metadata: */
XDP2_MAKE_PARSE_NODE(ipv6_frag_node, xdp2_parse_ipv6_frag_eh, ipv6_table,
                     (.ops.extract_metadata = ipv6_frag_metadata));
```

**Why xdp2 is faster:** Same tail-call elimination advantage. The
`ipv6_frag_proto()` helper returns a negative code for non-first fragments,
which the framework translates into an early stop -- no manual flag checking.

#### GRE

**Kernel** ([bpf_flow.c lines 193--225](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_flow.c#L193),
also [flow_dissector.c lines 652--769](https://github.com/torvalds/linux/blob/master/net/core/flow_dissector.c#L652)):
The kernel's in-tree GRE dissector is 117 lines handling version detection,
flag-conditional optional fields (checksum, key, sequence), encapsulated
Ethernet, and PPTP:

```c
/* From flow_dissector.c __skb_flow_dissect_gre() -- 117 lines */
static enum flow_dissect_ret
__skb_flow_dissect_gre(const struct sk_buff *skb, ...)
{
    struct gre_base_hdr *hdr, _hdr;
    int offset = 0;
    u16 gre_ver;

    hdr = __skb_header_pointer(skb, *p_nhoff, sizeof(_hdr), ...);
    if (!hdr) return FLOW_DISSECT_RET_OUT_BAD;

    if (hdr->flags & GRE_ROUTING) return FLOW_DISSECT_RET_OUT_GOOD;

    gre_ver = ntohs(hdr->flags & GRE_VERSION);
    if (gre_ver > 1) return FLOW_DISSECT_RET_OUT_GOOD;

    *p_proto = hdr->protocol;
    offset += sizeof(struct gre_base_hdr);

    if (hdr->flags & GRE_CSUM)
        offset += 4;  /* checksum + padding */
    if (hdr->flags & GRE_KEY) {
        /* Read key, store in flow keys */
        const __be32 *keyid;
        keyid = __skb_header_pointer(skb, *p_nhoff + offset, ...);
        if (!keyid) return FLOW_DISSECT_RET_OUT_BAD;
        key_keyid->keyid = *keyid;
        offset += 4;
    }
    if (hdr->flags & GRE_SEQ)
        offset += 4;

    /* Handle GRE v0 vs v1 (PPTP), Ethernet-over-GRE, etc. */
    /* ... 50+ more lines ... */
}
```

**xdp2**: GRE is handled entirely through the flag-fields mechanism -- a
declarative way to describe variable-length headers with flag-conditional
optional fields:

```c
/* Protocol definitions (proto_defs/proto_gre.h): */

/* Base overlay: reads version field */
static const struct xdp2_proto_def xdp2_parse_gre_base = {
    .name = "GRE base",
    .overlay = 1,
    .min_len = sizeof(struct gre_hdr),
    .ops.next_proto = gre_proto_version,
};

/* GRE v0: flag-fields node handles optional fields declaratively */
static const struct xdp2_proto_flag_fields_def xdp2_parse_gre_v0 = {
    .proto_def.node_type = XDP2_NODE_TYPE_FLAG_FIELDS,
    .proto_def.name = "GRE v0",
    .proto_def.encap = 1,                    /* Marks encapsulation */
    .proto_def.min_len = sizeof(struct gre_hdr),
    .proto_def.ops.next_proto = gre_v0_proto,
    .proto_def.ops.len = gre_v0_len_check,
    .ops.get_flags = gre_get_flags,          /* Read flag bits */
    .ops.start_fields_offset = gre_fields_offset,
    .flag_fields = &gre_flag_fields,         /* Declarative field table */
};

/* Each optional field is a separate metadata node: */
XDP2_MAKE_FLAG_FIELD_PARSE_NODE(gre_flag_csum_node,
    (.ops.extract_metadata = gre_checksum_metadata));
XDP2_MAKE_FLAG_FIELD_PARSE_NODE(gre_flag_key_node,
    (.ops.extract_metadata = gre_keyid_metadata));
XDP2_MAKE_FLAG_FIELD_PARSE_NODE(gre_flag_seq_node,
    (.ops.extract_metadata = gre_seq_metadata));

/* Flag-fields dispatch table: */
XDP2_MAKE_FLAG_FIELDS_TABLE(gre_v0_flag_fields_table,
    ( GRE_FLAGS_CSUM_IDX, gre_flag_csum_node ),
    ( GRE_FLAGS_KEY_IDX,  gre_flag_key_node ),
    ( GRE_FLAGS_SEQ_IDX,  gre_flag_seq_node )
);
```

**Why xdp2 is faster:** The kernel manually checks each flag bit and
calculates offsets with arithmetic. xdp2's flag-fields mechanism is a
pre-defined table: the framework iterates set flag bits and applies the
corresponding field parsers. In the optimized parser, this entire dispatch
is inlined and the flag checks become direct bit tests with pre-computed
offsets.

#### VLAN (802.1Q / 802.1AD)

**Kernel** ([bpf_flow.c lines 404--435](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_flow.c#L404)):
A separate BPF tail-call program handles double-tagging:

```c
PROG(VLAN)(struct __sk_buff *skb)
{
    struct bpf_flow_keys *keys = skb->flow_keys;
    struct vlan_hdr *vlan, _vlan;

    /* Account for double-tagging */
    if (keys->n_proto == bpf_htons(ETH_P_8021AD)) {
        vlan = bpf_flow_dissect_get_header(skb, sizeof(*vlan), &_vlan);
        if (!vlan) return export_flow_keys(keys, BPF_DROP);
        if (vlan->h_vlan_encapsulated_proto != bpf_htons(ETH_P_8021Q))
            return export_flow_keys(keys, BPF_DROP);
        keys->nhoff += sizeof(*vlan);
        keys->thoff += sizeof(*vlan);
    }

    vlan = bpf_flow_dissect_get_header(skb, sizeof(*vlan), &_vlan);
    if (!vlan) return export_flow_keys(keys, BPF_DROP);
    keys->nhoff += sizeof(*vlan);
    keys->thoff += sizeof(*vlan);

    /* Reject triple tagging */
    if (vlan->h_vlan_encapsulated_proto == bpf_htons(ETH_P_8021AD) ||
        vlan->h_vlan_encapsulated_proto == bpf_htons(ETH_P_8021Q))
        return export_flow_keys(keys, BPF_DROP);

    keys->n_proto = vlan->h_vlan_encapsulated_proto;
    return parse_eth_proto(skb, vlan->h_vlan_encapsulated_proto);
}
```

**xdp2**: Two parse nodes share the same protocol definition and dispatch
table. QinQ double-tagging is handled by the parse graph recursion:

```c
/* Protocol definition (proto_defs/proto_vlan.h): */
static const struct xdp2_proto_def xdp2_parse_vlan = {
    .name = "VLAN",
    .min_len = sizeof(struct vlan_hdr),   /* 4 bytes */
    .ops.next_proto = vlan_proto,         /* Returns encapsulated ethertype */
};

/* Two separate nodes for 802.1Q and 802.1AD (different metadata): */
XDP2_MAKE_PARSE_NODE(e8021Q_node, xdp2_parse_vlan, ether_table,
                     (.ops.extract_metadata = e8021Q_metadata));
XDP2_MAKE_PARSE_NODE(e8021AD_node, xdp2_parse_vlan, ether_table,
                     (.ops.extract_metadata = e8021AD_metadata));

/* ether_table handles QinQ recursion naturally: */
XDP2_MAKE_PROTO_TABLE(ether_table,
    ( __cpu_to_be16(ETH_P_IP),     ip_check_node ),
    ( __cpu_to_be16(ETH_P_IPV6),   ip_check_node ),
    ( __cpu_to_be16(ETH_P_8021AD), e8021AD_node ),    /* Recurse for QinQ */
    ( __cpu_to_be16(ETH_P_8021Q),  e8021Q_node ),
    ( __cpu_to_be16(ETH_P_MPLS_UC), mpls_node ),
    ( __cpu_to_be16(ETH_P_MPLS_MC), mpls_node )
);
```

**Why xdp2 is faster:** The kernel uses an explicit tail call (expensive
context switch) and manually handles the double-tag case. xdp2 handles QinQ
through graph recursion -- the outer VLAN node dispatches to the ether_table,
which may dispatch to another VLAN node. In the optimized parser, this
becomes direct inlined code with no call overhead.

#### IP-in-IP / IPv6-in-IPv4

**Kernel** ([bpf_flow.c lines 181--192](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_flow.c#L181)):

```c
case IPPROTO_IPIP:
    keys->is_encap = true;
    if (keys->flags & BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP)
        return export_flow_keys(keys, BPF_OK);
    return parse_eth_proto(skb, bpf_htons(ETH_P_IP));
case IPPROTO_IPV6:
    keys->is_encap = true;
    if (keys->flags & BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP)
        return export_flow_keys(keys, BPF_OK);
    return parse_eth_proto(skb, bpf_htons(ETH_P_IPV6));
```

**xdp2**: Overlay nodes with encapsulation flag -- the framework recurses
back to the IP version check node:

```c
/* Protocol definitions (proto_defs/proto_ipv4ip.h, proto_ipv6ip.h): */
static const struct xdp2_proto_def xdp2_parse_ipv4ip = {
    .name = "IPv4 in IP",
    .encap = 1,            /* Marks as encapsulation layer */
    .overlay = 1,           /* Don't advance past header (it IS the inner IP) */
    .min_len = sizeof(struct iphdr),
};
static const struct xdp2_proto_def xdp2_parse_ipv6ip = {
    .name = "IPv6 in IP",
    .encap = 1,
    .overlay = 1,
    .min_len = sizeof(struct ipv6hdr),
};

/* Auto-next nodes: unconditionally proceed to the inner IP parser */
XDP2_MAKE_AUTONEXT_PARSE_NODE(ipv4ip_node, xdp2_parse_ipv4ip,
                              ipv4_node, ());
XDP2_MAKE_AUTONEXT_PARSE_NODE(ipv6ip_node, xdp2_parse_ipv6ip,
                              ipv6_node, ());
```

**Why xdp2 is faster:** The `overlay = 1` flag tells the framework not to
advance the header pointer -- the inner IP header starts at the same offset.
The `encap = 1` flag manages the encapsulation counter and frame advancement.
With `max_frames = 0`, inner metadata overwrites outer, giving the innermost
flow keys automatically.

#### ICMP / ICMPv6

**Kernel** ([bpf_flow.c lines 176--180](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_flow.c#L176)):

```c
case IPPROTO_ICMP:
    icmp = bpf_flow_dissect_get_header(skb, sizeof(*icmp), &_icmp);
    if (!icmp)
        return export_flow_keys(keys, BPF_DROP);
    return export_flow_keys(keys, BPF_OK);
```

Note: the kernel BPF selftest does not extract ICMP type/code/id. The
in-kernel flow_dissector.c does
([line 191](https://github.com/torvalds/linux/blob/master/net/core/flow_dissector.c#L191)).

**xdp2**: Leaf nodes that extract type, code, and ID:

```c
/* Metadata template extracts type, code, and ID (with echo detection): */
XDP2_METADATA_TEMP_icmp(icmp_metadata, xdp2_metadata_all)
/* Expands to:
 *   frame->icmp.type = icmp->type;
 *   frame->icmp.code = icmp->code;
 *   if (icmp_has_id(icmp->type))
 *       frame->icmp.id = icmp->un.echo.id;
 */

XDP2_MAKE_LEAF_PARSE_NODE(icmpv4_node, xdp2_parse_icmpv4,
                          (.ops.extract_metadata = icmp_metadata));
XDP2_MAKE_LEAF_PARSE_NODE(icmpv6_node, xdp2_parse_icmpv6,
                          (.ops.extract_metadata = icmp_metadata));
```

#### MPLS

**Kernel** ([bpf_flow.c lines 392--402](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_flow.c#L392)):

```c
PROG(MPLS)(struct __sk_buff *skb)
{
    struct mpls_label *mpls, _mpls;
    mpls = bpf_flow_dissect_get_header(skb, sizeof(*mpls), &_mpls);
    if (!mpls)
        return export_flow_keys(keys, BPF_DROP);
    return export_flow_keys(keys, BPF_OK);
}
```

**xdp2**:

```c
static const struct xdp2_proto_def xdp2_parse_mpls = {
    .name = "MPLS",
    .min_len = 2 * sizeof(struct mpls_label),
};

/* Metadata extracts label, TTL, TC, BOS, and entropy label: */
XDP2_METADATA_TEMP_mpls(mpls_metadata, xdp2_metadata_all)

XDP2_MAKE_LEAF_PARSE_NODE(mpls_node, xdp2_parse_mpls,
                          (.ops.extract_metadata = mpls_metadata));
```
