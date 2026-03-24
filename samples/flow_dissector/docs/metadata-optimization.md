[Back to Summary](../SUMMARY.md)

## The Metadata Struct Size Problem

> **Status:** Not yet implemented. This is the single highest-impact
> optimization remaining — it would close the memset performance gap and
> make "with memset" numbers match flowdis.

The remaining performance gap between xdp2 "with memset" and flowdis comes
from the metadata struct sizes:

| Struct | Size | Used for |
|---|---|---|
| `struct xdp2_metadata_all` | ~200 bytes | xdp2 parser output |
| `struct flow_keys` (flowdis) | ~88 bytes | flowdis output |

The per-packet `memset` zeroing costs roughly 10--20 ns for
`xdp2_metadata_all` vs ~5 ns for `flow_keys`. This 10--15 ns difference
accounts for most of the gap between the "with memset" and "parse-only"
measurements.

### Current Structure: `struct xdp2_metadata_all` (~200 bytes)

This is the general-purpose metadata struct designed to hold metadata for
*any* protocol combination:

```c
struct xdp2_metadata_all {
    __u8  addr_type;                           /*   1 byte  -- NEEDED  */
    __u8  is_fragment : 1;                     /*           -- NEEDED  */
    __u8  first_frag  : 1;                     /*   1 byte  -- NEEDED  */
    __u8  vlan_count  : 2;                     /*   1 byte  -- NEEDED  */
    __u8  eth_addrs[12];                       /*  12 bytes -- unused  */
    struct {                                   /*           -- unused  */
        __u16 mss;                             /*                      */
        __u8  window_scaling;                  /*                      */
        struct { __u32 value, echo; } timestamp;                       /*
        struct { __u32 left, right; } sack[4]; /*                      */
    } tcp_options;                             /*  51 bytes -- unused  */
    struct {                                   /*           -- NEEDED  */
        __u32 ttl:8, bos:1, tc:3, label:20;   /*                      */
    } mpls;                                    /*   4 bytes -- NEEDED  */
    struct {                                   /*           -- unused  */
        __u32 sip, tip; __u8 op;               /*                      */
        __u8 sha[6], tha[6];                   /*                      */
    } arp;                                     /*  21 bytes -- unused  */
    struct {                                   /*           -- NEEDED  */
        __u32 flags; __be16 csum;              /*                      */
        __be32 keyid, seq, routing;            /*                      */
    } gre;                                     /*  18 bytes -- NEEDED  */
    struct {                                   /*           -- unused  */
        __u32 flags; __be16 length, callid;    /*                      */
        __be32 seq, ack;                       /*                      */
    } gre_pptp;                                /*  16 bytes -- unused  */
    __u16 l2_off;                              /*   2 bytes -- unused  */
    __u16 l3_off;                              /*   2 bytes -- NEEDED  */
    __u16 l4_off;                              /*   2 bytes -- unused  */
    __be16 eth_proto __aligned(8);             /*   8 bytes -- unused  */
                                               /*  (6 bytes padding)   */
    __u8  ip_proto;                            /*   1 byte  -- NEEDED  */
    __u32 flow_label;                          /*   4 bytes -- NEEDED  */
    struct { __u16 id:12, dei:1, priority:3;   /*                      */
             __be16 tpid;                      /*                      */
    } vlan[2];                                 /*   8 bytes -- NEEDED  */
    __be32 keyid;                              /*   4 bytes -- NEEDED  */
    union { __be32 ports; ... } port_pair;     /*   4 bytes -- NEEDED  */
    struct { __u8 type, code; __u16 id; } icmp;/*   4 bytes -- NEEDED  */
    union {                                    /*           -- NEEDED  */
        __be32 v4_addrs[2];                    /*   8 bytes (IPv4)     */
        struct in6_addr v6_addrs[2];           /*  32 bytes (IPv6)     */
    } addrs;  /* must be last */               /*  32 bytes -- NEEDED  */
};
/* Total: ~200 bytes. Unused fields: ~107 bytes (53%) */
```

### Proposed Structure: `struct flow_dissector_metadata` (~88 bytes)

Strip out the unused fields (`tcp_options`, `arp`, `gre_pptp`, `eth_addrs`,
`l2_off`, `l4_off`, `eth_proto`), keeping only what the flow dissector's
metadata extractors actually write to:

```c
struct flow_dissector_metadata {
    __u8  addr_type;                           /*   1 byte             */
    __u8  is_fragment : 1;                     /*                      */
    __u8  first_frag  : 1;                     /*   1 byte             */
    __u8  vlan_count  : 2;                     /*   1 byte             */
                                               /*                      */
    /* No eth_addrs (12 bytes saved) */        /*                      */
    /* No tcp_options (51 bytes saved) */       /*                      */
                                               /*                      */
    struct {                                   /*                      */
        __u32 ttl:8, bos:1, tc:3, label:20;   /*                      */
    } mpls;                                    /*   4 bytes            */
                                               /*                      */
    /* No arp (21 bytes saved) */               /*                      */
                                               /*                      */
    struct {                                   /*                      */
        __u32 flags; __be16 csum;              /*                      */
        __be32 keyid, seq, routing;            /*                      */
    } gre;                                     /*  18 bytes            */
                                               /*                      */
    /* No gre_pptp (16 bytes saved) */         /*                      */
    /* No l2_off (2 bytes saved) */            /*                      */
                                               /*                      */
    __u16 l3_off;                              /*   2 bytes            */
                                               /*                      */
    /* No l4_off (2 bytes saved) */            /*                      */
    /* No eth_proto + padding (8 bytes saved) */
                                               /*                      */
    __u8  ip_proto;                            /*   1 byte             */
    __u32 flow_label;                          /*   4 bytes            */
    struct { __u16 id:12, dei:1, priority:3;   /*                      */
             __be16 tpid;                      /*                      */
    } vlan[2];                                 /*   8 bytes            */
    __be32 keyid;                              /*   4 bytes            */
    union { __be32 ports; ... } port_pair;     /*   4 bytes            */
    struct { __u8 type, code; __u16 id; } icmp;/*   4 bytes            */
    union {                                    /*                      */
        __be32 v4_addrs[2];                    /*   8 bytes (IPv4)     */
        struct in6_addr v6_addrs[2];           /*  32 bytes (IPv6)     */
    } addrs;  /* must be last */               /*  32 bytes            */
};
/* Total: ~88 bytes -- comparable to flowdis's struct flow_keys (88 bytes) */
```

### Changes Required

1. **Define `struct flow_dissector_metadata`** in `common.h`. Field names
   must match exactly what the `XDP2_METADATA_TEMP_*` macros use, since they
   reference fields by name (e.g., `frame->addr_type`, `frame->addrs.v4_addrs`,
   `frame->gre.keyid`). The field types and union layouts must also match.

2. **Change the STRUCT parameter** on metadata extractor instantiations in
   `flow_dissector_metadata.h`. The `XDP2_METADATA_TEMP_*` templates are
   parameterized by struct type -- this is the only code change in the
   parser definition:
   ```c
   /* Before (200 bytes): */
   XDP2_METADATA_TEMP_ipv4(ipv4_metadata, xdp2_metadata_all)
   XDP2_METADATA_TEMP_ipv6(ipv6_metadata, xdp2_metadata_all)
   XDP2_METADATA_TEMP_ports(ports_metadata, xdp2_metadata_all)
   /* ... 13 extractors ... */

   /* After (88 bytes): */
   XDP2_METADATA_TEMP_ipv4(ipv4_metadata, flow_dissector_metadata)
   XDP2_METADATA_TEMP_ipv6(ipv6_metadata, flow_dissector_metadata)
   XDP2_METADATA_TEMP_ports(ports_metadata, flow_dissector_metadata)
   /* ... 13 extractors ... */
   ```

3. **Update the parser definition** in `flow_dissector_parsers.h`:
   ```c
   XDP2_PARSER(xdp2_parser_flow_dissector, "XDP2 BPF flow dissector",
       ip_check_node,
       (.metameta_size = 0,
        .frame_size = sizeof(struct flow_dissector_metadata),  /* was xdp2_metadata_all */
        .max_frames = 0));
   ```

4. **Update `benchmark.c`** to use `struct flow_dissector_metadata` instead
   of `struct xdp2_metadata_all` for the metadata variable and result
   extraction.

5. **Update `flow_dissector.bpf.c`** to use the new struct in the per-CPU
   map context and in `translate_metadata()`.

### Expected Impact

Reducing the metadata struct from ~200 to ~88 bytes would:

- Cut per-packet memset cost from ~15 ns to ~5 ns
- Make xdp2's setup cost comparable to flowdis's 88-byte memset
- Close the gap between "with memset" and "parse-only" performance
- Expected result: xdp2 optimized parser at **1.0--1.3x** flowdis speed
  including all setup overhead
