[Back to Summary](../SUMMARY.md)

## Recommended Kernel Patches

The following patches target the kernel's BPF flow dissector selftest
([`tools/testing/selftests/bpf/progs/bpf_flow.c`](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_flow.c)).
Each is small, self-contained, and improves either correctness or performance.

### Patch 1: Unified port extraction with single 32-bit load

**Commit message:** `bpf/selftests: flow_dissector: unify TCP/UDP port extraction`

The BPF selftest handles TCP and UDP as separate cases with different struct
types (`struct tcphdr`, `struct udphdr`), each doing two 16-bit field reads
for sport/dport. The kernel's own `skb_flow_get_ports()`
(`net/core/flow_dissector.c:119`) loads both ports as a single `__be32` from
offset 0, since TCP and UDP share the same port layout.

**Before** (bpf_flow.c lines 226--248):

```c
case IPPROTO_TCP:
    tcp = bpf_flow_dissect_get_header(skb, sizeof(*tcp), &_tcp);
    if (!tcp) return export_flow_keys(keys, BPF_DROP);
    if (tcp->doff < 5) return export_flow_keys(keys, BPF_DROP);
    if ((__u8 *)tcp + (tcp->doff << 2) > data_end)
        return export_flow_keys(keys, BPF_DROP);
    keys->sport = tcp->source;
    keys->dport = tcp->dest;
    return export_flow_keys(keys, BPF_OK);
case IPPROTO_UDP:
case IPPROTO_UDPLITE:
    udp = bpf_flow_dissect_get_header(skb, sizeof(*udp), &_udp);
    if (!udp) return export_flow_keys(keys, BPF_DROP);
    keys->sport = udp->source;
    keys->dport = udp->dest;
    return export_flow_keys(keys, BPF_OK);
```

**After:**

```c
case IPPROTO_TCP:
case IPPROTO_UDP:
case IPPROTO_UDPLITE: {
    __be32 *ports, _ports;
    ports = bpf_flow_dissect_get_header(skb, sizeof(_ports), &_ports);
    if (!ports) return export_flow_keys(keys, BPF_DROP);
    keys->sport = *(__be16 *)ports;
    keys->dport = *((__be16 *)ports + 1);
    return export_flow_keys(keys, BPF_OK);
}
```

**Why:** Eliminates separate struct types, reduces header load from 20/8 bytes
to 4 bytes, reduces instruction count. TCP doff validation is unnecessary when
only extracting ports from the fixed first 4 bytes. Follows the pattern the
kernel's own C dissector uses.

### Patch 2: Add SCTP/DCCP port extraction

**Commit message:** `bpf/selftests: flow_dissector: add SCTP and DCCP port extraction`

The kernel's C dissector handles SCTP and DCCP for port extraction (both have
source/dest ports at offset 0 with the same layout as TCP/UDP). The BPF
selftest is missing these. If Patch 1 is applied, this is just adding two
case labels.

**Change:** Add `case IPPROTO_SCTP:` and `case IPPROTO_DCCP:` to the port
extraction switch.

**After** (with Patch 1 applied):

```c
case IPPROTO_TCP:
case IPPROTO_UDP:
case IPPROTO_UDPLITE:
case IPPROTO_SCTP:
case IPPROTO_DCCP: {
    __be32 *ports, _ports;
    ports = bpf_flow_dissect_get_header(skb, sizeof(_ports), &_ports);
    if (!ports) return export_flow_keys(keys, BPF_DROP);
    keys->sport = *(__be16 *)ports;
    keys->dport = *((__be16 *)ports + 1);
    return export_flow_keys(keys, BPF_OK);
}
```

**Why:** Achieves parity with the kernel's C dissector for transport-layer
port extraction. SCTP and DCCP packets currently fall through to the default
case and return `BPF_DROP`.

### Patch 3: Add IPPROTO_ROUTING to IPv6 extension header handling

**Commit message:** `bpf/selftests: flow_dissector: handle IPv6 Routing extension header`

The kernel's C dissector (`flow_dissector.c:1548`) handles `NEXTHDR_ROUTING`
alongside `NEXTHDR_HOP` and `NEXTHDR_DEST`. The BPF selftest completely omits
it. The Routing header has the same `{nexthdr, hdrlen}` format as Hop-by-Hop
and Destination options, so it can share the same `IPV6OP` handler.

**Before** (bpf_flow.c lines 260--264):

```c
case IPPROTO_HOPOPTS:
case IPPROTO_DSTOPTS:
    bpf_tail_call_static(skb, &jmp_table, IPV6OP);
    break;
```

**After:**

```c
case IPPROTO_HOPOPTS:
case IPPROTO_ROUTING:
case IPPROTO_DSTOPTS:
    bpf_tail_call_static(skb, &jmp_table, IPV6OP);
    break;
```

**Why:** One-line fix. IPv6 packets with Routing headers currently fall
through to `parse_ip_proto()`'s default case and return `BPF_DROP`, silently
breaking flow dissection for packets with Routing extension headers.

### Patch 4: Use bpf_ntohs for GRE version check

**Commit message:** `bpf/selftests: flow_dissector: use bpf_ntohs for network-to-host conversion`

**Before** (bpf_flow.c line 198):

```c
if (bpf_htons(gre->flags & GRE_VERSION))
```

**After:**

```c
if (bpf_ntohs(gre->flags & GRE_VERSION))
```

**Why:** `gre->flags` is `__be16` (network byte order). Converting to host
order for comparison is semantically `ntohs`, not `htons`. While
`bpf_htons == bpf_ntohs` in practice (both are byte-swap on LE, no-op on BE),
using the correct name matches the kernel's C dissector
(`ntohs(hdr->flags & GRE_VERSION)` at `flow_dissector.c:675`) and avoids
confusion for readers.

### Patch 5: Remove export_flow_keys memcpy overhead

**Commit message:** `bpf/selftests: flow_dissector: pass keys directly to map update`

**Before** (bpf_flow.c lines 75--84):

```c
static __always_inline int export_flow_keys(struct bpf_flow_keys *keys, int ret)
{
    __u32 key = (__u32)(keys->sport) << 16 | keys->dport;
    struct bpf_flow_keys val;
    memcpy(&val, keys, sizeof(val));
    bpf_map_update_elem(&last_dissection, &key, &val, BPF_ANY);
    return ret;
}
```

**After:**

```c
static __always_inline int export_flow_keys(struct bpf_flow_keys *keys, int ret)
{
    __u32 key = (__u32)(keys->sport) << 16 | keys->dport;
    bpf_map_update_elem(&last_dissection, &key, keys, BPF_ANY);
    return ret;
}
```

**Why:** The struct copy to a stack-local `val` is unnecessary -- `keys`
already points to valid memory (`skb->flow_keys`). Passing `keys` directly to
`bpf_map_update_elem()` eliminates a ~60-byte memcpy on every call. This
function is called on every exit path (~15 call sites), so the savings
multiply.

**Note:** This is selftest infrastructure code, not production, but it adds
overhead to benchmark numbers and masks the actual flow dissector performance.
