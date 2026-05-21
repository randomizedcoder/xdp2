# Why c-bpf-flowdis is "fast" on pppoe-isp — measurement artifact

Date: 2026-05-20. On the post-R8 hp5 sweep, c-bpf-flowdis showed
65 ns/pkt on pppoe-isp.pcap — significantly faster than every
other parser including c-xdp2-mono (74 ns) and rust-mono (80 ns).
This is anomalous: on every other workload c-bpf-flowdis is
115-125 ns/pkt.

**Root cause: the kernel BPF flow_dissector does not support
PPPoE at all. It rejects PPPoE packets via `BPF_DROP` at the
entry switch without doing any actual parsing.**

The 65 ns/pkt is the cost of "load packet, dispatch on outer
etype, fall through to default case, return BPF_DROP" — i.e.
the bench is timing how fast BPF can REJECT the packet, not
how fast it can parse it.

## Evidence

### 1. pppoe-isp.pcap content

`tcpdump -nn -r pppoe-isp.pcap` shows 100% PPPoE-wrapped
TCP/ICMP traffic:

```
PPPoE  [ses 0x815f] IP 155.13.101.184.33587 > 167.214.112.115.443: Flags [.], seq ...
PPPoE  [ses 0x5c63] IP 46.154.7.182.443 > 137.64.140.12.39078: Flags [.], seq ...
PPPoE  [ses 0xdbb6] IP 10.50.116.35 > 10.226.164.69: ICMP echo request, ...
```

Every packet has ETH_P_PPP_SES (0x8864) as the outer etype.

### 2. BPF flow_dissector source

`samples/flow_dissector/kern_bpf/bpf_flow.c:128-153` is the
entry-point etype dispatch. Vendored directly from the Linux
kernel's `tools/testing/selftests/bpf/progs/bpf_flow.c`:

```c
static __always_inline int parse_eth_proto(struct __sk_buff *skb, __be16 proto)
{
    struct bpf_flow_keys *keys = skb->flow_keys;

    switch (proto) {
    case bpf_htons(ETH_P_IP):
        bpf_tail_call_static(skb, &jmp_table, IP);
        break;
    case bpf_htons(ETH_P_IPV6):
        bpf_tail_call_static(skb, &jmp_table, IPV6);
        break;
    case bpf_htons(ETH_P_MPLS_MC):
    case bpf_htons(ETH_P_MPLS_UC):
        bpf_tail_call_static(skb, &jmp_table, MPLS);
        break;
    case bpf_htons(ETH_P_8021Q):
    case bpf_htons(ETH_P_8021AD):
        bpf_tail_call_static(skb, &jmp_table, VLAN);
        break;
    default:
        /* Protocol not supported */
        return export_flow_keys(keys, BPF_DROP);
    }

    return export_flow_keys(keys, BPF_DROP);
}
```

The kernel's in-tree BPF dissector handles only:
- IP / IPv6 (with tail-call sub-programs)
- MPLS (with tail-call sub-program)
- VLAN 802.1Q / 802.1AD (with tail-call sub-program)

**PPPoE (ETH_P_PPP_SES, 0x8864) is NOT in the dispatch list.**

Every PPPoE packet in pppoe-isp.pcap → hits the `default:`
arm → `return export_flow_keys(keys, BPF_DROP)` → no parsing.

### 3. Cross-impl correctness check

The single-protocol `pppoe.pcap` test in our protocol-coverage
matrix confirms c-bpf-flowdis cannot parse PPPoE:

```csv
pppoe,c-bpf-flowdis,False,1,0,parse-error,0,reject:parse-error,REJ-expected
```

REJ-expected means: declared upfront that c-bpf-flowdis is
expected to reject PPPoE (and it does).

For pppoe-isp.pcap (the bench workload), c-bpf-flowdis is
running but rejecting every packet at the entry switch.

## Why the bench reports 65 ns/pkt anyway

`benchmark_bpf` uses `BPF_PROG_TEST_RUN` to execute the BPF
program in a tight loop and measures wallclock time per
iteration. The BPF program runs regardless of whether it
successfully parses anything. For PPPoE input:

1. BPF program loads (already loaded — measured once at startup)
2. Per packet: BPF_PROG_TEST_RUN sets up skb, invokes program
3. Program: load eth_proto, switch dispatch, default → BPF_DROP
4. BPF_PROG_TEST_RUN returns to userspace, increments counter

That's ~65 ns of overhead per "iteration", but ZERO ns of actual
parsing because the program never enters a sub-program for IP/
TCP extraction.

For comparison on https-web (which BPF CAN parse):
- ~65 ns of "BPF_PROG_TEST_RUN entry+exit overhead"
- ~50 ns of actual parsing (eth → IP → TCP via tail calls)
- Total: 115 ns/pkt

The 50 ns difference (115 - 65) is the "real cost" of BPF
dissection when it runs.

## Implication for the kernel-vs-XDP2 comparison

**c-bpf-flowdis on pppoe-isp.pcap is NOT a valid datapoint for
comparing parser speed.** The BPF dissector isn't doing the work
the bench is measuring.

To make this cell honest, we'd need either:
1. **A BPF flow_dissector that supports PPPoE** — the in-tree
   one doesn't, so this isn't available.
2. **A pppoe-isp variant pcap with IP-outer packets** — but then
   it's not a PPPoE workload.
3. **Mark the cell as "rejects" rather than reporting ns/pkt** —
   what we should be doing in the comparison table.

For the kernel-team narrative, the honest framing is:

> The kernel's in-tree BPF flow_dissector does not support
> PPPoE. On a PPPoE-heavy workload it rejects every packet at
> the entry dispatch in ~65 ns. The 65 ns/pkt number is the
> floor cost of BPF_PROG_TEST_RUN entry+exit, not the cost of
> parsing.

c-xdp2-mono at 74 ns/pkt on pppoe-isp DOES parse every packet
and emit the full L2+L3+L4 metadata (eth_proto, eth_addrs,
ip_proto, addrs, ports). It's strictly more work for ~9 ns
extra.

## Action

Updated `docs/kernel-vs-xdp2-comparison.md` to flag the cell
with a † (REJ — does not parse PPPoE) annotation.

Considered also adjusting the bench harness to filter out
"all packets rejected" runs from the per-cell ns/pkt
calculation, but that's a larger change. The doc annotation
is sufficient for kernel-team review.

## Other cells where c-bpf-flowdis "rejects"?

Audit of the other workloads:

| workload | dominant etype | BPF dispatch result |
|---|---|---|
| https-web | ETH_P_IP (0x0800) | parses via IP sub-program |
| nfs-server | ETH_P_IP | parses |
| pppoe-isp | ETH_P_PPP_SES (0x8864) | **REJECTS at entry** |
| vlan-tcp-mix | ETH_P_8021Q (0x8100) | parses via VLAN sub-program → IP |
| k8s-microservices | ETH_P_IP outer | parses outer, stops before VXLAN |
| vxlan-k8s-pure | ETH_P_IP outer | parses outer, stops before VXLAN |

Only pppoe-isp is affected. The other "fast" BPF cells
(nfs-server 121, vlan-tcp-mix 125, etc.) are honest measurements.
