# R8.1 — IPIP fast-path attempt (reverted)

Date: 2026-05-20. Continuing the R8 fast-path-extension strategy
that yielded -8 ns on vxlan-k8s-pure. Inspection of
`k8s-microservices.pcap` via `tcpdump -nn` showed mixed-traffic
content including a small number of IPIP packets (line shape:
"IP A > B: IP C > D: ..."). Hypothesised that adding an
IPIP+IPv4+TCP/ICMP fast-path chain might capture those packets
and close another few ns on k8s-microservices.

**Reverted** because:
- k8s-microservices delta was -1 ns (within noise band)
- hp5 https-web went 72 → 75 (+3 ns, edge-of-noise regression)
- Net: no measurable gain on target workload, small regression
  elsewhere from fast-path layout shift

## Change attempted

`mono_def.template.c:343` — IPIP chain added BEFORE the R8
VXLAN chain in the `enable_fast_paths` block:

```c
/* eth+ipv4(no opts/no frag, ipproto=4 IPIP)
 * +inner_ipv4(no opts/no frag)+inner_{tcp,icmp} */
if (len >= 62 &&
    p[0] == 0x08 && p[1] == 0x00 &&
    p[2] == 0x45 && /* outer IPv4 no opts no frag */ &&
    p[11] == 4 &&  /* IPPROTO_IPIP */
    p[22] == 0x45 && /* inner IPv4 no opts no frag */) {
    unsigned char inner_ip_proto = p[31];
    if (inner_ip_proto == 6 || inner_ip_proto == 1) {
        /* write inner 5-tuple metadata */
        return XDP2_STOP_OKAY;
    }
}
```

~40 lines of template C.

## Perf delta vs R8 baseline

### hp5

| workload | R8 | R8.1 | Δ |
|---|---:|---:|---:|
| **https-web** | 72 | **75** | **+3 (regression)** |
| k8s-microservices | 127 | 126 | -1 (noise) |
| nfs-server | 70 | 68 | -2 |
| pppoe-isp | 74 | 73 | -1 |
| vlan-tcp-mix | 70 | 69 | -1 |
| vxlan-k8s-pure | 128 | 130 | +2 (noise) |

### hp2

| workload | R8 | R8.1 | Δ |
|---|---:|---:|---:|
| https-web | 69 | 70 | +1 |
| k8s-microservices | 124 | 123 | -1 |
| nfs-server | 70 | 71 | +1 |
| pppoe-isp | 79 | 73 | -6 (variance) |
| vlan-tcp-mix | 70 | 70 | 0 |
| vxlan-k8s-pure | 130 | 132 | +2 |

## Why null on k8s-microservices

The k8s-microservices.pcap is dominated by VXLAN-tunneled
traffic (matching the R8 chain) and direct TCP traffic (matching
the R3.4.1 chain). IPIP packets are rare (<1% of the pcap based
on the tcpdump sample), so adding a chain for them doesn't move
the per-packet average.

## Why hp5 https-web regressed

The added ~40 lines of template C land BEFORE the existing
chains in the entry function's fast-path block. The block grew
from ~250 lines to ~290 lines. gcc's code-layout heuristics
chose a slightly different basic-block order for the larger
block, causing https-web's path (which hits R3.4.1 chain at the
top) to take a 3 ns hit on hp5 from icache or branch-predictor
sequencing differences.

hp2 didn't show the regression (+1 vs +3), suggesting hp5's
specific i-cache / BPU state was sensitive to the layout shift.

## Lesson learned: chain proliferation has costs

Each new fast-path chain has TWO costs:
1. **Compile-time**: ~40 lines of template C → ~100-200
   instructions in the generated entry function.
2. **Runtime layout**: every NEW chain shifts the position of
   existing chains in the entry function, potentially affecting
   their codegen.

The benefit per chain depends on how often it hits. For
high-hit chains (like R8 VXLAN, ~95% of vxlan-k8s-pure
packets), the benefit dwarfs the layout cost. For low-hit
chains (like R8.1 IPIP, <1% of k8s-microservices), the layout
cost exceeds the benefit.

**Heuristic for future chain additions**: profile the workload
first. Only add chains for shapes that are >10% of the target
pcap. Otherwise the fast-path block's size cost outweighs the
chain's per-packet savings.

## R8 strategy status

After R8 (VXLAN chain) + R8.1 (IPIP chain reverted), the
fast-path framework has captured the dominant traffic shapes
in our workloads:
- `eth+ipv4+{tcp,icmp}` (R3.4.1)
- `eth+ipv6+{tcp,icmpv6}` (R3.4.5)
- `eth+vlan+ipv4+{tcp,icmp}` (R3.4.5b)
- `eth+vlan+ipv6+{tcp,icmpv6}` (R3.4.5c)
- `eth+pppoe+ipv4+{tcp,icmp}` (R3.4.5d)
- `eth+pppoe+ipv6+{tcp,icmpv6}` (R3.4.5e)
- `eth+ipv4+udp(4789=vxlan)+vxlan+inner_eth+inner_ipv4+inner_{tcp,icmp}` (R8)

Total 7 chains. They cover https-web, nfs-server, pppoe-isp,
vlan-tcp-mix, k8s-microservices, vxlan-k8s-pure — i.e., every
workload in the sweep.

Further chains would be for outlier shapes (GENEVE, GTP-U,
IPIP, MPLS-UDP, IPv6 outer tunnels). Without a target workload
that's dominated by one of these shapes, adding chains
opportunistically risks the same null-or-regression outcome
as R8.1.

## Decision

R8.1 reverted. R8 (VXLAN chain) stays as the most recent
shipping perf change.

R8 final state (this is the point we stop adding chains):

| workload | hp5 c-xdp2-mono | vs rust-mono |
|---|---:|---|
| https-web | 72 | tied (+1) |
| nfs-server | 70 | mono ahead (-1) |
| pppoe-isp | 74 | mono ahead (-6) |
| vlan-tcp-mix | 70 | mono way ahead (-19) |
| k8s-microservices | 127 | structural gap +42 |
| vxlan-k8s-pure | 128 | structural gap +36 |

Cumulative R3.4 → R8: vxlan-k8s-pure 141 → 128 ns (-9%).

## Files

- `findings.md` — this analysis
- `sweep.md` — full hp2+hp5 6-workload matrix from R8.1
  (REVERTED, not in tree)
- `mono-perf.md` — mono-perf ceiling (still 0 violations even
  with the layout shift)
