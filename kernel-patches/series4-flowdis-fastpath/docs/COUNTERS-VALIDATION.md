# Per-shape counters — userspace validation (test_parser)

The kernel counters patch (patch 08/11) is mirrored into the userspace flow
dissector (`src/lib/flowdis/flow_dissector.c`) with the **same enum and the same
increment placement**, so the classification/counting logic is unit-testable on
real pcaps without a kernel build.

## How to run

```
make -C src/lib/flowdis && make -C src/test/parser        # (inside nix develop)
FLOWDIS_STATS=1 [FLOWDIS_NOFAST=1] \
  src/test/parser/test_parser -c flowdis -i pcap,<file> -o null
```

`FLOWDIS_STATS=1` dumps the per-shape table (occurrences, fast_hits, total,
eligible%) at end; `FLOWDIS_NOFAST=1` forces the slow path.

Harness note: `test_parser` builds a **superset** dissector (all keys), not
`flow_keys_dissector`, so `flow_dissect_fast()`'s eligibility guard correctly
declines it and every packet takes the slow path. So test_parser exercises the
**occurrences[]** classification (the eligible-fraction signal); `fast_hits[]`
placement is covered by the kernel compile + the gate-invariant argument (each
shaped packet increments exactly one of occurrences/fast_hits depending on gate
state, so occurrences+fast_hits is the shape total either way).

## Results — per-shape attribution is correct

Ground-truthed against `tcpdump -e` (names are misleading; actual contents shown):

| pcap | actual contents | counted | correct? |
|---|---|---|---|
| `tcp_ipv6` | plain IPv6/TCP ×12 | eth_ip=12 | ✓ top-level eth+IP+TCP → eth_ip |
| `ipip` | IPIP carrying ICMP ×10 | ipip=10, eth_ip=0 | ✓ inner ICMP ≠ eth_ip; outer encap excluded |
| `QinQ` | ARP over double-VLAN ×2 | vlan=2, qinq=2, eth_ip=0 | ✓ both tags counted; inner ARP ≠ eth_ip |
| `vlan_icmp` | vlan118→vlan10→IPv4/ICMP ×1 | vlan=1, qinq=1, eth_ip=0 | ✓ double-tagged; inner ICMP ≠ eth_ip |
| `6in4` | PPPoE+IPv6 (11/20 also VLAN) | pppoe=20, vlan=11 | ✓ pppoe every pkt; vlan where tagged |
| `gre-pptp` | VLAN→IP→GRE(→inner) ×2 | vlan=2, gre=2, ipip=2 | ✓ each nested header counted |
| `broad-coverage` | mixed ×5200 | eth_ip=380 vlan=3780 qinq=1180 pppoe=450 mpls=820 ipip=20 gre=240 | ✓ all 7 shapes exercised, incl. mpls |

Key correctness points confirmed:

- **eth_ip is top-level + TCP/UDP + no-encap only** — the three negative cases
  (ipip-inner-ICMP, QinQ-inner-ARP, vlan_icmp-inner-ICMP) all correctly yield
  `eth_ip=0`, while plain IPv6/TCP yields `eth_ip=12`. This is the subtle gate
  from the kernel `out:` placement.
- **vlan/qinq count first/second tag** — a double-tagged packet increments both
  (QinQ ARP: 2/2; vlan_icmp: 1/1), matching the kernel `ETH_P_8021Q` placement.
- **Nested headers each count** — gre-pptp increments vlan, gre, and the inner
  ipip; broad-coverage exercises all seven shapes including mpls.

Note the per-shape totals are **not** mutually exclusive (a VLAN+IP packet counts
under vlan; a double-tagged packet counts under both vlan and qinq) — this is by
design: each shape's counter is its own fast-path's independent eligible
fraction, which is what the adaptive controller thresholds per shape.
