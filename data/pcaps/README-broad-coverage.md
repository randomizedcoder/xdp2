# broad-coverage.pcap — discovery resource

Generated 2026-05-18 via `samples/flow_dissector/gen_test_pcap.py
-o broad-coverage.pcap -n 5200` (10 packets × 520 combinations).

Covers 8 L2 prefixes (bare, vlan_p0/p3/p7, qinq, pppoe,
qinq_pppoe, vlan_pppoe) × the full L3/L4/tunnel combination set:
TCP/UDP/ICMP/SCTP/ESP/AH variants on IPv4 + IPv6 (plain and with
extension headers: hop-by-hop, dest-opts, routing, fragments),
plus L2-only protocols (ARP, IGMP, TIPC, LLDP, EAPOL, PTP, MVRP,
CFM, FIP, FCoE, MACsec, slow-protocols, STP, EtherCAT, MPLS,
PPPoE, GRE, L2TP) and various combinations.

## Why it isn't in the standing parity gate

Running `flow-dissector-parity-check` against this pcap surfaces
2099 acceptance disagreements + 59700 field disagreements across
12 parsers. Most of these are SCOPE differences (rust-graph-enum
is ipv4-only by design; rust-template only matches declared
templates), not bugs:

| parser | accepted / 5200 | rejected — expected by scope | rejected — unexpected |
|---|---:|---:|---:|
| `c-flowdis-usp` (kernel C) | 4220 (81%) | 0 | 980 |
| `c-xdp2-mono` / `parse-only` / `usp` | 5167 (99.4%) | 0 | 33 each |
| `rust-graph` / `rust-mono` / `rust-mono-x4` / `rust-compiled` / `rust-simd` | 5200 (100%) | 0 | 0 |
| `rust-graph-enum` | 150 (2.9%) | 4030 (ipv4-only) | 1020 |
| `rust-template` / `rust-template-simd` | 1520 (29%) | 3680 (no-template) | 0 |

## Real bugs the pcap surfaces (need investigation)

These are FIELD disagreements between parsers that DID accept the
packet — i.e. one parser produced wrong metadata, not "didn't
parse." Top categories:

| pair | field | count |
|---|---|---:|
| `c-xdp2-mono` vs `rust-{compiled,graph,mono-x4,mono,simd}` | `ip_proto` | 600 each |
| `c-xdp2-mono` vs `c-xdp2-{usp,parse-only}` | `l3_off` | 400 each |
| `c-xdp2-mono` vs `rust-{compiled,graph,mono-x4,mono,simd}` | `sport`/`dport` | 320 each (640 total per pair) |
| `c-xdp2-parse-only` / `c-xdp2-usp` vs `rust-*` | `ip_proto` | 404 each |

The `c-xdp2-mono` row is suspicious in light of recent R3.4 fast-path
additions (R3.4.1, R3.4.5a, R3.4.5b) which hardcoded chain shapes.
A fast-path that writes the wrong `ip_proto` or `l3_off` for some
packet shape would explain this. Investigation priority: TBD.

Also notable: `c-flowdis-usp` rejects 980 packets — the kernel's
own dissector doesn't handle many L2 protocols (ARP, IGMP, LLDP,
EAPOL, etc.) and several IPv6 extension header chains.
`rust-graph-enum` rejects 1020 packets beyond its declared
`ipv4-only` scope — likely additional shapes it can't handle.

## Reproducing

```
nix-shell -p python3.withPackages\(p:[p.scapy]\) \
    --run "python3 samples/flow_dissector/gen_test_pcap.py \
              -o data/pcaps/broad-coverage.pcap -n 5200"

PARITY=$(nix build .#flow-dissector-parity-check --no-link --print-out-paths)
OUT=$(mktemp -d)
$PARITY/bin/flow-dissector-parity-check \
    --pcap data/pcaps/broad-coverage.pcap --out $OUT \
    --parsers "c-flowdis-usp,c-xdp2-usp,c-xdp2-parse-only,c-xdp2-mono,rust-graph,rust-graph-enum,rust-mono,rust-mono-x4,rust-compiled,rust-simd,rust-template,rust-template-simd"

cat $OUT/parity-report.md
```

`broad-coverage-parity-report.md` (in this directory) is the
2026-05-18 snapshot from when this pcap was first generated.

## Recommended next steps

1. **Investigate the 600+ `c-xdp2-mono` vs Rust `ip_proto`
   disagreements** to confirm whether R3.4.5b's VLAN fast-path
   writes a wrong `ip_proto` for some VLAN-tagged shapes.
2. **Investigate the 400 `c-xdp2-mono` vs `c-xdp2-usp` `l3_off`
   disagreements** — different parsers in the same C family
   shouldn't disagree on the basic packet offset.
3. **Document the kernel-flowdis 980-packet rejection set** — for
   each L2 protocol family the kernel doesn't handle, mark it as
   expected-rejection in `parity_scope.json` so the gate can
   include those packets without false alarms.
4. **Map the `rust-graph-enum` 1020 unexpected rejections** to
   specific protocol shapes, so we can either implement them or
   document the scope explicitly.

Each of these is a separate phase. See
`xdp2-rs/docs/dispatch-architecture-cost.md` for context on the
R3 phase ladder and which parsers should support what.
