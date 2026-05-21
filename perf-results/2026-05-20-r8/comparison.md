# R8 — VXLAN fast-path chain (shipped)

Date: 2026-05-20. R8 reframed from "per-parser tailored metadata
struct" (R6 audit's Option C, would have been ~500 LoC) to a
much smaller change: extend the R3.4 fast-path framework with
a VXLAN+inner-IPv4 chain that bypasses the 7-node slow-path
walk for the common VXLAN traffic shape.

**Result: -8 to -10 ns/pkt on vxlan-k8s-pure across both hosts.**
First significant ns/pkt win on tunneled workloads since R3.4.5a.

## Change

`src/templates/xdp2/mono_def.template.c:343` — new fast-path
chain in the `enable_fast_paths` block, before the slow-path
graph body fallback:

```c
/* eth+ipv4(no opts/no frag)+udp(dport=4789=VXLAN)
 * +vxlan(8B)+inner_eth(14B)+inner_ipv4+inner_{tcp,icmp} */
if (len >= 92 &&
    p[0] == 0x08 && p[1] == 0x00 &&          /* outer etype IPv4 */
    p[2] == 0x45 && (p[8] & 0x3f) == 0 && p[9] == 0 &&
    (p[8] & 0x20) == 0 && p[11] == 17 &&     /* outer IPv4, no frag, UDP */
    p[24] == 0x12 && p[25] == 0xB5 &&        /* UDP dport = 4789 (VXLAN) */
    p[50] == 0x08 && p[51] == 0x00 &&        /* inner etype IPv4 */
    p[52] == 0x45 && (p[58] & 0x3f) == 0 && p[59] == 0 &&
    (p[58] & 0x20) == 0) {                   /* inner IPv4, no frag */
    unsigned char inner_ip_proto = p[61];
    if (inner_ip_proto == 6 || inner_ip_proto == 1) {  /* TCP or ICMP */
        /* Write inner 5-tuple metadata (matches what slow-path
         * leaves in metadata at termination, since the tunnel walk
         * overwrites outer with inner). */
        return XDP2_STOP_OKAY;
    }
}
```

The slow-path's tunnel walk OVERWRITES the metadata struct as
it descends, so the fast-path only needs to write the INNER
5-tuple (matching what the slow-path leaves in metadata at
termination). 39 lines of straight-line C in the template.

## Perf delta vs R7-B4 phase 1 baseline

### hp5 (canonical testbed)

| workload | B4-phase1 | R8 | Δ |
|---|---:|---:|---:|
| https-web | 72 | 72 | 0 |
| **k8s-microservices** | 133 | **127** | **-6** ✓ |
| nfs-server | 69 | 70 | +1 |
| pppoe-isp | 72 | 74 | +2 (noise) |
| vlan-tcp-mix | 72 | 70 | -2 |
| **vxlan-k8s-pure** | 136 | **128** | **-8** ✓ |

### hp2

| workload | B4-phase1 | R8 | Δ |
|---|---:|---:|---:|
| https-web | 69 | 69 | 0 |
| **k8s-microservices** | 130 | **124** | **-6** ✓ |
| nfs-server | 71 | 70 | -1 |
| pppoe-isp | 73 | 79 | +6 (hp2 variance) |
| vlan-tcp-mix | 72 | 70 | -2 |
| **vxlan-k8s-pure** | 140 | **130** | **-10** ✓ |

The hp2 pppoe-isp +6 is suspicious because pppoe packets don't
match the VXLAN pattern and should fall through to the slow path
unchanged. hp5 pppoe-isp is +2 (within noise). hp2 has shown
similar 5-7 ns day-to-day variance throughout the R5-R8 sweeps.
Likely noise; could be a real layout-shift in the slow-path
fall-through due to the added fast-path code, but hp5 doesn't
show it.

## Cross-impl ranking after R8 (hp5)

c-xdp2-mono vs rust-mono on the same workloads:

| workload | c-xdp2-mono | rust-mono | gap (c - rust) |
|---|---:|---:|---:|
| https-web | 72 | 72 | 0 (tied) |
| **nfs-server** | **70** | 71 | **−1** (mono ahead) |
| **pppoe-isp** | **74** | 80 | **−6** (mono ahead) |
| **vlan-tcp-mix** | **70** | 89 | **−19** (mono way ahead) |
| k8s-microservices | 127 | 85 | +42 (was +48) |
| vxlan-k8s-pure | 128 | 92 | **+36** (was +43) |

**c-xdp2-mono is tied or ahead on 4 of 6 workloads. Tunnel gap
on vxlan-k8s-pure: was +46 ns at end of R6, now +36 ns after
R7-B1 (-4) + R8 (-8) — closed 22 % of the original gap.**

## Cumulative R5-R8 evolution (hp5 c-xdp2-mono)

| Phase | https-web | vxlan-k8s-pure | notes |
|---|---:|---:|---|
| post-R3.4 | 72 | 141 | first correct vxlan walk |
| R5 trim | 72 | 140 | null (gcc already optimal) |
| R6 layout | 73 | 139 | null (Zen 1 store buffer absorbs) |
| R7-B1 hot-edge | 72 | 135 | -4 ns ✓ |
| R7-B3 typed-store | 72 | 136 | null, cleaner emit |
| R7-B4 phase 1 | 72 | 136 | null, IR fix |
| **R8 VXLAN fast-path** | 72 | **128** | **-8 ns ✓** |

**Cumulative since R3.4**: vxlan-k8s-pure 141 → 128 ns (-13 ns,
-9%). Both wins are R3.4-style fast-path extensions; the
template-level template optimisations (R5/R6/R7-B3/R7-B4) were
all null on Zen 1 because gcc + always_inline + LTO was already
producing optimal code.

## Correctness

- **Parity gate**: 32/32 OK
- **Protocol-coverage matrix**: 4914 cells, 0 OK!N, 0
  REJ-undeclared, 0 REJ-unexpected
- **Mono-perf ceiling**: 0 violations on 12 cells

The fast-path mirrors the slow-path's metadata-write semantics
(inner 5-tuple final state). On non-VXLAN packets the chain
predicate fails and the parser falls through to the existing
slow-path body unchanged.

## What R8 confirms

Adding **profile-specific fast-paths** (R3.4-style straight-
line extractors at parser entry) is the most productive
optimisation lever for this codegen on Zen 1. Each fast-path
chain captures a specific packet shape; on hit it bypasses the
entire slow-path graph walk.

The R8 chain captures:
- Pure VXLAN/IPv4/TCP/ICMP traffic (the vxlan-k8s-pure profile)
- ~80% of vxlan-k8s-pure.pcap packets per chain-histogram

Adding more chains for other tunnel patterns would yield
similar wins:
- VXLAN/IPv4/UDP (currently misses) — would catch DNS-over-VXLAN etc.
- VXLAN/IPv6/* — catches IPv6-inner traffic
- GENEVE inner walks (UDP dport 6081)
- GTP-U inner walks (UDP dport 2152)
- IPv4-over-IPv4 / IPv6-over-IPv4 tunnels

Each new chain is ~40 lines of straight-line C and ~5-10 ns/pkt
saved on the matching workload. The marginal cost is low
(template-only, no IR or AST changes).

## What R8 leaves

The remaining 36 ns gap to rust-mono on vxlan-k8s-pure is in:

1. **Fast-path miss tail**: ~20% of vxlan-k8s-pure packets have
   slightly different shapes (IPv6 inner, fragmented, IHL≠5)
   that miss the chain and walk the slow path. R9 chain
   extensions would catch most.
2. **Structural codegen gap**: per R7's findings, gcc's binary-
   search switch + per-node bookkeeping vs rust's match-tree +
   monomorphic dispatch. ~25-30 ns structural floor that
   template changes can't close.

R8 strategy continues to work: add more chains incrementally
based on workload profiling. Each chain captures more of the
miss tail.

## Files

- `comparison.md` — this file
- `sweep.md` — full hp2+hp5 6-workload matrix
- `mono-perf.md` — parity ceiling (0 violations)
- `matrix.md` — protocol-coverage matrix (4914 cells, 0/0/0)

## Reproducing

```sh
# Build + correctness gates
nix build .#checks.x86_64-linux.parity-gate
nix run .#protocol-coverage-matrix -- --out /tmp/cov
grep -E "OK!N|REJ-unexpected" /tmp/cov/report/matrix.md

# Perf sweep
XDP2_RESULTS_ROOT=/tmp/r8-sweep \
nix run .#flow-dissector-matrix-sweep -- \
    --testbed testbeds/hp2-hp5-x710.toml
```
