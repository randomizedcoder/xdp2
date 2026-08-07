# eBPF path — per-encapsulation loadable fast-dissector menu

Design for the "subjective shapes → eBPF" half of the response to Willem
(see `README.md`). Instead of one in-kernel fast path per shape (his objection:
subjective, +2500 LoC, duplicative), each encapsulation is a **separate loadable
BPF flow-dissector object** and the operator loads exactly the one their
deployment uses. The kernel makes no shape choice at all.

## Why per-object (not one monolith, not in-kernel)

- A netns attaches exactly **one** `BPF_PROG_TYPE_FLOW_DISSECTOR` program. So each
  object must self-contain the common `eth + IPv4/IPv6 + TCP/UDP` inner **and**
  its encapsulation, returning `BPF_FLOW_DISSECTOR_CONTINUE` for anything else
  (fall back to the kernel software dissector — no drops).
- "Load the one you need" answers Willem's "which shapes are subjective / why
  GRE": the PPPoE broadband operator loads `fast_flow_pppoe`, the GRE-tunnel shop
  loads `fast_flow_gre`; nobody carries shapes they don't use, and none of it is
  in-kernel maintenance surface.

## Menu

| Object | Fast-paths | Parity oracle |
|---|---|---|
| `fast_flow_eth_ip.bpf.o` | eth + IPv4/IPv6 + TCP/UDP (+ICMP) | in-tree `bpf_flow.kern.o` |
| `fast_flow_vlan.bpf.o` | above + 802.1Q (v4/v6) | in-tree ✓ |
| `fast_flow_qinq.bpf.o` | above + 802.1AD / QinQ | in-tree ✓ |
| `fast_flow_mpls.bpf.o` | above + single MPLS label + IP | in-tree ✓ |
| `fast_flow_ipip.bpf.o` | above + IPIP / 4in6 / 6in4 | in-tree ✓ |
| `fast_flow_gre.bpf.o` | above + plain GRE inner | in-tree ✓ |
| `fast_flow_pppoe.bpf.o` | above + PPPoE session | **series2-patched** `bpf_flow.kern.o` |
| `fast_flow_vxlan.bpf.o` | above + VXLAN inner-flow descent | descent-patched C dissector |
| `fast_flow_geneve.bpf.o` | above + Geneve inner-flow descent | descent-patched C dissector |
| `fast_flow_gtpu.bpf.o` | above + GTP-U inner-flow descent | descent-patched C dissector |
| `fast_flow_gue.bpf.o` | above + GUE inner-flow descent (configured port) | descent-patched C dissector |
| `fast_flow_fou.bpf.o` | above + direct-FOU inner-flow descent (configured port) | descent-patched C dissector |

The full menu is **12 objects** = the 7 fast-path shapes (series5-fastpath) + the 5
UDP-tunnel descents (series5-descent: vxlan, geneve, gtpu, gue, fou), i.e. one
loadable eBPF object for every shape in both posted kernel series.

**FOU/GUE note:** neither has a well-known UDP port — in-kernel the `fou` module's
per-netns table maps a port to the tunnel. A standalone BPF object can't reach
that table, so both take the UDP port as a load-time policy choice (`GUE_UDP_PORT`
/ `FOU_UDP_PORT` `#define`). GUE is self-describing (`guehdr.proto_ctype` → inner
proto); direct FOU is bare (inner protocol not on the wire), so `fast_flow_fou`
handles the common IP-carrying case by inferring the inner IP version from the
first nibble (like GTP-U).

**PPPoE oracle nuance:** the in-tree BPF dissector drops PPPoE (the gap
`../series2-bpf-pppoe/` closes), so PPPoE parity must run against the
series2-patched `bpf_flow.kern.o`, not the stock one. Every other shape uses the
stock in-tree dissector as oracle.

## Structure — shared inner, thin per-encap shims

- `fast_bpf/fast_flow_inner.h` — the four inner extractors (IPv4/IPv6 × TCP/UDP,
  +ICMP) as `SEC("flow_dissector")` tail-call targets, the `jmp_table` PROG_ARRAY,
  and the `CHAIN_*` ids. Factored out of today's monolithic `fast_flow.bpf.c`.
- `fast_bpf/fast_flow_<encap>.bpf.c` — includes the header; defines the `_dissect`
  entry that recognises plain IP **and** its encap, advances `keys->nhoff` past the
  L2/encap stride + rewrites `keys->n_proto` (the kernel unwrap pattern), then
  `bpf_tail_call`s into the shared inner. One source of truth for the inner
  5-tuple; each encap shim is tiny (directly answers the duplication concern).

Loader compatibility: `parity_test.c`, `benchmark_bpf.c`, and
`xdp2-rs/crates/xdp2-flow-loader` all find `_dissect` and populate `jmp_table`
with non-entry programs in declaration order — generic, no per-object hardcoding
(only `CHAIN_DYNAMIC = 7` for the optional slow-path slot). Per-object `CHAIN_*`
indices are local to each object.

## Oracle-semantics finding (read from `kern_bpf/bpf_flow.c`)

The in-tree BPF dissector does NOT treat all shapes equally — this changes both
the per-shape parity oracle and the reply narrative:

| Shape | In-tree BPF dissector does… | Inner 5-tuple? | Parity oracle for our object |
|---|---|---|---|
| VLAN (802.1Q) | unwraps tag, re-dispatches to inner IP | **yes** | in-tree `bpf_flow.kern.o` ✓ |
| QinQ (802.1AD+Q) | unwraps both tags, re-dispatches | **yes** | in-tree ✓ |
| GRE (v0) | steps over GRE (+csum/key/seq), descends to inner | **yes** | in-tree ✓ |
| IPIP / 4in6 / 6in4 | `is_encap=true`, re-dispatches to inner IP | **yes** | in-tree ✓ |
| **MPLS** | `PROG(MPLS)` is a **stub**: validates one label present, returns `BPF_OK`, **no descent, no addr/ports** | **NO** | *not* in-tree — see below |
| **PPPoE** | no case → **`BPF_DROP`** | **NO** | *not* in-tree — series2-patched |

Implications:
- **VLAN/QinQ/GRE/IPIP** — our objects are faithful faster replacements; parity vs
  the stock in-tree dissector is meaningful and is the Gold gate.
- **MPLS** — matching the in-tree stub byte-for-byte would be *useless* (no 5-tuple
  → no useful RSS/hash). To be worth loading, `fast_flow_mpls` must **extract the
  inner IP 5-tuple** — going *beyond* the in-tree BPF dissector. Then its oracle
  can't be `bpf_flow.kern.o`; it must be the in-kernel **C** dissector's MPLS
  behaviour (cf. series5 patch 05, which itself *added* inner-MPLS descent — so
  even mainline C may not descend by default; decision pending).
- **PPPoE** — the in-tree dissector drops it, so `fast_flow_pppoe` is pure new
  value; oracle = the **series2-patched** `bpf_flow.kern.o`.

Reply consequence: "the BPF dissector already offers that" is **true** for
VLAN/QinQ/GRE/IPIP, **partial** for MPLS (recognised, not extracted), and **false**
for PPPoE (dropped). Our loadable objects add the most value exactly where the
in-tree BPF dissector is weakest — a clean, honest point to make to Willem.

## Completeness bar (proto-audit-calibrated)

Per shape, a cell must report all of:
- **Parity: Gold** — every fast-path hit's `bpf_flow_keys` byte-identical to the
  oracle over the corpus (`parity_test`, exit 0). Gold = zero mismatches, like
  proto-audit's round-trip tier.
- **Perf: ns/pkt** vs the in-tree BPF dissector (`benchmark_bpf` /
  `flow-dissector-matrix-unified`, `BPF_PROG_TEST_RUN`).
- **Size: LoC + object bytes** of the per-encap `.bpf.c` (feeds Willem-reply gate 2).
- **ISA:** x86 (hp5/t), ARM Cortex-A76 (pi5-2), RISC-V X60 (bpi-f3).

Corpus: reuse existing captures — `data/pcaps/` (QinQ, ipip, 6in4, gre-*,
vlan_icmp, tcp_ipv4/ipv6) + `samples/proto_audit/pcap_templates/` (vlan, qinq,
pppoe, mpls, gre/gre6/nvgre). No generation.

## Build / verify

```
nix develop --command make -C samples/flow_dissector bpf     # build all objects
sudo ./benchmark_bpf -b fast_bpf/fast_flow_<encap>.bpf.o <pcap>   # ns/pkt
sudo ./fast_bpf/parity_test -f fast_bpf/fast_flow_<encap>.bpf.o \
        -r kern_bpf/bpf_flow.kern.o <per-shape.pcap>             # Gold gate
```
Extend `flake.nix` dev shell / matrix wrappers if more tooling is needed rather
than installing by hand. Wire the per-shape parity into a nix check (analogue of
`proto-audit-validate-all`) so it's CI-gated.

## Status (2026-08-05)

**Written + compiling clean** (x86 `clang -target bpf`, via `make bpf`; each object
= 5 shared inner extractors + its `_dissect` shim, correct declaration order):

| Object | Source LoC | .o bytes | Descends? | Oracle | Parity verified |
|---|---:|---:|---|---|---|
| `fast_flow_inner.h` (shared) | 329 | — | — | — | — |
| `fast_flow_eth_ip.bpf.c` | 46 | 25640 | n/a (plain) | in-tree | ⏳ testbed |
| `fast_flow_vlan.bpf.c` | 53 | 26576 | inner IP | in-tree | ⏳ testbed |
| `fast_flow_qinq.bpf.c` | 64 | 26936 | inner IP | in-tree | ⏳ testbed |
| `fast_flow_mpls.bpf.c` | 73 | 29208 | inner IP | **C dissector** | ⏳ (no BPF oracle) |
| `fast_flow_ipip.bpf.c` | 66 | 28760 | inner IP (v4 outer) | in-tree | ⏳ testbed |
| `fast_flow_gre.bpf.c` | 94 | 30504 | inner IP | in-tree | ⏳ testbed |
| `fast_flow_pppoe.bpf.c` | 75 | 29088 | inner IP | **series2-patched** | ⏳ testbed |
| `fast_flow_vxlan.bpf.c` | 75 | 32384 | inner IP (UDP tunnel) | **descent-patched C** | ⏳ testbed |
| `fast_flow_geneve.bpf.c` | 81 | 32632 | inner IP (UDP tunnel) | **descent-patched C** | ⏳ testbed |
| `fast_flow_gtpu.bpf.c` | 88 | 32544 | inner IP (UDP tunnel) | **descent-patched C** | ⏳ testbed |

**Total ~1080 source LoC** for the whole "subjective shapes + UDP-tunnel descent"
menu — *out of the kernel* — vs the +2500 (fast-path) plus +1507 (descent) in-kernel
LoC of the two posted series. Makefile wired (`MENU_BPF` +
`fast_bpf/fast_flow_%.bpf.o` pattern rule); `make bpf` builds all ten.

### UDP-tunnel inner-flow descent (vxlan / geneve / gtpu)

These mirror the companion **series5-descent** (VXLAN/Geneve/GTP-U/FOU-GUE) and are
the motivating production case: without descent, every inner flow between two
tunnel endpoints collapses onto the *outer* 5-tuple, so RSS/RPS/fq/cake pin them to
one queue and traffic **reorders under load** (observed in production on VXLAN;
GTP-U is worse — no outer source-port entropy at all, millions of subscriber flows
per tunnel). Descent hashes on the inner flow instead. This **deliberately changes
the hash**, so it is exactly a "load it when you want it" object — the operator
opts in by loading `fast_flow_vxlan`/`geneve`/`gtpu` on a netns where that port is
the tunnel by policy. Header validation matches series5-descent:
- vxlan: UDP 4789, `vx_flags == VXLAN_HF_VNI` (plain RFC 7348; GBP/GPE defer),
  inner Ethernet → inner IP at `udp+30`.
- geneve: UDP 6081, version 0, `opt_len==0` (no TLVs), not OAM, `proto_type==TEB`,
  inner Ethernet → inner IP at `udp+30`.
- gtpu: UDP 2152, GTPv1 G-PDU (PT=1, no E/S/PN, type 0xFF), inner IP at `udp+16`
  (no inner Ethernet; IP version inferred from the first nibble).

Oracle = the **series5-descent-patched C dissector** (the in-tree BPF dissector
stops at outer UDP for all of these). **FOU/GUE deferred**: no well-known UDP port,
so it can't be recognised from the wire alone — series5-descent consults the
per-netns FOU table, which a standalone BPF object can't reach without a
configured port / map. Add once a port-config mechanism is decided.

Known scope notes baked into the code (documented in each file):
- `ipip`: only IPv4-outer tunnels (IPIP 4in4, 6in4). Outer-IPv6 (4in6/6in6) defers
  — needs `STOP_AT_FLOW_LABEL` handling to stay byte-identical.
- `gre`: version-0 only (PPTP/v1 defers), incl. optional csum/key/seq + TEB.
- `mpls`: single label (bottom-of-stack set); multi-label defers. Beyond the
  in-tree stub → C-dissector oracle.

## Benchmark harness (built)

`samples/flow_dissector/fast_bpf/bench_menu.sh` + `nix/flow-menu-bench.nix`
(flake target `flow-menu-bench`): builds the 10 objects + `bpf_flow.kern.o` oracle
+ `benchmark_bpf` + `parity_test`, bakes a normalised per-shape corpus, and for
each object runs `benchmark_bpf` (ns/pkt vs the in-tree dissector) and, where an
in-tree BPF oracle exists, `parity_test` as a Gold gate. Emits CSV.
Run: `nix run .#run-on-host -- l2 -- flow-menu-bench` (SSH-as-root), or
`sudo $(nix build --no-link --print-out-paths .#flow-menu-bench)/bin/xdp2-flow-menu-bench`.

**Per-shape corpus** (all git-tracked; `BPF_PROG_TEST_RUN` repeats each packet, so
templates suffice for ns/pkt):

| shape | pcap | parity oracle |
|---|---|---|
| eth_ip | `data/pcaps/tcp_ipv4.pcap` | in-tree → **GOLD gate** |
| vlan | `proto_audit/…/vlan.pcap` | in-tree → GOLD gate |
| qinq | `data/pcaps/QinQ.pcap` | in-tree → GOLD gate |
| ipip | `data/pcaps/ipip.pcap` | in-tree → GOLD gate |
| gre | `data/pcaps/gre-sample.pcap` | in-tree → GOLD gate |
| mpls | `proto_audit/…/mpls.pcap` | C dissector → bench only |
| pppoe | `proto_audit/…/pppoe.pcap` | series2-patched → bench only (oracle TBD) |
| vxlan | `data/pcaps/vxlan.pcap` | C dissector → bench only |
| geneve | `proto_audit/…/geneve.pcap` | C dissector → bench only |
| gtpu | `proto_audit/…/gtp_u.pcap` | C dissector → bench only |

## Remaining before the full verification run

1. **Host availability** — 2026-08-05: only **l2** (Zen 2, x86) is reachable
   (root-ssh OK). hp5/hp2 (X710 pair) are down ("No route to host"); the ARM
   (pi5-2) / RISC-V (bpi-f3) DUTs and Intel `t` were not reachable. So the first
   real run is x86-only on l2; the cross-ISA matrix waits on the other DUTs.
2. **Series2-patched PPPoE oracle** — build `bpf_flow_pppoe.kern.o` (apply
   `series2-bpf-pppoe` to `kern_bpf/bpf_flow.c`) and wire it as PPPoE's parity
   oracle so PPPoE gets a Gold gate too.
3. **C-dissector parity for mpls + vxlan/geneve/gtpu** — these descend beyond any
   BPF oracle; validate against the (descent-/patch-)modified C dissector via the
   userland `libflowdis` path or a KUnit-style skb harness. Bench numbers don't
   need it; correctness does.
4. **Run** `flow-menu-bench` on l2 now; extend to hp5/pi5-2/bpi-f3 when up; drop
   CSVs into `perf/` and fill the completeness table (ns/pkt + Gold per shape/ISA).
