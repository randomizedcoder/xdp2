# series6-common-case — response to Willem's v1 review

Working folder for our response to Willem de Bruijn's review of the
flow_dissector fast-path series (v1, posted 2026-07-16:
`lore.kernel.org/netdev/20260716004357.3652679-1-dave.seddon.ca@gmail.com`).

## Willem's review (verbatim)

> This series adds a lot of code: +2500 LoC.
> If you want a linear fast path, the BPF dissector offers that.
> I don't think the purported benefit justifies the significant new code, I'm afraid.
> The code is duplicative of existing paths, so there may be additional
> maintenance cost keeping the two consistent.
> And which paths justify a fast paths and which do not is highly
> subjective. Why is GRE included, for instance?

Ref: `willemdebruijn.kernel.c1b4383fb19c@gmail.com`

## Response strategy — split along the line the review draws

- **In-kernel C, minimal:** keep only `eth + IPv4/IPv6 + TCP/UDP` — the one shape
  that isn't a subjective judgment call. Always-on-capable, no eBPF, no config;
  what `skb_get_hash()` (RPS/RFS, fq/cake, bonding) sees most. This is the posted
  patches **01 + 02** reduced to a v2.
- **Subjective shapes → eBPF:** VLAN/QinQ, PPPoE, MPLS, IP-in-IP, GRE — Willem's
  own suggestion. The in-tree BPF flow dissector (`bpf_flow.c`) **already parses
  all of these except PPPoE**; `../series2-bpf-pppoe/` closes that one gap.
  Optionally offer a faster loadable BPF dissector (extend
  `samples/flow_dissector/fast_bpf/fast_flow.bpf.c`) — perf + size TBD.

## Line-count reduction (solid, goes in the reply)

| Scope | Files | Insertions | Deletions |
|-------|-------|-----------:|----------:|
| Full posted series | 12 | +2500 | −49 |
| Patch 01 (gate BPF-lookup behind static key) | 3 | +75 | −47 |
| Patch 02 (eth+IPv4/IPv6+TCP/UDP fast path) | 3 | +302 | −3 |
| **Reduced v2 (01 + 02)** | **5** | **+377** | **−50** |

≈ one-seventh of the +2500 objected to.

## Files here

- `reply/willem-reply.txt` — the draft reply (full version + a lean variant).
  **NOT SENT.**

## Send gates — decide to send only after both are known

1. **BPF perf numbers** — micro-bench the loadable dissector vs the in-tree one
   via `BPF_PROG_TEST_RUN`:
   `nix run .#run-on-host -- hp5 -- flow-dissector-matrix-unified`
   (baseline `perf-results/2026-05-17-hot-edge/summary.md`; existing `c-bpf-fast`
   ~12–22 ns/pkt vs `c-bpf-flowdis` ~91–119). Fills `[X ns/pkt vs Y]`.
2. **eBPF size** — lines the full-menu program adds. Today
   `fast_bpf/fast_flow.bpf.c` has 7 chains; missing shapes (QinQ, VLAN-over-IPv6,
   PPPoE, MPLS, IPIP/4in6/6in4, GRE) add ~N tail-call slots. Fills `[N lines]`.
   If N is large, use the **lean variant** (defer to existing in-tree BPF
   coverage) instead of promising a new program.

Then choose: full draft (with numbers) / lean variant / hold.

Build env: BPF work uses `nix develop` + `make -C samples/flow_dissector bpf` and
the `flow-dissector-matrix*` flake outputs; extend `flake.nix` if more tools are
needed rather than installing by hand.

## eBPF menu

The "subjective shapes → eBPF" half is designed and built as a per-encapsulation
loadable menu — see [`ebpf-menu.md`](ebpf-menu.md). **Ten** objects under
`samples/flow_dissector/fast_bpf/fast_flow_<encap>.bpf.c` (shared
`fast_flow_inner.h`), ~1080 source LoC total, all compiling via `make bpf`:
- L2/simple: eth_ip, vlan, qinq, mpls, ipip, gre, pppoe
- UDP-tunnel inner-flow **descent**: vxlan, geneve, gtpu (mirrors series5-descent;
  fixes the outer-5-tuple hash collapse that reorders overlay/mobile traffic).
  FOU/GUE deferred (no well-known port).

## Status

- [x] Draft reply written (full + lean variant)
- [x] eBPF full-menu size known — **~1080 source LoC** (10 objects + shared header),
      out-of-kernel, vs +2500 (fast-path) + +1507 (descent) in-kernel
- [x] eBPF menu written + compiling clean (eth_ip, vlan, qinq, mpls, ipip, gre,
      pppoe, + UDP-tunnel descent: vxlan, geneve, gtpu)
- [x] Makefile wired (`MENU_BPF` + pattern rule)
- [x] Benchmark + parity harness built (`bench_menu.sh` + `nix/flow-menu-bench.nix`,
      flake target `flow-menu-bench`); per-shape corpus mapped (all git-tracked)
- [ ] BPF perf numbers measured — **l2 (x86 Zen2) run pending**; hp5/hp2 down,
      ARM/RISC-V DUTs unreachable as of 2026-08-05, so cross-ISA waits
- [ ] Per-shape Gold parity verified (in-tree oracle for eth_ip/vlan/qinq/gre/ipip;
      series2 oracle for PPPoE; C-dissector for MPLS + vxlan/geneve/gtpu)
- [ ] Reduced v2 (patches 01–02) regenerated
- [ ] Reply sent (`git send-email --in-reply-to=<willem-msg-id>`)
