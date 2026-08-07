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

- `reply/willem-reply-v3.txt` — **current send-ready draft.** Measured, focused
  concession: agrees the protocol boundary is subjective, so most of the series
  should drop; breaks down the +2500 by patch (KUnit test is the biggest chunk);
  proposes a reduced v2 = static-key gate + the single Eth+IPv4/IPv6+TCP/UDP fast
  path (~+377/−50); cites the verified 47–55% isolated / 4.7–31.6% allshapes perf
  gains; points the subjective shapes at the eBPF repo. Plain-text (no markdown
  fences), headers included → this file IS the email git send-email consumes.
  Rehearsed to dave.seddon@runpod.io (--suppress-cc=all). **NOT SENT to the list.**
- `reply/willem-reply-v2.txt` — prior draft (ease-of-use framing + VXLAN always-on
  descent + frozen-structs/low-churn maintenance data). Superseded by v3, which
  drops the descent pitch and the struct-stability data for focus; kept for reference
  (that material is in reserve for a reply-to-the-reply).
- `reply/willem-reply.txt` — earliest concession-heavy draft. Superseded.

## Send gates — RESOLVED

The two original placeholders (`[X ns/pkt vs Y]`, `[N lines]`) are **moot in v2**:
instead of promising a new inline BPF program with numbers, v2 cites the in-kernel
per-patch line breakdown and points at the public
`github.com/randomizedcoder/flow_dissector_ebpf` repo (which already carries the
byte-identical eth+IP object and the VXLAN descent). The perf/size work is captured
in `PERFORMANCE.md` / `ebpf-menu.md` for reference but is no longer a send gate.

Decision: **send v2** (user-gated).

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

- [x] Draft reply written (full + lean variant) — superseded
- [x] **Reply v2 written** (`reply/willem-reply-v2.txt`) — concede breadth, keep
      eth+IP in-kernel, +2500 per-patch breakdown, end-user ease-of-use framing,
      eBPF repo link, offer to upstream the eBPF objects as a `samples/` example
- [x] eBPF full-menu size known — **~1080 source LoC** (10 objects + shared header),
      out-of-kernel, vs +2500 (fast-path) + +1507 (descent) in-kernel
- [x] eBPF menu written + compiling clean (eth_ip, vlan, qinq, mpls, ipip, gre,
      pppoe, + UDP-tunnel descent: vxlan, geneve, gtpu)
- [x] Makefile wired (`MENU_BPF` + pattern rule)
- [x] Benchmark + parity harness built (`bench_menu.sh` + `nix/flow-menu-bench.nix`,
      flake target `flow-menu-bench`); per-shape corpus mapped (all git-tracked)
- [x] BPF perf numbers measured — microbench on l2 (Zen2) + hp5 (Zen1): GOLD +
      ~2–4× faster; **pktgen soak** hp2→hp5 (`perf/2026-08-05-hp2-hp5-soak/`): our
      object +158 cyc/pkt over the C path vs the in-tree BPF dissector's +4673
      (~30× cheaper). ARM/RISC-V DUTs still to come for cross-ISA.
- [ ] Per-shape Gold parity verified (in-tree oracle for eth_ip/vlan/qinq/gre/ipip;
      series2 oracle for PPPoE; C-dissector for MPLS + vxlan/geneve/gtpu)
- [ ] Reduced v2 (patches 01–02) regenerated
- [x] Reply v3 SENT 2026-08-07 — To Willem, Cc netdev@vger.kernel.org
      (`willem-reply-v3.txt`, git send-email, In-Reply-To Willem's msg-id,
      SMTP Result 250). Rehearsed to runpod first. Now awaiting Willem's response.
