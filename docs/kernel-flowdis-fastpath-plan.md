# Kernel flow_dissector fast-path series — plan

**Date**: 2026-05-26
**Branch**: TBD (likely `kernel-flowdis-fastpath` off
  `flow-keys-compat-reorder`)
**Target outlet**: netdev — Linux kernel net-next, RFC first
**Base commit**: same as series 1 + 2 — net-next
  `c0aa5f13826dcb035bec3d6b252e6b2020fa5f88`
**Companion docs**:
  - `docs/upstream-options.md` — this series is "Path A" (backport
    techniques) of the four-path analysis
  - `docs/kernel-vs-xdp2-comparison.md` — the measurement table
    this series derives from
  - `docs/perf-summary.md` — phase-by-phase XDP2 win attribution
  - `xdp2-rs/docs/dispatch-architecture-cost.md` — mechanism
    analysis behind the 38% headline

## TL;DR

Apply XDP2's R3.4 fast-path technique to the in-tree
`__skb_flow_dissect()`. The technique alone captures **~95% of
XDP2's 38% headline win** and is portable straight-line C — no
codegen, no new tooling, no XDP2 in-tree.

Expected on-the-wire result: **117 → 85-90 ns/pkt** on flat
internet traffic (~25-30% faster vs vanilla). Patches preserve
byte-identical `struct flow_keys` output, fall-through cost on
unmatched packets is ≤5 cycles (one ethertype switch), and BPF
flow_dissector override semantics are unchanged.

This is the **most pragmatic** of the four upstream paths
identified in `upstream-options.md`. Path A: low controversy,
incremental review surface, doesn't require XDP2 framework
upstream.

## Why this works — perf decomposition

XDP2's journey on https-web (`perf-summary.md`):

| Phase | What it did | ns/pkt | delta |
|---|---|---:|---:|
| Pre-R3.3 | Indirect-call dispatch | 116 | — |
| R3.3 IR-coverage devirt | Inline metadata writes | 116 | **0 (null)** |
| **R3.4 fast-paths** | **Bypass slow-path state machine on common shapes** | **71** | **-45 (-39%)** |
| R5/R6/R7 polish | Bookkeeping, layout | 72 | +1 (noise) |
| R8 VXLAN fast-path | Bypass tunnel walk | 72 | 0 on flat workloads |

One technique — R3.4 fast-paths — produces essentially the entire
flat-workload speedup. R3.3 devirt was a NULL because gcc -O3 +
LTO already inlines indirect calls at compile time. The kernel
builds with -O2 by default but gets the same indirect-call
inlining when targets are constant.

### What the kernel CAN capture (the bulk of the win)

The R3.4 technique is roughly 30 lines of straight-line C:

```c
/* Pseudo-code from xdp2's mono_def.template.c, R3.4.1 phase */
if (len >= 14 + 20 + 4) {
    __be16 etype = *(__be16 *)(p + 12);
    if (etype == htons(ETH_P_IP)) {
        const struct iphdr *iph = (void *)(p + 14);
        if (((__u8 *)iph)[0] == 0x45 &&        /* version=4, IHL=5 */
            !(((__u8 *)iph)[6] & 0x3f) &&      /* no fragment */
            !(((__u8 *)iph)[7]) &&
            (iph->protocol == IPPROTO_TCP ||
             iph->protocol == IPPROTO_UDP)) {
            /* Inline straight-line metadata extraction */
            extract_5tuple_v4(iph, keys);
            return TRUE;
        }
    }
}
/* Fall through to slow path */
```

Nothing here requires:
- libclang / Python codegen at build time
- LTO across translation units
- `always_inline` annotations
- A new struct layout
- BPF backend changes

It's a decision tree at function entry. The kernel can drop this
verbatim into `__skb_flow_dissect()`.

### What the kernel structurally CAN'T capture

Three things, in decreasing order of impact:

1. **always_inline + LTO into the caller's translation unit**
   (~5-10 ns/pkt). XDP2's mono parser inlines into the
   benchmark's parse loop as one ~10KB block. The kernel can't:
   `flow_dissector.o` and `sch_cake.o` are different TUs, no
   `always_inline`, function too large to reasonably inline.

2. **Constant-folding of `static const` proto_def fields**
   (~2-5 ns/pkt). XDP2 mono parser folds protocol-table constants
   at compile time. The kernel reads runtime data structures.

3. **Per-callsite specialisation** (~0-3 ns/pkt). XDP2 produces a
   fresh parser per use-site; kernel `flow_dissector` is one
   function serving many callers.

**Total un-recoverable**: 10-15 ns/pkt. The kernel can capture
30-35 of XDP2's 45-ns win, landing at ~85-90 ns/pkt vs XDP2's 71.
That's still a **25-30% improvement** over today's 117 ns/pkt —
substantial and absolutely worth shipping. The 10-15 ns gap is
the inherent price of being a generic kernel API.

## The patch series — proposed shape (6 patches in v1 RFC)

```
0/N  cover letter — measurements, motivation, fall-through cost
                    analysis, byte-exact output guarantee
1/N  flow_dissector: add fast-path entry-point skeleton
                    (~150 LoC, no behaviour change yet)
2/N  flow_dissector: add eth+IPv4+TCP fast-path
                    (~100 LoC, ~30 ns/pkt win on https-web etc.)
3/N  flow_dissector: add eth+IPv4+UDP fast-path
                    (~80 LoC, similar gain on UDP traffic)
4/N  flow_dissector: add eth+IPv6+TCP fast-path
                    (~100 LoC, IPv6 dual-stack and v6-only DCs)
5/N  flow_dissector: add eth+IPv6+UDP fast-path
                    (~80 LoC, IPv6 QUIC and UDP)
6/N  (optional) flow_dissector: add VLAN dispatch + 4 variants
                    (~150 LoC, datacenter VLAN tagging)
```

### Architectural commitment lives in patch 1

Patch 1 is the design contract. It establishes:

- **Function signature**: `static bool flow_dissect_fast(skb,
  flow_dissector, target_container, data, proto, nhoff, hlen,
  flags)` — same arguments as `__skb_flow_dissect()` so it can
  share state cleanly.

- **Insertion point**: AFTER the BPF override check (line ~1131 in
  current net-next), BEFORE the main slow-path dispatch (line
  ~1175+). BPF semantics unchanged: if BPF dissector is loaded,
  fast-path never runs.

- **Dispatcher shape**: one ethertype switch, ~5 cycles. Each
  arm calls a per-shape extractor that returns true (handled)
  or false (fall through to slow path).

- **Dissector compat check**: only enable fast-path for
  `flow_keys_dissector` and `flow_keys_dissector_symmetric` (the
  standard dissectors used by sch_cake, RPS/RFS, ECMP routing).
  Custom tc cls_flow dissectors with weird key sets fall through
  to slow path.

- **Output guarantee**: fast-path produces byte-identical
  `struct flow_keys` to the slow-path. ALL key slots that the
  slow-path would write are written. We don't skip "cold" keys
  (vlan, cvlan, flow_label, etc.) even though the consumer-touch
  matrix says they're unread; the win comes from bypassing
  dispatch, not from skipping writes. Trade ~3 ns for forward-
  compat safety.

- **Fall-through cost guarantee**: on a packet that misses every
  fast-path, total added overhead is one ethertype switch (~5
  cycles). Does NOT grow with the number of fast-path shapes.

Patches 2-6 are mechanical applications of the patch-1 framework.

## Per-patch design

### Patch 1: framework skeleton

```c
/* In net/core/flow_dissector.c, after the BPF override block: */

static bool flow_dissect_fast(const struct sk_buff *skb,
                              struct flow_dissector *fd,
                              void *target,
                              const void *data,
                              __be16 proto,
                              int nhoff, int hlen,
                              unsigned int flags)
{
    /* Only attempt fast-path for the standard dissectors. */
    if (fd != &flow_keys_dissector &&
        fd != &flow_keys_dissector_symmetric)
        return false;

    /* Don't fast-path when callers want behaviours we don't
     * support (encap, MPLS deep parse, key types we don't
     * cover, etc.) */
    if (flags & ~(FLOW_DISSECTOR_F_PARSE_1ST_FRAG))
        return false;

    /* Dispatch by outer ethertype — one switch, ~5 cycles. */
    switch (ntohs(proto)) {
    case ETH_P_IP:
        return flow_dissect_fast_ipv4(skb, fd, target, data,
                                       nhoff, hlen);
    case ETH_P_IPV6:
        return flow_dissect_fast_ipv6(skb, fd, target, data,
                                       nhoff, hlen);
    /* VLAN added in patch 6 */
    default:
        return false;  /* fall through to slow path */
    }
}

static bool flow_dissect_fast_ipv4(...) { return false; /* stub */ }
static bool flow_dissect_fast_ipv6(...) { return false; /* stub */ }

/* In __skb_flow_dissect(), after the BPF override block: */
if (flow_dissect_fast(skb, flow_dissector, target_container,
                      data, proto, nhoff, hlen, flags))
    return true;
/* Else fall through to existing slow path. */
```

Patch 1 adds the skeleton, the dispatch site in
`__skb_flow_dissect()`, and the two stub functions. **No
behaviour change**: every fast-path stub returns false, so every
packet still goes to the slow path. Measurable cost: one ethertype
switch on every packet (~5 cycles or ~1-2 ns).

**Why patch 1 is its own patch**: reviewers can scrutinise the
architectural contract (dispatcher shape, fall-through cost,
dissector compat) without being distracted by the per-shape
extraction code.

### Patch 2: eth+IPv4+TCP fast-path

Replaces the `flow_dissect_fast_ipv4` stub body:

```c
static bool flow_dissect_fast_ipv4(...)
{
    const struct iphdr *iph;

    if (hlen - nhoff < sizeof(*iph) + sizeof(struct tcphdr))
        return false;

    iph = (void *)(data + nhoff);

    /* Reject IP options (IHL != 5), fragmented packets,
     * and anything but the L4 protos we cover. */
    if (((const u8 *)iph)[0] != 0x45)
        return false;  /* version=4, IHL=5 */
    if ((iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0)
        return false;

    if (iph->protocol != IPPROTO_TCP)
        return false;

    /* Write key_basic — basic.n_proto + basic.ip_proto */
    if (dissector_uses_key(fd, FLOW_DISSECTOR_KEY_BASIC)) {
        struct flow_dissector_key_basic *kb = ...;
        kb->n_proto = htons(ETH_P_IP);
        kb->ip_proto = IPPROTO_TCP;
    }

    /* Write key_control — addr_type, thoff */
    if (dissector_uses_key(fd, FLOW_DISSECTOR_KEY_CONTROL)) {
        struct flow_dissector_key_control *kc = ...;
        kc->addr_type = FLOW_DISSECTOR_KEY_IPV4_ADDRS;
        kc->thoff = nhoff + 20;
        kc->flags = 0;
    }

    /* Write key_addrs.v4addrs */
    if (dissector_uses_key(fd, FLOW_DISSECTOR_KEY_IPV4_ADDRS)) {
        struct flow_dissector_key_addrs *ka = ...;
        memcpy(&ka->v4addrs, &iph->saddr, 8);  /* src + dst */
    }

    /* Write key_ports — TCP src + dst */
    if (dissector_uses_key(fd, FLOW_DISSECTOR_KEY_PORTS)) {
        struct flow_dissector_key_ports *kp = ...;
        const __be16 *ports = (void *)(data + nhoff + 20);
        kp->src = ports[0];
        kp->dst = ports[1];
    }

    return true;  /* fast-path handled it */
}
```

Reuse the kernel's existing `skb_flow_dissector_target()` to look
up where each key lives in `target_container`. Don't invent a
parallel mechanism.

**Expected delta**: -30 ns/pkt on https-web (matrix benchmark).
Hit rate: depends on workload. On internet traffic, eth+IPv4+TCP
is 40-60% of packets; on IPv6-dominant DCs, much lower.

### Patches 3-5: same pattern, different shapes

- **Patch 3 (IPv4+UDP)**: identical structure, `iph->protocol ==
  IPPROTO_UDP`, write src/dst ports from UDP header at iph+20.
- **Patch 4 (IPv6+TCP)**: IPv6 header is fixed 40 B (no IHL), no
  fragments unless extension header present. Reject any
  `nexthdr` other than IPPROTO_TCP. Write `v6addrs.{src,dst}` as
  two 16-byte memcpys (or four 8-byte stores).
- **Patch 5 (IPv6+UDP)**: same as patch 4, UDP instead of TCP.

Each patch is mechanically similar. The bulk of the diff is the
per-key write block (4 keys × 5-10 lines each).

### Patch 6 (optional): VLAN dispatch + 4 VLAN variants

Adds:
- `ETH_P_8021Q` arm in `flow_dissect_fast()` dispatch
- `flow_dissect_fast_vlan()` reads tag, looks up inner ethertype,
  dispatches to `flow_dissect_fast_ipv{4,6}()` with adjusted
  nhoff
- Writes `key_vlan` with TCI and inner ethertype

VLAN-tagged packets are common in datacenter and on some
prosumer NICs that don't strip the tag in hardware. Combined
saving on VLAN+IPv4+TCP: similar magnitude to patch 2 (~30 ns)
since the slow-path also walks the VLAN node + chains to IPv4
node.

Defer VXLAN/GRE encap variants to v2 — they have higher review
controversy (inner-vs-outer semantics) and the win is workload-
specific.

## Testing protocol

This is the major work surface of the series. Each patch must
pass:

1. **Build** — kernel compiles clean with W=1 on the patched
   tree.
2. **Boot** — patched kernel boots on all four testbed hosts
   (hp1, hp2, hp3, hp5) within 2 minutes; no console
   intervention needed.
3. **Correctness — parity** — fast-path output is byte-identical
   to slow-path output on a comprehensive pcap corpus.
4. **Hit-rate distribution** — what fraction of packets in each
   workload hit the fast-path?
5. **Performance — microbench** — flow-dissector ns/pkt on the
   matrix benchmark, on hp5 canonical + hp2 sanity check.
6. **Performance — macrobench** — iperf3 + iperf2 through cake
   triple-isolate on hp1↔hp3 mlx5_core 25 GbE.
7. **Stress — short sustained** — 30-min iperf3 to catch any
   pathology that microbench misses.
8. **Soak (final series only)** — 24h iperf3 + 24h iperf2 for
   stability under prolonged load.

### 3.1 Correctness — the byte-exact requirement

The fast-path MUST produce identical `struct flow_keys` to the
slow-path for every packet shape it handles. A diff in any field
is a release blocker.

**How to verify**: write a kernel selftest that:
- Loads a corpus of test packets (start with the 6 XDP2 sweep
  pcaps + the parity-gate's 22-pcap set; add specific synthetic
  packets per fast-path shape).
- Runs `__skb_flow_dissect()` once with the fast-path enabled,
  once with the fast-path forcibly disabled via a sysctl or
  CONFIG knob.
- Compares the two `flow_keys` structs byte-for-byte. Any
  mismatch fails the selftest.

The CONFIG knob can be `CONFIG_NET_FLOW_DISSECTOR_FAST_PATH`
(default y, but tunable for the parity selftest). Alternative:
runtime sysctl `net.core.flow_dissect_fast_path` that the
selftest toggles.

This selftest lives in `tools/testing/selftests/net/` and is part
of the patch series — probably patch 1 introduces the selftest
harness with stub data, each subsequent patch adds its shape's
test cases.

### 3.2 Hit-rate distribution

Per workload, what fraction of packets hits each fast-path arm?
This determines per-workload speedup and also identifies workloads
where the fast-path is null (won't measure a delta).

Easy to measure via the existing flow-dissector-matrix harness:
add a counter in `flow_dissect_fast()` that increments per arm
(or per "fell through to slow path"). Dump counters after each
benchmark run.

Expected on hp5 sweep pcaps:

| pcap | IPv4-TCP | IPv4-UDP | IPv6-TCP | IPv6-UDP | VLAN+v4 | slow |
|---|---:|---:|---:|---:|---:|---:|
| https-web | ~95 % | ~5 % | 0 | 0 | 0 | 0 |
| nfs-server | ~85 % | ~15 % | 0 | 0 | 0 | 0 |
| pppoe-isp | 0 | 0 | 0 | 0 | 0 | ~100 % |
| vlan-tcp-mix | 0 | 0 | 0 | 0 | ~95 % | ~5 % |
| k8s-microservices | ~20 % | ~80 % | 0 | 0 | 0 | 0 |
| vxlan-k8s-pure | ~5 % | ~95 % | 0 | 0 | 0 | 0 |

(estimates — measure these in patch 2 testing to confirm.)

pppoe-isp falls through entirely; XDP2 handled PPPoE with a
dedicated R3.4.5a chain, but the kernel-side PPPoE fast-path is
out of scope for this series (separate review surface, related
to series 2). vxlan-k8s-pure's outer dispatch hits IPv4-UDP
fast-path but stops there; the kernel doesn't walk inner today.

### 3.3 Performance — microbench

Use the existing `nix run .#flow-dissector-matrix-unified`
benchmark for ns/pkt measurements.

**Setup** (per-patch and final):
- Build the patched kernel as a NixOS flake derivation (same
  pattern as `kernel-patches/test-kernel/`).
- Boot all four hosts.
- Run the matrix benchmark with `c-flowdis-usp` as the parser
  driver — that exercises the kernel's
  `__skb_flow_dissect_err()` in userspace via libflowdis.so.
  Patched kernel binary headers go to libflowdis.so so we test
  the patched code path.
- Compare to vanilla kernel baseline.

**Iteration counts**: full mode (200 iter × 19822 pkt = 3.96M
parses per cell). ±1 ns noise band.

**Hardware controls**: taskset -c 3 (isolated CPU), full-CPU loop
to keep boost active, brief enough run to avoid thermal
throttling.

**Per-patch claim**: each patch must show a measurable delta on
at least one workload where its fast-path hits, AND must not
regress (>1 ns) any workload where its fast-path misses (the
fall-through cost claim).

### 3.4 Performance — macrobench

The microbench measures parser cost. The macrobench measures
whether that cost reduction translates to user-visible
throughput.

**Setup**: hp1 (gen) ↔ hp3 (DUT), mlx5_core 25 GbE, cake
triple-isolate on enp1s0f0np0.

**Tests per patch**:
- iperf3 -P 16 -t 60 — single quick measurement
- iperf2 -P 16 -t 60 -f m — multi-threaded comparison

**Tests for final series**:
- Phase A controlled comparison (N=10 per kernel: patched vs
  unpatched at same net-next base, tuned TCP profile). Same
  shape as the controlled comparison we ran for series 1
  (`perf-results/2026-05-24/controlled-comparison.md`).

**Expected**: on this Zen 1 / mlx5 testbed, both vanilla and
patched are CPU-bound on the hp3 receiver at ~16 Gbit/s. The
flow_dissector saving (~30 ns/pkt × ~24 Mpps = ~720 ms/sec of
CPU freed) might NOT show up as throughput gain — that CPU is
freed but the iperf3 stack also has other bottlenecks. Honest
framing: the macro test confirms NO REGRESSION at high load,
not necessarily a throughput WIN. The microbench shows the
parser cost; the macro shows real-traffic stability.

### 3.5 Short sustained — 30 min

Per-patch (during development, not final): 30-min iperf3 run
through patched cake. Catches:
- Memory accumulation that doesn't show in 60-s tests
- Cumulative cake drop counters drifting upward
- dmesg alerts that take time to surface

Quick gate, not a full soak. ~30 minutes per patch × 6 patches =
3 hours total during development.

### 3.6 Soak — 24h iperf3 + 24h iperf2

For the FINAL series only, before non-RFC submission.

**Why for final only**: each soak is 24h, plus result analysis.
Doing per-patch soaks would consume 6 × 24h = 6 days minimum.
Per-patch incremental testing (3.1-3.5) is enough to catch
correctness/regression issues during development.

**Pattern**: same as Phase B.1 (`perf-results/2026-05-25/`).
- 24h iperf3 -P 16 on patched final-series kernel
- 24h iperf2 -P 16 on patched final-series kernel (separately;
  link is single-DUT)
- Hourly snapshots: cake stats, RSS, dmesg alert count, TCP retx
- Comparison to B.1 baseline (16.023 Gbit/s mean, CV 1.27 %).
  Patched mean within ±1 % of baseline = pass.

### 3.7 BPF compat verification

The BPF flow_dissector hook semantics must be unchanged. Verify
on hp5:

- Load `tools/testing/selftests/bpf/progs/bpf_flow.bpf.o` via
  `flow_dissector_load.c`
- Confirm BPF dissector is invoked (not the C fast-path) when
  loaded
- Unload, confirm fast-path resumes

The patch 1 selftest harness should cover this case.

## Testing cadence — incremental vs batch (the open question)

Two viable shapes:

### Option A: Incremental — test each patch as written

```
Day 1:     Write patch 1 (framework) →  smoke test → ⚠ commit only if clean
Day 2-3:   Write patch 2 (IPv4 TCP)   →  full test (3.1-3.5) → commit
Day 4-5:   Write patch 3 (IPv4 UDP)   →  full test → commit
Day 6-7:   Write patch 4 (IPv6 TCP)   →  full test → commit
Day 8-9:   Write patch 5 (IPv6 UDP)   →  full test → commit
Day 10-11: Optional patch 6 (VLAN)    →  full test → commit
Day 12-13: Final 24h soaks (iperf3 + iperf2)
Day 14:    Cover letter + post RFC
```

**Pros**:
- Catch bugs early (e.g. if patch 1's dispatch is wrong, find
  out at smoke test, not at patch 5)
- Each patch's measurement data is fresh when the commit
  message is written
- Matches how kernel maintainers will review (patch-by-patch)
- Lower cognitive load — write one shape, test it, move on

**Cons**:
- Slower wall-clock — kernel rebuild + boot + bench cycle is
  ~1h per round
- More context switching between writing and testing

### Option B: Batch — write all, then test the lot

```
Day 1-2:   Write patches 1-5 (and 6 if doing it). Pure C
           authoring, no kernel boots between.
Day 3-4:   Build the final series tree. Boot. Run full test
           matrix (3.1-3.7) against the final patched kernel.
Day 5-6:   Iterate on any failures. Re-test.
Day 7-9:   24h iperf3 + 24h iperf2 soaks.
Day 10:    Cover letter + post RFC.
```

**Pros**:
- Faster wall-clock for the "happy path" (no rebuilds between
  patches)
- Can see the complete shape before committing to specifics —
  may catch design problems by seeing the series whole
- One full test run instead of six

**Cons**:
- If patch 1's dispatch is wrong (e.g. wrong insertion point
  relative to BPF override), patches 2-5 inherit the bug. Hard
  to disentangle later.
- Risk of writing more code than necessary if the design needs
  rework
- Per-patch measurement data harder to fish out from a single
  final test run

### Hybrid (RECOMMENDED): patch 1 incremental, 2-5 batched

```
Day 1:    Write patch 1 framework + selftest harness
Day 2:    Smoke test patch 1 — boot on hp5, verify the
          dispatch site, confirm fall-through cost ≤5 cycles
          on a flat workload. STOP if anything's off.
Day 3-5:  Write patches 2-5 (the four flat fast-paths).
          Build series as a unit.
Day 6-7:  Full test (3.1-3.5) on the 4-patch series.
          Per-patch measurements extracted from a single full
          sweep using the CONFIG knob to enable/disable each
          shape.
Day 8:    Iterate on failures.
Day 9-10: Optional patch 6 (VLAN) — write + test.
Day 11-12: 24h iperf3 + 24h iperf2 soaks on final series.
Day 13:   Cover letter + post RFC.
```

**Rationale**: Patch 1 is the architectural commitment. If its
dispatch shape, BPF interaction, or fall-through cost is wrong,
everything downstream is wrong. So patch 1 gets independent
validation. Once that's nailed, patches 2-5 are mechanical
applications of the same pattern — testing them as a batch is
fine, and the per-patch measurement can be extracted via the
CONFIG knob (compile fast-path-2 in, fast-path-3 out, etc., or
runtime sysctl).

**~12-13 day estimate** assumes one engineer working full-time
with no major design surprises. Tom-coordination time is
additional.

## Open questions before posting RFC

1. **CONFIG knob naming**. `CONFIG_NET_FLOW_DISSECTOR_FAST_PATH`
   (default y)? Or no knob, always-on with a runtime
   `/proc/sys/net/core/flow_dissect_fast` for testing? Kernel
   convention favours always-on for "this just works, no
   tradeoff" features. But the selftest needs a way to disable
   it to compare against slow-path. **Recommendation**:
   runtime sysctl for the selftest, default-on, no CONFIG knob
   (always compiled in).

2. **IP options handling (IHL != 5)**. Reject in fast-path → fall
   through. IP options are rare on modern internet but common
   on some enterprise networks. Falling through is safe; never
   incorrect.

3. **Fragmented packet handling**. Reject in fast-path → fall
   through. Fragmentation is correctness-critical and the
   slow-path has explicit fragment handling.

4. **IPv6 extension headers**. The IPv6 fast-path should reject
   any nexthdr that's an extension header (HBH, routing, frag,
   dest-opts, etc.) — only handle the "clean" case where nexthdr
   == TCP or UDP. Extension headers are rare on internet
   traffic and the slow-path handles them correctly.

5. **VXLAN inner dispatch**. Out of scope for v1 of the series.
   Different review surface (changes semantics — kernel currently
   stops at outer 5-tuple). Defer to v2 or a separate series
   after Path A lands.

6. **PPPoE**. The kernel's C dissector handles PPPoE today; a
   fast-path for PPPoE is feasible but adds complexity to the
   eth-ethertype dispatch. Out of scope for v1.

7. **MPLS, GRE, GENEVE, ESP, AH**. Out of scope. All rare enough
   that the fall-through cost is acceptable.

## Risks and mitigations

| risk | mitigation |
|---|---|
| Patch 1 dispatch site is wrong (e.g. wrong order vs BPF, breaks netns) | Independent patch-1 testing on hp5 before writing 2-5 |
| Hit rate is much lower than expected on real traffic, neutralising the win | Measure hit rate during patch 2 testing on multiple pcap corpora before writing 3-5 |
| Some consumer reads a key slot we don't populate in fast-path | Byte-exact selftest catches it before submission |
| The 30 ns/pkt microbench win doesn't translate to macro speedup | Honest framing in cover letter: "parser cost reduced; macro stability unaffected." Don't claim macro throughput win |
| Kernel reviewer wants the fast-path implemented differently (e.g. inline expansion vs separate functions) | Patch 1 is RFC framing; expect 2-3 rounds of design feedback before non-RFC. Plan for 4-6 weeks of total review cycle |
| BPF maintainers worry about hook precedence | Cover letter explicitly addresses: fast-path runs AFTER BPF check, BPF semantics unchanged |
| Each patch is too small to justify the review burden | Combine into 2-3 larger patches if reviewers prefer (e.g. 1: framework + IPv4, 2: IPv6, 3: optional VLAN) |

## Talking points for Tom

Use these to structure the conversation when patches are ready:

1. **The R3.4 fast-path technique is 95% of the XDP2 win and is
   fully portable to in-tree C.** Not a codegen requirement — a
   30-line decision tree at function entry.

2. **R3.3 devirtualization was a NULL.** gcc -O3 + LTO already
   inlines indirect calls at compile time when targets are
   constant. The kernel gets this from the compiler.

3. **The ~10-15 ns/pkt the kernel can't capture** comes from
   being a generic API (no per-callsite specialisation, no LTO
   into caller TUs). That's the inherent price of `struct
   flow_keys` being ABI; not worth trying to recover.

4. **Expected kernel speedup**: 117 → ~85-90 ns/pkt on
   https-web. ~25-30% faster vs today, captured purely with a
   portable technique. No new tooling, no new structs, no XDP2
   in-tree.

5. **Patch shape**: 5-6 patches (framework + 4 flat shapes +
   optional VLAN). Each independently measurable. Each ~50-150
   LoC.

6. **This series doesn't preclude future XDP2 work** — it's
   the incremental backport. The wholesale-replacement path
   (Path B-2 in `upstream-options.md`) remains a separate
   conversation. Path A captures most of the user-visible win
   now without waiting on the framework conversation.

## Prior art and references

- `xdp2-rs/docs/dispatch-architecture-cost.md` — original
  perf decomposition by XDP2 phase
- `docs/r3.4-and-hot-edge-plan.md` — R3.4 implementation plan
  (the work we're backporting)
- `docs/perf-summary.md` — the 6-workload comparison table
- `perf-results/2026-05-23-flow-keys-consumer-audit/findings.md`
  — what kernel consumers actually read from `flow_keys`
  (informs which slots fast-path must write)
- `kernel-patches/series1-flow-hash-small/v1/` — patch series
  shape, cover-letter style, build/test docs
- `perf-results/2026-05-25/soak-B1-iperf3-24h-results.md` — soak
  test pattern + pass criteria

## Followups (after RFC v1 posted)

- Capture lore.kernel.org message-id for citation
- Send patch series to Tom + project Slack/email separately for
  internal feedback
- Watch netdev reviewer feedback for 1-2 weeks
- Iterate per feedback; v2 posting
- Update `docs/upstream-options.md` Path A status from "planned"
  to "in flight" / "submitted"
