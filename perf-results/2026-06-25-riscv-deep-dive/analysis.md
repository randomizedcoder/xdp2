# RISC-V flow_dissector fast-path: a deeper analysis (SpacemiT K1 / X60)

**Date**: 2026-06-25. Why the series-3 fast-path matters on RISC-V, how
the earlier "didn't help much" macro result reconciles with the ~50%
microbench win, and what the instruction-level data says.

## 1. Reconciling the two stories

Earlier macro runs (Phase F iperf3, Phase G pktgen) on the bpi-f3 showed
no clean A/B, and we attributed it to "not saturating the CPU." The
dual-sender stress test (both pi5s flooding both 1 GbE ports) makes the
real reason precise:

- The K1's in-tree `k1_emac` is **single-RX-queue**. Under a small-packet
  flood it received only ~682k pps **at ~17% CPU** and dropped the rest —
  it is **NIC-ring / NAPI-bound, not CPU-bound**. Packets are dropped at
  the ring before the dissector even runs.
- So on this hardware the flow dissector is **never the network
  bottleneck**, and a macro A/B cannot show a dissector effect — the
  bottleneck is elsewhere (the single queue), and the per-packet RX
  overhead (~3300 cyc/pkt of NAPI/ring/RPS) dwarfs the dissector.

The fast-path *always* helped RISC-V; the macro tests just can't see it
on a single-queue NIC. The right instrument is the **userland microbench**,
which isolates the dissector from the NIC/queue. There, the win is large
and unambiguous.

## 2. Instruction-level breakdown (perf stat, eth+IPv4+TCP, 20 M iters, core-pinned)

Per-packet, slow path (baseline) → fast path (patched):

| metric / pkt | RISC-V X60 (bpi-f3) | x86 Zen2 (l, TR 3945WX) |
|---|---|---|
| ns/pkt | 98.15 → 49.38  (**−50%**) | 10.19 → 5.97  (**−41%**) |
| cycles | 158.2 → 79.8  (−50%) | 41.9 → 24.6  (−41%) |
| **instructions** | **220.4 → 111.8  (−49%)** | **175.0 → 98.6  (−44%)** |
| branches | 27.2 → 14.1  (−48%) | 37.2 → 18.1  (−51%) |
| L1-dcache loads | 49.3 → 25.2  (−49%) | 67.4 → 49.3  (−27%) |
| branch-misses | ~0 (hot loop) | ~0 (hot loop) |
| **IPC** | **1.39 → 1.40** | **4.17 → 4.00** |

## 3. What this says

**(a) The win is algorithmic — instruction count, not microarchitecture.**
On both ISAs the fast-path roughly *halves the instructions retired* per
dissect: the slow path walks a generic protocol graph (loop iterations,
per-field `__skb_header_pointer`, indirect dispatch, key-by-key writes),
the fast-path is straight-line for the common eth+IP+L4 shape. Branch
mispredicts and D-cache misses are negligible in steady state, so this
is not a prediction or cache effect — it is simply fewer instructions.
Because it is algorithmic, it reproduces across x86, ARM, and RISC-V
(the cross-arch matrix: ~47-55% everywhere).

**(b) RISC-V benefits more directly than big x86 — the IPC tells why.**
The X60 runs at **IPC ≈ 1.4, and it is flat** between slow and fast. A
narrow core cannot hide the slow path's extra instructions behind
instruction-level parallelism, so each removed instruction removes a
cycle ≈ 1:1 → a clean −50%. The Zen2, at **IPC ≈ 4.2**, actually runs the
*slow* path at slightly **higher** IPC than the fast path (4.17 vs 4.00):
its wide out-of-order engine **absorbs** some of the slow path's
redundant work as extra ILP, partially masking the cost — so its relative
win is smaller (−41%). In short: **the wider/deeper the core, the more it
hides a bloated dissector; the narrower the core, the more a leaner
dissector helps.** RISC-V cores in the networking/edge space today (the
X60 here, and the in-order class generally) sit on the "narrow" end.

**(c) Absolute cost makes it matter for RISC-V networking.** The X60
spends ~158 cyc / ~98 ns per slow-path dissect vs ~42 cyc / ~10 ns on
Zen2 — about **8× more wall-clock per packet** (lower IPC × lower clock,
~1.6 GHz). The fast-path returns ~48 ns/pkt to RISC-V vs ~4 ns on Zen2.
On a RISC-V router/gateway/concentrator doing software qdisc (cake/fq),
RPS, or WireGuard (every encrypted packet hits the dissector via cake —
see `../2026-06-25-wireguard-flowdis/`), that ~48 ns × Mpps is real CPU
headroom on exactly the class of device where cycles are scarcest.

## 4. Why this is interesting for the kernel network community

As RISC-V grows in networking and edge roles, the kernel's hot paths get
run on **narrower cores than the x86 server CPUs they were tuned on**.
This data shows a concrete instance: a generic, ILP-friendly-but-bloated
slow path (the flow dissector) costs proportionally **more** on RISC-V,
and a straight-line fast-path for the common shapes recovers it nearly
1:1 in cycles. The same code change that buys x86 ~40% buys the X60 ~50%
and 8× the absolute time per packet. Leaning out kernel hot paths is
disproportionately valuable on RISC-V — and measurable today.

## Method / reproduce

`perf stat -e cycles,instructions,branches,branch-misses,L1-dcache-loads,
L1-dcache-load-misses taskset -c 3 ./micro_flowdis 20000000`, run against
the patched (eth_ip fast-path) and baseline (`5960a9c6^`, no fast-path)
`libflowdis.so` via `LD_LIBRARY_PATH`. RISC-V binaries cross-built with
`pkgsCross.riscv64.stdenv.cc` (rv64gc); x86 native. Same `micro_flowdis.c`
as the rest of the series. The K1 PMU exposes these counters via
`sscofpmf` + the SBI PMU extension.

## 5. IPv6 — the other half of "the common case"

IPv6 is ~half of global traffic, so a "default-on for eth+IP" argument
lives or dies on IPv6. The eth_ip knob already covers it: the same
sysctl gates `flow_dissect_fast_ipv6`, which handles eth + IPv6
(no extension headers, nexthdr directly TCP/UDP — the common case) and
defers ext-header / requested-nonzero-flow-label packets to the slow
path to stay byte-identical.

Measured (eth + IPv6 + TCP, 20 M iters, byte-identical verified — same
addr fingerprint, addr_type, and ports patched vs baseline):

| | IPv4 base→fast | IPv6 base→fast |
|---|---|---|
| x86 Zen2 (l) | 10.10 → 5.86 ns (**−42%**) | 10.22 → 6.25 ns (**−39%**) |
| RISC-V X60 (bpi-f3) | 97.56 → 48.60 ns (**−50%**) | 123.41 → 92.34 ns (**−25%**) |

On x86 the IPv6 win ≈ the IPv4 win. **On RISC-V the IPv6 win is about
half the IPv4 win** (−25% vs −50%). The cause is the **unavoidable
32-byte IPv6 address copy** (two 16-byte addresses into the flow key):
both the fast and slow paths must do it, so for IPv6 it is a larger,
fixed fraction of the work that the fast-path cannot remove — leaving
less generic overhead to cut. On the narrow X60 (IPC ~1.4, ~1.6 GHz)
that copy stands out; x86's wider core and faster memcpy hide it, so
v6 ≈ v4 there. Note the v6 fast-path absolute (92 ns) is still well
below the v6 slow path (123 ns), and byte-identical.

**Implication for default-on:** the eth_ip fast-path is a net,
byte-identical win for *both* IPv4 and IPv6 on every arch tested — so it
does cover "the common case." But the per-arch/per-family size varies:
biggest on narrow cores for IPv4 (−50%), smallest for IPv6 on narrow
cores (−25%, address-copy-bound). A future refinement specifically for
narrow cores would be to speed the IPv6 address copy itself (it now
dominates the v6 fast-path); that is orthogonal to the dispatch
fast-path and would lift the v6 number toward the v4 number.
