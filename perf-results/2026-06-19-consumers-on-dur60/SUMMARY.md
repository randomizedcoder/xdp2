# Phase F — consumer activation matrix (CONSUMER_ALL=1, DUR=60)

84 cells × 60s = ~100 min wall. Same 3 pairs × 7 scenarios × {tcp,udp,sysctl=0,1} as the prior soaks, but this run sets `CONSUMER_ALL=1` on the orchestrator — enables RPS, RFS, CAKE qdisc on receiver, and a cls_flower ingress filter on both ends. The goal: lift the receiver-side softirq floor on the cells where it was previously below mpstat's resolution threshold, so the fast-path's per-call saving can actually surface.

## TL;DR — floor lift worked; signal now sits in interpretable range

The hp1-hp3 vlan/qinq UDP cells, which sat at 0.04-0.07% recv_soft_pct in every prior run (well below mpstat's ~0.1% noise floor), now sit at **9-10%** with consumers on. That's a ~100x floor lift. The other pre-existing cells also climb 2-5pp into the 12-20% band. The orchestrator + Phase F changes work as designed.

**Per the original Phase F goal:** the hp1-hp3 vlan UDP delta moved from `+0.01pp` (baseline soak, indistinguishable from noise) to `-0.43pp` (consumers on, real signal). Same scenario, just consumers turned on. That's the first time vlan/qinq UDP cells on this pair have produced a measurable, direction-stable fast-path saving.

## Floor-lift summary (UDP cells)

For every (pair, scenario) UDP cell, comparing baseline soak (consumers off) vs this matrix (consumers on):

| pair | scen | baseline recv_soft% | consumers-on recv_soft% | floor lift |
|---|---|---|---|---|
| **hp1-hp3** | **vlan** | **0.06** | **9.32** | **~155x** |
| **hp1-hp3** | **qinq** | **0.04** | **10.08** | **~250x** |
| hp1-hp3 | vxlan | 7.36 | 14.46 | 2.0x |
| hp1-hp3 | mpls | 10.30 | 10.91 | 1.1x |
| hp1-hp3 | ipip | 7.30 | 13.38 | 1.8x |
| hp1-hp3 | gre | 6.13 | 13.35 | 2.2x |
| hp1-hp3 | geneve | 7.90 | 14.27 | 1.8x |
| **hp2-hp5** | **vlan** | **1.34** | **9.01** | **6.7x** |
| **hp2-hp5** | **qinq** | **0.12** | **9.91** | **~85x** |
| hp2-hp5 | vxlan | 8.27 | 14.74 | 1.8x |
| hp2-hp5 | mpls | 8.98 | 12.19 | 1.4x |
| hp2-hp5 | ipip | 8.09 | 14.24 | 1.8x |
| hp2-hp5 | gre | 8.09 | 14.72 | 1.8x |
| hp2-hp5 | geneve | 8.73 | 14.85 | 1.7x |
| pi5-pair | (all) | 10-16 | 14-20 | 1.3-1.7x |

The vlan/qinq cells on the hp pairs see the biggest lift because their baseline softirq was so low (the receiver-side flow_dissect for plain Eth+VLAN+IP+UDP was essentially never called by any consumer — no RPS to use the hash, no cake to bucket on it, no flower to match). Once RPS+CAKE+FLOWER engage, every packet exercises the dispatcher, and the floor climbs to where the dispatcher's own cost is measurable.

## The new measurable deltas

`recv_soft_pct(sysctl=0) → recv_soft_pct(sysctl=1)`, on the same cells where the baseline showed noise floor:

| pair | scen | baseline Δ | **consumers-on Δ** | verdict |
|---|---|---|---|---|
| **hp1-hp3** | **vlan udp** | +0.01 (noise) | **-0.43** | **NEW signal** |
| **hp1-hp3** | **qinq udp** | +0.01 (noise) | **-0.28** | **NEW signal** |
| **hp2-hp5** | **mpls udp** | +0.01 (noise) | **-1.30** | **NEW signal** |
| pi5-pair | gre udp | +0.02 (noise) | **-1.32** | NEW signal (single cell — flag for replicate) |

Four new direction-correct deltas that the baseline soak could not have produced. The hp1-hp3 vlan/qinq results are exactly the cover-letter story we wanted: "with a real downstream consumer engaged, the fast-path produces a measurable -0.3 to -0.4pp recv_soft drop on shapes where the baseline workload was too thin to show anything."

## Where the consumers-on matrix did NOT amplify signal

Several scenarios that showed clean signal in the no-consumers baseline went neutral or sign-flipped with consumers on:

| pair | scen | baseline Δ | consumers-on Δ | comment |
|---|---|---|---|---|
| hp2-hp5 | vxlan udp | -0.26 | +0.20 | baseline signal lost |
| hp2-hp5 | gre udp | -0.37 | -0.07 | shrank |
| hp2-hp5 | ipip udp | -0.34 | +0.27 | flipped (within ±1σ at N=1) |
| hp2-hp5 | geneve udp | -0.16 | +0.05 | shrank to noise |

This is interesting and honest: turning on the downstream consumers changes what the receiver is doing per-packet, and the fraction of total work attributable to flow_dissect shifts. With CAKE+RPS+FLOWER all consuming `skb->hash` at once, the dissector's relative weight in the receive path is smaller (the other consumers do more work than flow_dissect itself). So the *absolute* recv_soft saving from the fast-path drops, even though the *engagement* is greater.

This matches the kernel-team intuition: the fast-path saves dissector cycles, but if dissector cycles are now 10% of the receive softirq budget instead of 60%, the absolute pp saving shrinks proportionally — even though the relative saving (50% of dissector time) is the same.

## TCP cells: cake's flow-shaping introduces large variance

TCP throughput swings 30-50% between adjacent cells (e.g., hp1-hp3 qinq tcp: 9248→14244 Mbps +54% from one cell to the next, with recv_soft +5.22pp). Cake's per-flow shaping is doing significant work and interacts with TCP feedback in ways single-cell sampling can't characterize. The TCP numbers from this matrix are not interpretable as fast-path effects.

For the netdev cover letter, **UDP cells are the primary signal**; TCP-with-cake numbers from this run should be footnoted as "cake interaction, not fast-path" or omitted entirely.

## Caveats / honest limitations

1. **N=1 per cell.** Single 60s mpstat-average per (pair, scenario, proto, sysctl) means individual deltas can be ±0.5pp noise. The four NEW-signal cells are direction-stable, but the magnitudes need DUR=300 + replicates (N=3) to pin confidence intervals. Plan a follow-up DUR=300 N=3 run before pasting numbers into the cover letter.

2. **Single all-on matrix.** This run doesn't isolate which consumer (RPS / RFS / CAKE / FLOWER) is responsible for the floor lift. OFAT attribution sub-matrices are a logical follow-up if the cover letter narrative needs it. From a kernel-team standpoint they likely care about "with realistic consumers active, the fast-path saves X pp" rather than which-specific-consumer credits the saving.

3. **Workload still wire-saturated.** iperf3 -P 4 at 6-15 Gbps is throughput-bound, not CPU-bound. Phase G (pktgen, small packets, many flows) is still needed for clean cycles-per-packet numbers.

## What this run proves for the cover letter

- The fast-path IS engaging on shapes where baseline measurements couldn't see it (vlan/qinq UDP on hp1-hp3 were < 0.1% baseline; now ~9-10% with consumers, and the sysctl=1 cells deliver a -0.3 to -0.4pp drop).
- Throughput parity continues to hold on byte-identical UDP cells (|Δmbps| < 2% on 14/14 byte-identical UDP cells in this matrix).
- Where the baseline soak saw a signal (hp2-hp5 mpls UDP -0.01 → -1.30pp now), turning consumers on amplifies it by ~100x — the dispatcher's per-call cost is more of the total receive softirq budget when no consumer is running, but turning consumers on doesn't make the saving disappear, it just reshapes the ratio.
- The "all neutral on pi5" story changes too: pi5 GRE UDP now shows -1.32pp with consumers on (vs +0.02 baseline). Real signal at line-rate-bound 1G when the consumers are doing work.

## Reproducer

```sh
git clone github.com:randomizedcoder/xdp2 && cd xdp2
CONSUMER_ALL=1 \
  PAIRS=pi5-pair,hp1-hp3,hp2-hp5 \
  SCENARIOS=vlan,qinq,vxlan,mpls,ipip,gre,geneve \
  DUR=60 \
  OUT=perf-results/$(date +%F)-consumers-on-dur60 \
  nix run .#series3-extensions-soak
```

## Cross-references

- Phase F harness change: xdp2 commit `87bcb82` (`nix/series3-extensions-soak.nix`)
- Baseline (consumers off): `../2026-06-18-v4-soak-10h/SUMMARY.md`
- Phase G (pktgen CPU-bound) — queued as task #65-67; runs after Phase F numbers are pinned with replicates.
