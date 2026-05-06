# AF_XDP Live-Wire Baseline — 2026-05-06

First live-wire offered-load sweep with the post-17.E parity gate
in place. Real NIC RX path; not PCAP replay.

## Configuration

- **Path:** pktgen (hp2, generator) → 10 GbE link → X710 NIC (hp5, DUT)
  → Flow Director ntuple rule (UDP/443 → queue 1) → AF_XDP zero-copy
  → `xdp2-bench --mode af-xdp-template` on queue 1.
- **Frame:** 64 B UDP/443, single 5-tuple (no flow spread).
- **DUT receive:** **single queue, single core** — by design; this
  measures one-pipeline throughput, not aggregate cluster
  throughput.
- **Loads swept:** 1, 2, 5, 10 Mpps offered for 30s each.
- **Mode:** xdpdrv (native) + XSKMAP → zerocopy=true on every load.

## Results

| Offered (Mpps) | Received (pps) | Received (Mpps) | ns/pkt | drops_pct (vs. requested) | zerocopy |
|---:|---:|---:|---:|---:|:---:|
| 1  | 877,796 | 0.88 | 1139 | 12.2% | true |
| 2  | 877,785 | 0.88 | 1139 | 56.1% | true |
| 5  | 877,791 | 0.88 | 1139 | 82.4% | true |
| 10 | 877,792 | 0.88 | 1139 | 91.2% | true |

**The receive side caps at ~0.88 Mpps regardless of offered load.**
That's the single-queue, single-consumer ceiling on this hardware.

## What this tells us

**PCAP-replay vs. live-wire gap:**

| Path | Mode | ns/pkt | Mpps |
|---|---|---:|---:|
| PCAP replay (xdp2-bench, in-memory) | rust-template | 18 | 55 |
| PCAP replay | rust-graph-enum | 17 (combo) | 63 |
| **Live wire** (AF_XDP + 1 queue + 1 core) | af-xdp-template | **1139** | **0.88** |

Live-wire is **~50–60× slower** per packet than PCAP replay on the
same hardware. That gap is the entire RX pipeline — DMA, NAPI poll,
XDP attach, XSKMAP, AF_XDP umem refill, userspace batch — that
disk-replay benchmarks short-circuit by handing the parser a buffer
already in cache.

**Why drops_pct varies but pps_received doesn't:**
- At 1 Mpps requested, pktgen actually delivers ~947 K pps (it's
  open-loop and can't quite hit 1 M from one core); receiver gets
  877 K of those → ~7% real NIC RX drops + ~5% pktgen-shortfall
  (the JSON's drops formula uses requested rate × duration, so it
  blends both into the same number).
- At 10 Mpps requested, pktgen pushes harder; receiver still caps
  at 877 K and the rest is dropped at the NIC RX. drops_pct = 91 %.
- Identical pps_received across loads = consumer-side cap, full
  stop. Offering more just changes how much gets thrown away
  before the AF_XDP socket sees it.

## What this changes about the headline numbers

Before this run, the matrix campaign's headline was
"rust-graph-enum: 17 ns/pkt = 63 Mpps on combo.pcap." That number
is real, **for the in-memory parse-only path**. For end-to-end
"how fast can XDP2 process traffic arriving on a 10 GbE NIC?", the
answer on this hardware is closer to **0.88 Mpps per RX queue.**
Scaling out to 8 queues × 8 cores would in principle reach
~7 Mpps; verifying that requires a multi-queue ntuple sweep, not
done in this run.

The PCAP-replay numbers are still useful — they characterise the
parser's *intrinsic* per-packet cost (which composes with whatever
ingest pipeline you put in front of it). The live-wire number tells
you what that pipeline actually delivers today.

## Files

- `afxdp/{1,2,5,10}mpps.json` — per-load metrics.
- `afxdp/{1,2,5,10}mpps.log` — full bench output.
- `afxdp/{1,2,5,10}mpps-bench/` — pktgen counters, ntuple rules,
  raw xdp2-bench output preserved for diagnosis.

## Follow-ups (not in this run)

- Multi-queue ntuple sweep (RSS across 8 queues, multiple consumers)
  to measure aggregate ceiling.
- Frame-size sweep (64, 128, 256, 1500 B) — small frames are
  pps-bound; large frames will saturate link-rate before queue cap.
- Compare af-xdp-template vs. af-xdp-graph-enum to see if the
  single-protocol fixed-offset advantage that PCAP replay shows
  also lands on the live-wire path.
- Trace where the 1139 ns/pkt budget goes (DMA + NAPI + XSKMAP
  + parse + free) to identify the next optimisation target.
