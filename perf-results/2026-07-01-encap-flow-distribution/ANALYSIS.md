# Encapsulation inner-descent: flow-hash distribution study (2026-07-01)

## Question

The flow_dissector produces the canonical flow identity (`flow_keys` →
`skb->hash`) that ~50 call sites consume for load distribution and
classification: **RSS, RPS/RFS, ECMP/multipath, bonding/LAG (xmit_hash_policy),
tc-flower, and hardware aRFS**. For VXLAN / GENEVE / GTP-U overlay traffic the
dissector today **stops at the outer tunnel header**, so every one of those
consumers sees the *outer* tunnel identity, not the inner flow. Does descending
into the inner packet (the opt-in `net.flow_dissector.{vxlan,geneve,gtpu}_inner`
patches) give them a better identity — and by how much?

This is measured directly on the **hash**, so it is **consumer-agnostic**: every
spreader is `hash mod N`; every classifier reads the same keys. No qdisc is
assumed. (cake/fq_codel are simply among the consumers; they are not the point.)

## Method — faithful, low-risk

We use the repo's userspace port of the **real mainline dissector**
(`src/lib/flowdis/flow_dissector.c`, genuine `flow_hash_from_keys()` /
`__flow_hash_consistentify()` / siphash), driven by
`test_parser -i pcap,X -c flowdis -o text -H` (prints the true per-packet hash).
Stock, it has no VXLAN/GENEVE/GTP-U descent — it faithfully models current
mainline.

Rather than risk a mis-ported descent, we exploit an equivalence: the
inner-descent fast-path produces `flow_keys` (addrs/ports/basic) **identical to
dissecting the encapsulated inner frame standalone**, and the hash is over exactly
those fields. So:

- **OUTER-only (today):** run the harness on the full overlay pcap.
- **INNER-descent (patch):** run the *same unmodified harness* on the inner frame
  alone (`*.inner.pcap`) — byte-equivalent, for the hash, to what the patch computes.

Traffic (`gen_encap_dist.py`): a **single VTEP pair** (fixed outer src/dst IP +
MACs — the whole point: outer L3 does not vary) carrying **2000 distinct inner
flows** (k8s-microservices-ish: pod /24s, grpc/kafka/https/redis/dns), 20000
packets. Outer UDP source-port variants — the crux of the honesty:

- **kernelsport** — outer sport = `crc32(inner 5-tuple)` mapped to the ephemeral
  range, modelling real Linux `udp_flow_src_port()`. The *hard* case: the outer
  tuple already carries per-inner-flow entropy.
- **fixedsport** — outer sport pinned: HW VTEPs / configs that don't inner-hash.
- GTP-U has no sport-entropy mechanism (dport 2152) → generated fixed.

Metrics (`dist_metrics.py`), per bucket count N ∈ {8,16,64,256} (RSS-table / CPU
sizes): occupied buckets, chi² vs uniform, normalized entropy, Gini; plus
**distinct-hash count = flow-identity resolution** (independent of N).

## Results (2000 flows, 20000 packets)

| scenario | OUTER distinct | INNER distinct | OUTER occ@256 / entropy | INNER occ@256 / entropy |
|---|---|---|---|---|
| **gtpu (fixed)** | **1** | **2000** | 1/256 · 0.000 | 256/256 · 0.986 |
| **vxlan-fixedsport** | **1** | 2000 | 1/256 · 0.000 | 256/256 · 0.985 |
| **geneve-fixedsport** | **1** | 1999 | 1/256 · 0.000 | 256/256 · 0.986 |
| **vxlan-kernelsport** | 1883 | 2000 | 255/256 · 0.984 | 256/256 · 0.986 |
| **geneve-kernelsport** | 1883 | 2000 | 256/256 · 0.985 | 256/256 · 0.986 |

(Full per-N chi²/entropy/gini in `results.txt`.)

## Honest analysis

**1. GTP-U and fixed-sport tunnels collapse completely — descent fixes it.**
Outer-only resolves **1** flow: all 2000 inner flows land in **one** hash bucket
(chi² up to 5.1M vs uniform, entropy 0). Every hash-based consumer — RSS queue,
RPS/RFS CPU, ECMP nexthop, LAG member — sees a single flow and cannot spread or
distinguish them. Inner-descent restores full resolution (2000 distinct, uniform
across all 256 buckets, entropy 0.99). **GTP-U is the unambiguous flagship**: it
*never* has outer sport entropy, and it is the telco/5G mobile-core data path
(millions of subscriber flows behind one GTP-U tunnel between two endpoints).

**2. Kernel-sport VXLAN/GENEVE already spreads well — we say so.** With the
realistic Linux outer sport = f(inner flow), the outer 5-tuple already resolves
**1883** of 2000 flows and distributes near-uniformly (entropy 0.98–0.99). For
pure **hash-spreading** consumers (RSS/RPS/ECMP/bonding), outer-only is
**already fine** here; inner-descent's measurable gain is only the last ~6%
(1883→2000) lost to 14-bit sport collisions. We do **not** claim a spreading win
for this case.

**3. Where inner-descent still matters for kernel-sport overlays — identity, not
spread.** The outer sport is an *opaque* per-flow token: it spreads, but it is
**not** the inner flow. Any consumer that must read the *actual* inner flow —
**tc-flower** classification/policy/offload ("match inner dst 10.244/16 tcp
dport 9092"), connection tracking, per-tenant accounting, or ECMP path
*stability* under re-encapsulation — cannot use it. Outer-only exposes only the
VTEP IPs + tunnel port; the inner 5-tuple is invisible regardless of sport
entropy. This is a correctness/identity property, not captured by the spreading
metrics above, and it holds for all three encapsulations.

## Takeaway for the series4 cover letter

Frame generically (all `skb->hash`/`flow_keys` consumers, no qdisc):

- **Lead with GTP-U** (and fixed-sport tunnels): outer-only collapses 2000 flows
  → 1 bucket; descent → full spread. Unattackable, and it is *the* telco data path.
- **Be upfront** that kernel-sport VXLAN/GENEVE already spreads for RSS/ECMP —
  descent's value there is **inner-flow identity** for classification/policy/CT,
  not queue-spread.
- Every number is the **real kernel hash**; the result applies to every consumer
  at once.

## Reproduce

```sh
nix shell nixpkgs#python313 --command bash -c \
  "PYTHONPATH=<scapy site-packages> bash run_ab.sh"   # FLOWS/PACKETS overridable
```
Artifacts: `gen_encap_dist.py` (pcaps), `dist_metrics.py` (metrics),
`run_ab.sh` (driver), `pcaps/`, `hashes/`, `results.txt`.

**Caveat / follow-up:** the inner-descent numbers come from the equivalence
(dissecting the inner frame == descent output for the hash). A follow-up can
confirm by compiling the actual descent into `flow_dissector.c` and re-running;
expected to be identical. A *live* generic-spreading demo (RSS RX-queue occupancy
on the `netconf-vxlan`/`netconf-gtpu` overlays) is the visceral confirmation.
