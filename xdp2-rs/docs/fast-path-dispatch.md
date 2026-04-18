# Fast-Path Dispatch — Design Exploration

Companion to
[performance-next-steps.md](./performance-next-steps.md). Captures the design
discussion that followed the graph-enum A/B (Option A), so a new reader can
pick up the thread without reconstructing it from Git history.

## Where we are

The graph-enum experiment gave us a clear, repeatable signal
([perf-results/graph-enum/](../../perf-results/graph-enum/)):

| Mode | ns/pkt | Instr/pkt | Notes |
|------|-------:|----------:|-------|
| `graph` (dyn)        | 142 | 751 | vtable indirect-call per node |
| `graph-enum` (match) |  29 | 285 | static `match` dispatch |
| `compiled`           |  18 | 132 | monomorphic per-chain |
| `template`           |  17 | ~126 | pre-classified → fixed-offset extractor |

TMA confirmed everything is retirement-bound: gains come from **cutting
instructions per packet**, not recovering stalls. So the interesting question
now is: **what is the cheapest way to pick the right parse path for each
packet?**

This doc catalogs the options under consideration and lays out the
measurement plan.

## Two lookup problems, often confused

Before enumerating options it helps to separate two lookups that live inside
any parser:

1. **Protocol-table lookup** — "given the current node and its `next_proto()`
   result, pick the next node." Small cardinality: every `ProtoTable` in the
   graph has 2–15 entries. The branch predictor nails these (<0.25 % miss in
   TMA). Exotic data structures don't help here — they add a cache-line load
   without removing an instruction.
2. **Chain / flow-selection lookup** — "given an incoming packet, pick the
   whole parse chain to run on it." Potentially high cardinality (tens to
   thousands of distinct chains across a deployment), and heavily Zipfian in
   real traffic: a web server sees mostly TCP/IPv4 and TCP/IPv6, everything
   else is long tail.

The `graph`/`graph-enum`/`compiled` axis is about (1). The `template` mode
hints at (2) — classify first, then run a fixed extractor — but today that
classification is hard-coded and the template set is small.

## Is the enum really size-bounded?

Less than instinct suggests. Rust enums have no practical variant limit; a
40-variant `match` lowers to a jump table of 40 entries (≈320 B) that fits
trivially in L1. What does break down is **codegen ergonomics**: 40 arms ×
~10 `NodeOps` methods = 400 boilerplate lines per change. That's a
maintenance cliff, not a performance cliff, and a declarative macro that
takes the existing `ParseNode` definitions and emits `NodeOps` arms handles
it cleanly.

So "we can't enum past ~50 protocols" is wrong. The correct framing is: an
enum over *every* XDP2 node stays fast (we've measured 5 variants; scaling
to 40–60 is free), the cost is just the macro we'd have to write.

## Dispatch options surveyed

### For small protocol tables (lookup problem 1)

| Option | Expected delta vs linear | Complexity | When worth it |
|--------|--------------------------|------------|---------------|
| Linear scan (today) | baseline | — | n ≤ ~15, values predictable |
| Indexed LUT `[Option<&Node>; 256]` | 0 to +3 % | trivial | dense value space (IP proto) |
| Perfect hash (gperf/FKS) | ≈ 0 % | medium | static set, sparse values |
| `match` on dense enum | see graph-enum | medium | any — already measured |
| Cuckoo / SwissTable | ≤ 0 % | high | n ≫ 15 — not this problem |

Rough conclusion: the current linear scan is already near-optimal; the only
spot worth trying an indexed LUT is the IP-proto table (dense 8-bit key, a
256-slot table of pointers = 2 KB, fits in L1). Everything else is churn.

### For chain selection (lookup problem 2)

| Option | Latency profile | Throughput | Warmup | Notes |
|--------|-----------------|------------|--------|-------|
| **(a) Static top-N classifier** | deterministic | high on hot chains | none | pick from a fixed set of specialized extractors; fallback to graph |
| **(b) Runtime LRU of chain fingerprints** | hot=fast, cold=slow + spike on eviction | peak high, tails worse | yes | adaptive, matches skewed real traffic |
| **(c) Hash table keyed on fingerprint** (cuckoo / SwissTable / DPDK `rte_hash`) | hot=fast, cold=O(1) expected | high | yes | classic DPDK pattern, bounded probes |
| **(d) SIMD prefilter** (AVX2/AVX-512 byte compares) | deterministic | very high if chain count small | none | classify 4–8 packets in parallel against N signatures |
| **(e) B-tree / ordered search** | log n | lower than above | none | useful if key is range-based (CIDR, port range), not header-tag fingerprint |

Hash family is a whole sub-menu on its own — FNV-1a (small, cheap), CRC32C
(hardware on x86), Toeplitz (what NIC RSS uses — so the fingerprint could be
reused from RSS hash), xxHash-3 (fast, good distribution), jhash (Linux
kernel classic). For **chain fingerprints** (a few header bytes feeding a
coarse key) the hash is almost free; quality matters less than having no
pathological clusters.

## The fast-path architecture

All of (a)–(c) are variations on one theme: **optimize for the common chain,
fall back for the rest.** Same principle as a CPU's branch predictor or a
memory cache hierarchy.

```
    pkt ──► [classify] ─┬─► fast path: specialized extractor (17–20 ns/pkt)
                         │
                         └─► slow path: full graph / graph-enum (30–150 ns/pkt)
```

The three realistic variants:

### (a) Static top-N

Hand-pick the top N chains from a traffic survey (e.g. "TCP/IPv4 direct,
TCP/IPv6 direct, UDP/IPv4 direct, QUIC") and compile a specialized extractor
for each. A small classifier — `match` on `(ethertype, ip_proto)` plus a few
VLAN/tunnel checks, or a SIMD byte compare of the first 16 B against a
signature set — picks the index. Miss → graph engine.

- **Pros:** deterministic latency (critical for HFT). No warmup. Easy to
  reason about. Zero data-plane state.
- **Cons:** deployment-specific — `N=5` TCP/web is different from `N=5` NFS
  is different from `N=5` DPI/CDN. Requires recompile to change the set.

### (b) Runtime LRU

Compute a fingerprint from the first ~40 B (e.g. xxhash of `(ethertype,
vlan_mask, ip_proto, hdr-length bytes)`). Look up in a bounded LRU keyed on
fingerprint. Hit → dispatch to pre-registered specialized extractor for that
chain. Miss → graph engine, install result.

- **Pros:** adapts automatically to traffic. Works well under Zipfian
  distributions (which is basically always).
- **Cons:** warmup cost. Eviction causes latency spikes. "Pre-registered
  specialized extractor" is the hard part — real JIT is heavy; pragmatic
  version is "pick from a pre-built catalog of 16–32 extractors indexed by
  fingerprint."

### (c) Hash-table chain cache

Same idea as (b) but cuckoo/SwissTable instead of LRU. Lookup is O(1)
expected, 2 probes worst-case. No eviction unless the table fills.

- **Pros:** better worst-case than LRU. Simpler accounting.
- **Cons:** unbounded if traffic is diverse. Fills → rehash or evict.

## HFT vs DPI: pick your poison

- **HFT** (our primary performance target) cares about tail latency above
  all. LRU evictions — tens to hundreds of nanoseconds on rare packets —
  kill the p99.99. Static top-N (a) wins here; the trading desk knows its
  protocol chains, and pinning them at compile time is a feature, not a
  limit.
- **DPI / real-world mix** cares about throughput over many chains and
  evolves over time. (b) or (c) with a generous fast-path catalog is the
  match. The p99 penalty of an occasional eviction is a reasonable cost.
- **Commodity workload** (web server, NFS server) probably sees >99 % of
  packets in ≤5 chains — both (a) and (b) degenerate to the same thing.
  Whichever is easier to maintain wins.

## Measurement plan

Order matters — each step is cheap and the data from it decides whether the
next step is worth the engineering.

1. **Chain-histogram probe.** Parse every packet in a PCAP with the graph
   engine, derive a chain signature from the resulting `FlowMeta`, count.
   Print top-N with cumulative percentage. This tells us the shape of the
   distribution. If 80 % of `mixed-real.pcap` hits <10 chains, the
   fast-path architecture has large headroom. If it's uniform across 50+
   chains, the ceiling is lower and the priority changes.

   Implementation is a new `--chain-histogram` flag on `xdp2-bench`; no
   changes to the hot path. Cost: tens of minutes of coding.
2. **Static top-N fast-path prototype.** Using the top chains from step 1,
   hand-build specialized extractors (or reuse existing `template::*`
   entries), add a small classifier, fallback to `graph-enum`. Measure on
   the same PCAP. This is the (a)-variant upper bound.
3. **LRU/hash fast-path.** Only if (2)'s gains are large *and* the
   distribution in (1) is broad enough that a static set wouldn't cover
   real deployments. Warmup and tail-latency characterization required.

Reproducibility: every step below has a Nix target — see
[Reproducing this analysis](#reproducing-this-analysis) for the full
command catalogue. A dedicated-machine run can replay the whole
sequence and produce deterministic before/after numbers.

## Probe results (2026-04-18)

Ran the chain-histogram probe on three PCAPs. Raw report in
[`perf-results/chain-histogram/report.txt`](../../perf-results/chain-histogram/report.txt).

| PCAP | Packets | Distinct chains | Top-1 % | Top-5 % | Top-10 % |
|------|--------:|----------------:|--------:|--------:|---------:|
| `tcp_ipv4.pcap`        |     11 |  1 | 100.0 | 100.0 | 100.0 |
| `mixed-real.pcap`      |    815 | 12 |  80.9 |  95.7 |  99.5 |
| `combo.pcap` (500 k)   | 445 178 | 49 |  46.4 |  77.5 |  83.6 |

**Headline finding:** `mixed-real.pcap` — the merge of real captures that
matches a typical Linux-box mix — has **only 12 distinct chains, with
top-10 covering 99.5 % of packets**. Exactly the Zipfian shape the
fast-path architecture needs. A static top-10 classifier (option a) would
hit >99 % of packets on the fast path; even top-5 at 95.7 % is already a
strong result.

`combo.pcap`, which is synthetic/adversarial (VLAN/QinQ stacking with
exotic inner ethertypes, MPLS, PPPoE, VXLAN combinations), is much
flatter — 49 chains, top-10 only 83.6 %. This confirms the earlier
intuition: the fast-path win is **deployment-specific**. Real traffic
rewards it; pathological traffic flattens the curve.

Notable limitations of this first-pass signature:

- The `eth-0xXXXX` chains (large counts on combo.pcap — top two are
  `eth/vlan/eth-0x8100` and `eth/vlan/vlan/eth-0x88a8`) mean the graph
  stopped at L2 because the post-VLAN ethertype wasn't in the Rust graph's
  node set (only 5 protocols in `graph_enum`, and limited VLAN inner
  coverage in `graph`). These would become proper `/ipv4/tcp` etc.
  signatures if the graph covered them, so the true hot-chain
  concentration is likely even higher than the raw numbers suggest.
- Signatures are derived from `FlowMeta`, which flattens nested tunnels.
  `+vxlan?` and `+gre-inner` are best-effort hints. A precision upgrade
  would instrument the graph engine to record the actual node sequence.

**Decision gate passed**: on the real-traffic PCAP, ≥10 specialized
extractors cover ~99.5 % of packets. This is enough signal to justify
moving to step 2 of the measurement plan — prototyping a static top-N
fast-path with classifier + fallback to `graph-enum`.

## Probe results — workload profiles (2026-04-18)

Beyond the three stock PCAPs, we now have three **synthetic workload
profiles** modeling real deployments. Each is 20 000 packets generated by
[`samples/flow_dissector/gen_workload_pcap.py`](../../samples/flow_dissector/gen_workload_pcap.py)
with a fixed seed, cached as a Nix derivation for byte-identical reruns
across machines. Raw report:
[`perf-results/chain-histogram-workloads/report.txt`](../../perf-results/chain-histogram-workloads/report.txt).

| PCAP | Packets | Distinct chains | Top-1 % | Top-5 % | Top-10 % |
|------|--------:|----------------:|--------:|--------:|---------:|
| `https-web.pcap`         | 20 000 | 6 | 76.4 |  97.8 | 100.0 |
| `nfs-server.pcap`        | 20 000 | 5 | 88.5 | 100.0 | 100.0 |
| `k8s-microservices.pcap` | 20 000 | 5 | 79.5 | 100.0 | 100.0 |

**Confirmation of the Zipfian hypothesis.** All three profiles collapse
into ≤6 distinct chains with top-5 at ≥97.8 %. Even stronger than
`mixed-real.pcap` (top-5 = 95.7 %), because each profile models a single
deployment role rather than a merge of heterogeneous captures. The
architectural consequence: a static top-5 fast-path catalogue (option a)
would cover essentially all traffic for any of these roles.

**K8s / overlay caveat.** The K8s workload is 60 % VXLAN/IPIP-wrapped
(30 % gRPC-over-VXLAN, 15 % Kafka-over-VXLAN, 10 % other overlay), yet
the probe shows 79.5 % as plain `eth/ipv4/tcp`. That is because the
current signature function is derived from `FlowMeta`, which the graph
engine flattens through VXLAN — an inner TCP flow and a direct TCP flow
produce the same signature. In an overlay-heavy environment these are
*different* dispatch targets (the hot path needs to handle VXLAN
decap before running the TCP extractor), so the probe currently
**under-counts distinct chains in tunnel-heavy traffic**. A precision
upgrade — instrumenting the graph engine to record the actual node
sequence rather than relying on the flattened `FlowMeta` — is tracked
for a follow-up.

## Reproducing this analysis

Every target below is a Nix derivation or `writeShellApplication`
— nothing depends on a machine-local install. Cached derivations
(`nix build …`) produce byte-identical outputs on any Nix host;
interactive runners (`nix run …`) execute on the current machine and
write to `./perf-results/`.

### Graph-enum A/B (lookup problem 1)

    # cargo test + perf bench + flamegraph for graph / graph-enum / compiled
    # → perf-results/graph-enum/{test.log,bench_*.json,flamegraph_*.svg,summary.txt}
    nix run .#perf-graph-enum-compare

    # Focused cargo test only (byte-for-byte FlowMeta equality vs graph)
    nix build .#xdp2-rs-test-graph-enum

### Chain-histogram probes (lookup problem 2, step 1)

    # Single PCAP, custom top-N
    nix run .#chain-histogram -- /path/to/file.pcap 30

    # The three reference PCAPs (tcp_ipv4 + mixed-real + combo)
    # → perf-results/chain-histogram/report.txt
    nix run .#chain-histogram-all

    # The three workload profiles (https-web + nfs-server + k8s-microservices)
    # → perf-results/chain-histogram-workloads/report.txt
    nix run .#chain-histogram-workloads

### Workload PCAPs

Cached deterministic builds (20 000 packets, seed = 42):

    nix build .#workload-pcap-https-web
    nix build .#workload-pcap-nfs-server
    nix build .#workload-pcap-k8s-microservices

Interactive generator for ad-hoc sizes / seeds / workloads:

    nix run .#gen-workload-pcap -- --list
    nix run .#gen-workload-pcap -- \
        --workload k8s-microservices -n 100000 --seed 7 \
        -o /tmp/k8s-big.pcap

### Performance sweeps (ns/pkt, Mpps, perf counters, all modes × thread counts)

    # Reference sweeps
    nix run .#perf-sweep-tcp        # tcp_ipv4.pcap (baseline, 11 pkts)
    nix run .#perf-sweep-mixed      # mixed-real.pcap (~871 pkts)
    nix run .#perf-sweep-combo      # combo.pcap (500 k pkts)

    # Workload-profile sweeps
    nix run .#sweep-workload-https-web
    nix run .#sweep-workload-nfs-server
    nix run .#sweep-workload-k8s
    nix run .#sweep-workloads-all   # all three, sequentially

    # Pin to an isolated core to cut jitter
    CORE_PIN=3 nix run .#sweep-workloads-all

### CPU profiling (requires `kernel.perf_event_paranoid <= 2`)

    nix run .#perf-flamegraph       # flamegraphs for 4 modes on combo.pcap
    nix run .#perf-annotate         # assembly-level hot-function listings
    nix run .#perf-analysis-all     # every sweep + flamegraph + annotate

## Adding a new workload mix

The generator lives in
[`samples/flow_dissector/gen_workload_pcap.py`](../../samples/flow_dissector/gen_workload_pcap.py).
A workload is a weighted mix of packet builders; adding a new one is
three steps.

1. **Pick or add packet builders.** Builders are Python callables
   returning a single scapy packet. A typical builder looks like:

   ```python
   def build_eth_ipv4_tcp_https():
       return (Ether(src=rand_mac(), dst=rand_mac()) /
               IP(src=rand_public_ipv4(), dst=rand_public_ipv4()) /
               TCP(sport=rand_ephemeral(), dport=443,
                   flags="PA", seq=rand_u32()) /
               Raw(load=rand_bytes(bimodal_payload_len())))
   ```

   The existing helpers (`rand_rfc1918`, `rand_ipv6_ula`,
   `bimodal_payload_len`, `wrap_vxlan`, `wrap_ipip`, …) cover common
   shapes. Reuse them if you can; add one next to the others if you
   can't.

2. **Define the mix.** Add an entry to the `WORKLOADS` dict whose value
   is a list of `(weight, builder)` tuples. Weights are integers and
   should sum to 100 so the percentages match the workload description.

   ```python
   "cdn-edge": [
       (70, build_eth_ipv4_tcp_https),
       (15, build_eth_ipv6_tcp_https),
       (10, build_eth_ipv4_udp_quic),
       ( 3, build_eth_ipv4_icmp),
       ( 2, build_eth_arp),
   ],
   ```

3. **Wire up Nix targets** in [`nix/perf-analysis.nix`](../../nix/perf-analysis.nix):

   ```nix
   workload-pcap-cdn-edge = workloadPcap { name = "cdn-edge"; };
   ```

   Add the output to the `inherit …` block at the top of the returned
   attrset so it's exported, plus a `sweep-workload-cdn-edge` runner
   and the matching `flake.nix` entry. Append the cached PCAP to the
   loop inside `chain-histogram-workloads` if you want it included in
   the combined probe report.

Rebuild (`nix build .#workload-pcap-cdn-edge`) to get a deterministic
derivation you can drop into any sweep or perf target. The `--list`
subcommand of `gen-workload-pcap` prints the full mix so reviewers
can sanity-check weights without reading the Python.

## Related prior work

- `template` mode in `xdp2-bench` — today's manually-classified fast path
  for a handful of chains. The natural seed corpus for step 2.
- DPDK's `rte_hash`, `rte_flow_classify`, `rte_fbk_hash_table` — mature
  hash-based classifiers, worth studying for (c).
- Linux XDP generic receive — `sk_buff` fast path vs generic path is the
  same two-tier pattern at a different layer.
- Flow caches in Open vSwitch (EMC → megaflow → slow path) — three tiers
  instead of two, but the same principle.
