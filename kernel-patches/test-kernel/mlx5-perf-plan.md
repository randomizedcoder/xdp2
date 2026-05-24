# Deep performance comparison plan — mlx5/25GE pair (hp1 ↔ hp3)

**Date**: 2026-05-24
**Hosts**: hp1 (generator) ↔ hp3 (DUT), Mellanox CX-4 Lx 25 GbE
  DAC back-to-back, both on patched 7.1.0-rc4-flowdis-pppoe.
**Comparison axis**: vs hp2/hp5 (Intel X710 i40e 10 GbE),
  both pairs Zen 1 Ryzen 5 PRO 2400G, isolcpus 2-7.

## Why this pair matters

Three things the mlx5 pair adds beyond what hp2/hp5 give us:

1. **Higher link rate** — 25 GbE vs 10 GbE means we can drive
   higher pps to actually saturate cake_hash() on the DUT. At
   10 GbE the cake_hash cost is too small a fraction of the
   total per-packet cost to dominate any cycle measurement;
   at 25 GbE with small packets, host_keys hash overhead
   becomes visible in cake's throughput ceiling.
2. **Different NIC driver path** — mlx5_core has a different
   RX path (TC-flower based flow steering vs ethtool ntuple
   on i40e). Our patch doesn't touch driver code, but
   validating that the patched kernel works correctly on
   both drivers is meaningful for the cover-letter framing.
3. **Wider hardware coverage in the validation set** — the
   cover letter currently cites "validated on Zen 1
   Ryzen 5 PRO 2400G with Intel X710". Adding the
   mlx5_core case turns that into "with two distinct NICs
   on the same uarch", strengthening the
   driver-independence claim.

## Tests to run (in order of cost/value)

### Tier 1 — cheap, runs on a single host

These don't need the DUT pair; just need hp1 OR hp3 with the
patched kernel.

**1.1 hash_bench.c on hp1 and hp3** (already validated on
hp5/hp2 — same Zen 1 SKU, expect identical cycle bands).

```bash
# Build + run on each host (hash_bench.c lives at
# perf-results/2026-05-23-flow-keys-consumer-audit/hash_bench.c
# in the xdp2 repo; copy + build identical pattern as on hp2/hp5).

scp perf-results/2026-05-23-flow-keys-consumer-audit/hash_bench.c \
    root@hp1:/tmp/
ssh root@hp1 'cd /tmp && /run/current-system/sw/bin/gcc \
    -O2 -Wall hash_bench.c -lsiphash -o hash_bench && \
    ./hash_bench'
```

Expected outcome: matches hp5/hp2 numbers (siphash bands at
108 and 144 cycles, v4 hash p50=108, v6 hash p50=144).
Confirms the cycle measurements are property of the CPU,
not of the NIC. Mostly a sanity check.

**Time cost**: ~5 min including scp + build.

### Tier 2 — sch_cake throughput ceiling test (pair, real traffic)

The most-direct measurement of patch 3's value: drive hp3's
cake qdisc with traffic from hp1 at increasing rates until
something tops out, with and without the patched hash.

**2.1 Baseline cake throughput on PATCHED kernel** (current
state — both hp1 and hp3 on 7.1.0-rc4-flowdis-pppoe).

```bash
# On hp3 (DUT): cake on the data-plane interface with
# triple-isolate (= exercise patched host_keys hash)
ssh root@hp3 '
  tc qdisc replace dev enp1s0f0np0 root cake bandwidth 25Gbit triple-isolate
  tc -s qdisc show dev enp1s0f0np0
'

# On hp1 (gen): saturate the link with multiple flows
# Use pktgen or iperf3 with --parallel to generate many distinct
# 5-tuples (so host_keys hash sees variation).
ssh root@hp1 '
  # Option A: iperf3 with 16 parallel TCP flows
  iperf3 -c 10.10.2.3 -t 60 -P 16 -O 5 | tail -10

  # Option B: pktgen at line rate with rotating dst IPs
  # (more deterministic for hash testing)
'

# On hp3: read cake stats during + after the run
ssh root@hp3 'tc -s qdisc show dev enp1s0f0np0 | head -40'
```

Capture:
- iperf3 throughput / pps (gen-side measurement)
- cake "Sent" / "drops" / "overlimits" (DUT-side)
- cake host accounting stats from `tc -s class show dev enp1s0f0np0`

**2.2 Compare to baseline** (unpatched kernel) — switch hp3
back to `pkgs.linuxPackages_latest` temporarily, repeat the
same run, compare. If patch 3 saves cycles per host_keys
hash and the link is hash-bound, the patched kernel should
sustain more pps before cake's drop threshold kicks in.

Realistic expectation: the difference will be SMALL even
at 25 GbE, because cake_hash is one of many per-packet
costs (skb allocation, qdisc lock, classification,
classifier match, etc.). The Zen 1 cycle saving per
host_keys hash is ~36 cycles at p10 (masked at p50 by
rdtsc floor), times 2 hashes/pkt = 72 cycles ≈ 24 ns/pkt
at 3 GHz. At 25 GbE with 64-byte packets that's ~37 Mpps,
where 24 ns/pkt saving = ~3% throughput ceiling lift IF
cake is hash-bound. If cake is bound by anything else
(lock contention, NIC RX path) the patch's contribution
won't be visible.

**Time cost**: ~30 min per direction (60 min total for
patched + baseline) + setup.

### Tier 3 — xdp2 protocol-coverage matrix on the mlx5 pair

The xdp2 project has a `flow-dissector-matrix-unified`
test harness driven via
`nix run .#run-on-host -- --testbed testbeds/hp1-hp3-mlx5.toml`
(per docs/physical-testbed.md §14). This runs all parsers
against the curated pcap set and produces a results matrix.

```bash
nix run .#run-on-host -- \
  --testbed testbeds/hp1-hp3-mlx5.toml -- \
  flow-dissector-matrix-unified
```

What this validates for the kernel patches: nothing
directly, since the matrix tests XDP2 parsers, not our
flow_hash_from_keys_small. BUT it does validate that the
patched kernel doesn't break the XDP2 test infrastructure
or any of its parsers — useful as a regression check.

If the matrix is green on the patched kernel, that's
evidence the kernel changes don't affect any of the
protocols XDP2 parses.

**Time cost**: ~30 min for the matrix run.

### Tier 4 — bpf_flow PROG(PPPOE) end-to-end packet test (mlx5)

The BPF verifier accepts PROG(PPPOE); we've validated load
but not actual packet dispatch. Drive a PPPoE packet
through the loaded BPF flow_dissector and verify it
classifies correctly.

```bash
# On hp3: attach the BPF flow_dissector
ssh root@hp3 '
  bpftool prog loadall /tmp/bpf_flow.bpf.o /sys/fs/bpf/test_flow_v3 \
    type flow_dissector
  bpftool net attach flow_dissector pinned \
    /sys/fs/bpf/test_flow_v3/_dissect dev enp1s0f0np0
'

# On hp1: send a synthetic PPPoE-encapsulated TCP packet
# (use scapy or pktgen)
ssh root@hp1 '
  python3 -c "
from scapy.all import *
p = Ether()/PPPoED()/PPP(proto=0x21)/IP(dst=\"10.10.2.3\")/TCP(dport=80)/Raw(b\"X\"*100)
sendp(p, iface=\"enp1s0f0np0\", count=10)
  "
'

# On hp3: dump the last_dissection map to see what PROG(PPPOE)
# extracted
ssh root@hp3 '
  bpftool map dump name last_dissection | head -20
'
```

If `last_dissection` shows correctly-parsed inner 5-tuples
(ip_proto=6, the right ports/addrs), PROG(PPPOE) is working
end-to-end.

**Time cost**: ~20 min including scapy install + scripting.

### Tier 5 — full hp2/hp5 + hp1/hp3 cross-comparison

Once Tiers 1-4 are done, the patched kernel has been
exercised on:

- two NIC drivers (i40e + mlx5_core)
- two link rates (10 GbE + 25 GbE)
- two test pairs (hp2↔hp5 + hp1↔hp3)
- BPF runtime + cake runtime + full kernel boot

That's the strongest reasonable claim a kernel-patch RFC
can make on the testing front. The cover letters update to
include this matrix.

**Time cost**: just doc updates after Tiers 1-4 run.

## Recommended sequencing

Probably:

1. **Tier 1 first** (5 min) — sanity that Zen 1 cycle
   numbers reproduce on hp1/hp3. Cheap, removes uncertainty.
2. **Tier 4 next** (20 min) — end-to-end PPPoE BPF dispatch.
   The most-meaningful BPF validation we don't yet have.
3. **Tier 2** (60 min) — cake throughput. The headline
   number that makes the cover letter cite the mlx5/25GE
   pair, IF patch 3 is hash-bound at 25 GbE. If not, we'll
   know quickly from the iperf3 output.
4. **Tier 3** (30 min) — XDP2 matrix regression. Background
   while Tier 2 runs would be ideal but they share the link;
   serialize.

If we hit Tier 2 and cake isn't hash-bound at 25 GbE, the
mlx5 pair's main value is "patched kernel works on mlx5
hardware" + cycle reproduction. Still worth doing the
Tier 4 PPPoE end-to-end test for the BPF side.

## What this plan does NOT include

- **Driver-side performance comparison** (mlx5 vs i40e at
  same link rate) — interesting but orthogonal to our
  patches; the per-NIC perf difference doesn't depend on
  our kernel changes.
- **Multi-host stress testing** — only 2 hosts per pair;
  can't drive cake_mq at scale with the gear we have.
- **Long-duration soak tests** — useful but not blocking.
  Can be a follow-up if cover-letter reviewers ask.
- **VXLAN / tunnel encap tests** — XDP2 has this in the
  protocol matrix (Tier 3) but it doesn't exercise our
  specific patches more than the standard TCP/IPv4 path
  does.

## After the perf runs

Update `kernel-patches/series1-flow-hash-small/v1/0000-cover-letter.patch`
and `kernel-patches/series2-bpf-pppoe/v1/0000-cover-letter.patch`
to include the mlx5/25GE validation results in the "Pre-post
checklist done" section. Reference this plan doc + the
runtime-validation.md.

Possibly add a brief paragraph to the LWN article plan
about the multi-NIC validation since that strengthens the
"this works in production" framing.
