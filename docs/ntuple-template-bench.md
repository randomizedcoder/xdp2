# Live Ntuple + Template Benchmark (X710 Hardware Classification)

## Why this test exists

xdp2-rs already has four parser dispatch modes measurable via
`xdp2-bench`: `graph` (dyn dispatch), `mono` (hand-rolled
monomorphic), `compiled` (xdp2-compiler-generated monomorphic), and
`template` (fixed-offset extract). The template mode is the fastest
of the four — the published 2 ns/pkt / 493 Mpps headline assumes the
packet has **already been classified**, so the per-packet hot path is
just `extract_by_id(pkt, fixed_template_id, &mut meta)`.

But `xdp2-bench --mode template` measured against a PCAP still runs
`select_template_id()` per packet — walking the headers to figure
out *which* of the 63 fixed-offset extractors to call. That cost
shows up in the numbers; it's exactly the software classification
work a NIC with ntuple / Flow Director can eliminate in hardware.

This test is the hardware-classified version. The Intel X710 NICs on
the physical testbed expose i40e Flow Director:

- Up to 8192 per-rule 5-tuple match/action entries.
- Actions include "steer to specific RX queue".
- Zero software cost per packet.

When we pair a Flow Director rule ("tcp4 dst-port 443 -> queue 2")
with an AF_XDP zerocopy socket bound to queue 2 that is pre-mapped
to `TemplateId::EthIpv4Tcp`, the per-packet path is literally:

1. Poll the ring, pull a descriptor.
2. Call `template::extract_by_id(pkt, EthIpv4Tcp, meta)`.

No graph walk, no `select_template_id`, no classifier branch. The
NIC did the classification, and the queue itself is the proof.

This is what the physical testbed was set up for: not a synthetic
ceiling number, but a production-shaped measurement of the lowest
latency the parser can deliver in the hardware-offloaded path.

## The Flow Director → queue → AF_XDP → template ladder

```
                   host bus
wire ──► X710  ────────────► RX queues ──► AF_XDP sockets ──► xdp2-bench threads
         │                  ┌─────────┐    ┌──────────────┐   ┌──────────────┐
         │ Flow Director    │ queue 0 │ ◄──┤ (kernel, not  │   │              │
         │ rules match ─────┤ queue 1 │ ◄──┤  bound here)  │   │              │
         │ 5-tuple and     │ queue 2 │ ◄──┼─ xsk(queue 2) ├──►│ thread(q=2)  │
         │ pick queue      │ queue 3 │ ◄──┼─ xsk(queue 3) ├──►│ thread(q=3)  │
         │                  └─────────┘    └──────────────┘   └──────────────┘
         │                                                    per-queue template
         │                                                    (pre-mapped, fixed)
```

Each arrow in the right half happens exactly once per packet:

- **FD match** (hardware, ~0 CPU cycles).
- **DMA to queue ring** (hardware).
- **AF_XDP recv** batch pull (tens of ns for the whole batch).
- **extract_by_id** (fixed-offset reads, SIMD-friendly, ~2 ns in isolation).

There is **no** software classification step on any packet.

## What's actually configured

### 1. NixOS module options

`nix/modules/physical-testbed.nix` exposes:

```nix
xdp2.testbed = {
  enable = true;
  # …standard tuning…

  # Per-rule Flow Director steering. Each rule's list-index is its
  # ethtool location slot, so reapplying is idempotent.
  flowDirectorRules = [
    { interface = "enp1s0f0np0"; flowType = "tcp4"; destPort = 22;  queue = 1; }
    { interface = "enp1s0f0np0"; flowType = "tcp4"; destPort = 443; queue = 2; }
  ];

  # Re-enable nginx (port 443, snake-oil cert, 1-byte body) and add
  # wrk2 + h2load to systemPackages. Nginx is pinned to CPUs 0,1 via
  # CPUAffinity so it never competes with parser threads on 2-7.
  realServicesBench = true;
};
```

The rules are applied by the `xdp2-nic-tune-<ifname>.service` unit
(see nix/modules/physical-testbed.nix). Verify post-boot:

```console
$ ssh root@hp5 'ethtool -n enp1s0f0np0'
2 RX rings available
Filter: 0
        Rule Type: TCP over IPv4
        Src IP addr: 0.0.0.0 mask: 255.255.255.255
        Dest IP addr: 0.0.0.0 mask: 255.255.255.255
        TOS: 0x0 mask: 0xff
        Src port: 0 mask: 0xffff
        Dest port: 22 mask: 0x0
        VLAN EtherType: 0x0 mask: 0xffff
        VLAN: 0x0 mask: 0xffff
        User-defined: 0x0 mask: 0xffffffffffffffff
        Action: Direct to queue 1
Filter: 1
        …Dest port: 443 mask: 0x0 …
        Action: Direct to queue 2
```

### 2. The `af-xdp-template` bench mode

`xdp2-bench` grew a new mode in Commit 3 of this bundle:

```
xdp2-bench --mode af-xdp-template \
  --interface enp1s0f0np0 \
  --queue-template 1=eth-ipv4-tcp \
  --queue-template 2=eth-ipv4-tcp \
  --duration 30
```

One AF_XDP-bound thread per `--queue-template`. Each thread runs
`template::extract_by_id(pkt, <fixed_id>, meta)` directly — no
per-packet classification. Output is one per-queue row of
`packets | bytes | ns/pkt | Mpps`.

The full list of 63 template names is in
`xdp2-rs/crates/xdp2-bench/src/af_xdp_template.rs::template_id_from_str`.

### 3. The orchestration wrapper

`samples/flow_dissector/run_ntuple_template_bench.sh` (exposed as
`nix run .#flow-dissector-ntuple-template-bench`) drives the whole
thing from a dev box:

```
nix run .#flow-dissector-ntuple-template-bench -- hp5 hp2
```

- Verifies the FD rules and nginx on the target (hp5).
- Starts `wrk2 -R 200000 https://<target_ip>/` and a long-lived
  `ssh -N root@target` on the peer (hp2).
- Runs `xdp2-bench --mode af-xdp-template` on the target.
- Pulls the per-queue report back to
  `perf-results/hp5/ntuple-template-bench-<ts>/`.

## What the numbers mean — and what they DON'T mean

### The per-queue ns/pkt row IS:

- The time to go from "packet hits the AF_XDP ring" to "FlowMeta
  populated and discarded". This is the per-packet parse-and-extract
  cost on pre-classified traffic.
- Comparable across queues (same code path, different templates) and
  comparable against `xdp2-bench --mode template` against a filtered
  pcap (same extract_by_id call, different classification cost).

### The per-queue ns/pkt row IS NOT:

- **Nginx request-handling latency.** Once the Flow Director rule
  steers TCP/443 to queue 2 and the AF_XDP socket binds that queue
  in zerocopy mode, the kernel never sees TCP/443 bulk data on
  queue 2. Nginx completes the handshake through queue 0 (because
  wrk's ephemeral src port doesn't match any rule and hashes to
  queue 0), but the data segments sent by wrk go straight to the
  AF_XDP socket and never touch nginx. Conclusion: `wrk2` will
  report ~0 successful requests; that's **expected** and correct.
  nginx is there to complete the handshake so the TCP connection
  stays alive; the segments it *would* have served are what we're
  measuring the parser on.
- **An apples-to-apples comparison with `flow_dissector`.** That
  C parser classifies-then-parses on every packet. This test
  parses-only on already-classified packets. The useful comparison
  is `flow_dissector` ns/pkt MINUS `af-xdp-template` ns/pkt ≈ the
  amortised classification cost per packet in the C path.

## Reproducing end-to-end

Prerequisites:

- Two X710-equipped hosts cabled back-to-back (the docs/physical-testbed.md
  setup).
- Both running NixOS with `xdp2.nixosModules.physical-testbed`.
- Target host has `flowDirectorRules = [ …TCP/22 → q1…, …TCP/443 → q2… ]`
  and `realServicesBench = true`.
- xdp2-bench binary on target (`cargo build --release -p xdp2-bench`
  or `nix run .#run-on-host -- <target> -- xdp2-rs-build`).

Run:

```bash
# From the dev box:
nix run .#flow-dissector-ntuple-template-bench -- hp5 hp2

# Or with custom duration / CPU pinning:
nix run .#flow-dissector-ntuple-template-bench -- \
  -d 60 -c 2 hp5 hp2
```

Result artifacts land in
`perf-results/hp5/ntuple-template-bench-<ts>/`:

- `ntuple-rules.txt` — pre-flight `ethtool -n` dump.
- `xdp2-bench-af-xdp-template.txt` — the per-queue table.
- `wrk2.log` — wrk2's own (mostly-zero) report for completeness.
- `ssh-keepalive.log` — ssh session log.

Cross-reference the numbers with
`samples/flow_dissector/docs/benchmarks.md` "Live Ntuple + Template"
section to see them alongside the 10-row unified matrix.

## Future work

- **Zerocopy headroom tuning.** i40e needs a specific UMEM alignment
  for zerocopy to succeed; the current code tries ZC and falls back
  to copy mode. Instrument which path is actually active and surface
  it in the report.
- **Multi-rule / scaling study.** We run two rules today. Characterise
  8, 64, 512, 4096 rules to find the i40e Flow Director scaling knee.
- **IPv6 templates.** `flowDirectorRules` already accepts `tcp6`/`udp6`
  flow types; wire a corresponding IPv6 template in the bench and add
  an `eth-ipv6-tcp` row to the test matrix.
- **Sustained Mpps ceiling.** Pair the af-xdp-template path with a
  non-handshaking synthetic source (`pktgen`, `trafgen`) so wrk's
  TCP state machine isn't the bottleneck.

## Cross-references

- `docs/physical-testbed.md` §6 (module options) and §9 (test catalog).
- `samples/flow_dissector/docs/benchmarks.md` — where the live numbers
  are pasted once runs complete.
- `xdp2-rs/crates/xdp2-bench/src/af_xdp_template.rs` — the bench code.
- `nix/modules/physical-testbed.nix` — the `flowDirectorRules` and
  `realServicesBench` option definitions.
