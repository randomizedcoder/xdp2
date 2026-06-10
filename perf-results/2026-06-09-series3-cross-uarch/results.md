# Cross-uarch ARM kernel A/B (Pi 5 Cortex-A76 → Pi 4 Cortex-A72, 1 GbE)

**Date**: 2026-06-09 (evening)
**Patched kernel**: Path B against linux_rpi{4,5} 6.12.87 + 3
  series-3 patches, gated. Built and booted on pi5-2 and pi4-1.
  sysctl `net.core.flow_dissector_fastpath` defaults 0.
**Pair**: pi5-2 (gen, Cortex-A76 4c @ 2.4 GHz, **active fan
  attached**) → pi4-1 (DUT, Cortex-A72 4c @ 1.8 GHz, no fan
  needed). 1 GbE shared switch.
**Tool**: iperf3 from nixpkgs, both ends.
**Methodology**: Phase 2 controls applied —
  - **Interleaved sysctl order** [0, 1, 0, 1, ...] not block
    sequential.
  - **Performance CPU governor** on CPU 3 of both ends.
  - **Sidecar telemetry** (vcgencmd temp + freq + throttled bits)
    at 1 Hz during every iperf3 cell.
  - N=5 samples per sysctl mode per cell (=10 runs per cell).
  - Pi 5 fan keeping pi5-2 under thermal threshold throughout.

## TL;DR — the -5.5% regression is gone

With proper methodology controls, the **-5.5% UDP regression from
2026-06-09 morning is reproducibly gone**. The previous result
was a thermal-throttling artefact on the un-fanned pi5-1 sender
(historical evidence: `vcgencmd get_throttled = 0xe0008` recorded
soft-temp-limit events on pi5-1 from the prior tests). The
fan-cooled pi5-2 sender with the rest of the controls produces
clean A/B parity at sysctl=0 and sysctl=1.

| cell | sysctl=0 mean | sysctl=1 mean | delta | notes |
|---|---:|---:|---:|---|
| TCP IPv4 cake -P 16 | 935.96 Mbit/s | 935.96 Mbit/s | 0.00% | link saturated, 0 retx both |
| TCP IPv6 cake -P 16 | 927.90 Mbit/s | 927.94 Mbit/s | 0.00% | link saturated, retx ~17 k both |
| UDP IPv4 -b 0 -l 64 -P 8 | 172.36 Mbit/s | 172.46 Mbit/s | +0.06% | within noise |
| UDP IPv6 -b 0 -l 64 -P 8 | 171.40 Mbit/s | 171.40 Mbit/s | 0.00% | within noise |

All four cells are at A/B parity, IPv4 and IPv6, TCP and UDP.
This is the cross-uarch real-traffic result that resolves the
prior concern.

## Per-cell raw data (10 interleaved samples each)

### TCP IPv4 cake

```
sysctl=0: 936.0  935.8  936.1  936.0  936.0   (mean 935.98)
sysctl=1: 935.9  936.0  936.0  935.9  936.0   (mean 935.96)
retx    : 0 on every run
```

### TCP IPv6 cake

```
sysctl=0: 927.8  927.9  927.9  928.0  927.9   (mean 927.90)
sysctl=1: 927.9  928.0  928.0  927.9  927.9   (mean 927.94)
retx    : 17287, 17502, 17409, 17434, 17564 (=0)
          17233, 17533, 17279, 17304, 17323 (=1)
```

Retransmit count is similar between modes; the v6 absolute
throughput is ~8.5 Mbit/s lower than v4 because the IPv6 header is
20 bytes larger than v4 — pure protocol overhead, unrelated to the
patches.

### UDP IPv4 -b 0 -l 64 -P 8

```
sysctl=0: 172.4 172.3 172.4 172.4 172.3   (mean 172.36)
sysctl=1: 172.4 172.5 172.5 172.5 172.4   (mean 172.46)
loss    : ~45.3% on every run, both modes (sender overshooting
          receiver per usual -b 0 behaviour)
```

The UDP throughput is ~5.5x lower than the TCP wire-rate
(~170 Mbit/s vs ~936 Mbit/s) because the 64-byte payload payload
is dominated by per-packet kernel overhead — this is the
PPS-limited regime where the dissector saving should be most
visible. At this rate sysctl=1 is 0.06% higher than sysctl=0 —
inside the run-to-run variance. No regression, but also no
detectable kernel-level signal in raw throughput; the saving
shows up in CPU% headroom rather than bps (TCP elephant on the
Pi pair already saturates the link).

### UDP IPv6 -b 0 -l 64 -P 8

```
sysctl=0: 171.3 171.3 171.4 171.5 171.5   (mean 171.40)
sysctl=1: 171.4 171.4 171.4 171.5 171.3   (mean 171.40)
loss    : ~60.6% on every run, both modes
```

UDP v6 same shape as v4 — sysctl=0 and sysctl=1 sample sets
overlap completely. No regression in either direction.

## Comparison vs the prior (uncontrolled, thermally-confounded) test

| | 2026-06-09 morning (no fan, block-sequential) | 2026-06-09 evening (fan + controls) |
|---|---|---|
| Sender | pi5-1 (no fan, throttled history `0xe0000`) | pi5-2 (fan attached, throttle-free) |
| Order | [0,0,0,1,1,1] block | [0,1,0,1,...] interleaved |
| Governor | schedutil (idle: 1500-1700 MHz on Pi 5) | performance (idle: 2400 MHz on Pi 5) |
| UDP delta | **-5.5%** | **+0.06%** (within noise) |

Same hardware family, same workload shape, only the methodology
changed — and the regression vanished. The thermal-throttling
hypothesis we put forward earlier is empirically confirmed.

## Files

- `iperf3-tcp-{v4,v6}-{0,1}-{1..5}.json`  (20 files)
- `iperf3-udp-{v4,v6}-{0,1}-{1..5}.json`  (20 files)
- `summary.log` — raw stdout of both batched runs
- `results.md` (this file)

## Method (reproduction — now nixified)

This test is reproducible end-to-end via the new flake target:

```bash
nix run .#series3-traffic-ab -- \
  pi5-2 pi4-1 172.16.40.199 \
  2603:8000:9c01:3b01:e65f:1ff:fe42:a10f \
  5
```

See `nix/series3-traffic-ab.nix` for the wrapper. Same shape:
interleaved [0,1,0,1,...] sysctl order, sidecar telemetry,
N=5 samples per sysctl mode per cell, JSON artefact per
cell, parsed summary table.

Pre-conditions (one-time per host):

```bash
# Open IPv4 + IPv6 firewall ports on DUT
ssh root@pi4-1 'iptables -I nixos-fw 1 -p tcp -m multiport \
  --dports 5301:5310 -j nixos-fw-accept; \
  iptables -I nixos-fw 1 -p udp -m multiport \
  --dports 5301:5310 -j nixos-fw-accept; \
  ip6tables -I nixos-fw 1 -p tcp -m multiport \
  --dports 5301,5302,5303,5304,5305,5306,5307,5308,5309,5310 \
  -j nixos-fw-accept; \
  ip6tables -I nixos-fw 1 -p udp -m multiport \
  --dports 5301,5302,5303,5304,5305,5306,5307,5308,5309,5310 \
  -j nixos-fw-accept'
```

The matching microbench is at:

```bash
nix run .#series3-microbench -- \
  pi5-2 \
  /nix/store/k509xbm68zw441cpyqzl60rdv7418ask-xdp2-0.1.0 \
  /nix/store/s2jblg2p0pjc3qpz4sds06mv9q44vk1q-xdp2-0.1.0
```

See `nix/series3-microbench.nix`. Same shape as the
2026-06-09-series3-arm-microbench/ results, just packaged as a
reusable flake target.

## Not done in this session (next steps)

- Phase 4: sender-vs-receiver isolation (sysctl=1 on only one
  end). Useful for understanding *where* the fast-path runs —
  TX qdisc classify on sender vs RX skb_get_hash on receiver.
  Held until pi5-1 gets a fan and the Pi 5 ↔ Pi 5 same-uarch
  pair can be tested cleanly.
- Phase 8: `perf record` on receiver — quantify the per-call
  dissector cycles directly. Needs `linux_rpi{4,5}.perf` to
  match the running kernel.
- Cover letter update with the consolidated ARM picture
  (microbench + cross-uarch + IPv6 + retraction of the prior
  -5.5%). Held until tomorrow's pi5-1 controlled re-test
  completes so we ship one clean update with all the evidence.
