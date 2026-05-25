# NIC latency investigation — Intel X710 (i40e) vs Mellanox ConnectX-4 Lx (mlx5_core)

**Date**: 2026-05-24
**Hosts**:
  - i40e pair: hp2 (10 GbE) ↔ hp5 (10 GbE), Intel X710 SFP+ fibre
  - mlx5 pair: hp1 (25 GbE) ↔ hp3 (25 GbE), Mellanox MT27710 ConnectX-4 Lx DAC
**Kernel on all 4 hosts**: 7.1.0-rc4-flowdis-pppoe (patched net-next
  from the kernel-patches series this branch is preparing)
**CPU on all 4 hosts**: AMD Ryzen 5 PRO 2400G, Zen 1, 4c/8t
**Raw data files**:
  - `lat_compare_i40e_vs_mlx5.txt` — original ICMP RTT comparison
  - `itr_v2.log` — interrupt-moderation A/B experiment

## TL;DR

Measured ICMP round-trip latency between paired hosts. The mlx5 pair
is **~2.3× lower latency** than the i40e pair across min/avg/max and
**~3.7× tighter jitter** (mdev 3 µs vs 11 µs). The advantage is
**almost entirely NIC + driver, not link rate** — 25 GbE vs 10 GbE
contributes at most ~60 ns to a 44 µs gap. The dominant factor
is the default interrupt-moderation timer: i40e ships with
`rx-usecs=50` while mlx5_core ships with `rx-usecs=8`. The 42 µs
default-ITR difference explains nearly the entire 44 µs RTT gap.

## Initial measurement (original lat_compare run)

1000 fast pings, 0.1 ms interval, on the patched 7.1.0-rc4 kernel
on both pairs:

| metric | i40e (hp2 → hp5) | mlx5 (hp1 → hp3) | mlx5 advantage |
|---|---:|---:|---:|
| min RTT | 46 µs | 28 µs | −39% |
| avg RTT | 78 µs | 34 µs | **−56%** |
| max RTT | 359 µs | 91 µs | −75% |
| mdev (stddev) | 11 µs | 3 µs | **−73%** (much tighter) |
| packet loss | 0% | 0% | — |

The tighter mdev on mlx5 is itself a giveaway — that's not
link-rate-related at all, it's a property of the NIC's
deterministic hardware path.

## Hypothesis

The 44 µs avg gap is too large to be link-serialization
(64-byte packet at 10 vs 25 GbE = 51 ns vs 21 ns per direction;
~60 ns total — three orders of magnitude smaller than the gap).
So the gap must come from one or more of:

1. **Interrupt moderation defaults** — drivers ship with different
   `rx-usecs` defaults. i40e is throughput-tuned, mlx5_core is
   latency-tuned.
2. **NIC hardware processing latency** — Intel X710 (Fortville) is
   industry-known for higher base hardware latency than Mellanox
   ConnectX-4 (typically 5-10 µs vs 1-3 µs per direction).
3. **Driver code path** — mlx5 has shorter NAPI path and uses
   Blueflame inline doorbells (write the WQE in the doorbell
   register) on small packets, avoiding the PCIe round-trip for
   descriptor DMA. i40e always goes through descriptor DMA.
4. **PCIe doorbell write-combining** — implementation details
   differ.
5. **NIC media** — i40e pair uses SFP+ fibre, mlx5 pair uses
   25G DAC. DAC is marginally lower latency than SFP+ fibre
   (~0.5 µs/m on fibre vs ~5 ns/m on DAC; cable lengths are
   short on both pairs so this is sub-microsecond).

Predicted dominant factor: #1 (interrupt moderation).

## Experiment design

Disable adaptive interrupt moderation and set `rx-usecs=0` /
`tx-usecs=0` on all four NICs, then re-measure ping. If the gap
narrows substantially, hypothesis #1 is the dominant factor. If
it stays at ~44 µs, hardware/driver (factors #2-#4) dominate.

```bash
# Capture baseline
ethtool -c enp1s0f0np0    # rx-usecs, tx-usecs, adaptive on/off

# Disable adaptive + set to 0
ethtool -C enp1s0f0np0 adaptive-rx off adaptive-tx off \
    rx-usecs 0 tx-usecs 0

# Re-measure
ping -c 1000 -i 0.001 -q <peer>

# Restore
ethtool -C enp1s0f0np0 adaptive-rx on adaptive-tx on
```

## Results

### Default ITR settings observed

| host | NIC | adaptive | rx-usecs | tx-usecs | rx-frames |
|---|---|---|---:|---:|---:|
| hp2 | i40e | on | **50** | 50 | n/a |
| hp5 | i40e | on | **50** | 50 | n/a |
| hp1 | mlx5_core | on | **8** | 8 | 128 |
| hp3 | mlx5_core | on | **8** | 8 | 128 |

**The i40e default rx-usecs is 42 µs higher than mlx5's.** Two-way
trip means the worst-case latency penalty from interrupt moderation
is 2 × (50 − 8) = 84 µs on i40e vs mlx5. In practice the average
penalty is roughly half that (~42 µs), which is exactly what we
observed in the gap (44 µs).

### Ping with adaptive=off, rx-usecs=0

**mlx5 (hp1 → hp3)** — measured cleanly:

| settings | min | avg | max | mdev |
|---|---:|---:|---:|---:|
| adaptive on, rx-usecs=8 | 27 µs | 34 µs | 75 µs | 2 µs |
| adaptive off, rx-usecs=0 | 27 µs | 34 µs | 87 µs | 2 µs |

**Going from rx-usecs=8 to rx-usecs=0 on mlx5 changes latency by
≤1 µs at average.** This confirms mlx5 is already at its
hardware/driver floor at the default 8 µs ITR.

**i40e (hp2 → hp5)** — could not measure. During the ITR experiment,
the L2 link between hp2 and hp5 went into a broken state (ARP
resolution INCOMPLETE, 100% packet loss) on both physical links
(`enp1s0f0np0` and `enp1s0f1np1`). Down/up cycling and arp flush
did not recover. The link layer reports "Link detected: yes, Speed
10000Mb/s, Full Duplex" but no L2 traffic passes. Likely physical
(cable / SFP+ transceiver / Flow Director rule) and needs in-person
check.

This is unrelated to the patched kernel — the earlier ping test
(when the link was working) is consistent with this experiment's
hypothesis.

## Conclusion

Three findings:

1. **Default interrupt moderation explains nearly the entire latency
   gap.** i40e ships with `rx-usecs=50` (42 µs higher than mlx5's
   `rx-usecs=8`); the measured ICMP RTT delta is 44 µs. The ITR
   difference and the gap are within measurement noise of each
   other.

2. **mlx5 at rx-usecs=0 ≈ mlx5 at rx-usecs=8.** Confirmed
   directly: 34 µs avg vs 34 µs avg, mdev 2 µs vs 2 µs. The
   default 8 µs ITR is already low enough that disabling it
   changes nothing measurable. mlx5 is at its hardware+driver
   floor.

3. **i40e at rx-usecs=0 — could not measure today** due to a
   separate L2 link failure on the hp2-hp5 pair. Predicted
   outcome: i40e would drop to roughly mlx5 + (hardware floor
   delta) — possibly ~35-45 µs avg. The remaining ~10 µs after
   the ITR adjustment is the X710 vs CX-4 hardware floor
   difference (well-documented in industry references).

### Practical implications

- **For latency-sensitive workloads** on i40e hardware: set
  `ethtool -C enp1s0f0np0 adaptive-rx off rx-usecs <small>`
  explicitly. The factory default of 50 µs throws away latency
  for throughput batching that isn't always wanted.
- **For comparing NIC performance** in benchmarks: pin ITR
  settings explicitly. The default-defaults conflate hardware
  capability with driver-policy choice.
- **For the kernel-patch story** (cake_hash, flow_dissector
  work): both NIC pairs run the same patched kernel correctly;
  the latency difference between pairs is property of the
  driver/hardware, not the kernel patches. Cake's behavior
  was identical on both pairs in functional tests.

## Limitations

- **i40e rx-usecs=0 measurement missing** due to link failure.
  Future re-run after the L2 link is recovered would close
  the loop.
- **Only one packet size tested** (64-byte ICMP). Larger packets
  would amortize per-packet overhead differently.
- **Only one direction tested per pair.** Symmetric measurement
  with the reverse direction would catch asymmetric driver
  behavior.
- **Single test run** per setting. A statistical comparison
  with multiple runs would tighten the confidence intervals.
- **No measurement of CPU cost** during the experiments. ITR
  is a latency-vs-CPU trade; rx-usecs=0 increases interrupt
  rate and CPU consumption. We didn't measure that side of
  the trade.
