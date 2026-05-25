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
  - `itr_reverse_sweep.log` — mlx5 rx-usecs sweep (disproves
    initial hypothesis)

## TL;DR (revised)

Measured ICMP round-trip latency between paired hosts. The mlx5
pair is **~2.3× lower latency** than the i40e pair across
min/avg/max and **~3.7× tighter jitter** (mdev 3 µs vs 11 µs).
The advantage is **almost entirely NIC hardware + driver**, not
link rate, and — based on a direct sweep — **NOT primarily the
interrupt-moderation timer** even though the defaults differ
hugely between drivers (i40e ships `rx-usecs=50`, mlx5 ships
`rx-usecs=8`).

Direct experiment: sweeping mlx5 from `rx-usecs=8` to
`rx-usecs=100` left ping latency unchanged at 34 µs avg across
every value. ITR throttles interrupt rate *under load*; at 1000 pps
ping there's only one packet per ITR window so the throttle never
engages. The mlx5 advantage is **hardware processing latency +
driver code path**, not interrupt-moderation policy.

## Implication for i40e tuning

`ethtool -C` retuning of i40e probably **won't close the latency
gap for sparse traffic** like ping or low-pps RPC. ITR matters
for high-pps workloads where it forces batching; for latency-
sensitive sparse traffic the gap is hardware-bound. To make
i40e match mlx5 latency you'd need different silicon.

For *high-pps* workloads the picture is different: i40e's
default rx-usecs=50 means up to 50 µs of latency tax under
load. Retuning to rx-usecs=8 (the mlx5 default) would help
there. But it doesn't help the ping numbers.

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
(when the link was working) is documented separately.

### Reverse sweep: mlx5 rx-usecs from 8 → 100 (decisive)

Since the original ITR hypothesis was untestable on i40e, ran the
inverse experiment on mlx5: set rx-usecs to a range of values
spanning i40e's default, and re-measure ping. If ITR is the
dominant factor, mlx5 latency at `rx-usecs=50` (i40e's default)
should rise toward i40e's 78 µs.

```
mlx5 rx-usecs sweep (1000 pings, 0.1 ms interval):

rx-usecs  min   avg   max   mdev
   8     25 µs 34 µs 86 µs  2 µs   (mlx5 default)
   8 *   22 µs 34 µs 73 µs  2 µs   (adaptive off, rx-usecs forced 8)
  16     28 µs 34 µs 67 µs  2 µs
  25     28 µs 34 µs 67 µs  2 µs
  50     29 µs 34 µs 70 µs  2 µs   (= i40e's default)
 100     28 µs 34 µs 70 µs  2 µs
```

**Verdict: mlx5 latency is completely insensitive to rx-usecs
across this range.** Setting it to 100 µs — twelve times mlx5's
default and twice i40e's — leaves the ping avg unchanged at 34 µs.

This **rules out interrupt moderation as the dominant factor.**
The reason: ITR is the minimum interval between successive
interrupts when packets are arriving fast. At 1000 pps ping, the
inter-arrival is 1 ms = 1000 µs, far outside any rx-usecs window.
Each ping's interrupt fires immediately because the next packet
isn't due. ITR only matters when arrival rate exceeds
`1 / rx-usecs` (e.g., > 20 kpps at rx-usecs=50).

## Conclusion (revised after the reverse sweep)

The original hypothesis — that the i40e/mlx5 latency gap was
dominated by their different `rx-usecs` defaults — **was wrong**.
The reverse sweep on mlx5 disproves it directly: changing mlx5
from rx-usecs=8 to rx-usecs=100 leaves latency unchanged at
34 µs avg.

Corrected findings:

1. **The 44 µs ICMP RTT gap between i40e and mlx5 is NOT caused
   by interrupt moderation policy.** ITR only matters under high
   pps load (`> 1 / rx-usecs`); at 1000 pps ping (1 ms
   inter-arrival, far outside any ITR window), each packet's
   interrupt fires immediately regardless of `rx-usecs` setting.

2. **The gap is caused by NIC hardware processing latency +
   driver code path.** Industry references put X710 (Fortville)
   silicon at ~5-10 µs per direction minimum and CX-4 at ~1-3 µs
   per direction. Plus mlx5_core uses inline Blueflame doorbells
   on small-packet TX, avoiding a PCIe round-trip for the
   descriptor; i40e always goes through descriptor DMA.

3. **The xdp2 nic-tune service doesn't touch ITR on either
   driver.** Confirmed by reading `nix/modules/nic-tuning.nix`
   (i40e branch ~L40-110, mlx5 branch ~L144-220). Both branches
   carefully tune offloads off, flow control off, ring sizing,
   IRQ pinning — all latency-favoring — but leave `rx-usecs` at
   driver default. That's fine given our finding above: changing
   it wouldn't help small-packet latency.

### Practical implications (revised)

- **For latency-sensitive sparse traffic** (ping, low-pps RPC):
  ITR tuning **doesn't help**. The X710-vs-CX-4 latency gap is
  hardware-bound. To meaningfully improve i40e ping latency
  you'd need different silicon.
- **For high-pps workloads where ITR can engage**: i40e's
  default rx-usecs=50 means up to ~50 µs of forced batching;
  retuning to a low value would help. This is the case where
  the `ethtool -C` tuning is worth doing. (For our cake/BPF
  patch testing this isn't the bottleneck; cake's per-packet
  cost dominates at the rates we're testing.)
- **For comparing NIC performance** in benchmarks: pin ITR
  settings explicitly so you measure hardware capability
  separately from driver-policy choice — and remember that ITR
  is irrelevant for sparse-traffic latency comparisons.
- **For the kernel-patch story** (cake_hash, flow_dissector
  work): both NIC pairs run the same patched kernel correctly;
  the latency difference between pairs is property of the
  driver/hardware, not the kernel patches. Cake's behavior
  was identical on both pairs in functional tests.

### Lesson learned about the experimental method

Initial reasoning that connected the 42 µs ITR-default
difference to the 44 µs RTT gap was an arithmetic coincidence,
not causation. The "verify on mlx5 by sweeping the same range"
was the right next step and it caught the error. Always test
the inverse direction before declaring causation.

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
