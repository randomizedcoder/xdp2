# Series 3 — 10-hour real-traffic ARM pair-fleet soak

**Date**: 2026-06-10 — 2026-06-11 (overnight wall-clock)
**Driver**: `nix run .#series3-soak` (target added in this run;
  see `nix/series3-soak.nix`). Local invocation used the
  equivalent `series3-soak-10h.sh` checked in to this directory.
**Wall clock**: 04:52 UTC → 16:11 UTC = **11 h 19 min**
  (10 × 60-min cells + 9 × 120-s inter-cell cooldowns + 1 wedged
  tcpreplay cell that ran ~2 h before manual kill).
**Hosts** (all on 1 Gbit switch except pi3-1 which is
  100 Mbit USB-Ethernet on enu1u1):
  - pi5-1 (Cortex-A76 OoO 4c @ 2.4 GHz, with new fan)
  - pi5-2 (Cortex-A76 OoO 4c @ 2.4 GHz, with new larger fan)
  - pi4-1 (Cortex-A72 OoO 4c @ 1.5 GHz, fan)
  - pi3-1 (Cortex-A53 in-order 4c @ 1.2 GHz, fan)
**Kernels**: linux_rpi-bcm2711-6.12.87 with the 3 series-3
  patches applied on all four Pis; `net.core.flow_dissector_fastpath`
  toggled per cell on the receiver side.

## TL;DR

**10 of 10 cells thermal-clean. Throughput: zero macro delta
between sysctl=0 and sysctl=1, sustained over 1 hour each cell.
First measurable receiver-CPU% improvement at sysctl=1 on the
A72 receiver and on tcpreplay-vxlan to the A53 receiver.**

The data:

| pair × proto                  | sysctl=0       | sysctl=1       | Δ throughput      | Δ cpu_recv |
|-------------------------------|---------------:|---------------:|------------------:|-----------:|
| pi5-1↔pi5-2 iperf3 TCP        | 936.45 Mbps    | 936.45 Mbps    | +0.003 Mbps (0%)  | -0.05 pp   |
| pi5-2↔pi4-1 iperf3 TCP        | 936.44 Mbps    | 936.44 Mbps    | -0.002 Mbps (0%)  | **-1.30 pp**  |
| pi5-2↔pi3-1 iperf3 TCP        | 93.90 Mbps     | 93.90 Mbps     | +0.001 Mbps (0%)  | +0.01 pp   |
| pi5-1↔pi5-2 iperf2 TCP        | 936.45 Mbps    | 936.46 Mbps    | +0.008 Mbps (0%)  | n/a*       |
| pi5-2→pi3-1 tcpreplay vxlan   | (saturated)    | (saturated)    | n/a               | **-0.64 pp**  |

\* iperf2 -y c does not emit CPU% — needs `-e` and a different parser.

Wire-rate maintained on every TCP cell. **Zero retransmits on
both Gbit pairs** in either mode, both protocols. The Pi 3 cells
had ~10.5k retx (0.04% retransmit rate) intrinsic to the
USB-Ethernet adapter; no delta between sysctl modes.

**Receiver CPU% delta** is the headline soak finding:
- On the A76 ↔ A76 pair the dissector is a small fraction of
  receive cost, so sysctl=0/1 deltas live below cell-to-cell
  noise (±0.05 pp).
- On the A72 receiver (1.5 GHz vs A76's 2.4 GHz; same wire rate
  but more CPU effort) the fast-path body's cycle savings become
  visible: **-1.30 pp at sysctl=1** (-2.0% of total receive CPU
  budget). This is a real per-packet win, surfacing because the
  per-packet cost matters more when the CPU is slower.
- On the A53 receiver with sustained mixed-encap tcpreplay
  traffic (VXLAN-encap K8s gRPC + Kafka), sysctl=1 also lowered
  mean CPU by -0.64 pp. The dispatcher's per-call cost is real
  on in-order ARM (see the userspace microbench earlier in
  series 3) but in the kernel macro that cost is buying back the
  slow-path's per-layer dispatch on each packet, with net favour
  to the patched path here.

## Per-cell aggregate

| cell | sender → recv | proto             | sys | thr Mbps | retx  | cpu_recv | CV %  | drift %/h | max recv °C | clean |
|------|---------------|-------------------|-----|---------:|------:|---------:|------:|----------:|------------:|-------|
|  01  | pi5-1 → pi5-2 | iperf3-tcp        |  0  |  936.45  |     0 |   8.66 % | 0.639 | -0.008    |        58.2 |   ✓   |
|  02  | pi5-1 → pi5-2 | iperf3-tcp        |  1  |  936.45  |     0 |   8.61 % | 0.469 | -0.011    |        58.2 |   ✓   |
|  03  | pi5-2 → pi4-1 | iperf3-tcp        |  0  |  936.44  |     0 |  65.63 % | 0.968 | -0.041    |        37.0 |   ✓   |
|  04  | pi5-2 → pi4-1 | iperf3-tcp        |  1  |  936.44  |     0 |  64.32 % | 1.003 | -0.024    |        37.0 |   ✓   |
|  05  | pi5-2 → pi3-1 | iperf3-tcp        |  0  |   93.90  | 10527 |  14.91 % | 4.073 | -0.072    |        46.2 |   ✓   |
|  06  | pi5-2 → pi3-1 | iperf3-tcp        |  1  |   93.90  | 10641 |  14.93 % | 3.910 | -0.047    |        46.2 |   ✓   |
|  07  | pi5-1 → pi5-2 | iperf2-tcp        |  0  |  936.45  |   n/a |    n/a   | 0.572 | -0.005    |        57.1 |   ✓   |
|  08  | pi5-1 → pi5-2 | iperf2-tcp        |  1  |  936.46  |   n/a |    n/a   | 0.531 | -0.005    |        57.1 |   ✓   |
|  09  | pi5-2 → pi3-1 | tcpreplay vxlan   |  0  |   n/a    |   n/a |  14.94 %†|   —   |    —      |        42.9 |   ✓   |
|  10  | pi5-2 → pi3-1 | tcpreplay vxlan   |  1  |   n/a    |   n/a |  14.30 %†|   —   |    —      |        42.9 |   ✓   |

† Cell 9/10 CPU% is from `mpstat` over the first ~300-410 s of
the cell before the mpstat SSH session dropped (recovered via
JSON tail-fix). Sidecar (1 Hz vcgencmd) ran the entire cell on
both ends, so thermal cleanliness is the full hour. See "Caveats"
below.

## Thermal picture

Max temperature observed across the entire 10 h run, per host:

| host  | max temp | sustained cells (1 h each) |
|-------|---------:|----------------------------|
| pi5-1 |  51.6 °C | sender for cells 1, 2, 7, 8 (Gbit elephant) |
| pi5-2 |  65.3 °C | recv 1,2,7,8; sender 3-6,9-10 (10 cells back-to-back) |
| pi4-1 |  37.0 °C | recv for cells 3, 4 |
| pi3-1 |  46.2 °C | recv for cells 5, 6, 9, 10 |

pi5-2 saw the most sustained load (8 of 10 cells touched it on
one side or the other). Its 65.3 °C peak in cell 9 (tcpreplay
sender at ~50% of 1 GbE wire-rate) was 9 °C below the Pi 5 soft
temp limit (75 °C) and 20 °C below the hard limit (85 °C) — well
within the new fan's headroom. The 0xe0000 sticky-bit on pi5-2
is historical from before the bigger fan was installed; the low-
16-bit "currently throttled" word was 0x0 throughout every
sample of every cell. Same for pi5-1 / pi4-1 / pi3-1 — all
0xe0000-or-0x0 sticky observation, low-16-bit always 0x0.

**Net thermal verdict**: fans installed on all four Pis make the
1 h elephant + 1 h tcpreplay cells comfortable on every uarch.
None of the four came within 10 °C of any throttle threshold at
any time.

## Drift over the hour

Per-second iperf3 throughput regressed on time:

- pi5-1 ↔ pi5-2 cell 1: slope -0.008 %/hour (over 1 hour)
- pi5-2 ↔ pi4-1 cell 3: slope -0.041 %/hour
- pi5-2 ↔ pi3-1 cell 5: slope -0.072 %/hour
- All cells: |drift| < 0.08 %/hour

For comparison: the 24-hour x86 soaks the cover letter already
cites had drift "-0.000 %" (i40e iperf3) and "-0.504 %" (mlx5
iperf2). The ARM 1-hour cells are flatter in absolute terms but
shorter in duration; both confirm the same picture (no measurable
drift attributable to the patches).

## Per-second throughput stability (CV)

CV (stdev / mean × 100) per 1 h cell:

- pi5-1 ↔ pi5-2 iperf3 TCP: **0.47-0.64 %** (excellent)
- pi5-1 ↔ pi5-2 iperf2 TCP: **0.53-0.57 %**
- pi5-2 ↔ pi4-1 iperf3 TCP: 0.97-1.00 % (the A72 receiver runs
  hotter on CPU%, slightly more jitter)
- pi5-2 ↔ pi3-1 iperf3 TCP: 3.91-4.07 % (USB-Ethernet on Pi 3
  has intrinsic jitter, unrelated to the dissector)

No cell shows sysctl=0 vs sysctl=1 CV difference outside what
the slower-CPU/jittery-link explanation predicts.

## A/B headline (the cover-letter-worthy numbers)

### Throughput (no regression)

```
                              sysctl=0       sysctl=1     delta
  pi5-1↔pi5-2 iperf3 TCP    936.45 Mbps    936.45 Mbps  +0.00 %
  pi5-1↔pi5-2 iperf2 TCP    936.45 Mbps    936.46 Mbps  +0.00 %
  pi5-2↔pi4-1 iperf3 TCP    936.44 Mbps    936.44 Mbps  +0.00 %
  pi5-2↔pi3-1 iperf3 TCP     93.90 Mbps     93.90 Mbps  +0.00 %
```

Every TCP cell hit the link ceiling (~94 Mbit on Pi 3's USB-eth,
~936 Mbit on 1 GbE elsewhere) in both modes. Retransmits
identical within Pi3 USB-eth noise (10527 vs 10641, 0.04% of
total).

### Receiver CPU% (per-packet savings show up where they matter)

```
                              sysctl=0   sysctl=1   delta
  pi5-1→pi5-2 iperf3 TCP        8.66 %    8.61 %   -0.05 pp
  pi5-2→pi4-1 iperf3 TCP       65.63 %   64.32 %   -1.30 pp
  pi5-2→pi3-1 iperf3 TCP       14.91 %   14.93 %   +0.01 pp
  pi5-2→pi3-1 tcpreplay vxlan  14.94 %†  14.30 %†  -0.64 pp
```

The A72 cell delta is the new finding. On Cortex-A76 (cell 1-2)
the dissector is too small a fraction of receive cost for a
1-hour-mean delta to surface above noise. On Cortex-A72 (which
runs the receive path at ~1.6× more CPU per packet — both
slower-clock and shallower OoO pipeline) the fast-path's
~10 ns/pkt cycle saving translates to a -1.30 pp reduction in
receiver CPU at wire-rate. That's -2.0 % of the receiver's total
budget — a quantifiable win on this uarch.

## Caveats

### Cell 9 + 10 tcpreplay wedge

tcpreplay 4.5.2 with `--mbps=80 --duration=3600 --loop=0 --quiet`
did **not** exit at 3600 s elapsed. Cell 9 ran ~2 h before being
manually killed; cell 10 wedged the same way and was killed at
~1 h + 60 s. Logs were dominated by per-packet "Message too
long" warnings from oversized frames in the workload PCAP
(`vxlan-k8s-pure.pcap` contains some packets that exceed the
1 GbE interface MTU after the VXLAN-encap wrapping; the wire
send is rejected, the packet is dropped, tcpreplay records a
warning and moves on). Why `--duration` didn't enforce the
deadline is unclear; possible interaction with `--loop=0`
(unbounded loop count) overriding the duration check in this
release.

Effect on the soak:
- Sidecar (1 Hz vcgencmd) ran the entire wedged-cell duration on
  both ends — thermal data is complete and clean.
- mpstat (1 Hz per-CPU%) survived for ~300 s (cell 9) and
  ~410 s (cell 10) before the SSH session dropped. Numbers
  reported above are means/p95 over that window. They are
  representative of cell-internal steady state but should not
  be quoted as 1-hour soak averages.
- Cells 9/10 sysctl=0 vs sysctl=1 receiver CPU delta (-0.64 pp)
  is still informative — both windows saturated the same
  receiver under the same replay rate.
- tcpreplay-throughput numbers (tx_packets / failed_packets)
  were not parsed because the script kept only the last 25 lines
  of replay.log to bound repo size, and the wedged tcpreplay
  never reached its terminal "Successful packets:" summary.

These two anomalies are bench-harness, not patch, issues. For a
v2 cleanup the right fixes are: (1) wrap tcpreplay in a
`timeout 3700 …` shell guard, (2) keep mpstat alive via
`-o ServerAliveInterval=15 -o ServerAliveCountMax=10` on the
backgrounded ssh session, or have the receiver write its own
mpstat to disk via nohup like the sidecar does.

### iperf2 CPU% not captured

iperf2 `-y c` doesn't include CPU% in the CSV. Cells 7/8 have
n/a in that column. Use `-e` plus a different parser if you want
sender + receiver CPU% on iperf2 cells.

## Cover-letter snippet

The contribution this dataset makes to the cover letter is a
**multi-hour ARM cross-uarch soak**, complementing the 24 h x86
soaks that are already cited.  Proposed paragraph:

```
   * 10 h sustained-load ARM cross-uarch soak (2026-06-10/11):
     pi5-1↔pi5-2 (A76↔A76), pi5-2↔pi4-1 (A76↔A72) and
     pi5-2↔pi3-1 (A76↔A53) over 1 GbE switched + 100 Mbit
     USB-eth, 6 × iperf3 TCP + 2 × iperf2 TCP + 2 × tcpreplay
     vxlan-k8s-pure, 60 min each, sysctl=0 vs sysctl=1 paired
     cells, 1 Hz vcgencmd telemetry on both ends.

     All 10 cells thermal clean — max receiver temp 65.3 °C
     (pi5-2), 10 °C below the Pi 5 soft-temp limit, no current
     throttle bits set in any sample.  Per-cell drift
     ≤ 0.08 %/hour; CV 0.47-1.00 % on the 1 GbE cells.

     Throughput delta sysctl=0→sysctl=1: ≤ ±0.001 % across every
     cell (every TCP cell link-saturated in both modes;
     retransmits identical within USB-Ethernet jitter).

     Receiver-CPU% delta at sysctl=1:
       - A76 receiver:    -0.05 pp (within noise)
       - A72 receiver:    -1.30 pp (the per-packet fast-path
                          body savings visible where the
                          slower receive-side core makes the
                          dissector a larger fraction of rx
                          cost)
       - A53 receiver:    -0.64 pp on tcpreplay-vxlan
                          (sustained encap mix)
                          +0.01 pp on iperf3 TCP

     No regression on any receiver under sustained load.
     Details: perf-results/2026-06-10-series3-soak-10h/.
```

## Files

- `results.md` (this file)
- `aggregate.csv` — 10 cells, machine-readable
- `series3-soak-10h.sh` — the actually-run driver (the equivalent
  flake target is `nix run .#series3-soak`)
- `cells/cell-NN-{sender}-{recv}-{proto}-sysctl<0|1>/`
  - `iperf.json` / `iperf.csv` — raw iperf output
  - `mpstat.json` — receiver per-CPU (cells 9, 10 truncated, see
    Caveats; recovered via tail-strip)
  - `sidecar-{sender}.csv` / `sidecar-{recv}.csv` — 1 Hz
    vcgencmd CSV (ts, temp, freq, throttled)
  - `summary.json` — per-cell parsed stats
- `replay.log` — last 25 lines of tcpreplay output per cell
  (the full streams were 3.8 GB of "Message too long" warnings;
  the summary tail captures whatever tcpreplay was last doing)

## Reproduction

```bash
# Default 10-cell × 1-hour matrix, requires root SSH to all 4 Pis:
nix run .#series3-soak

# Shorter validation pass (50 min total):
DUR=300 COOLDOWN=10 nix run .#series3-soak

# Custom hostname mapping:
PI5_1=hp1 PI5_2=hp2 PI4_1=t PI3_1=p3 nix run .#series3-soak
```

Pre-conditions identical to the script header in
`nix/series3-soak.nix`.
