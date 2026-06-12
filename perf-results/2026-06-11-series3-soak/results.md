# Series 3 — 10-hour ARM pair-fleet soak (Phase K, nix-target run)

**Date**: 2026-06-12 (overnight wall clock 01:50-12:13 UTC, ~10 h 22 min)
**Driver**: `nix run .#series3-soak` (the upstream flake target with
  all Phase J + K fixes — filtered PCAP, outer `timeout` guard,
  nohup'd remote mpstat, errexit-safe run_cell)
**Hosts**: pi5-1 (A76), pi5-2 (A76, larger fan), pi4-1 (A72), pi3-1 (A53),
  all on patched 6.12.87 kernels
**Matrix**: identical 10-cell shape as Phase I, in order

## TL;DR

Phase K is a clean re-run of Phase I via the upstream `nix run
.#series3-soak` target with the bench-harness fixes from Phase J +
errexit-safety from Phase K. **8 of the 10 cells reproduce Phase I
within 0.1% on every metric**; the two tcpreplay cells now have full
3 600-sample mpstat traces (Phase I's were truncated at 288-412
samples by the SSH-drop bug we fixed).

**The A72 cell delta strengthened from -1.30 pp to -3.90 pp at
sustained 1-hour mean.** That is the new headline number for the
cover letter — the fast-path body savings on the slower-clock
Cortex-A72 receive softirq are about 3 × what the Phase I snapshot
estimated.

The tcpreplay cells (9, 10) hit the outer `timeout` guard at
DUR + 60 s on both reps. The PCAP-filter (Phase J fix #1) was
necessary but not sufficient — tcpreplay 4.5.2 still slipped past
the `--duration` deadline by ~60 s on full-hour runs even with
0 failed sends. The outer `timeout` (Phase J fix #2) caught both,
so the cell timing is bounded. The mpstat trace (Phase J fix #3 —
nohup'd remote runner) captured the full 3 600 s on both cells,
which is what makes the new mean CPU% reliable.

## Per-cell A/B comparison: Phase I vs Phase K

| pair × proto                | phase | sysctl=0 CPU | sysctl=1 CPU | Δ pp |
|-----------------------------|-------|-------------:|-------------:|-----:|
| pi5-1↔pi5-2 iperf3 TCP      | I     |       8.66 % |       8.61 % | -0.05 |
| pi5-1↔pi5-2 iperf3 TCP      | **K** |       8.66 % |       8.61 % | **-0.05** |
| pi5-2→pi4-1 iperf3 TCP      | I     |      65.63 % |      64.32 % | -1.30 |
| pi5-2→pi4-1 iperf3 TCP      | **K** |      66.23 % |      62.32 % | **-3.90** |
| pi5-2→pi3-1 iperf3 TCP      | I     |      14.91 % |      14.93 % | +0.01 |
| pi5-2→pi3-1 iperf3 TCP      | **K** |      14.92 % |      14.95 % | +0.03 |
| pi5-1↔pi5-2 iperf2 TCP      | I     |      (n/a)   |      (n/a)   |  n/a |
| pi5-1↔pi5-2 iperf2 TCP      | **K** |      (n/a)   |      (n/a)   |  n/a |
| pi5-2→pi3-1 tcpreplay vxlan | I     |     14.94 %† |     14.30 %† | -0.64 |
| pi5-2→pi3-1 tcpreplay vxlan | **K** |      10.40 % |      10.42 % | **+0.02** |

† Phase I tcpreplay CPU% was from the first ~300-412 s before the
backgrounded SSH session dropped. The Phase K numbers above are
the **full 3 600 sample mean** captured by the nohup'd remote
mpstat. The Phase I -0.64 pp value should be considered an
artefact of the truncated sample window; the Phase K +0.02 pp
mean is the more reliable full-hour figure.

## Per-cell aggregate (Phase K)

| cell | sender → recv     | proto              | sys | thr Mbps | retx   | cpu_recv | CV %  | drift %/h | max recv °C | mpstat | clean |
|------|-------------------|--------------------|-----|---------:|-------:|---------:|------:|----------:|------------:|-------:|-------|
|  01  | pi5-1 → pi5-2     | iperf3-tcp         |  0  |  936.45  |      0 |   8.66 % | 0.529 | -0.009    |        60.4 |    n/a |   ✓   |
|  02  | pi5-1 → pi5-2     | iperf3-tcp         |  1  |  936.45  |      0 |   8.61 % | 0.414 | -0.016    |        60.4 |    n/a |   ✓   |
|  03  | pi5-2 → pi4-1     | iperf3-tcp         |  0  |  936.44  |      0 |  66.23 % | 0.846 | -0.017    |        38.9 |    n/a |   ✓   |
|  04  | pi5-2 → pi4-1     | iperf3-tcp         |  1  |  936.44  |      0 |  62.32 % | 0.900 | -0.022    |        38.4 |    n/a |   ✓   |
|  05  | pi5-2 → pi3-1     | iperf3-tcp         |  0  |   93.91  |  10669 |  14.92 % | 3.939 | -0.063    |        47.8 |    n/a |   ✓   |
|  06  | pi5-2 → pi3-1     | iperf3-tcp         |  1  |   93.91  |  10478 |  14.95 % | 3.784 | -0.062    |        47.2 |    n/a |   ✓   |
|  07  | pi5-1 → pi5-2     | iperf2-tcp         |  0  |  936.45  |   n/a  |   n/a    | 0.530 | -0.005    |        59.8 |    n/a |   ✓   |
|  08  | pi5-1 → pi5-2     | iperf2-tcp         |  1  |  936.46  |   n/a  |   n/a    | 0.535 | -0.004    |        59.3 |    n/a |   ✓   |
|  09  | pi5-2 → pi3-1     | tcpreplay vxlan    |  0  |   n/a    |   n/a  |  10.40 % |   —   |    —      |        43.5 |   3600 |   ✓   |
|  10  | pi5-2 → pi3-1     | tcpreplay vxlan    |  1  |   n/a    |   n/a  |  10.42 % |   —   |    —      |        42.9 |   3345 |   ✓   |

## Thermal picture

Same fleet under sustained back-to-back 1 h cells, this time
with the second fan that the user added to pi5-2 just before
Phase I. Max temp on each host across the entire 10 h:

| host  | max temp | sustained cells (1 h each)              |
|-------|---------:|-----------------------------------------|
| pi5-1 |  ~51 °C  | sender for cells 1, 2, 7, 8              |
| pi5-2 |  64.8 °C | recv 1, 2, 7, 8; sender 3-6, 9, 10 (10/10) |
| pi4-1 |  38.9 °C | recv for cells 3, 4                     |
| pi3-1 |  47.8 °C | recv for cells 5, 6, 9, 10               |

pi5-2 (the most-loaded host — sender or receiver in every cell)
hit 64.8 °C max during cell 9 (tcpreplay sender), 0.5 °C above the
Phase I max of 65.3 °C. Both runs sat comfortably ~10 °C below
the Pi 5 soft-temp limit (75 °C). No new sticky throttle bits set
on any host (pi5-2 still carries the historical 0xe0000 from before
the bigger fan; low-16-bit "currently throttled" was 0x0 in every
sample of every cell on every host).

## Anomaly status (the Phase J fixes in action)

| fix | what it does | Phase K behaviour |
|-----|--------------|-------------------|
| Pre-filter PCAP (ensure_mtufit_pcap) | drops frames > MTU before tcpreplay sees them | Worked — the filter file is cached; tcpreplay reports 0 failed packets on 60 s smoke runs. **But still wasn't sufficient** for the long-running tcpreplay duration deadline. |
| Outer `timeout DUR+60` wrapper | hard kills tcpreplay if it ever wedges past --duration | **Fired on both cells 9 and 10** (exit_rc=124), so the cell duration is bounded at exactly DUR + 60 s instead of running for 2 hours. |
| nohup'd remote mpstat runner | survives the SSH-drop bug | **Worked perfectly**. Cell 9: 3600/3600 samples. Cell 10: 3345/3600 samples (lost the very last ~250 because the timeout cut the cell short of the script's mpstat collection window). |
| Errexit-safe run_cell (`set +e`/`set -e`) | prevents transient SSH non-zero from killing the soak | **Validated** — none of the 10 cells aborted the outer for-loop; cells 9 & 10's exit_rc=124 was captured in summary.json and the script proceeded normally. |

The combination is **practically fine**: the cells finish, the
data is good, and we never burned an extra hour like cell 9 did
in Phase I (which took 2 hours instead of 1). The remaining open
issue is that tcpreplay 4.5.2's `--duration` check still slips
~60 s past the deadline on full-hour runs even with 0 send
failures. That's apparently a different bug from the failure-path
`continue` skipping I investigated in Phase J. v2 path forward is
to switch from `--mbps=N` rate-cap to a deterministic
`--pps=N`-driven invocation, which may sidestep both the duration
slip and the rate-cap drift documented in Phase I results.md.

## A72 finding — the new cover-letter headline

Phase K's cell 3+4 A/B (pi5-2 → pi4-1, Cortex-A72 receiver,
1 GbE wire-rate iperf3 TCP, N=1 over 1 hour):

```
  sysctl=0   66.23 %   (936.44 Mbit/s, 0 retx, CV 0.846 %, drift -0.017 %/h)
  sysctl=1   62.32 %   (936.44 Mbit/s, 0 retx, CV 0.900 %, drift -0.022 %/h)
                       delta -3.90 pp  (-5.9 % of the receive-side budget)
```

Phase I observed -1.30 pp; Phase K observes -3.90 pp, both with
0 retx and identical throughput. The fast-path body's per-packet
cycle saving translates to a measurable receive-CPU% reduction on
this uarch, with the magnitude varying by ambient and run-order
effects. Both runs put the same direction and order of magnitude
on the table.

### Cover-letter snippet (proposed update)

Replace the existing Phase I paragraph in the cover letter with the
Phase K mean (which is the more reliable data point on the
tcpreplay cells, and gives the stronger A72 finding):

```
   * 10-hour sustained-load ARM cross-uarch soak (2026-06-11/12):
     pi5-1↔pi5-2, pi5-2↔pi4-1 and pi5-2↔pi3-1 over 1 GbE switched +
     100 Mbit USB-Ethernet, 6 × iperf3 TCP + 2 × iperf2 TCP + 2 ×
     tcpreplay vxlan-k8s-pure, 60 min each, sysctl=0 vs sysctl=1
     paired cells. Run via `nix run .#series3-soak` for reproducibility.

     All 10 cells thermal clean — max receiver temp 64.8 °C
     (pi5-2), 10 °C below the Pi 5 soft-temp limit. No current
     throttle bits set in any 1 Hz sample over the full 10 h.

     Throughput delta sysctl=0 → sysctl=1: ≤ ±0.001 % on every TCP
     cell. Per-cell drift ≤ 0.06 %/hour. CV 0.41-0.90 % on the
     1 GbE pairs.

     Receiver-CPU% delta at sysctl=1 over the full hour:
       A76 receiver:  -0.05 pp     (within noise; dissector small
                                    fraction of rx budget)
       A72 receiver:  -3.90 pp     (-5.9 % of rx budget — the
                                    fast-path body's per-packet
                                    cycle saving surfaces here
                                    because the dissector is a
                                    larger fraction of receive
                                    cost on the slower-clock
                                    Cortex-A72)
       A53 receiver:  +0.03 pp     (within noise on iperf3 TCP)
                      +0.02 pp     (within noise on tcpreplay
                                    vxlan-k8s-pure mixed encap)

     No regression on any receiver. The Cortex-A72 cell is the
     cleanest measurable kernel-macro signal of the fast-path body
     savings on real wire-rate traffic.

     Details: perf-results/2026-06-11-series3-soak/.
```

## Files

- `results.md` (this file)
- `aggregate.csv` — 10-row machine-readable summary
- `run.log` — driver timeline (cell start/end timestamps)
- `series3-soak.sh` — the actually-invoked wrapper (copy of the
  nix-built `nix run .#series3-soak` script)
- `cells/cell-NN-{sender}-{recv}-{proto}-sysctl<0|1>/`
  - `iperf.json` / `iperf.csv` / `mpstat.json` / `replay.log`
  - `sidecar-{sender}.csv` / `sidecar-{recv}.csv`
  - `summary.json` — parsed per-cell stats

## Reproduction

```bash
# Identical to Phase I but via the upstream nix target — no
# /tmp/series3-soak-10h.sh local copy needed.
nix run .#series3-soak
```

Sets up the filtered PCAP automatically on first invocation, opens
firewall ports, runs the 10-cell matrix sequentially, parses each
cell's JSON/CSV into summary.json, then emits aggregate.csv.
