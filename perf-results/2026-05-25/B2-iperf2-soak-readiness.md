# Phase B.2 — 24h iperf2 soak readiness

**Date authored**: 2026-05-24 (B.1 in flight, B.2 prep)
**Fire**: AFTER B.1 (24h iperf3 soak, PID 271722) completes
  ~22:06 PDT 2026-05-25.

## Status

- Launch script: `perf-results/2026-05-25/soak_iperf2_ready.sh`
  (executable, syntax-checked, parser-tested).
- iperf2 verified available via `nixpkgs#iperf2` — resolves to
  iperf-2.2.1 in the binary cache. `nixpkgs#iperf` is iperf**3**;
  do NOT use that attribute.
- Script aborts early if iperf3 from B.1 is still running on
  either host — defensive against accidental concurrent launch.

## Why this isn't a copy of B.1

iperf2 is multi-threaded; iperf3 is single-threaded. The two
stress kernel paths differently:

- iperf3: one socket per stream, single dispatcher thread on
  client/server. Hits the per-socket TCP path repeatedly.
- iperf2: thread-per-stream on both client and server. Hits
  scheduler, locking, and SMP cache-coherency paths harder.

A bug visible only under iperf2 (and not iperf3) would imply
either a multithreaded race or scheduler interaction in the
cake / flow_dissector code paths. Worth N=2 different soak
generators for that reason.

## iperf2 gotchas discovered while prepping

### Gotcha #1: `-i 0` does NOT suppress interval reports

Empirically tested 2026-05-24: `iperf -c ... -i 0` produces
output every microsecond (essentially), generating thousands
of `[SUM]` lines per second. That breaks naïve `awk '/^\[SUM\]/'`
parsers that pick the first match.

Fix: omit `-i` entirely. iperf2 then prints one per-thread
total line + ONE final `[SUM]` cumulative line. Clean and
parseable.

### Gotcha #2: A.1b's 52-85 Gbit/s aggregate numbers were a parser bug

The 2026-05-24 A.1b log shows 10 iperf2 runs reporting
52-85 Gbit/s on a 25 GbE link. That's physically impossible.
Root cause: the A.1b parser summed every `[SUM]` line it saw,
and with `-i 0` (or default `-i 1` over 60s = 60 SUM lines),
that produces a number 60x or more inflated.

The fix in `soak_iperf2_ready.sh` is: parse only the FINAL
[SUM] line, with no -i flag, so there's just one [SUM] per
run. Tested against captured iperf2 output (100515 Mbits/sec
→ correctly parsed as 100.515 Gbit/s on a localhost loopback
test).

### Gotcha #2.5 (not iperf2-specific, learned the hard way on B.1)

The B.1 launch script does:
```bash
ssh root@hp1 "... iperf3 -c ... -J 2>&1 > /tmp/soak_iperf_$RUN.json"
```

The redirect `> /tmp/soak_iperf_$RUN.json` runs INSIDE the
ssh-quoted command, so the JSON lands on **hp1's** /tmp, not
the local box. The subsequent local `python3` parse step
then sees no file, prints nothing, and the local log gets
no per-run summary lines.

This does NOT corrupt the soak — iperf3 ran fine, cake was
exercised, hourly snapshots still work (they query hp3
directly for cake stats / memory / dmesg). It only loses the
per-run throughput summary in the local log. JSONs are
recoverable from hp1 via `scp root@hp1:/tmp/soak_iperf_*.json`
at the end.

The B.2 script avoids this trap by capturing iperf2 output
via ssh's stdout (`OUT=$(ssh ... iperf -c ...)`), which sends
the data back to the local shell. See the comment above the
`OUT=$(ssh ...)` line in `soak_iperf2_ready.sh`.

### Gotcha #3: bidirectional (`-d`) is fragile

iperf2 `-d` (concurrent bidirectional) was historically
thread-bug-prone under heavy load. Modern iperf 2.1+ improved
it, but the safer choice for a long soak is forward-only
(`-c` without `-d` or `-r`). The summaries earlier in the
session that mentioned "TCP write failed" most plausibly
came from a `-d` attempt; not used in this script.

If we want bidirectional coverage in a future soak, use `-r`
(reverse, runs SEQUENTIALLY after forward — clean and
non-fragile) rather than `-d`.

## Launch checklist (run when B.1 done)

1. Confirm B.1 finished:
   ```
   ps -p 271722 || echo "B.1 PID gone — OK to launch B.2"
   tail -3 /tmp/soak_iperf3_main.log
   ```
2. Confirm hp1 + hp3 are quiet:
   ```
   ssh root@hp1 'pgrep -f iperf'   # should be empty
   ssh root@hp3 'pgrep -f iperf'   # should be empty
   ```
3. Fire-and-forget:
   ```
   /home/das/Downloads/xdp2/perf-results/2026-05-25/soak_iperf2_ready.sh \
     > /tmp/soak_iperf2_wrapper.log 2>&1 &
   disown
   ```
4. Verify started:
   ```
   ps -p $! -o pid,etime,cmd
   sleep 30 && tail -5 /tmp/soak_iperf2_main.log
   ```

## Expected output on success

- Aggregate throughput in the 22-25 Gbit/s range per 5-min
  run (close to but not exceeding the 25 GbE link cap, with
  some loss to TCP overhead and the cake shaper headroom).
- Hourly snapshot rows in `/tmp/soak_iperf2_snapshot.log`
  showing flat memory usage, monotonically increasing packet
  count, low/stable drop count, zero new dmesg alerts.
- Total ~288 runs over 24h (300s session + 5s gap = ~305s
  cadence × 86400/305 = 283 runs).

## What constitutes a fail

- ANY dmesg WARN/BUG/oops mentioning sch_cake, flow_hash, or
  the underlying mlx5_core driver.
- Cake "memory used" growing without bound between snapshots.
- Throughput dropping below 15 Gbit/s for >3 consecutive runs
  (B.1 will tell us the steady-state range; >25% drop from
  that is a fail).
- iperf2 connection refused or any "Broken pipe" / "TCP write
  failed" for 2+ consecutive runs.
