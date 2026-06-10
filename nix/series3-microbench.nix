# nix/series3-microbench.nix
#
# Userspace libflowdis A/B microbench harness for the series 3
# flow_dissector fast-path. Drives `micro_flowdis.c` (the same
# bench source used for the x86 measurements at
# perf-results/2026-06-04-series3-phase3-t/) against two libflowdis
# .so variants — one with the gate port applied (patched), one
# without (baseline) — via `LD_LIBRARY_PATH` switching. Reports
# ns/pkt mean ± stdev per variant and the speedup.
#
# This is the single highest-signal A/B test in the series 3
# investigation: it isolates the dissector cost from NICs, qdiscs,
# kernel scheduling, and platform thermal effects.
#
# Usage:
#   nix run .#series3-microbench -- HOST PATCHED BASELINE [N_RUNS] [OUTDIR]
#
# Examples:
#   # Bench pi5-2 with closures already nix-copy-closure'd:
#   nix run .#series3-microbench -- \
#     pi5-2 \
#     /nix/store/k509xbm68zw441cpyqzl60rdv7418ask-xdp2-0.1.0 \
#     /nix/store/s2jblg2p0pjc3qpz4sds06mv9q44vk1q-xdp2-0.1.0
#
#   # 20 runs and custom output dir:
#   nix run .#series3-microbench -- \
#     pi3-1 /nix/store/...-xdp2 /nix/store/...-xdp2 20 /tmp/a53-bench
#
# Pre-conditions:
#   - HOST is SSH-reachable as root.
#   - Both PATCHED and BASELINE closures already exist on HOST's
#     /nix/store (use `nix-copy-closure --to root@HOST <path>` to
#     push them from a build host).
#   - HOST has gcc available (the wrapper uses `nix shell
#     nixpkgs#gcc` to compile the bench, so HOST needs nix-shell
#     to be functional — true on any NixOS host).
#
# Outputs (in OUTDIR, defaults to
# perf-results/<YYYY-MM-DD>-series3-microbench/<host>/):
#   - micro_flowdis_<HOST>.log   raw 2 × N_RUNS bench iterations
#   - summary.txt                parsed table (mean, stdev, delta)

{ pkgs }:

let
  # The exact bench source we've used for every microbench since
  # the t (Comet Lake-H) measurement on 2026-06-04. Keep verbatim.
  benchSrc = ../perf-results/2026-06-04-series3-phase3-t/micro_flowdis.c;
in
pkgs.writeShellApplication {
  name = "series3-microbench";

  runtimeInputs = [
    pkgs.openssh
    pkgs.coreutils
    pkgs.python3
    pkgs.rsync
  ];

  text = ''
    set -u

    if [ "$#" -lt 3 ]; then
      cat <<'EOF'
    Usage: series3-microbench HOST PATCHED BASELINE [N_RUNS] [OUTDIR]

      HOST     SSH-reachable host with nix-shell available
      PATCHED  Path to xdp2-with-fast-path-port closure (libflowdis.so
               with the gate logic). Must exist in HOST:/nix/store.
      BASELINE Path to xdp2-without-port closure.
      N_RUNS   Number of 10M-iteration runs per variant. Default 10.
      OUTDIR   Output directory (default
               perf-results/<YYYY-MM-DD>-series3-microbench/<HOST>/)

    Env overrides:
      CPU_PIN  taskset core for the bench. Default 3.
      N_ITER   Iterations per run. Default 10000000 (10 M).
      GOVERNOR  Governor to set on CPU_PIN before bench. Default
                performance. Pass empty string to skip.
    EOF
      exit 64
    fi

    HOST="$1"; PATCHED="$2"; BASELINE="$3"
    N_RUNS="''${4:-10}"
    today="$(date +%Y-%m-%d)"
    OUTDIR="''${5:-perf-results/$today-series3-microbench/$HOST}"
    CPU_PIN="''${CPU_PIN:-3}"
    N_ITER="''${N_ITER:-10000000}"
    GOVERNOR="''${GOVERNOR:-performance}"

    mkdir -p "$OUTDIR"
    LOG="$OUTDIR/micro_flowdis_$HOST.log"

    SSH() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$@"; }

    echo "series3-microbench"
    echo "  HOST=$HOST CPU_PIN=$CPU_PIN N_RUNS=$N_RUNS N_ITER=$N_ITER"
    echo "  PATCHED=$PATCHED"
    echo "  BASELINE=$BASELINE"
    echo "  OUTDIR=$OUTDIR"

    # Verify both closures present on HOST
    for path in "$PATCHED" "$BASELINE"; do
      if ! SSH root@"$HOST" "test -e $path/lib/libflowdis.so"; then
        echo "FAIL: $path/lib/libflowdis.so not present on $HOST"
        echo "      run: nix-copy-closure --to root@$HOST $path"
        exit 2
      fi
    done

    # Ship the bench source
    SSH root@"$HOST" 'mkdir -p /root/microbench' > /dev/null 2>&1
    rsync -az ${benchSrc} root@"$HOST":/root/microbench/micro_flowdis.c

    # Compile against PATCHED (symbols match either; binary same)
    if ! SSH root@"$HOST" "cd /root/microbench && nix shell nixpkgs#gcc -c gcc -O3 -march=native -o micro_flowdis micro_flowdis.c -I $PATCHED/include -I $PATCHED/include/flowdis -L $PATCHED/lib -lflowdis -lsiphash" \
        > /dev/null 2>&1; then
      echo "FAIL: micro_flowdis build on $HOST"
      exit 3
    fi

    # Run the bench, log raw output
    SSH root@"$HOST" "
      echo '=== $HOST ===' ;
      if [ -n '$GOVERNOR' ]; then
        echo performance > /sys/devices/system/cpu/cpu''${CPU_PIN}/cpufreq/scaling_governor || true
        cat /sys/devices/system/cpu/cpu''${CPU_PIN}/cpufreq/scaling_governor ;
      fi
      vcgencmd measure_temp 2>/dev/null || true
      cd /root/microbench
      echo === PATCHED ===
      for i in \$(seq 1 $N_RUNS); do
        LD_LIBRARY_PATH=$PATCHED/lib taskset -c $CPU_PIN ./micro_flowdis $N_ITER | head -1
      done
      echo === BASELINE ===
      for i in \$(seq 1 $N_RUNS); do
        LD_LIBRARY_PATH=$BASELINE/lib taskset -c $CPU_PIN ./micro_flowdis $N_ITER | head -1
      done
      vcgencmd measure_temp 2>/dev/null || true
      vcgencmd get_throttled 2>/dev/null || true
    " > "$LOG"

    # Parse + summary
    python3 - "$LOG" "$OUTDIR/summary.txt" <<'PYEOF'
    import re, statistics, sys
    log, summary = sys.argv[1], sys.argv[2]
    patched, baseline = [], []
    mode = None
    for line in open(log):
        if "=== PATCHED ===" in line: mode = "p"; continue
        if "=== BASELINE ===" in line: mode = "b"; continue
        m = re.search(r"ns_per_pkt=([0-9.]+)", line)
        if not m or not mode: continue
        v = float(m.group(1))
        (patched if mode == "p" else baseline).append(v)
    def stats(xs):
        if not xs: return "(no samples)"
        return f"N={len(xs):3d}  mean={statistics.mean(xs):8.3f}  stdev={(statistics.stdev(xs) if len(xs)>1 else 0):6.3f}  range=[{min(xs):.2f}, {max(xs):.2f}]"
    with open(summary, "w") as f:
        f.write(f"series3-microbench summary\n  source: {log}\n\n")
        f.write(f"patched : {stats(patched)}\n")
        f.write(f"baseline: {stats(baseline)}\n")
        if patched and baseline:
            mp, mb = statistics.mean(patched), statistics.mean(baseline)
            f.write(f"delta   : {mp-mb:+.3f} ns/pkt ({100*(mp-mb)/mb:+.2f}%)\n")
    print(open(summary).read())
    PYEOF
  '';
}
