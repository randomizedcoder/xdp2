# nix/perf-record-c-xdp2-r1.nix
#
# R1.1 — focused perf-record on the post-S _opt path of the
# flow-dissector benchmark. Captures both -O (optimised, default
# post-S1) and -S (slow/generic) variants so the two can be
# attributed side-by-side. Designed to be invoked via
# xdp2-run-on-host on hp5.
#
# Outputs land in $PWD/result so the run-on-host orchestrator's
# result/ rsync-back carries them home.
#
#   result/perf-hp5/c-xdp2-opt-rec/{perf-record.data,perf-annotate.txt,perf-stat.txt}
#   result/perf-hp5/c-xdp2-slow-rec/...
#
# Usage:
#   nix run .#run-on-host -- hp5 -- perf-record-c-xdp2-r1
#
{ pkgs, flow-dissector-matrix-artifacts, test-pcap }:

let
  # The R1 target is the c-xdp2-usp impl (benchmark binary) on
  # combo.pcap. Lower iter count than the full perf-record-impl
  # because we only need the inlined entry-function distribution.
  ITER = "200";
in
pkgs.writeShellApplication {
  name = "xdp2-perf-record-c-xdp2-r1";
  runtimeInputs = [
    flow-dissector-matrix-artifacts
    pkgs.perf
    pkgs.coreutils
    pkgs.util-linux  # taskset
  ];
  text = ''
    set -euo pipefail

    OUT="''${1:-result/perf-hp5}"
    PCAP="${test-pcap}/combo.pcap"
    BMARK="${flow-dissector-matrix-artifacts}/bin/benchmark"
    CORE_PIN="''${CORE_PIN:-3}"

    [ -x "$BMARK" ] || { echo "perf-record-c-xdp2-r1: benchmark not found at $BMARK" >&2; exit 2; }
    [ -f "$PCAP" ] || { echo "perf-record-c-xdp2-r1: pcap not found at $PCAP" >&2; exit 2; }

    mkdir -p "$OUT"

    PERF_EVENTS="cycles,instructions,branches,branch-misses,L1-dcache-loads,L1-dcache-load-misses"

    run_one() {
        local impl="$1"; shift
        local impl_dir="$OUT/$impl"; mkdir -p "$impl_dir"
        echo "[perf-r1] === $impl ==="
        # perf stat (cheap, baseline counters)
        perf stat -e "$PERF_EVENTS" -- "$@" \
            > "$impl_dir/run.log" 2>"$impl_dir/perf-stat.txt" || \
            echo "  $impl perf-stat returned non-zero (continuing)" >&2
        # perf record + annotate for the inlined entry function
        local data="$impl_dir/perf-record.data"
        echo "[perf-r1] record $impl"
        if taskset -c "$CORE_PIN" perf record -F 999 -g -o "$data" -- "$@" \
                > "$impl_dir/record.log" 2>&1; then
            perf annotate -i "$data" --stdio > "$impl_dir/perf-annotate.txt" 2>&1 || true
            # Also: per-symbol top — quick way to see where time concentrates
            perf report -i "$data" --stdio --sort=overhead,symbol \
                > "$impl_dir/perf-report-by-symbol.txt" 2>&1 || true
        else
            echo "  $impl perf-record FAILED (see $impl_dir/record.log)" >&2
        fi
    }

    # _opt path (default post-S1) — this is the R1.1 target. Single
    # impl per run keeps the wall-clock short so the orchestrator's
    # SSH session completes before any timeout. Generic-engine data
    # is already captured in perf-results/asm/2026-05-08/perf-hp5/
    # c-all-usp-rec — no need to recapture.
    run_one "c-xdp2-opt-rec" "$BMARK" -p -n "${ITER}" "$PCAP"

    echo "[perf-r1] done. results at $OUT"
    find "$OUT" -type f | sort
  '';

  meta = {
    description = "R1.1 — focused perf-record on the post-S _opt path of c-xdp2-usp";
    mainProgram = "xdp2-perf-record-c-xdp2-r1";
  };
}
