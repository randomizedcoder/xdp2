# nix/perf-record-r7-mono-vs-rust.nix
#
# R7-A — focused perf-record on c-xdp2-mono and rust-mono running
# vxlan-k8s-pure.pcap, the workload where the cross-impl gap is
# biggest (c-xdp2-mono 139 vs rust-mono 93 ns/pkt on hp5).
# Identifies which generated code shapes consume the 280 extra
# instructions per packet in c-xdp2-mono.
#
# Outputs land in $PWD/result so the run-on-host orchestrator's
# result/ rsync-back carries them home.
#
#   result/perf-r7/c-xdp2-mono/{perf-record.data,perf-annotate.txt,
#                               perf-report-by-symbol.txt,perf-stat.txt}
#   result/perf-r7/rust-mono/{perf-record.data,perf-annotate.txt,
#                              perf-report-by-symbol.txt,perf-stat.txt}
#
# Usage:
#   nix run .#run-on-host -- hp5 -- perf-record-r7-mono-vs-rust
#
{ pkgs, flow-dissector-matrix-artifacts, xdp2-rs, workload-pcap-vxlan-k8s-pure }:

let
  ITER = "200";
  RUST_ITER = "200";
in
pkgs.writeShellApplication {
  name = "xdp2-perf-record-r7-mono-vs-rust";
  runtimeInputs = [
    flow-dissector-matrix-artifacts
    xdp2-rs
    pkgs.perf
    pkgs.coreutils
    pkgs.util-linux  # taskset
  ];
  text = ''
    set -euo pipefail

    OUT="''${1:-result/perf-r7}"
    PCAP="${workload-pcap-vxlan-k8s-pure}/vxlan-k8s-pure.pcap"
    BMARK="${flow-dissector-matrix-artifacts}/bin/benchmark"
    XDP2_BENCH="${xdp2-rs}/bin/xdp2-bench"
    CORE_PIN="''${CORE_PIN:-3}"

    [ -x "$BMARK" ] || { echo "perf-record-r7: benchmark not found at $BMARK" >&2; exit 2; }
    [ -x "$XDP2_BENCH" ] || { echo "perf-record-r7: xdp2-bench not found at $XDP2_BENCH" >&2; exit 2; }
    [ -f "$PCAP" ] || { echo "perf-record-r7: pcap not found at $PCAP" >&2; exit 2; }

    mkdir -p "$OUT"

    # High-frequency sampling — vxlan workload is ~7 Mpps so 9999 Hz
    # gives ~700 samples/sec per packet which is plenty for hotspot
    # attribution.
    PERF_EVENTS="cycles,instructions,branches,branch-misses,L1-dcache-loads,L1-dcache-load-misses,L1-icache-load-misses,iTLB-load-misses"

    run_c_impl() {
        local impl="$1"; shift
        # Remaining args (if any) are extra flags to benchmark, e.g. -O / -S.
        # With no extra flag the benchmark defaults to mono post-c5cbaf4.
        local -a extra_flags=("$@")
        local impl_dir="$OUT/$impl"; mkdir -p "$impl_dir"
        echo "[perf-r7] === $impl ==="

        # perf stat first (baseline counters)
        taskset -c "$CORE_PIN" perf stat -e "$PERF_EVENTS" -- \
            "$BMARK" -p -n "${ITER}" "''${extra_flags[@]}" "$PCAP" \
            > "$impl_dir/run.log" 2>"$impl_dir/perf-stat.txt" || \
            echo "  $impl perf-stat returned non-zero (continuing)" >&2

        # perf record + annotate
        local data="$impl_dir/perf-record.data"
        echo "[perf-r7] record $impl"
        if taskset -c "$CORE_PIN" perf record -F 9999 -g -o "$data" -- \
                "$BMARK" -p -n "${ITER}" "''${extra_flags[@]}" "$PCAP" \
                > "$impl_dir/record.log" 2>&1; then
            perf annotate -i "$data" --stdio > "$impl_dir/perf-annotate.txt" 2>&1 || true
            perf report -i "$data" --stdio --sort=overhead,symbol --no-children \
                > "$impl_dir/perf-report-by-symbol.txt" 2>&1 || true
            perf report -i "$data" --stdio --sort=overhead,dso --no-children \
                > "$impl_dir/perf-report-by-dso.txt" 2>&1 || true
        else
            echo "  $impl perf-record FAILED (see $impl_dir/record.log)" >&2
        fi
    }

    run_rust_mode() {
        local mode="$1"
        local impl="rust-$mode"
        local impl_dir="$OUT/$impl"; mkdir -p "$impl_dir"
        echo "[perf-r7] === $impl ==="

        taskset -c "$CORE_PIN" perf stat -e "$PERF_EVENTS" -- \
            "$XDP2_BENCH" --pcap "$PCAP" --iterations "${RUST_ITER}" \
                          --mode "$mode" --core-pin "$CORE_PIN" \
            > "$impl_dir/run.log" 2>"$impl_dir/perf-stat.txt" || \
            echo "  $impl perf-stat returned non-zero (continuing)" >&2

        local data="$impl_dir/perf-record.data"
        echo "[perf-r7] record $impl"
        if taskset -c "$CORE_PIN" perf record -F 9999 -g -o "$data" -- \
                "$XDP2_BENCH" --pcap "$PCAP" --iterations "${RUST_ITER}" \
                              --mode "$mode" --core-pin "$CORE_PIN" \
                > "$impl_dir/record.log" 2>&1; then
            perf annotate -i "$data" --stdio > "$impl_dir/perf-annotate.txt" 2>&1 || true
            perf report -i "$data" --stdio --sort=overhead,symbol --no-children \
                > "$impl_dir/perf-report-by-symbol.txt" 2>&1 || true
            perf report -i "$data" --stdio --sort=overhead,dso --no-children \
                > "$impl_dir/perf-report-by-dso.txt" 2>&1 || true
        else
            echo "  $impl perf-record FAILED (see $impl_dir/record.log)" >&2
        fi
    }

    # The headline pair: c-xdp2-mono (default post-c5cbaf4, no flag)
    # and rust-mono.
    run_c_impl "c-xdp2-mono"
    run_rust_mode "mono"

    # Bonus: c-xdp2-opt (with -O), so we can also diff mono-vs-opt
    # within the C codegen path — confirms whether the mono-specific
    # template shape is the bloat source vs the generic-engine slow
    # path.
    run_c_impl "c-xdp2-opt" "-O"

    echo "[perf-r7] done. results at $OUT"
    find "$OUT" -type f -name "*.txt" | sort | xargs -I{} wc -l {} | head -20
  '';

  meta = {
    description = "R7-A focused perf-record + annotate on c-xdp2-mono vs rust-mono (vxlan-k8s-pure)";
    mainProgram = "xdp2-perf-record-r7-mono-vs-rust";
  };
}
