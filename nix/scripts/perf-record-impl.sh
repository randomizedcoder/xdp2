#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# perf-record-impl — Phase A4 driver. Runs `perf stat` per-impl on the
# DUT and captures `perf record` + `perf annotate` for the four
# cross-impl diff pairs the synthesis doc focuses on.
#
# Run on hp5 (DUT). Needs root or
# /proc/sys/kernel/perf_event_paranoid <= 1.
#
# Output goes to <out>/<impl>/{perf-stat.txt,perf-record.data,perf-annotate.txt}
# and a summary <out>/perf-summary.csv.
#
# Usage on hp5:
#   sudo nix/scripts/perf-record-impl.sh \
#       --pcap data/pcaps/combo.pcap \
#       --xdp2-rs $(nix build --no-link --print-out-paths .#xdp2-rs) \
#       --artifacts $(nix build --no-link --print-out-paths .#flow-dissector-matrix-artifacts) \
#       --out perf-results/asm/2026-05-08/perf-hp5

set -euo pipefail

PCAP=""
XDP2_RS=""
ARTIFACTS=""
OUT=""
ITER=100
BPF_REPEAT=1000

usage() {
    cat <<'USAGE'
Usage: perf-record-impl.sh [OPTIONS]

  --pcap PATH       PCAP for the bench (combo.pcap recommended).
  --xdp2-rs PATH    Path to xdp2-rs build (provides bin/xdp2-bench).
  --artifacts PATH  Path to flow-dissector-matrix-artifacts build.
  --out DIR         Output dir.
  --iter N          xdp2-bench --iterations (default 100).
  --bpf-repeat N    benchmark_bpf -n (default 1000).
  -h, --help        This help.

Cross-impl diff pairs that get extra perf-record + annotate:
  - c-bpf-fast        vs  c-xdp2-usp
  - c-bpf-flowdis     vs  c-flowdis-usp
  - rust-graph-enum   vs  rust-compiled
  - c-xdp2-usp        vs  c-xdp2-parse-only
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --pcap) PCAP="$2"; shift 2 ;;
        --xdp2-rs) XDP2_RS="$2"; shift 2 ;;
        --artifacts) ARTIFACTS="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --iter) ITER="$2"; shift 2 ;;
        --bpf-repeat) BPF_REPEAT="$2"; shift 2 ;;
        *) echo "perf-record-impl: unknown arg '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

[ -n "$PCAP" ] && [ -f "$PCAP" ] || { echo "perf-record-impl: --pcap PATH required" >&2; exit 2; }
[ -n "$XDP2_RS" ] && [ -x "$XDP2_RS/bin/xdp2-bench" ] || { echo "perf-record-impl: --xdp2-rs missing" >&2; exit 2; }
[ -n "$ARTIFACTS" ] && [ -x "$ARTIFACTS/bin/benchmark" ] || { echo "perf-record-impl: --artifacts missing" >&2; exit 2; }
[ -n "$OUT" ] || OUT="perf-results/asm/$(date -I)/perf-hp5"
mkdir -p "$OUT"

BENCH="$XDP2_RS/bin/xdp2-bench"
BMARK="$ARTIFACTS/bin/benchmark"
BMARK_BPF="$ARTIFACTS/bin/benchmark_bpf"
BPF_DIR="$ARTIFACTS/lib/xdp2-flow-dissector-matrix"

echo "[perf-record] pcap:      $PCAP"
echo "[perf-record] xdp2-rs:   $XDP2_RS"
echo "[perf-record] artifacts: $ARTIFACTS"
echo "[perf-record] out:       $OUT"

# Common perf events. -dd doesn't work on i40e/Zen 1 sometimes; use
# explicit -e list to pick events known to exist on Zen 1.
PERF_EVENTS="cycles,instructions,branches,branch-misses,L1-dcache-loads,L1-dcache-load-misses,LLC-loads,LLC-load-misses,dTLB-loads,dTLB-load-misses"

# perf_stat_run <impl> <command...>
perf_stat_run() {
    local impl="$1"; shift
    local impl_dir="$OUT/$impl"; mkdir -p "$impl_dir"
    echo "[perf-record] === $impl ==="
    perf stat -e "$PERF_EVENTS" -- "$@" \
        > "$impl_dir/run.log" 2>"$impl_dir/perf-stat.txt" || \
        echo "  $impl perf-stat returned non-zero (continuing)" >&2
}

# perf_record_run <impl> <command...>
perf_record_run() {
    local impl="$1"; shift
    local impl_dir="$OUT/$impl"; mkdir -p "$impl_dir"
    local data="$impl_dir/perf-record.data"
    echo "[perf-record] record $impl"
    if perf record -F 99 -g -o "$data" -- "$@" \
            > "$impl_dir/record.log" 2>&1; then
        # Annotate top symbol(s) — guess based on the impl name. The
        # synthesis doc parses these for per-instruction sample
        # distribution.
        case "$impl" in
            rust-*)  perf annotate -i "$data" --stdio > "$impl_dir/perf-annotate.txt" 2>&1 || true ;;
            c-bpf-*) perf annotate -i "$data" --stdio > "$impl_dir/perf-annotate.txt" 2>&1 || true ;;
            c-*)     perf annotate -i "$data" --stdio > "$impl_dir/perf-annotate.txt" 2>&1 || true ;;
        esac
    else
        echo "  $impl perf-record FAILED (see $impl_dir/record.log)" >&2
    fi
}

# Rust impls — use xdp2-bench --perf detail (already captures cycles
# etc) plus perf stat for the standard event list.
RUST_MODES=(graph graph-enum mono mono-x4 compiled simd template template-simd)
for mode in "${RUST_MODES[@]}"; do
    perf_stat_run "rust-$mode" \
        "$BENCH" --pcap "$PCAP" --iterations "$ITER" --mode "$mode"
done

# C impls — userspace benchmark binary. The benchmark always runs all
# 3 (kernel-flowdis, xdp2-usp, xdp2-parse-only) per invocation, so a
# single run captures all 3. Filter the per-impl line out of the log.
perf_stat_run "c-all-usp" "$BMARK" -p -n "$ITER" "$PCAP"
# Materialize per-impl perf-stat by re-running with a label filter
# (benchmark binary doesn't have one); the c-all-usp directory has
# the joint counters, the synthesis pass splits them by ratio.

# BPF impls — benchmark_bpf, one per BPF object.
for spec in "c-bpf-flowdis:bpf_flow.kern.o:Kernel BPF flowdis" \
            "c-bpf-xdp2:flow_dissector.bpf.o:XDP2 BPF parser" \
            "c-bpf-fast:fast_flow.bpf.o:xdp2-flow-ebpf fast"; do
    impl="${spec%%:*}"
    rest="${spec#*:}"
    obj="${rest%%:*}"
    label="${rest#*:}"
    perf_stat_run "$impl" \
        "$BMARK_BPF" -p -n "$BPF_REPEAT" -l "$label" -b "$BPF_DIR/$obj" "$PCAP"
done

# Cross-impl diff pairs — perf record + annotate
echo "[perf-record] === record + annotate cross-impl pairs ==="
perf_record_run "rust-graph-enum-rec" \
    "$BENCH" --pcap "$PCAP" --iterations "$ITER" --mode graph-enum
perf_record_run "rust-compiled-rec" \
    "$BENCH" --pcap "$PCAP" --iterations "$ITER" --mode compiled
perf_record_run "c-all-usp-rec" \
    "$BMARK" -p -n "$ITER" "$PCAP"
perf_record_run "c-bpf-fast-rec" \
    "$BMARK_BPF" -p -n "$BPF_REPEAT" -l "xdp2-flow-ebpf fast" \
    -b "$BPF_DIR/fast_flow.bpf.o" "$PCAP"
perf_record_run "c-bpf-flowdis-rec" \
    "$BMARK_BPF" -p -n "$BPF_REPEAT" -l "Kernel BPF flowdis" \
    -b "$BPF_DIR/bpf_flow.kern.o" "$PCAP"

# Roll up perf-stat into a CSV
{
  printf 'impl,cycles,instructions,IPC,branches,branch_misses,L1d_loads,L1d_misses,LLC_loads,LLC_misses,dTLB_loads,dTLB_misses\n'
  for d in "$OUT"/*/; do
    impl=$(basename "$d")
    [ -f "$d/perf-stat.txt" ] || continue
    cycles=$(grep -oE '^\s*[0-9,]+\s+cycles' "$d/perf-stat.txt" | head -1 | grep -oE '[0-9,]+' | head -1 | tr -d ',')
    inst=$(grep -oE '^\s*[0-9,]+\s+instructions' "$d/perf-stat.txt" | head -1 | grep -oE '[0-9,]+' | head -1 | tr -d ',')
    ipc=$(grep -oE 'insn per cycle\s*$|insn per cycle\s*\(' "$d/perf-stat.txt" | head -1 || true)
    ipc_val=$(grep -oE '#\s*[0-9.]+\s+insn per cycle' "$d/perf-stat.txt" | grep -oE '[0-9.]+' | head -1 || echo "")
    branches=$(grep -oE '^\s*[0-9,]+\s+branches' "$d/perf-stat.txt" | head -1 | grep -oE '[0-9,]+' | head -1 | tr -d ',')
    bmiss=$(grep -oE '^\s*[0-9,]+\s+branch-misses' "$d/perf-stat.txt" | head -1 | grep -oE '[0-9,]+' | head -1 | tr -d ',')
    l1l=$(grep -oE '^\s*[0-9,]+\s+L1-dcache-loads' "$d/perf-stat.txt" | head -1 | grep -oE '[0-9,]+' | head -1 | tr -d ',')
    l1m=$(grep -oE '^\s*[0-9,]+\s+L1-dcache-load-misses' "$d/perf-stat.txt" | head -1 | grep -oE '[0-9,]+' | head -1 | tr -d ',')
    llcl=$(grep -oE '^\s*[0-9,]+\s+LLC-loads' "$d/perf-stat.txt" | head -1 | grep -oE '[0-9,]+' | head -1 | tr -d ',')
    llcm=$(grep -oE '^\s*[0-9,]+\s+LLC-load-misses' "$d/perf-stat.txt" | head -1 | grep -oE '[0-9,]+' | head -1 | tr -d ',')
    dtl=$(grep -oE '^\s*[0-9,]+\s+dTLB-loads' "$d/perf-stat.txt" | head -1 | grep -oE '[0-9,]+' | head -1 | tr -d ',')
    dtm=$(grep -oE '^\s*[0-9,]+\s+dTLB-load-misses' "$d/perf-stat.txt" | head -1 | grep -oE '[0-9,]+' | head -1 | tr -d ',')
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$impl" "${cycles:-}" "${inst:-}" "${ipc_val:-}" \
        "${branches:-}" "${bmiss:-}" "${l1l:-}" "${l1m:-}" "${llcl:-}" "${llcm:-}" "${dtl:-}" "${dtm:-}"
  done
} > "$OUT/perf-summary.csv"

echo "[perf-record] done. perf-summary.csv at $OUT/perf-summary.csv"
