#!/usr/bin/env bash
#
# perf-sweep.sh — Run the standard XDP2 benchmark matrix and emit a JSON report.
#
# Usage:
#   ./scripts/perf-sweep.sh <pcap-file> [iterations] [output-dir]
#
# Flags (set as environment variables):
#   FLAMEGRAPH=1  — generate a flamegraph SVG after the benchmark run
#   ANNOTATE=1    — run perf annotate on the hottest function
#   CORE_PIN=N    — pin benchmark to core N (reduces jitter)
#
# Example:
#   ./scripts/perf-sweep.sh ../data/pcaps/tcp_ipv4.pcap 500 results/
#   FLAMEGRAPH=1 CORE_PIN=3 ./scripts/perf-sweep.sh combo.pcap 500
#
# Output: one JSON file per mode+thread combination in the output directory.
# The filename encodes the run parameters for easy diffing across machines.
#
# Prerequisites:
#   - Built xdp2-bench in release mode (cargo build -p xdp2-bench --release)
#   - For perf counters: kernel.perf_event_paranoid <= 2
#   - For flamegraph: `perf` tool + `flamegraph` (cargo install flamegraph, or inferno)
#   - For annotate: `perf` tool

set -euo pipefail

PCAP="${1:?Usage: perf-sweep.sh <pcap-file> [iterations] [output-dir]}"
ITERATIONS="${2:-500}"
OUTDIR="${3:-perf-results}"

BENCH="${BENCH:-cargo run -p xdp2-bench --release --}"
FLAMEGRAPH="${FLAMEGRAPH:-0}"
ANNOTATE="${ANNOTATE:-0}"
CORE_PIN="${CORE_PIN:-}"

# Collect machine identity
HOSTNAME="$(hostname)"
ARCH="$(uname -m)"
KERNEL="$(uname -r)"
CPU_MODEL="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo unknown)"
CORES="$(nproc)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p "$OUTDIR"

PCAP_BASENAME="$(basename "$PCAP" .pcap)"

echo "=== XDP2 Performance Sweep ==="
echo "Host:       $HOSTNAME ($ARCH)"
echo "CPU:        $CPU_MODEL ($CORES cores)"
echo "Kernel:     $KERNEL"
echo "PCAP:       $PCAP"
echo "Iterations: $ITERATIONS"
echo "Output:     $OUTDIR/"
echo ""

# Standard measurement matrix
THREAD_COUNTS="1"
if [ "$CORES" -ge 4 ]; then
    THREAD_COUNTS="1 2 4"
fi
if [ "$CORES" -ge 8 ]; then
    THREAD_COUNTS="1 2 4 8"
fi
if [ "$CORES" -ge 16 ]; then
    THREAD_COUNTS="1 2 4 8 16"
fi

# Build core-pin argument if requested
PIN_ARG=""
if [ -n "$CORE_PIN" ]; then
    PIN_ARG="--core-pin $CORE_PIN"
    echo "Core pin:   $CORE_PIN"
fi
echo ""

# Single-threaded with perf counters (all four passes merged)
echo "--- Single-threaded (with perf counters: basic + stalls + detail + zen) ---"
OUTFILE="$OUTDIR/${PCAP_BASENAME}_${HOSTNAME}_1T.json"
$BENCH --pcap "$PCAP" --iterations "$ITERATIONS" --mode both --perf \
    --perf-pass basic --perf-pass stalls --perf-pass detail --perf-pass zen \
    $PIN_ARG --report > "$OUTFILE"
echo "Wrote: $OUTFILE"

# Multi-threaded sweeps (perf counters disabled)
for T in $THREAD_COUNTS; do
    if [ "$T" -eq 1 ]; then
        continue  # already done above
    fi
    echo "--- ${T} threads ---"
    OUTFILE="$OUTDIR/${PCAP_BASENAME}_${HOSTNAME}_${T}T.json"
    $BENCH --pcap "$PCAP" --iterations "$ITERATIONS" --mode both --threads "$T" --report > "$OUTFILE"
    echo "Wrote: $OUTFILE"
done

# Write machine metadata
META="$OUTDIR/${HOSTNAME}_meta.json"
cat > "$META" <<METAEOF
{
  "hostname": "$HOSTNAME",
  "arch": "$ARCH",
  "kernel": "$KERNEL",
  "cpu_model": "$CPU_MODEL",
  "cores": $CORES,
  "date": "$DATE"
}
METAEOF
echo ""
echo "Wrote metadata: $META"

# ── Optional: Flamegraph generation ──
if [ "$FLAMEGRAPH" = "1" ]; then
    echo ""
    echo "--- Flamegraph (compiled mode, $ITERATIONS iterations) ---"
    FLAME_SVG="$OUTDIR/${PCAP_BASENAME}_${HOSTNAME}_flamegraph.svg"
    PERF_DATA="$OUTDIR/.perf.data"

    if ! command -v perf &>/dev/null; then
        echo "warning: 'perf' not found — skipping flamegraph"
    else
        # Record samples at 10kHz for the compiled parser (best signal-to-noise).
        TASKSET_CMD=""
        if [ -n "$CORE_PIN" ]; then
            TASKSET_CMD="taskset -c $CORE_PIN"
        fi
        $TASKSET_CMD perf record -g -F 10000 -o "$PERF_DATA" -- \
            $BENCH --pcap "$PCAP" --iterations "$ITERATIONS" --mode compiled \
            $PIN_ARG 2>/dev/null

        # Generate flamegraph — try inferno (Rust), then flamegraph.pl.
        if command -v inferno-collapse-perf &>/dev/null; then
            perf script -i "$PERF_DATA" | inferno-collapse-perf | inferno-flamegraph > "$FLAME_SVG"
            echo "Wrote flamegraph: $FLAME_SVG"
        elif command -v stackcollapse-perf.pl &>/dev/null; then
            perf script -i "$PERF_DATA" | stackcollapse-perf.pl | flamegraph.pl > "$FLAME_SVG"
            echo "Wrote flamegraph: $FLAME_SVG"
        else
            echo "warning: neither inferno nor flamegraph.pl found"
            echo "  install: cargo install inferno"
        fi
        rm -f "$PERF_DATA"
    fi
fi

# ── Optional: perf annotate on hot function ──
if [ "$ANNOTATE" = "1" ]; then
    echo ""
    echo "--- perf annotate (compiled mode) ---"
    PERF_DATA="$OUTDIR/.perf.data"
    ANNOTATE_TXT="$OUTDIR/${PCAP_BASENAME}_${HOSTNAME}_annotate.txt"

    if ! command -v perf &>/dev/null; then
        echo "warning: 'perf' not found — skipping annotate"
    else
        TASKSET_CMD=""
        if [ -n "$CORE_PIN" ]; then
            TASKSET_CMD="taskset -c $CORE_PIN"
        fi
        $TASKSET_CMD perf record -g -F 10000 -o "$PERF_DATA" -- \
            $BENCH --pcap "$PCAP" --iterations "$ITERATIONS" --mode compiled \
            $PIN_ARG 2>/dev/null

        perf annotate -i "$PERF_DATA" --stdio > "$ANNOTATE_TXT" 2>/dev/null || true
        echo "Wrote annotation: $ANNOTATE_TXT"
        rm -f "$PERF_DATA"
    fi
fi

echo "Done. Results in $OUTDIR/"
