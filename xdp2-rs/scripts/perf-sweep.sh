#!/usr/bin/env bash
#
# perf-sweep.sh — Run the standard XDP2 benchmark matrix and emit a JSON report.
#
# Usage:
#   ./scripts/perf-sweep.sh <pcap-file> [iterations] [output-dir]
#
# Example:
#   ./scripts/perf-sweep.sh ../data/pcaps/tcp_ipv4.pcap 500 results/
#
# Output: one JSON file per mode+thread combination in the output directory.
# The filename encodes the run parameters for easy diffing across machines.
#
# Prerequisites:
#   - Built xdp2-bench in release mode (cargo build -p xdp2-bench --release)
#   - For perf counters: kernel.perf_event_paranoid <= 2

set -euo pipefail

PCAP="${1:?Usage: perf-sweep.sh <pcap-file> [iterations] [output-dir]}"
ITERATIONS="${2:-500}"
OUTDIR="${3:-perf-results}"

BENCH="${BENCH:-cargo run -p xdp2-bench --release --}"

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

# Single-threaded with perf counters
echo "--- Single-threaded (with perf counters) ---"
OUTFILE="$OUTDIR/${PCAP_BASENAME}_${HOSTNAME}_1T.json"
$BENCH --pcap "$PCAP" --iterations "$ITERATIONS" --mode both --perf --report > "$OUTFILE"
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
echo "Done. Results in $OUTDIR/"
