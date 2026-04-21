#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Unified xdp2-rs vs C-matrix benchmark (portable, non-Nix).
#
# Runs the 6-way C matrix AND xdp2-bench (graph / mono / compiled /
# template) against the SAME filtered pcap, so every number in the
# resulting table comes from the same packet set.
#
# Nix users: prefer `nix run .#flow-dissector-matrix-unified` — that
# target wires benchmark binaries + xdp2-bench from the Nix store,
# no PATH assumptions. This script is for developers who want to
# drive the same flow without Nix.
#
# Binaries expected on PATH:
#   xdp2-bench                       (from xdp2-rs workspace)
#   benchmark, benchmark_bpf         (from samples/flow_dissector/)
# and BPF objects passed via -b / -x / -f.
#
# Usage:
#   ./xdp2_rs_matrix.sh [-n <iter>] [-N <bpf_repeat>] [-c <cpu>] \
#                       [-b <bpf_obj>] [-x <xdp2_bpf_obj>] \
#                       [-f <fast_bpf_obj>] <pcap_file>

set -euo pipefail

ITER=100
BPF_REPEAT=1000
CORE_PIN=""
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BPF_OBJ="$SCRIPT_DIR/bpf_flow.kern.o"
XDP2_BPF_OBJ="$SCRIPT_DIR/flow_dissector.bpf.o"
FAST_BPF_OBJ="$SCRIPT_DIR/fast_bpf/fast_flow.bpf.o"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS] <pcap_file>

  -n <N>   xdp2-bench iterations per mode         (default: $ITER)
  -N <N>   BPF_PROG_TEST_RUN repeat count         (default: $BPF_REPEAT)
  -c <N>   Pin xdp2-bench + C usp to CPU N        (default: unset)
  -b <o>   Kernel BPF flowdis object              (default: $BPF_OBJ)
  -x <o>   XDP2 BPF parser object                 (default: $XDP2_BPF_OBJ)
  -f <o>   xdp2-flow-ebpf fast-path object        (default: $FAST_BPF_OBJ)
  -h       This help.
EOF
    exit 1
}

while getopts "n:N:c:b:x:f:h" opt; do
    case $opt in
        n) ITER="$OPTARG" ;;
        N) BPF_REPEAT="$OPTARG" ;;
        c) CORE_PIN="$OPTARG" ;;
        b) BPF_OBJ="$OPTARG" ;;
        x) XDP2_BPF_OBJ="$OPTARG" ;;
        f) FAST_BPF_OBJ="$OPTARG" ;;
        h|*) usage ;;
    esac
done
shift $((OPTIND - 1))

[[ $# -eq 1 ]] || usage
INPUT_PCAP="$1"
[[ -f "$INPUT_PCAP" ]] || { echo "Error: PCAP not found: $INPUT_PCAP" >&2; exit 1; }

command -v xdp2-bench >/dev/null 2>&1 || {
    echo "Error: xdp2-bench not on PATH. Build with:"          >&2
    echo "  cd xdp2-rs && cargo build --release -p xdp2-bench" >&2
    echo "then add target/release to PATH."                    >&2
    exit 1
}

BENCHMARK="$SCRIPT_DIR/benchmark"
BENCHMARK_BPF="$SCRIPT_DIR/benchmark_bpf"
[[ -x "$BENCHMARK"     ]] || { echo "Error: $BENCHMARK not found — build with make" >&2; exit 1; }
[[ -x "$BENCHMARK_BPF" ]] || { echo "Error: $BENCHMARK_BPF not found — build with make" >&2; exit 1; }

TMPDIR=$(mktemp -d -t xdp2-matrix-unified-XXXX)
trap 'rm -rf "$TMPDIR"' EXIT
FILTERED="$TMPDIR/filtered.pcap"

extract_nspkt() {
    local m
    m=$(echo "$1" | grep -oE '[0-9]+ ns/pkt' | head -1 || true)
    echo "${m:-N/A}"
}
extract_mpps() {
    local m
    m=$(echo "$1" | grep -oE '[0-9]+ Mpps' | head -1 || true)
    echo "${m:-N/A}"
}

echo "=== Unified xdp2-rs vs C-matrix Performance Comparison ==="
echo "Input PCAP:            $INPUT_PCAP"
echo "xdp2-bench iterations: $ITER"
echo "BPF repeat count:      $BPF_REPEAT"
[[ -n "$CORE_PIN" ]] && echo "CPU pin:               $CORE_PIN"
echo ""

# ─── Step 1: filter ──────────────────────────────────────────────
echo "--- Pre-filtering pcap with xdp2-bench (Rust parse filter) ---"
FILTER_ARGS=(--pcap "$INPUT_PCAP" --output-pcap "$FILTERED" --iterations 1 --warmup 0)
[[ -n "$CORE_PIN" ]] && FILTER_ARGS+=(--core-pin "$CORE_PIN")
xdp2-bench "${FILTER_ARGS[@]}" 2>&1 | grep -E '^(Loaded|Filtered|Wrote)' || true
echo ""
[[ -s "$FILTERED" ]] || { echo "Error: filter produced empty pcap" >&2; exit 1; }

# ─── Step 2: C usp (ways 1-3) ────────────────────────────────────
echo "--- C matrix: userspace (ways 1-3) on filtered pcap ---"
USP_OUT=$("$BENCHMARK" -p -n "$ITER" "$FILTERED" 2>&1)
echo "$USP_OUT"
echo ""

FLOWDIS_LINE=$(echo "$USP_OUT" | grep "^Kernel flowdis:" || true)
XDP2_LINE=$(echo "$USP_OUT" | grep "^XDP2 parser:" || true)
XDP2_PO_LINE=$(echo "$USP_OUT" | grep "^XDP2 parse-only:" || true)

FLOWDIS_NSPKT=$(extract_nspkt "$FLOWDIS_LINE"); FLOWDIS_MPPS=$(extract_mpps "$FLOWDIS_LINE")
XDP2_NSPKT=$(extract_nspkt "$XDP2_LINE");       XDP2_MPPS=$(extract_mpps "$XDP2_LINE")
XDP2_PO_NSPKT=$(extract_nspkt "$XDP2_PO_LINE"); XDP2_PO_MPPS=$(extract_mpps "$XDP2_PO_LINE")

# ─── Step 3: C BPF (ways 4-6) ────────────────────────────────────
run_bpf() {
    local label="$1" obj="$2"
    if [[ ! -f "$obj" ]]; then
        echo "--- Skipping $label ($obj not found) ---"
        echo "N/A N/A"
        return
    fi
    echo "--- C matrix: $label ($(basename "$obj")) ---" >&2
    local out line
    if out=$("$BENCHMARK_BPF" -p -n "$BPF_REPEAT" -l "$label" -b "$obj" "$FILTERED" 2>&1); then
        echo "$out" >&2
        line=$(echo "$out" | grep "^$label:" || true)
        echo "$(extract_nspkt "$line") $(extract_mpps "$line")"
    else
        echo "Warning: $label failed (need root / CAP_BPF?)" >&2
        echo "$out" >&2
        echo "N/A N/A"
    fi
}

read -r BPF_NSPKT BPF_MPPS            < <(run_bpf "Kernel BPF flowdis"  "$BPF_OBJ")
read -r XDP2_BPF_NSPKT XDP2_BPF_MPPS  < <(run_bpf "XDP2 BPF parser"     "$XDP2_BPF_OBJ")
read -r FAST_BPF_NSPKT FAST_BPF_MPPS  < <(run_bpf "xdp2-flow-ebpf fast" "$FAST_BPF_OBJ")
echo ""

# ─── Step 4: xdp2-bench modes ────────────────────────────────────
run_rust() {
    local mode="$1"
    local args=(--pcap "$FILTERED" --iterations "$ITER" --mode "$mode")
    [[ -n "$CORE_PIN" ]] && args+=(--core-pin "$CORE_PIN")
    echo "--- xdp2-bench --mode $mode ---" >&2
    local out line nspkt mpps
    if out=$(xdp2-bench "${args[@]}" 2>&1); then
        echo "$out" >&2
        line=$(echo "$out" | grep -E "^Rust " | head -1 || true)
        nspkt=$(echo "$line" | grep -oE '[0-9]+ ns/pkt' | head -1 || true); nspkt="${nspkt:-N/A}"
        mpps=$(echo "$line" | grep -oE '[0-9]+ Mpps' | head -1 || true);    mpps="${mpps:-N/A}"
        echo "$nspkt $mpps"
    else
        echo "Warning: xdp2-bench --mode $mode failed" >&2
        echo "$out" >&2
        echo "N/A N/A"
    fi
}

read -r GRAPH_NSPKT GRAPH_MPPS       < <(run_rust graph)
read -r MONO_NSPKT MONO_MPPS         < <(run_rust mono)
read -r COMPILED_NSPKT COMPILED_MPPS < <(run_rust compiled)
read -r TEMPLATE_NSPKT TEMPLATE_MPPS < <(run_rust template)
echo ""

# ─── Unified table ───────────────────────────────────────────────
echo "================================================================="
echo "      Unified xdp2-rs vs C-matrix Comparison (same pcap)"
echo "================================================================="
echo ""
printf "%-32s | %-18s | %-9s\n" "Mode" "ns/pkt" "Mpps"
printf -- "---------------------------------+--------------------+----------\n"
printf "%-32s | %-18s | %-9s\n" "C kernel flowdis (usp)"       "$FLOWDIS_NSPKT"   "$FLOWDIS_MPPS"
printf "%-32s | %-18s | %-9s\n" "C XDP2 parser (usp)"          "$XDP2_NSPKT"      "$XDP2_MPPS"
printf "%-32s | %-18s | %-9s\n" "C XDP2 parse-only (usp)"      "$XDP2_PO_NSPKT"   "$XDP2_PO_MPPS"
printf "%-32s | %-18s | %-9s\n" "C kernel BPF flowdis"         "$BPF_NSPKT"       "$BPF_MPPS"
printf "%-32s | %-18s | %-9s\n" "C XDP2 BPF parser"            "$XDP2_BPF_NSPKT"  "$XDP2_BPF_MPPS"
printf "%-32s | %-18s | %-9s\n" "C xdp2-flow-ebpf fast (BPF)"  "$FAST_BPF_NSPKT"  "$FAST_BPF_MPPS"
printf -- "---------------------------------+--------------------+----------\n"
printf "%-32s | %-18s | %-9s\n" "Rust graph (dyn dispatch)"    "$GRAPH_NSPKT"     "$GRAPH_MPPS"
printf "%-32s | %-18s | %-9s\n" "Rust mono (hand-rolled)"      "$MONO_NSPKT"      "$MONO_MPPS"
printf "%-32s | %-18s | %-9s\n" "Rust compiled (monomorphized)" "$COMPILED_NSPKT" "$COMPILED_MPPS"
printf "%-32s | %-18s | %-9s\n" "Rust template (fixed-offset)" "$TEMPLATE_NSPKT"  "$TEMPLATE_MPPS"
echo ""
echo "Notes:"
echo "  - All rows measure the SAME filtered pcap (xdp2-bench pre-filter)."
echo "  - Rust 'template' still runs select_template_id() per packet;"
echo "    the hardware-classified equivalent is --mode af-xdp-template"
echo "    (see docs/ntuple-template-bench.md)."
