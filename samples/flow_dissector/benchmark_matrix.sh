#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# 5-way flow dissector performance comparison matrix.
#
# Runs both the userspace benchmark (benchmark) and the BPF benchmark
# (benchmark_bpf) and formats the results into a comparison matrix.
#
# The BPF benchmark requires root / CAP_BPF.
#
# Usage:
#   sudo ./benchmark_matrix.sh [-n <repeat>] [-b <bpf_obj>] \
#                              [-f <fast_bpf_obj>] <pcap_file>
#
# Ways:
#   1. Userspace: Kernel flowdis port (flowdis.c)
#   2. Userspace: XDP2 parser (full write-metadata path)
#   3. Userspace: XDP2 parse-only (no-metadata baseline)
#   4. BPF:       Upstream kernel selftest (bpf_flow.kern.o)
#   5. BPF:       XDP2 compiler-generated (flow_dissector.bpf.o)
#   6. BPF:       xdp2-flow-ebpf fast-path (fast_bpf/fast_flow.bpf.o)  [A3]
#

set -euo pipefail

REPEAT=100
BPF_OBJ="bpf_flow.kern.o"
XDP2_BPF_OBJ="flow_dissector.bpf.o"
# xdp2-flow-ebpf fast-path (Track D output). Default relative to
# SCRIPT_DIR, mirroring the other BPF_OBJ defaults.
FAST_BPF_OBJ="fast_bpf/fast_flow.bpf.o"
BPF_REPEAT=1000
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
    echo "Usage: $0 [-n <userspace_repeat>] [-N <bpf_repeat>] [-b <bpf_obj>] [-f <fast_bpf_obj>] <pcap_file>"
    echo ""
    echo "  -n  Userspace benchmark iterations (default: $REPEAT)"
    echo "  -N  BPF_PROG_TEST_RUN repeat count (default: $BPF_REPEAT)"
    echo "  -b  Path to BPF flow dissector .o file (default: $BPF_OBJ)"
    echo "  -f  Path to xdp2-flow-ebpf fast-path .o (default: $FAST_BPF_OBJ)"
    exit 1
}

while getopts "n:N:b:f:h" opt; do
    case $opt in
        n) REPEAT="$OPTARG" ;;
        N) BPF_REPEAT="$OPTARG" ;;
        b) BPF_OBJ="$OPTARG" ;;
        f) FAST_BPF_OBJ="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

if [[ $# -ne 1 ]]; then
    usage
fi

PCAP="$1"

if [[ ! -f "$PCAP" ]]; then
    echo "Error: PCAP file not found: $PCAP"
    exit 1
fi

# Parse "NN ns/pkt" from a benchmark output line.
# Returns "N/A" if not found.
extract_nspkt() {
    local line="$1"
    local match
    match=$(echo "$line" | grep -oE '[0-9]+ ns/pkt' | head -1) || true
    echo "${match:-N/A}"
}

# Parse "MM Mpps" from a benchmark output line.
# Returns "N/A" if not found.
extract_mpps() {
    local line="$1"
    local match
    match=$(echo "$line" | grep -oE '[0-9]+ Mpps' | head -1) || true
    echo "${match:-N/A}"
}

echo "=== 6-Way Flow Dissector Performance Matrix ==="
echo "PCAP: $PCAP"
echo "Userspace iterations: $REPEAT"
echo "BPF repeat count: $BPF_REPEAT"
echo ""

# ─── Run userspace benchmark ───
echo "--- Running userspace benchmark ---"
USERSPACE_OUT=$("$SCRIPT_DIR/benchmark" -p -n "$REPEAT" "$PCAP" 2>&1) || {
    echo "Error: userspace benchmark failed"
    echo "$USERSPACE_OUT"
    exit 1
}
echo "$USERSPACE_OUT"
echo ""

# Extract userspace results
FLOWDIS_LINE=$(echo "$USERSPACE_OUT" | grep "^Kernel flowdis:" || true)
XDP2_LINE=$(echo "$USERSPACE_OUT" | grep "^XDP2 parser:" || true)
XDP2_PO_LINE=$(echo "$USERSPACE_OUT" | grep "^XDP2 parse-only:" || true)

FLOWDIS_NSPKT=$(extract_nspkt "$FLOWDIS_LINE")
FLOWDIS_MPPS=$(extract_mpps "$FLOWDIS_LINE")
XDP2_NSPKT=$(extract_nspkt "$XDP2_LINE")
XDP2_MPPS=$(extract_mpps "$XDP2_LINE")
XDP2_PO_NSPKT=$(extract_nspkt "$XDP2_PO_LINE")
XDP2_PO_MPPS=$(extract_mpps "$XDP2_PO_LINE")

# ─── Run BPF benchmark (needs root) ───
BPF_NSPKT="N/A"
BPF_MPPS="N/A"

if [[ -f "$SCRIPT_DIR/$BPF_OBJ" ]] || [[ -f "$BPF_OBJ" ]]; then
    # Resolve BPF object path
    if [[ -f "$SCRIPT_DIR/$BPF_OBJ" ]]; then
        BPF_PATH="$SCRIPT_DIR/$BPF_OBJ"
    else
        BPF_PATH="$BPF_OBJ"
    fi

    echo "--- Running kernel BPF benchmark ---"
    if BPF_OUT=$("$SCRIPT_DIR/benchmark_bpf" -p -n "$BPF_REPEAT" -l "Kernel BPF flowdis" -b "$BPF_PATH" "$PCAP" 2>&1); then
        echo "$BPF_OUT"
        echo ""

        BPF_LINE=$(echo "$BPF_OUT" | grep "^Kernel BPF flowdis:" || true)
        BPF_NSPKT=$(extract_nspkt "$BPF_LINE")
        BPF_MPPS=$(extract_mpps "$BPF_LINE")
    else
        echo "Warning: kernel BPF benchmark failed (need root / CAP_BPF?)"
        echo "$BPF_OUT"
        echo ""
    fi
else
    echo "--- Skipping kernel BPF benchmark (no $BPF_OBJ found) ---"
    echo ""
fi

# ─── Run XDP2 BPF benchmark (needs root) ───
XDP2_BPF_NSPKT="N/A"
XDP2_BPF_MPPS="N/A"

if [[ -f "$SCRIPT_DIR/$XDP2_BPF_OBJ" ]] || [[ -f "$XDP2_BPF_OBJ" ]]; then
    # Resolve XDP2 BPF object path
    if [[ -f "$SCRIPT_DIR/$XDP2_BPF_OBJ" ]]; then
        XDP2_BPF_PATH="$SCRIPT_DIR/$XDP2_BPF_OBJ"
    else
        XDP2_BPF_PATH="$XDP2_BPF_OBJ"
    fi

    echo "--- Running XDP2 BPF benchmark ---"
    if XDP2_BPF_OUT=$("$SCRIPT_DIR/benchmark_bpf" -p -n "$BPF_REPEAT" -l "XDP2 BPF parser" -b "$XDP2_BPF_PATH" "$PCAP" 2>&1); then
        echo "$XDP2_BPF_OUT"
        echo ""

        XDP2_BPF_LINE=$(echo "$XDP2_BPF_OUT" | grep "^XDP2 BPF parser:" || true)
        XDP2_BPF_NSPKT=$(extract_nspkt "$XDP2_BPF_LINE")
        XDP2_BPF_MPPS=$(extract_mpps "$XDP2_BPF_LINE")
    else
        echo "Warning: XDP2 BPF benchmark failed"
        echo "$XDP2_BPF_OUT"
        echo ""
    fi
else
    echo "--- Skipping XDP2 BPF benchmark (no $XDP2_BPF_OBJ found) ---"
    echo ""
fi

# ─── Run xdp2-flow-ebpf fast-path BPF benchmark (needs root) ───
FAST_BPF_NSPKT="N/A"
FAST_BPF_MPPS="N/A"

if [[ -f "$SCRIPT_DIR/$FAST_BPF_OBJ" ]] || [[ -f "$FAST_BPF_OBJ" ]]; then
    # Resolve fast-path BPF object path
    if [[ -f "$SCRIPT_DIR/$FAST_BPF_OBJ" ]]; then
        FAST_BPF_PATH="$SCRIPT_DIR/$FAST_BPF_OBJ"
    else
        FAST_BPF_PATH="$FAST_BPF_OBJ"
    fi

    echo "--- Running xdp2-flow-ebpf fast-path BPF benchmark ---"
    if FAST_BPF_OUT=$("$SCRIPT_DIR/benchmark_bpf" -p -n "$BPF_REPEAT" -l "xdp2-flow-ebpf fast" -b "$FAST_BPF_PATH" "$PCAP" 2>&1); then
        echo "$FAST_BPF_OUT"
        echo ""

        FAST_BPF_LINE=$(echo "$FAST_BPF_OUT" | grep "^xdp2-flow-ebpf fast:" || true)
        FAST_BPF_NSPKT=$(extract_nspkt "$FAST_BPF_LINE")
        FAST_BPF_MPPS=$(extract_mpps "$FAST_BPF_LINE")
    else
        echo "Warning: xdp2-flow-ebpf fast-path benchmark failed"
        echo "$FAST_BPF_OUT"
        echo ""
    fi
else
    echo "--- Skipping xdp2-flow-ebpf fast-path benchmark (no $FAST_BPF_OBJ found) ---"
    echo ""
fi

# ─── Format matrix table ───
echo "================================================================="
echo "              6-Way Performance Comparison Matrix"
echo "================================================================="
echo ""
printf "%-24s | %-24s | %-24s\n" "" "Non-BPF (userspace)" "BPF (in-kernel)"
printf "%-24s-+-%-24s-+-%-24s\n" "------------------------" "------------------------" "------------------------"
printf "%-24s | %-24s | %-24s\n" "Kernel flowdis" "$FLOWDIS_NSPKT, $FLOWDIS_MPPS" "$BPF_NSPKT, $BPF_MPPS"
printf "%-24s | %-24s | %-24s\n" "XDP2 parser" "$XDP2_NSPKT, $XDP2_MPPS" "$XDP2_BPF_NSPKT, $XDP2_BPF_MPPS"
printf "%-24s | %-24s | %-24s\n" "XDP2 parse-only" "$XDP2_PO_NSPKT, $XDP2_PO_MPPS" ""
printf "%-24s | %-24s | %-24s\n" "xdp2-flow-ebpf fast" "" "$FAST_BPF_NSPKT, $FAST_BPF_MPPS"
echo ""
echo "Notes:"
echo "  - Non-BPF: clock_gettime(CLOCK_MONOTONIC_RAW) around userspace loops"
echo "  - BPF: BPF_PROG_TEST_RUN with repeat=$BPF_REPEAT, kernel reports avg ns"
echo "  - Numbers across columns are not directly comparable (different contexts)"
echo ""
