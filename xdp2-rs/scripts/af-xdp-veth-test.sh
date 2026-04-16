#!/usr/bin/env bash
#
# af-xdp-veth-test.sh — Set up veth pair and test AF_XDP receive path.
#
# Creates a veth pair, loads the AF_XDP XDP program on one end,
# runs the Rust AF_XDP reader, and sends traffic from the other end.
#
# Usage:
#   sudo ./scripts/af-xdp-veth-test.sh [pcap-file] [duration]
#
# Requirements:
#   - Root (for veth, XDP, AF_XDP)
#   - Built xdp2-bench: cargo build -p xdp2-bench --release
#   - Built XDP program: make -C samples/xdp/af_xdp_parser/
#   - tcpreplay (for PCAP injection) or ping (for basic test)
#
# Example:
#   sudo ./scripts/af-xdp-veth-test.sh ../data/pcaps/tcp_ipv4.pcap 5

set -euo pipefail

PCAP="${1:-}"
DURATION="${2:-5}"
BENCH="${BENCH:-cargo run -p xdp2-bench --release --}"
XDP_OBJ="${XDP_OBJ:-samples/xdp/af_xdp_parser/af_xdp_parser.xdp.o}"

VETH_TX="xdp2-tx"
VETH_RX="xdp2-rx"
ADDR_TX="10.99.0.1/24"
ADDR_RX="10.99.0.2/24"

cleanup() {
    echo "Cleaning up..."
    ip link set dev "$VETH_RX" xdp off 2>/dev/null || true
    ip link del "$VETH_TX" 2>/dev/null || true
    echo "Done."
}

trap cleanup EXIT

echo "=== AF_XDP veth Test ==="

# Check prerequisites
if [ "$(id -u)" -ne 0 ]; then
    echo "error: this script requires root" >&2
    exit 1
fi

# Create veth pair
echo "Creating veth pair: $VETH_TX <-> $VETH_RX"
ip link add "$VETH_TX" type veth peer name "$VETH_RX"
ip link set "$VETH_TX" up
ip link set "$VETH_RX" up
ip addr add "$ADDR_TX" dev "$VETH_TX"
ip addr add "$ADDR_RX" dev "$VETH_RX"

# Load XDP program on RX side (generic mode for veth)
if [ -f "$XDP_OBJ" ]; then
    echo "Loading XDP program on $VETH_RX..."
    ip link set dev "$VETH_RX" xdpgeneric obj "$XDP_OBJ" sec xdp
    echo "XDP loaded."
else
    echo "warning: XDP program not found at $XDP_OBJ"
    echo "  Build with: make -C samples/xdp/af_xdp_parser/ XDP2DIR=\$(pwd)"
    echo "  Continuing without XDP (AF_XDP socket may not receive packets)"
fi

# Start AF_XDP reader in background
echo ""
echo "Starting AF_XDP reader on $VETH_RX for ${DURATION}s..."
$BENCH --mode af-xdp --interface "$VETH_RX" --queue 0 --duration "$DURATION" &
BENCH_PID=$!

# Give the reader a moment to bind
sleep 1

# Send traffic
echo ""
if [ -n "$PCAP" ] && command -v tcpreplay &>/dev/null; then
    echo "Replaying $PCAP on $VETH_TX..."
    tcpreplay -i "$VETH_TX" "$PCAP" 2>/dev/null || true
elif [ -n "$PCAP" ]; then
    echo "warning: tcpreplay not found, using ping instead"
    echo "Sending pings to 10.99.0.2..."
    ping -c 20 -i 0.1 10.99.0.2 > /dev/null 2>&1 || true
else
    echo "Sending pings to 10.99.0.2..."
    ping -c 20 -i 0.1 10.99.0.2 > /dev/null 2>&1 || true
fi

# Wait for reader to finish
echo ""
echo "Waiting for reader to finish..."
wait $BENCH_PID || true

echo ""
echo "=== Test Complete ==="
