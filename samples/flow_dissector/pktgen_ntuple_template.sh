#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Kernel pktgen driver for the ntuple+template bench.
#
# Runs on the PEER host (the traffic source). Configures kernel pktgen
# via /proc/net/pktgen/ to blast synthetic UDP packets at the TARGET,
# at a rate the NIC can sustain. The TARGET's X710 Flow Director rules
# steer each flow to a specific RX queue where xdp2-bench consumes
# them via AF_XDP + template extraction.
#
# Why pktgen and not wrk2/iperf3/scapy:
#   - Kernel pktgen bypasses socket syscalls entirely -- it crafts
#     skbs in a kernel thread and hands them directly to the NIC
#     driver's ndo_start_xmit. Ceiling is ~line rate (10+ Mpps on
#     10G, ~30 Mpps on 40G with multiple threads).
#   - It doesn't need the target to reply. Our AF_XDP redirect
#     bypasses nginx; any TCP generator would stall waiting for
#     ACKs. pktgen sends open-loop, which is what we want.
#   - Pktgen is kernel-native UDP only -- which is fine here since
#     we're testing per-template parser throughput, not TCP state
#     machinery. Template differentiation is per (L3proto, L4proto)
#     and dport, not per TCP flag.
#
# Usage:
#   pktgen_ntuple_template.sh start <iface> <dst_ip> <dst_mac> \
#       [--dport 443] [--pkt-size 1400] [--threads 2] [--rate 0]
#   pktgen_ntuple_template.sh stop
#   pktgen_ntuple_template.sh status
#
# `--rate 0` means "as fast as possible" (default). For a rate-limited
# run set --rate <pps>; pktgen implements this via per-packet delay in
# nanoseconds (delay = 1e9 / pps).

set -euo pipefail

PGCTRL=/proc/net/pktgen/pgctrl

usage() {
    sed -n '3,30p' "$0"
    exit 1
}

cmd="${1:-}"
[[ -z "$cmd" ]] && usage

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: pktgen requires root (writes to /proc/net/pktgen/)" >&2
        exit 1
    fi
}

require_pktgen() {
    if [[ ! -e "$PGCTRL" ]]; then
        modprobe pktgen 2>/dev/null || true
    fi
    if [[ ! -e "$PGCTRL" ]]; then
        echo "ERROR: pktgen module not available. modprobe pktgen failed." >&2
        exit 1
    fi
}

pg_ctrl() {
    echo "$1" > "$PGCTRL"
}

# Write a setting to a per-device pktgen control file. Each "device"
# is pktgen's abstraction for a thread-bound NIC; the name is
# "<iface>@<thread_id>" when multiple threads drive the same NIC.
pg_dev() {
    local dev="$1" setting="$2"
    echo "$setting" > "/proc/net/pktgen/$dev"
}

case "$cmd" in
    stop)
        require_root
        require_pktgen
        # pgctrl "stop" halts all running threads. rem_device_all on
        # each thread drops the device bindings so the next "start"
        # doesn't inherit stale config.
        pg_ctrl "stop" 2>/dev/null || true
        for t in /proc/net/pktgen/kpktgend_*; do
            [[ -e "$t" ]] || continue
            echo "rem_device_all" > "$t" 2>/dev/null || true
        done
        echo "pktgen stopped, all devices removed"
        exit 0
        ;;
    status)
        require_pktgen
        echo "=== pktgen control ==="
        cat "$PGCTRL" 2>/dev/null || true
        echo ""
        echo "=== threads ==="
        for t in /proc/net/pktgen/kpktgend_*; do
            [[ -e "$t" ]] || continue
            echo "--- $(basename "$t") ---"
            head -5 "$t" 2>/dev/null || true
        done
        echo ""
        echo "=== per-device counters ==="
        for d in /proc/net/pktgen/*; do
            name=$(basename "$d")
            case "$name" in
                kpktgend_*|pgctrl) continue ;;
            esac
            echo "--- $name ---"
            grep -E "Result|pkts-sofar|errors|bps|pps" "$d" 2>/dev/null | head -10 || true
        done
        exit 0
        ;;
    start)
        ;;
    *)
        usage
        ;;
esac

# start command
require_root
require_pktgen
shift  # consume "start"

[[ $# -ge 3 ]] || usage
IFACE="$1"
DST_IP="$2"
DST_MAC="$3"
shift 3

DPORT=443
PKT_SIZE=1400
THREADS=2
RATE=0
IS_IPV6=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dport)     DPORT="$2"; shift 2 ;;
        --pkt-size)  PKT_SIZE="$2"; shift 2 ;;
        --threads)   THREADS="$2"; shift 2 ;;
        --rate)      RATE="$2"; shift 2 ;;
        --ipv6)      IS_IPV6=true; shift ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done

# Compute per-packet delay in nanoseconds for rate-limiting.
# delay=0 in pktgen means "as fast as possible".
DELAY=0
if [[ "$RATE" -gt 0 ]]; then
    DELAY=$(( 1000000000 / RATE ))
fi

# Clear any previous config.
pg_ctrl "reset" 2>/dev/null || true
for t in /proc/net/pktgen/kpktgend_*; do
    [[ -e "$t" ]] || continue
    echo "rem_device_all" > "$t" 2>/dev/null || true
done

echo "=== pktgen config ==="
echo "  interface:  $IFACE"
echo "  dst:        $DST_IP (mac $DST_MAC)"
L3="IPv4"
$IS_IPV6 && L3="IPv6"
echo "  dport:      $DPORT ($L3/UDP)"
echo "  pkt_size:   $PKT_SIZE"
echo "  threads:    $THREADS"
echo "  rate:       ${RATE:-unlimited} pps (delay=${DELAY}ns)"
echo ""

# Bind N threads to the interface. Each thread handles a slice of
# the flow-hash space so we get parallel TX with proper scaling.
for ((i=0; i<THREADS; i++)); do
    thread="kpktgend_$i"
    devname="${IFACE}@${i}"
    echo "binding thread $thread -> $devname"
    echo "add_device $devname" > "/proc/net/pktgen/$thread"

    pg_dev "$devname" "count 0"           # 0 = run forever
    pg_dev "$devname" "clone_skb 100000"  # reuse skb for speed
    pg_dev "$devname" "pkt_size $PKT_SIZE"
    pg_dev "$devname" "delay $DELAY"
    pg_dev "$devname" "dst_mac $DST_MAC"

    if $IS_IPV6; then
        pg_dev "$devname" "dst6 $DST_IP"
    else
        pg_dev "$devname" "dst $DST_IP"
    fi

    # Fixed src port, fixed dst port -- FD rule steers by dport only,
    # so we want a stable dport. src port is arbitrary.
    pg_dev "$devname" "udp_src_min $((12345 + i))"
    pg_dev "$devname" "udp_src_max $((12345 + i))"
    pg_dev "$devname" "udp_dst_min $DPORT"
    pg_dev "$devname" "udp_dst_max $DPORT"

    # flag IPDST_RND would randomize dst IPs; we want a fixed dst
    # (the target NIC) so Flow Director rules match.
done

echo ""
echo "Starting pktgen... (run \"$0 stop\" to halt)"
# "start" is blocking for the duration the threads run -- but since
# count=0 means forever, we background the wait via pgctrl in a way
# that returns immediately: invoke start in a nohup background pid,
# the kernel threads run independently.
nohup bash -c "echo start > $PGCTRL" >/dev/null 2>&1 &
disown || true

sleep 0.2
echo "pktgen started on $IFACE with $THREADS threads."
echo "Monitor with: $0 status"
