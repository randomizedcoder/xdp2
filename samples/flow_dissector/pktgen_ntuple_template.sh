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

# ─── Env-overridable tunables (Deliverable 1 — pktgen TX-cap diagnosis)
#
# These default to "today's behaviour" — the baseline experiment run
# sets no env and reproduces the existing ~1.37 Mpps RX ceiling. Every
# other Deliverable-1 experiment flips exactly one of these and
# records the resulting Mpps/ns-pkt in docs/physical-testbed.md §9
# Category H. See also samples/flow_dissector/run_ntuple_template_bench.sh
# which forwards these over ssh verbatim.
#
#   PKTGEN_BURST          N per-softirq-dispatch packet count. Kernel
#                         default is 1; setting 32 amortises softirq
#                         overhead if TX is softirq-bound.
#   PKTGEN_CLONE_SKB      skb reuse factor. Default 100000 (today's
#                         hardcoded value); set 0 to force a fresh
#                         skb per packet — proves whether skb alloc
#                         or descriptor recycling dominates.
#   PKTGEN_QUEUE_MAP_MODE "none" (default) | "per-thread". per-thread
#                         sets queue_map_min/max to the thread index
#                         so threads fan out across distinct TX rings
#                         instead of colliding on the default ring.
#   PKTGEN_CPU_PIN_MODE   "none" (default) | "isolcpus-aligned". In
#                         the isolcpus-aligned mode, kpktgend binding
#                         starts at kpktgend_${PKTGEN_CPU_OFFSET:-2}
#                         instead of kpktgend_0 — skips housekeeping
#                         CPUs on hp2 where isolcpus=2-15.
#   PKTGEN_CPU_OFFSET     kpktgend starting index when CPU_PIN_MODE=
#                         isolcpus-aligned (default 2).
#   PKTGEN_RANDOMIZE_FLOWS  0 (default) | 1. When 1, every packet
#                         gets a random UDP src port in
#                         [PKTGEN_SRC_PORT_MIN, PKTGEN_SRC_PORT_MAX]
#                         via pktgen's UDPSRC_RND flag, producing
#                         thousands of distinct flow 5-tuples per
#                         second. Use for Phase G CPU-bound runs
#                         where the goal is to defeat per-flow
#                         GRO/hash-cache amortization. Default off
#                         preserves the Flow Director steering use
#                         case where a stable dport per thread is
#                         what the FD rules match on.
#   PKTGEN_SRC_PORT_MIN   low end of the randomized range (default 1024)
#   PKTGEN_SRC_PORT_MAX   high end (default 65535)
PKTGEN_BURST="${PKTGEN_BURST:-1}"
PKTGEN_CLONE_SKB="${PKTGEN_CLONE_SKB:-100000}"
PKTGEN_QUEUE_MAP_MODE="${PKTGEN_QUEUE_MAP_MODE:-none}"
PKTGEN_CPU_PIN_MODE="${PKTGEN_CPU_PIN_MODE:-none}"
PKTGEN_CPU_OFFSET="${PKTGEN_CPU_OFFSET:-2}"
PKTGEN_RANDOMIZE_FLOWS="${PKTGEN_RANDOMIZE_FLOWS:-0}"
PKTGEN_SRC_PORT_MIN="${PKTGEN_SRC_PORT_MIN:-1024}"
PKTGEN_SRC_PORT_MAX="${PKTGEN_SRC_PORT_MAX:-65535}"

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
echo "  burst:      $PKTGEN_BURST"
echo "  clone_skb:  $PKTGEN_CLONE_SKB"
echo "  queue_map:  $PKTGEN_QUEUE_MAP_MODE"
echo "  cpu_pin:    $PKTGEN_CPU_PIN_MODE (offset=$PKTGEN_CPU_OFFSET)"
echo "  rand_flows: $PKTGEN_RANDOMIZE_FLOWS (range=$PKTGEN_SRC_PORT_MIN-$PKTGEN_SRC_PORT_MAX)"
echo ""

# Bind N threads to the interface. Each thread handles a slice of
# the flow-hash space so we get parallel TX with proper scaling.
#
# kpktgend_N is a per-CPU kernel thread that the scheduler
# auto-pins to CPU N. PKTGEN_CPU_PIN_MODE=isolcpus-aligned shifts
# the thread-index base by PKTGEN_CPU_OFFSET so we land on isolated
# CPUs rather than housekeeping ones (hp2 has isolcpus=2-15).
thread_base=0
if [[ "$PKTGEN_CPU_PIN_MODE" == "isolcpus-aligned" ]]; then
    thread_base="$PKTGEN_CPU_OFFSET"
fi

for ((i=0; i<THREADS; i++)); do
    thread_idx=$((thread_base + i))
    thread="kpktgend_${thread_idx}"
    devname="${IFACE}@${i}"
    echo "binding thread $thread -> $devname"
    echo "add_device $devname" > "/proc/net/pktgen/$thread"

    pg_dev "$devname" "count 0"                      # 0 = run forever
    pg_dev "$devname" "clone_skb $PKTGEN_CLONE_SKB"  # 0 disables reuse
    pg_dev "$devname" "pkt_size $PKT_SIZE"
    pg_dev "$devname" "delay $DELAY"
    pg_dev "$devname" "dst_mac $DST_MAC"

    # burst > 1 amortises softirq overhead; default 1 = today's
    # behaviour (one packet per softirq wake).
    if [[ "$PKTGEN_BURST" -gt 1 ]]; then
        pg_dev "$devname" "burst $PKTGEN_BURST"
    fi

    if $IS_IPV6; then
        pg_dev "$devname" "dst6 $DST_IP"
    else
        pg_dev "$devname" "dst $DST_IP"
    fi

    # Default: fixed src port, fixed dst port -- FD rule steers by dport
    # only, so we want a stable dport. src port is arbitrary.
    # PKTGEN_RANDOMIZE_FLOWS=1 widens the src-port range and sets
    # UDPSRC_RND so every packet picks a new src port — produces
    # thousands of distinct 5-tuples per second, which is what we
    # want for CPU-bound flow_dissect benchmarking (Phase G).
    if [[ "$PKTGEN_RANDOMIZE_FLOWS" == "1" ]]; then
        pg_dev "$devname" "udp_src_min $PKTGEN_SRC_PORT_MIN"
        pg_dev "$devname" "udp_src_max $PKTGEN_SRC_PORT_MAX"
        pg_dev "$devname" "flag UDPSRC_RND"
    else
        pg_dev "$devname" "udp_src_min $((12345 + i))"
        pg_dev "$devname" "udp_src_max $((12345 + i))"
    fi
    pg_dev "$devname" "udp_dst_min $DPORT"
    pg_dev "$devname" "udp_dst_max $DPORT"

    # per-thread TX queue pinning — without this, threads may
    # collide on the NIC's default TX ring. With PKTGEN_QUEUE_MAP_MODE=
    # per-thread, thread i writes to NIC TX queue i (0..THREADS-1).
    if [[ "$PKTGEN_QUEUE_MAP_MODE" == "per-thread" ]]; then
        pg_dev "$devname" "queue_map_min $i"
        pg_dev "$devname" "queue_map_max $i"
    fi

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
