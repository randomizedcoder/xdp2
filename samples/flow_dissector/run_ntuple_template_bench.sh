#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Live X710 Flow Director + AF_XDP + template-extraction benchmark.
#
# Orchestrates a two-host run from a dev box:
#
#   1. Verify the TARGET host has the expected Flow Director ntuple
#      rules installed (ethtool -n), plus nginx active.
#   2. On the PEER, spin up traffic generators (wrk2 against TCP/443,
#      a long-lived ssh -N for TCP/22).
#   3. On the TARGET, run `xdp2-bench --mode af-xdp-template` binding
#      one AF_XDP socket per matched RX queue. Captures the per-queue
#      ns/pkt + Mpps report.
#   4. Collect the report back to the dev box under
#      perf-results/${TARGET}/ntuple-template-bench-${ts}/.
#
# This measures the "pure parser" path: NIC classifies, AF_XDP delivers,
# we call extract_by_id directly — no software select_template_id. See
# docs/ntuple-template-bench.md for the full rationale and caveats
# (wrk traffic lands on an AF_XDP-bound queue and therefore bypasses
# nginx entirely; nginx is just the handshake listener).

set -euo pipefail

DURATION=30
INTERFACE="enp1s0f0np0"
DPORT_SSH=22
DPORT_HTTPS=443
QUEUE_SSH=1
QUEUE_HTTPS=2
TEMPLATE_SSH="eth-ipv4-tcp"
TEMPLATE_HTTPS="eth-ipv4-tcp"
WRK_RATE=200000
WRK_THREADS=4
WRK_CONNS=200
CORE_PIN=""

# Path to af_xdp_parser.xdp.o on the local dev box. The nix wrapper
# (nix/ntuple-template-bench.nix) passes this in via XDP_OBJ. If unset,
# we try a few well-known locations before bailing.
XDP_OBJ="${XDP_OBJ:-}"
# Remote scratch path where we drop the object on the target. bpffs
# pin path the XDP program's xsks_map lands at after iproute2 loads
# it (iproute2 uses /sys/fs/bpf/xdp/globals/<mapname> for PIN_GLOBAL_NS).
XDP_OBJ_REMOTE="/tmp/xdp2-af-xdp-parser.xdp.o"
# With modern LIBBPF_PIN_BY_NAME, the xsks_map pins at
# /sys/fs/bpf/<mapname> — which is exactly xdp2-bench's
# DEFAULT_XSKMAP_PATH. iproute2 may still drop it under
# /sys/fs/bpf/xdp/globals/ for backwards compat; handle both.
XSKS_MAP_EXPECTED="/sys/fs/bpf/xsks_map"
XSKS_MAP_LEGACY="/sys/fs/bpf/xdp/globals/xsks_map"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS] <target_host> <peer_host>

Runs the live Flow Director + AF_XDP + template bench. Both hosts must
be SSH-reachable as root. TARGET must have the xdp2-bench binary on
PATH (or at ~/xdp2/xdp2-rs/target/release/xdp2-bench) and the
xdp2.testbed module configured with flowDirectorRules and
realServicesBench = true.

Required positional args:
  <target_host>   Host binding AF_XDP / running xdp2-bench (e.g. hp5).
  <peer_host>     Host driving traffic with wrk2 + ssh -N (e.g. hp2).

Options:
  -d <secs>       Bench duration                      (default: $DURATION)
  -i <ifc>        NIC name on target                  (default: $INTERFACE)
  -c <N>          Pin xdp2-bench to CPU starting at N (default: unset)
  -r <rate>       wrk2 requests/sec                   (default: $WRK_RATE)
  -t <N>          wrk2 threads                        (default: $WRK_THREADS)
  -C <N>          wrk2 concurrent connections         (default: $WRK_CONNS)
  -h              This help.

Queue / port / template mapping is wired from the testbed module's
flowDirectorRules; the defaults here assume:
   TCP/22 -> queue $QUEUE_SSH ($TEMPLATE_SSH)
  TCP/443 -> queue $QUEUE_HTTPS ($TEMPLATE_HTTPS)
Override with env vars QUEUE_SSH / QUEUE_HTTPS / TEMPLATE_SSH /
TEMPLATE_HTTPS / DPORT_SSH / DPORT_HTTPS if your rule set differs.
EOF
    exit 1
}

while getopts "d:i:c:r:t:C:h" opt; do
    case $opt in
        d) DURATION="$OPTARG" ;;
        i) INTERFACE="$OPTARG" ;;
        c) CORE_PIN="$OPTARG" ;;
        r) WRK_RATE="$OPTARG" ;;
        t) WRK_THREADS="$OPTARG" ;;
        C) WRK_CONNS="$OPTARG" ;;
        h|*) usage ;;
    esac
done
shift $((OPTIND - 1))

[[ $# -eq 2 ]] || usage
TARGET="$1"
PEER="$2"

ts=$(date +%Y%m%dT%H%M%S)
RESULT_DIR="${RESULT_DIR:-perf-results/${TARGET}/ntuple-template-bench-${ts}}"
mkdir -p "$RESULT_DIR"

echo "=== Live Ntuple + AF_XDP + Template Bench ==="
echo "Target:      $TARGET (runs xdp2-bench on $INTERFACE)"
echo "Peer:        $PEER (runs wrk2 + ssh -N)"
echo "Duration:    ${DURATION}s"
echo "Rules:       TCP/$DPORT_SSH -> q$QUEUE_SSH ($TEMPLATE_SSH), TCP/$DPORT_HTTPS -> q$QUEUE_HTTPS ($TEMPLATE_HTTPS)"
echo "Result dir:  $RESULT_DIR"
echo ""

# ─── Pre-flight ────────────────────────────────────────────────
echo "--- Pre-flight: Flow Director rules on $TARGET ---"
NTUPLE_OUT=$(ssh -o StrictHostKeyChecking=no "root@$TARGET" "ethtool -n '$INTERFACE' 2>&1" || true)
echo "$NTUPLE_OUT" | tee "$RESULT_DIR/ntuple-rules.txt"
for dp in "$DPORT_SSH" "$DPORT_HTTPS"; do
    if ! echo "$NTUPLE_OUT" | grep -q "Dest port: $dp"; then
        echo "ERROR: Flow Director rule for TCP/$dp not present on $TARGET:$INTERFACE." >&2
        echo "       Ensure xdp2.testbed.flowDirectorRules includes this dport"  >&2
        echo "       and run \`sudo nixos-rebuild switch\`."                      >&2
        exit 2
    fi
done

echo ""
echo "--- Pre-flight: nginx on $TARGET ---"
NGINX_STATUS=$(ssh "root@$TARGET" 'systemctl is-active nginx || true')
echo "nginx: $NGINX_STATUS"
if [[ "$NGINX_STATUS" != "active" ]]; then
    echo "ERROR: nginx is not active on $TARGET."                         >&2
    echo "       Set xdp2.testbed.realServicesBench = true and rebuild." >&2
    exit 3
fi

echo ""
echo "--- Pre-flight: xdp2-bench on $TARGET ---"
BENCH_PATH=$(ssh "root@$TARGET" \
    'command -v xdp2-bench 2>/dev/null || ls ~/xdp2/xdp2-rs/target/release/xdp2-bench 2>/dev/null || true')
if [[ -z "$BENCH_PATH" ]]; then
    echo "ERROR: xdp2-bench not found on $TARGET." >&2
    echo "       Build with: cd ~/xdp2/xdp2-rs && cargo build --release -p xdp2-bench" >&2
    exit 4
fi
echo "xdp2-bench: $BENCH_PATH"
echo ""

# ─── Pre-flight: locate af_xdp_parser.xdp.o and stage it on target ───
echo "--- Pre-flight: af_xdp_parser.xdp.o ---"
if [[ -z "$XDP_OBJ" ]]; then
    for candidate in \
        "$(dirname "$0")/../../result/lib/xdp/af_xdp_parser.xdp.o" \
        "./result/lib/xdp/af_xdp_parser.xdp.o"; do
        if [[ -f "$candidate" ]]; then
            XDP_OBJ="$(readlink -f "$candidate")"
            break
        fi
    done
fi
if [[ -z "$XDP_OBJ" || ! -f "$XDP_OBJ" ]]; then
    echo "ERROR: af_xdp_parser.xdp.o not found." >&2
    echo "  Build with: nix build .#xdp-samples"  >&2
    echo "  Or set XDP_OBJ=/path/to/af_xdp_parser.xdp.o" >&2
    exit 6
fi
echo "Local XDP object: $XDP_OBJ"
echo "Staging to $TARGET:$XDP_OBJ_REMOTE ..."
scp -q -o StrictHostKeyChecking=no "$XDP_OBJ" "root@$TARGET:$XDP_OBJ_REMOTE"

# Trap-driven cleanup: always detach + remove pins, even if the bench
# or any later step fails. Without this, the interface stays in XDP
# mode and the next run fails "device or resource busy".
cleanup_xdp() {
    ssh "root@$TARGET" "
        ip link set dev '$INTERFACE' xdpgeneric off 2>/dev/null || true
        ip link set dev '$INTERFACE' xdp off 2>/dev/null || true
        rm -f '$XSKS_MAP_EXPECTED' 2>/dev/null || true
        rm -f /sys/fs/bpf/xdp2-af-xdp/* 2>/dev/null || true
        rmdir /sys/fs/bpf/xdp2-af-xdp 2>/dev/null || true
        rm -rf /sys/fs/bpf/xdp/globals/ 2>/dev/null || true
        rm -f '$XDP_OBJ_REMOTE' 2>/dev/null || true
    " || true
}
trap cleanup_xdp EXIT

echo "Loading XDP program on $TARGET:$INTERFACE ..."
ssh "root@$TARGET" "
    # Detach any stale XDP prog first (idempotent).
    ip link set dev '$INTERFACE' xdpgeneric off 2>/dev/null || true
    ip link set dev '$INTERFACE' xdp off 2>/dev/null || true
    rm -f '$XSKS_MAP_EXPECTED' 2>/dev/null || true
    rm -f '$XSKS_MAP_LEGACY' 2>/dev/null || true
    rm -f /sys/fs/bpf/ctx_map /sys/fs/bpf/parsers /sys/fs/bpf/af_xdp_stats 2>/dev/null || true

    # Load with bpftool 'loadall' because the object has TWO XDP
    # programs (xdp_prog entry + parser_prog tail-call) both in
    # SEC(\"xdp\"). 'ip link set xdpgeneric obj ... sec xdp' would only
    # pick one and skip the other, causing maps referenced only by the
    # skipped prog (xsks_map, referenced by xdp_prog) to never be
    # created. bpftool loadall loads every program in the object.
    #
    # We don't specify 'pinmaps' -- the xsks_map has
    # LIBBPF_PIN_BY_NAME in its struct definition, so libbpf auto-pins
    # it at /sys/fs/bpf/xsks_map, which is DEFAULT_XSKMAP_PATH.
    mkdir -p /sys/fs/bpf/xdp2-af-xdp
    bpftool prog loadall '$XDP_OBJ_REMOTE' /sys/fs/bpf/xdp2-af-xdp type xdp

    # Attach the main entry program to the interface.
    ip link set dev '$INTERFACE' xdpgeneric pinned /sys/fs/bpf/xdp2-af-xdp/xdp_prog

    if [[ ! -e '$XSKS_MAP_EXPECTED' ]]; then
        echo 'ERROR: xsks_map not auto-pinned at $XSKS_MAP_EXPECTED' >&2
        ls -la /sys/fs/bpf/ /sys/fs/bpf/xdp2-af-xdp/ >&2
        exit 1
    fi
"
echo "XDP program loaded; xsks_map pinned at $XSKS_MAP_EXPECTED."
echo ""

# Figure out target IPs on the peer link (ask the target).
TARGET_IP=$(ssh "root@$TARGET" \
    "ip -4 -o addr show dev '$INTERFACE' | awk '{print \$4}' | cut -d/ -f1 | head -1")
if [[ -z "$TARGET_IP" ]]; then
    echo "ERROR: no IPv4 on $TARGET:$INTERFACE" >&2
    exit 5
fi
echo "Target IP on $INTERFACE: $TARGET_IP"
echo ""

# ─── Launch traffic on peer (background) ──────────────────────
echo "--- Launching traffic on $PEER ---"
WRK_LOG="$RESULT_DIR/wrk2.log"
SSH_LOG="$RESULT_DIR/ssh-keepalive.log"

# wrk2 against https. Insecure flag for the snake-oil cert.
ssh "root@$PEER" \
    "nohup wrk2 -t$WRK_THREADS -c$WRK_CONNS -d$((DURATION + 5))s -R$WRK_RATE https://$TARGET_IP/ \
       >/tmp/wrk2.log 2>&1 &" </dev/null
# A handful of SSH packets on TCP/22 to keep queue $QUEUE_SSH warm.
# '-N' = no remote command; 'sleep' keeps the session alive.
ssh "root@$PEER" \
    "nohup ssh -o StrictHostKeyChecking=no -N root@$TARGET \
       >/tmp/ssh-keepalive.log 2>&1 &
     sleep 0.1; echo ssh-keepalive started" </dev/null

echo "wrk2 + ssh keepalive started on $PEER; warming up 2s..."
sleep 2

# ─── Run xdp2-bench on target ─────────────────────────────────
echo ""
echo "--- Running xdp2-bench on $TARGET (${DURATION}s) ---"
BENCH_ARGS="--mode af-xdp-template --interface $INTERFACE --duration $DURATION"
BENCH_ARGS="$BENCH_ARGS --queue-template $QUEUE_SSH=$TEMPLATE_SSH"
BENCH_ARGS="$BENCH_ARGS --queue-template $QUEUE_HTTPS=$TEMPLATE_HTTPS"
[[ -n "$CORE_PIN" ]] && BENCH_ARGS="$BENCH_ARGS --core-pin $CORE_PIN"

BENCH_OUT="$RESULT_DIR/xdp2-bench-af-xdp-template.txt"
ssh "root@$TARGET" "$BENCH_PATH $BENCH_ARGS" 2>&1 | tee "$BENCH_OUT"

# ─── Clean up peer processes ──────────────────────────────────
echo ""
echo "--- Cleaning up traffic on $PEER ---"
ssh "root@$PEER" 'pkill -f "wrk2.*'"$TARGET_IP"'" 2>/dev/null || true; pkill -f "ssh -N root@'"$TARGET"'" 2>/dev/null || true'
ssh "root@$PEER" "cat /tmp/wrk2.log" > "$WRK_LOG" 2>/dev/null || true
ssh "root@$PEER" "cat /tmp/ssh-keepalive.log" > "$SSH_LOG" 2>/dev/null || true

# XDP detach happens via the EXIT trap (cleanup_xdp).

# ─── Summary ──────────────────────────────────────────────────
echo ""
echo "=================================================================="
echo "          Live Ntuple + AF_XDP + Template Bench Summary"
echo "=================================================================="
grep -E "queue|---|^[0-9]" "$BENCH_OUT" 2>/dev/null | tail -20 || \
    echo "(no per-queue table in output — check $BENCH_OUT)"
echo ""
echo "Artifacts saved in $RESULT_DIR:"
ls -1 "$RESULT_DIR"
echo ""
echo "Reminder: nginx handshakes on queue 0 (ephemeral ports); bulk"
echo "TCP/443 data is redirected via AF_XDP and bypasses nginx entirely."
echo "See docs/ntuple-template-bench.md for the measurement model."
