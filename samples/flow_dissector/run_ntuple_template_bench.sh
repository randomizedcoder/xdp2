#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Live X710 Flow Director + AF_XDP + template-extraction benchmark.
#
# Orchestrates a two-host run from a dev box:
#
#   1. Verify the TARGET host has the expected Flow Director ntuple
#      rule installed (ethtool -n): UDP/$DPORT -> queue $QUEUE.
#   2. Load the XDP parser object on the TARGET and attach it so
#      xsks_map auto-pins at /sys/fs/bpf/xsks_map.
#   3. On the PEER, start kernel pktgen blasting open-loop UDP at
#      the target's IP/MAC with dport=$DPORT. No TCP handshake, no
#      ACKs -- pktgen drives the NIC directly from a kernel thread.
#   4. On the TARGET, run `xdp2-bench --mode af-xdp-template` binding
#      one AF_XDP socket per matched RX queue and dispatching through
#      the matching template with zero software classification.
#   5. Stop pktgen; collect the report back to the dev box under
#      perf-results/${TARGET}/ntuple-template-bench-${ts}/.
#
# This measures the "pure parser" path: NIC classifies, AF_XDP delivers,
# we call extract_by_id directly — no software select_template_id. See
# docs/ntuple-template-bench.md for the full rationale and caveats.

set -euo pipefail

DURATION=30
INTERFACE="enp1s0f0np0"
# Single-queue / single-template bench (Option 1). FD rule on the target
# steers UDP/443 to queue 1; xdp2-bench binds AF_XDP there and dispatches
# through eth-ipv4-udp template with zero software classification.
DPORT=443
QUEUE=1
TEMPLATE="eth-ipv4-udp"
# pktgen (kernel) on the peer. Blasts open-loop UDP at ~line rate; no
# ACKs needed (that's why we ditched wrk2 -- it stalled when bulk data
# got redirected away from nginx).
PKTGEN_PKT_SIZE=1400
PKTGEN_THREADS=2
PKTGEN_RATE=0   # 0 = unlimited (as fast as the thread can push)
CORE_PIN=""
# AF_XDP fast-path tunables. Defaults assume native XDP attach succeeds
# (i40e/X710 supports it). Override via env vars to A/B test.
#   ZEROCOPY=1     — XDP_ZEROCOPY: kernel hands RX descs straight into
#                    UMEM. No copy. Only works with native XDP attach;
#                    if attach falls back to xdpgeneric this flag is
#                    ignored by the kernel.
#   NEED_WAKEUP=1  — XDP_USE_NEED_WAKEUP: app polls fill ring only when
#                    kernel signals; cuts unconditional sendto() syscalls.
#   BUSY_POLL_US=50 — kernel busy-poll timeout. Beats the default
#                    poll(10ms) latency for low-rate streams.
ZEROCOPY="${ZEROCOPY:-1}"
NEED_WAKEUP="${NEED_WAKEUP:-1}"
BUSY_POLL_US="${BUSY_POLL_US:-50}"
# Deliverable-3 AF_XDP ring/UMEM sizing overrides. Each defaults to
# empty ("use xdp2-af-xdp crate defaults: rx=2048/fill=2048/frames=4096").
# Set nonempty to pass --rx-ring-size / --fill-ring-size / --frame-count
# through to xdp2-bench — the RX-drop diagnosis in docs/physical-testbed.md
# §13 hypothesises that the default fill ring (2048) is too tight at
# ≥1.37 Mpps + busy-poll to absorb momentary stalls. A paired experiment
# sets RX_RING=4096 FILL_RING=4096 FRAME_COUNT=16384 to test it.
RX_RING="${RX_RING:-}"
FILL_RING="${FILL_RING:-}"
FRAME_COUNT="${FRAME_COUNT:-}"

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

# Peer-side pktgen driver. Always set by the nix wrapper
# (nix/ntuple-template-bench.nix exports PKTGEN_SCRIPT to the
# writeShellApplication-packaged driver in the nix store). When
# run outside of `nix run`, the caller must export it explicitly.
PKTGEN_SCRIPT="${PKTGEN_SCRIPT:?PKTGEN_SCRIPT must be set; run via \`nix run .#flow-dissector-ntuple-template-bench\` or export it manually}"
PKTGEN_SCRIPT_REMOTE="/tmp/xdp2-pktgen-ntuple-template.sh"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS] <target_host> <peer_host>

Runs the live Flow Director + AF_XDP + template bench. Both hosts must
be SSH-reachable as root. TARGET must have the xdp2-bench binary on
PATH (or at ~/xdp2/xdp2-rs/target/release/xdp2-bench) and the
xdp2.testbed module configured with flowDirectorRules steering
UDP/$DPORT -> queue $QUEUE.

Required positional args:
  <target_host>   Host binding AF_XDP / running xdp2-bench (e.g. hp5).
  <peer_host>     Host running kernel pktgen as traffic source (e.g. hp2).

Options:
  -d <secs>       Bench duration                       (default: $DURATION)
  -i <ifc>        NIC name on target + peer            (default: $INTERFACE)
  -c <N>          Pin xdp2-bench to CPU starting at N  (default: unset)
  -s <bytes>      pktgen pkt_size                      (default: $PKTGEN_PKT_SIZE)
  -t <N>          pktgen TX threads                    (default: $PKTGEN_THREADS)
  -r <pps>        pktgen rate limit (0 = unlimited)    (default: $PKTGEN_RATE)
  -h              This help.

Defaults: UDP/$DPORT -> queue $QUEUE (template: $TEMPLATE).
Override via env vars DPORT / QUEUE / TEMPLATE if your rule set differs.
EOF
    exit 1
}

while getopts "d:i:c:s:t:r:h" opt; do
    case $opt in
        d) DURATION="$OPTARG" ;;
        i) INTERFACE="$OPTARG" ;;
        c) CORE_PIN="$OPTARG" ;;
        s) PKTGEN_PKT_SIZE="$OPTARG" ;;
        t) PKTGEN_THREADS="$OPTARG" ;;
        r) PKTGEN_RATE="$OPTARG" ;;
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
echo "Peer:        $PEER (runs kernel pktgen)"
echo "Duration:    ${DURATION}s"
echo "Rule:        UDP/$DPORT -> q$QUEUE ($TEMPLATE)"
echo "Result dir:  $RESULT_DIR"
echo ""

# ─── Pre-flight ────────────────────────────────────────────────
echo "--- Pre-flight: Flow Director rules on $TARGET ---"
# Pass $INTERFACE as a separate argv to ssh so it's expanded on the
# dev box (intentional) without embedding in a quoted command string
# that would trip SC2029. ssh concatenates argv[2..] with spaces and
# ships it as the remote command.
NTUPLE_OUT=$(ssh -o StrictHostKeyChecking=no "root@$TARGET" \
    ethtool -n "$INTERFACE" 2>&1 || true)
echo "$NTUPLE_OUT" | tee "$RESULT_DIR/ntuple-rules.txt"
# Walk the ethtool output filter-by-filter and check that there is a
# UDP-over-IPv4 rule whose Dest port matches $DPORT. Grepping the
# raw output for "Dest port: $DPORT" false-matches on any other
# protocol's rule with the same port number.
if ! awk -v dport="$DPORT" '
    /^Filter:/        { rt=""; dp=""; next }
    /Rule Type:/      { rt=$0; next }
    /Dest port:/      { dp=$3; if (rt ~ /UDP over IPv4/ && dp == dport) { found=1; exit } }
    END               { exit !found }
  ' <<< "$NTUPLE_OUT"; then
    echo "ERROR: No Flow Director rule on $TARGET:$INTERFACE steers UDP/$DPORT." >&2
    echo "       Need: flow-type udp4 dst-port $DPORT action $QUEUE"             >&2
    echo "       Add via \`ethtool -N $INTERFACE flow-type udp4 dst-port $DPORT action $QUEUE\`" >&2
    echo "       or set xdp2.testbed.flowDirectorRules + nixos-rebuild."          >&2
    exit 2
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

# Trap-driven cleanup: always detach + remove pins + stop pktgen,
# even if the bench or any later step fails. Without this, the
# interface stays in XDP mode and the next run fails "device or
# resource busy", and pktgen keeps blasting the peer's NIC.
#
# Two separate functions composed under one trap so we don't have
# to string-splice prior traps (which trips shellcheck SC2064).
# cleanup_peer is safe to call before pktgen is staged; `|| true`
# handles the not-yet-started case.
PKTGEN_STARTED=0
# All remote command blocks below use the same pattern:
#   ssh host bash -s -- "$arg1" "$arg2" ... <<'REMOTE_EOF'
#       ... remote script referencing "$1" "$2" ... ...
#   REMOTE_EOF
# The single-quoted heredoc prevents client-side interpolation (no
# SC2029), and positional args carry the dev-box values we want the
# remote shell to see. `bash -s` reads the heredoc from stdin.
cleanup_peer() {
    if [[ "$PKTGEN_STARTED" -eq 1 ]]; then
        ssh "root@$PEER" bash -s -- "$PKTGEN_SCRIPT_REMOTE" <<'REMOTE_EOF' || true
bash "$1" stop 2>/dev/null || true
REMOTE_EOF
    fi
}
cleanup_xdp() {
    ssh "root@$TARGET" bash -s -- \
        "$INTERFACE" "$XSKS_MAP_EXPECTED" "$XDP_OBJ_REMOTE" <<'REMOTE_EOF' || true
iface=$1
xsks=$2
xdp_obj=$3
ip link set dev "$iface" xdpgeneric off 2>/dev/null || true
ip link set dev "$iface" xdpdrv off 2>/dev/null || true
ip link set dev "$iface" xdp off 2>/dev/null || true
rm -f "$xsks" 2>/dev/null || true
rm -f /sys/fs/bpf/xdp2-af-xdp/* 2>/dev/null || true
rmdir /sys/fs/bpf/xdp2-af-xdp 2>/dev/null || true
rm -rf /sys/fs/bpf/xdp/globals/ 2>/dev/null || true
rm -f "$xdp_obj" 2>/dev/null || true
REMOTE_EOF
}
cleanup_all() {
    cleanup_peer
    cleanup_xdp
}
trap cleanup_all EXIT

echo "Loading XDP program on $TARGET:$INTERFACE ..."
# Note on comments inside the heredoc: they use backticks-free plain
# text because the heredoc is single-quoted — no client-side expansion,
# no SC2029. The remote shell's `bash -s` reads this verbatim.
ssh "root@$TARGET" bash -s -- \
    "$INTERFACE" "$XSKS_MAP_EXPECTED" "$XSKS_MAP_LEGACY" "$XDP_OBJ_REMOTE" <<'REMOTE_EOF'
set -eu
iface=$1
xsks=$2
xsks_legacy=$3
xdp_obj=$4

# Detach any stale XDP prog first (idempotent).
ip link set dev "$iface" xdpgeneric off 2>/dev/null || true
ip link set dev "$iface" xdpdrv off 2>/dev/null || true
ip link set dev "$iface" xdp off 2>/dev/null || true
rm -f "$xsks" 2>/dev/null || true
rm -f "$xsks_legacy" 2>/dev/null || true
rm -f /sys/fs/bpf/ctx_map /sys/fs/bpf/parsers /sys/fs/bpf/af_xdp_stats 2>/dev/null || true

# Load with bpftool 'loadall' because the object has TWO XDP
# programs (xdp_prog entry + parser_prog tail-call) both in
# SEC("xdp"). 'ip link set xdpgeneric obj ... sec xdp' would only
# pick one and skip the other, causing maps referenced only by the
# skipped prog (xsks_map, referenced by xdp_prog) to never be
# created. bpftool loadall loads every program in the object.
#
# We don't specify 'pinmaps' -- the xsks_map has
# LIBBPF_PIN_BY_NAME in its struct definition, so libbpf auto-pins
# it at /sys/fs/bpf/xsks_map, which is DEFAULT_XSKMAP_PATH.
mkdir -p /sys/fs/bpf/xdp2-af-xdp
bpftool prog loadall "$xdp_obj" /sys/fs/bpf/xdp2-af-xdp type xdp

# Attach the main entry program. Try native (xdpdrv) first — on i40e/X710
# this is the only path that can hit line-rate; xdpgeneric is the SKB-mode
# fallback that copies every packet through the kernel softirq path and
# costs ~1500 ns/pkt overhead. If native attach fails (driver doesn't
# implement ndo_bpf, or kernel/firmware mismatch), fall back to xdpgeneric
# so the bench still produces a number rather than aborting.
if ip link set dev "$iface" xdpdrv pinned /sys/fs/bpf/xdp2-af-xdp/xdp_prog 2>/dev/null; then
    echo "XDP_MODE=xdpdrv (native — i40e ndo_bpf path)"
else
    echo "XDP_MODE=xdpgeneric (FALLBACK — native attach failed)" >&2
    ip link set dev "$iface" xdpgeneric pinned /sys/fs/bpf/xdp2-af-xdp/xdp_prog
fi

if [[ ! -e "$xsks" ]]; then
    echo "ERROR: xsks_map not auto-pinned at $xsks" >&2
    ls -la /sys/fs/bpf/ /sys/fs/bpf/xdp2-af-xdp/ >&2
    exit 1
fi
REMOTE_EOF
echo "XDP program loaded; xsks_map pinned at $XSKS_MAP_EXPECTED."
# Post-attach verification: print the live XDP mode flag from `ip link
# show`. Native attach reports `xdp/id N` (no `generic` prefix);
# xdpgeneric reports `xdpgeneric`. If we asked for native and got
# generic, --zero-copy will silently fail at bind time.
echo "--- Live XDP attach mode on $TARGET:$INTERFACE ---"
ssh "root@$TARGET" bash -s -- "$INTERFACE" <<'REMOTE_EOF'
ip link show "$1" | grep -oE 'xdp(generic|drv)?[^ ]*' | head -1 || echo "no xdp prog attached"
REMOTE_EOF
echo ""

# Figure out target IP + MAC on the peer link (ask the target). pktgen
# needs both: dst IP goes in the L3 header, dst MAC in L2 (pktgen
# doesn't ARP — we feed it the MAC directly).
TARGET_IP=$(ssh "root@$TARGET" bash -s -- "$INTERFACE" <<'REMOTE_EOF'
ip -4 -o addr show dev "$1" | awk '{print $4}' | cut -d/ -f1 | head -1
REMOTE_EOF
)
if [[ -z "$TARGET_IP" ]]; then
    echo "ERROR: no IPv4 on $TARGET:$INTERFACE" >&2
    exit 5
fi
TARGET_MAC=$(ssh "root@$TARGET" bash -s -- "$INTERFACE" <<'REMOTE_EOF'
cat /sys/class/net/"$1"/address
REMOTE_EOF
)
if [[ -z "$TARGET_MAC" ]]; then
    echo "ERROR: no MAC for $TARGET:$INTERFACE" >&2
    exit 5
fi
echo "Target IP/MAC on $INTERFACE: $TARGET_IP / $TARGET_MAC"
echo ""

# ─── Stage pktgen driver on peer ──────────────────────────────
echo "--- Staging pktgen driver on $PEER ---"
if [[ ! -f "$PKTGEN_SCRIPT" ]]; then
    echo "ERROR: pktgen driver not found at $PKTGEN_SCRIPT" >&2
    exit 8
fi
scp -q -o StrictHostKeyChecking=no "$PKTGEN_SCRIPT" "root@$PEER:$PKTGEN_SCRIPT_REMOTE"
ssh "root@$PEER" bash -s -- "$PKTGEN_SCRIPT_REMOTE" <<'REMOTE_EOF'
chmod +x "$1"
REMOTE_EOF

# ─── Launch traffic on peer ───────────────────────────────────
echo ""
echo "--- Launching kernel pktgen on $PEER ---"
PKTGEN_LOG="$RESULT_DIR/pktgen-start.log"
# Deliverable-1 env tunables for the peer-side pktgen driver. Each
# defaults to "today's behaviour"; experiment wrappers
# (nix/lib/mkBenchExperiment.nix) set exactly one at a time.
# Forwarded to the peer inside the heredoc so the remote bash sees
# them at the top of its environment before execing the pktgen
# script. Client-side interpolation is intentional here — we need
# the LOCAL env values to land on the REMOTE shell — so this is one
# of the rare places we use an unquoted heredoc delimiter. `\$@` is
# escaped to defer expansion to the remote bash.
PKTGEN_BURST="${PKTGEN_BURST:-1}"
PKTGEN_CLONE_SKB="${PKTGEN_CLONE_SKB:-100000}"
PKTGEN_QUEUE_MAP_MODE="${PKTGEN_QUEUE_MAP_MODE:-none}"
PKTGEN_CPU_PIN_MODE="${PKTGEN_CPU_PIN_MODE:-none}"
PKTGEN_CPU_OFFSET="${PKTGEN_CPU_OFFSET:-2}"
# shellcheck disable=SC2087
ssh "root@$PEER" bash -s -- \
    "$PKTGEN_SCRIPT_REMOTE" start "$INTERFACE" "$TARGET_IP" "$TARGET_MAC" \
    --dport "$DPORT" --pkt-size "$PKTGEN_PKT_SIZE" \
    --threads "$PKTGEN_THREADS" --rate "$PKTGEN_RATE" \
    <<REMOTE_EOF 2>&1 | tee "$PKTGEN_LOG"
export PKTGEN_BURST="$PKTGEN_BURST"
export PKTGEN_CLONE_SKB="$PKTGEN_CLONE_SKB"
export PKTGEN_QUEUE_MAP_MODE="$PKTGEN_QUEUE_MAP_MODE"
export PKTGEN_CPU_PIN_MODE="$PKTGEN_CPU_PIN_MODE"
export PKTGEN_CPU_OFFSET="$PKTGEN_CPU_OFFSET"
exec bash "\$@"
REMOTE_EOF
PKTGEN_STARTED=1

echo "pktgen running on $PEER; warming up 2s..."
sleep 2

# ─── Run xdp2-bench on target ─────────────────────────────────
echo ""
echo "--- Running xdp2-bench on $TARGET (${DURATION}s) ---"
# Build as a bash array so the flags pass through to ssh as separate
# argv items. No shell-command string means no SC2029 concern.
BENCH_ARGS=(--mode af-xdp-template --interface "$INTERFACE" --duration "$DURATION")
BENCH_ARGS+=(--queue-template "$QUEUE=$TEMPLATE")
[[ -n "$CORE_PIN" ]] && BENCH_ARGS+=(--core-pin "$CORE_PIN")
# Without --zero-copy / --need-wakeup / --busy-poll the bench runs
# pure interrupt + copy mode AF_XDP, which caps at <1 Mpps on this
# NIC regardless of XDP attach mode (validated 2026-04-24).
[[ "$ZEROCOPY"    -eq 1 ]] && BENCH_ARGS+=(--zero-copy)
[[ "$NEED_WAKEUP" -eq 1 ]] && BENCH_ARGS+=(--need-wakeup)
[[ "$BUSY_POLL_US" -gt 0 ]] && BENCH_ARGS+=(--busy-poll "$BUSY_POLL_US")
# Deliverable-3 ring/frame overrides (only appended when caller set the
# env var). Leaving them unset preserves today's behaviour — the bench
# falls back to the xdp2-af-xdp crate defaults, so baseline experiments
# stay comparable to pre-C6 runs.
[[ -n "$RX_RING"     ]] && BENCH_ARGS+=(--rx-ring-size   "$RX_RING")
[[ -n "$FILL_RING"   ]] && BENCH_ARGS+=(--fill-ring-size "$FILL_RING")
[[ -n "$FRAME_COUNT" ]] && BENCH_ARGS+=(--frame-count    "$FRAME_COUNT")

BENCH_OUT="$RESULT_DIR/xdp2-bench-af-xdp-template.txt"
# Ship BENCH_PATH + BENCH_ARGS through a single-quoted heredoc so the
# remote shell re-executes argv verbatim — no client-side interpolation.
ssh "root@$TARGET" bash -s -- "$BENCH_PATH" "${BENCH_ARGS[@]}" \
    <<'REMOTE_EOF' 2>&1 | tee "$BENCH_OUT"
exec "$@"
REMOTE_EOF

# ─── Capture final peer counters (stop + detach run via EXIT trap) ─
echo ""
echo "--- Capturing pktgen final counters on $PEER ---"
ssh "root@$PEER" bash -s -- "$PKTGEN_SCRIPT_REMOTE" <<'REMOTE_EOF' \
    > "$RESULT_DIR/pktgen-final-status.log" 2>&1 || true
bash "$1" status 2>/dev/null || true
REMOTE_EOF

# pktgen stop + XDP detach both happen in cleanup_all (EXIT trap).

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
echo "Reminder: pktgen is open-loop UDP — no handshakes, no ACKs. The"
echo "Flow Director rule (UDP/$DPORT -> q$QUEUE) steers every pktgen"
echo "packet to AF_XDP; nothing touches the kernel UDP stack."
echo "See docs/ntuple-template-bench.md for the measurement model."
