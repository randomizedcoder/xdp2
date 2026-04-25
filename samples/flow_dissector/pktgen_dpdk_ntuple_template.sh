#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# DPDK-pktgen driver for the ntuple+template bench (peer-side).
#
# Drop-in replacement for pktgen_ntuple_template.sh with an identical
# CLI (start/stop/status; same start-arg shape) so the existing
# orchestrator (run_ntuple_template_bench.sh) can drive either by
# swapping PKTGEN_SCRIPT. The asymmetry is intentional: the PEER
# (traffic source) swaps its NIC to vfio-pci and runs userspace DPDK;
# the TARGET keeps its NIC on i40e so the X710 Flow Director rules
# (kernel state) survive and xsks_map/XDP attach still works.
#
# Usage mirrors the kernel variant:
#   pktgen_dpdk_ntuple_template.sh start <iface> <dst_ip> <dst_mac> \
#       [--dport 443] [--pkt-size 1400] [--threads 2] [--rate 0]
#   pktgen_dpdk_ntuple_template.sh stop
#   pktgen_dpdk_ntuple_template.sh status
#
# Env tunables (no kernel-pktgen overlap):
#   PKTGEN_DPDK_LUA       path to the Lua startup script (default: sibling .lua)
#   PKTGEN_DPDK_LCORES    core list for DPDK EAL (default: "0@0,1@1,2@2")
#   PKTGEN_DPDK_SOCKET_MEM per-socket hugepage reservation (default: 1024)
#   PKTGEN_DPDK_HUGE_DIR  hugetlbfs mount (default: /dev/hugepages)
#   PKTGEN_DPDK_STATE_DIR where the saved driver name + PID file live
#                         (default: /var/run/xdp2-pktgen-dpdk)
#
# The `--threads` arg is translated into the DPDK core map: -l implies
# (1 main + N workers). We keep `--rate` / `--pkt-size` / `--dst_ip`
# env-forwarded to the Lua script. `--rate 0` = unlimited (pktgen
# "rate 100" at line rate).

set -euo pipefail

PKTGEN_DPDK_STATE_DIR="${PKTGEN_DPDK_STATE_DIR:-/var/run/xdp2-pktgen-dpdk}"
PKTGEN_DPDK_HUGE_DIR="${PKTGEN_DPDK_HUGE_DIR:-/dev/hugepages}"
PKTGEN_DPDK_LCORES="${PKTGEN_DPDK_LCORES:-0@0,1@1,2@2}"
PKTGEN_DPDK_SOCKET_MEM="${PKTGEN_DPDK_SOCKET_MEM:-1024}"
PKTGEN_DPDK_LUA="${PKTGEN_DPDK_LUA:-$(dirname "$0")/pktgen_dpdk_ntuple_template.lua}"
PKTGEN_DPDK_LUA_REMOTE="$PKTGEN_DPDK_STATE_DIR/pktgen.lua"

PID_FILE="$PKTGEN_DPDK_STATE_DIR/pktgen.pid"
DRIVER_FILE="$PKTGEN_DPDK_STATE_DIR/original-driver"
PCI_FILE="$PKTGEN_DPDK_STATE_DIR/pci-addr"
IFACE_FILE="$PKTGEN_DPDK_STATE_DIR/iface"
LOG_FILE="$PKTGEN_DPDK_STATE_DIR/pktgen.log"

usage() {
    sed -n '3,35p' "$0"
    exit 1
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: DPDK pktgen requires root (driver rebind + hugepages)" >&2
        exit 1
    fi
}

# Find the DPDK devbind helper — shipped with pkgs.dpdk. The wrapper
# (nix/pktgen-dpdk-ntuple-template.nix) adds pkgs.dpdk to runtimeInputs
# so it's on PATH at runtime.
find_devbind() {
    if command -v dpdk-devbind.py >/dev/null 2>&1; then
        echo "dpdk-devbind.py"
    elif command -v dpdk-devbind >/dev/null 2>&1; then
        echo "dpdk-devbind"
    else
        echo "ERROR: dpdk-devbind.py not on PATH. Install pkgs.dpdk or the peer's physical-testbed module with dpdkBenchHost=true." >&2
        exit 3
    fi
}

pci_of() {
    # Resolve an interface name to its PCI bus address by walking
    # /sys/class/net/$iface/device — a symlink into /sys/devices.
    local iface="$1"
    local devpath
    devpath="$(readlink -f /sys/class/net/"$iface"/device 2>/dev/null || true)"
    if [[ -z "$devpath" ]]; then
        echo "ERROR: no device entry for $iface" >&2
        return 1
    fi
    basename "$devpath"
}

driver_of() {
    # Read the driver currently bound to the NIC. `ethtool -i` is the
    # usual way but we avoid adding ethtool to runtimeInputs — the
    # driver symlink under /sys gives the same answer.
    local iface="$1"
    local drvpath
    drvpath="$(readlink -f /sys/class/net/"$iface"/device/driver 2>/dev/null || true)"
    if [[ -z "$drvpath" ]]; then
        echo ""
        return 0
    fi
    basename "$drvpath"
}

ensure_hugepages() {
    # The physical-testbed module with dpdkBenchHost=true reserves
    # 1024x2MB at boot. Belt-and-braces in case someone runs this
    # outside that module: try to top up now.
    if ! mountpoint -q "$PKTGEN_DPDK_HUGE_DIR"; then
        mkdir -p "$PKTGEN_DPDK_HUGE_DIR"
        mount -t hugetlbfs nodev "$PKTGEN_DPDK_HUGE_DIR" 2>/dev/null || true
    fi
    local free_pages
    free_pages="$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages 2>/dev/null || echo 0)"
    if [[ "$free_pages" -lt 512 ]]; then
        echo "WARNING: only $free_pages free 2MB hugepages (<512). DPDK may OOM." >&2
        echo "  Set xdp2.testbed.dpdkBenchHost=true + nixos-rebuild to reserve 1024 at boot." >&2
    fi
}

cmd="${1:-}"
[[ -z "$cmd" ]] && usage

case "$cmd" in
    stop)
        require_root
        if [[ -f "$PID_FILE" ]]; then
            pid="$(cat "$PID_FILE")"
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                echo "stopping pktgen (pid=$pid)..."
                kill -TERM "$pid" 2>/dev/null || true
                for _ in $(seq 1 20); do
                    kill -0 "$pid" 2>/dev/null || break
                    sleep 0.25
                done
                kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || true
            fi
            rm -f "$PID_FILE"
        fi
        # Restore original driver. Without this the NIC stays bound to
        # vfio-pci and the peer loses its tx path after the experiment.
        if [[ -f "$PCI_FILE" && -f "$DRIVER_FILE" ]]; then
            pciaddr="$(cat "$PCI_FILE")"
            orig_drv="$(cat "$DRIVER_FILE")"
            iface="$(cat "$IFACE_FILE" 2>/dev/null || echo "")"
            devbind="$(find_devbind)"
            if [[ -n "$orig_drv" ]]; then
                echo "rebinding $pciaddr -> $orig_drv (was vfio-pci)"
                "$devbind" --force -b "$orig_drv" "$pciaddr" 2>&1 || true
            fi
            if [[ -n "$iface" ]]; then
                # Driver rebind recreates the netdev; bring it back up.
                ip link set dev "$iface" up 2>/dev/null || true
            fi
            rm -f "$PCI_FILE" "$DRIVER_FILE" "$IFACE_FILE"
        fi
        echo "pktgen-dpdk stopped, driver restored"
        exit 0
        ;;
    status)
        echo "=== pktgen-dpdk status ==="
        if [[ -f "$PID_FILE" ]]; then
            pid="$(cat "$PID_FILE")"
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                echo "running: pid=$pid"
            else
                echo "pid file present but process gone"
            fi
        else
            echo "not running"
        fi
        if [[ -f "$LOG_FILE" ]]; then
            echo ""
            echo "=== tail pktgen log ==="
            tail -40 "$LOG_FILE" 2>/dev/null || true
        fi
        # Surface the same pkts-sofar / errors fields the kernel pktgen
        # driver emits so downstream mkBenchExperiment parsers work
        # unchanged. pktgen's own stats live in its log; scrape them.
        if [[ -f "$LOG_FILE" ]]; then
            echo ""
            echo "=== pktgen counters ==="
            # pktgen prints lines like "Port 0: TX pkts: 12345678 ..."
            # Normalise to kernel-pktgen shape so the orchestrator's
            # summary code continues to work without branching.
            awk '/TX pkts/ {
                    for (i=1; i<=NF; i++) {
                        if ($i=="pkts:") tx=$(i+1);
                        if ($i=="errors:") err=$(i+1);
                    }
                    if (tx) print "pkts-sofar:", tx, " errors:", (err ? err : 0)
                 }' "$LOG_FILE" | tail -20 || true
        fi
        exit 0
        ;;
    start)
        ;;
    *)
        usage
        ;;
esac

# ── start ─────────────────────────────────────────────────────
require_root
shift  # consume "start"
[[ $# -ge 3 ]] || usage
IFACE="$1"
DST_IP="$2"
DST_MAC="$3"
shift 3

DPORT=443
PKT_SIZE=1400
THREADS=2
RATE=0  # unused in DPDK path (pktgen ramps to 100% line rate); kept for CLI compat

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dport)     DPORT="$2"; shift 2 ;;
        --pkt-size)  PKT_SIZE="$2"; shift 2 ;;
        --threads)   THREADS="$2"; shift 2 ;;
        --rate)      RATE="$2"; shift 2 ;;
        --ipv6)      echo "ERROR: DPDK path is IPv4-only in this config" >&2; exit 2 ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done

mkdir -p "$PKTGEN_DPDK_STATE_DIR"

# Stage the Lua config in a stable remote path so `-f` works regardless
# of cwd (the peer invokes us via ssh without a working directory).
if [[ ! -f "$PKTGEN_DPDK_LUA" ]]; then
    echo "ERROR: Lua config not found at $PKTGEN_DPDK_LUA" >&2
    echo "  Expected next to this script, or set PKTGEN_DPDK_LUA." >&2
    exit 4
fi
cp -f "$PKTGEN_DPDK_LUA" "$PKTGEN_DPDK_LUA_REMOTE"

PCI_ADDR="$(pci_of "$IFACE")"
ORIG_DRIVER="$(driver_of "$IFACE")"
echo "=== pktgen-dpdk start ==="
echo "  interface:   $IFACE"
echo "  pci:         $PCI_ADDR"
echo "  orig driver: ${ORIG_DRIVER:-<none>}"
echo "  dst:         $DST_IP ($DST_MAC)"
echo "  dport:       $DPORT"
echo "  pkt_size:    $PKT_SIZE"
echo "  threads:     $THREADS"
echo "  rate:        ${RATE:-unlimited} (DPDK path runs at line rate)"
echo "  lcores:      $PKTGEN_DPDK_LCORES"
echo ""

# Save state for `stop` to undo.
echo "$PCI_ADDR"   > "$PCI_FILE"
echo "$ORIG_DRIVER" > "$DRIVER_FILE"
echo "$IFACE"      > "$IFACE_FILE"

ensure_hugepages

# Load vfio-pci (physical-testbed module loads at boot when
# dpdkBenchHost=true; retry here for safety).
if [[ ! -d /sys/module/vfio_pci ]]; then
    modprobe vfio-pci 2>/dev/null || {
        echo "ERROR: failed to load vfio-pci. Kernel cmdline needs iommu=pt intel_iommu=on." >&2
        exit 5
    }
fi

# Bring iface down before rebinding — otherwise the kernel may race
# with vfio-pci's claim and leave the device in half-bound state.
ip link set dev "$IFACE" down 2>/dev/null || true

DEVBIND="$(find_devbind)"
echo "rebinding $PCI_ADDR -> vfio-pci (was ${ORIG_DRIVER:-<none>})"
"$DEVBIND" --force -b vfio-pci "$PCI_ADDR"

# Launch pktgen detached. -a <pci> whitelists exactly our NIC; -l
# maps lcores; --file-prefix isolates this instance's shared hugepage
# files so multiple DPDK runs on the same host don't collide.
echo ""
echo "launching pktgen -> $LOG_FILE"
PKTGEN_DST_IP="$DST_IP" \
PKTGEN_DST_MAC="$DST_MAC" \
PKTGEN_DPORT="$DPORT" \
PKTGEN_PKT_SIZE="$PKT_SIZE" \
nohup pktgen \
    -l "0-$((THREADS))" \
    -n 4 \
    --socket-mem "$PKTGEN_DPDK_SOCKET_MEM" \
    --file-prefix "xdp2pg-$$" \
    -a "$PCI_ADDR" \
    -- \
    -P \
    -m "$(seq 1 "$THREADS" | paste -sd, -).0" \
    -f "$PKTGEN_DPDK_LUA_REMOTE" \
    >"$LOG_FILE" 2>&1 &
pktgen_pid=$!
echo "$pktgen_pid" > "$PID_FILE"
disown || true

sleep 1
if ! kill -0 "$pktgen_pid" 2>/dev/null; then
    echo "ERROR: pktgen exited immediately. Tail of log:" >&2
    tail -30 "$LOG_FILE" >&2 || true
    # Try to restore driver so stop is a no-op cleanup.
    "$DEVBIND" --force -b "$ORIG_DRIVER" "$PCI_ADDR" 2>/dev/null || true
    ip link set dev "$IFACE" up 2>/dev/null || true
    rm -f "$PID_FILE" "$PCI_FILE" "$DRIVER_FILE" "$IFACE_FILE"
    exit 6
fi
echo "pktgen-dpdk started: pid=$pktgen_pid (log: $LOG_FILE)"
echo "Monitor with: $0 status"
