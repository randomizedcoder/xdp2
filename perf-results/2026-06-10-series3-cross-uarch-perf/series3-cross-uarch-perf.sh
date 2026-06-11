#!/bin/bash
# Cross-uarch perf matrix — sender pi5-2 (Cortex-A76),
# receivers pi4-1 (A72, 1 GbE) and pi3-1 (A53, 100 Mbit USB-eth).
#
# Protocols x receivers x sysctl-on-receiver x N reps.
# Captures iperf3 / iperf2 JSON or extended output and parses
# throughput + CPU% (iperf3) / sender retransmits.
#
# Outputs:
#   $OUT/raw/<recv>-<proto>-sysctl<0|1>-iter<n>.log
#   $OUT/aggregate.csv

set -u
SENDER=pi5-2
RECVS=("pi4-1" "pi3-1")
PROTOS=(iperf3-tcp iperf3-udp-small iperf2-tcp iperf2-udp-small)
SYSCTLS=(0 1)
N=${N:-3}
DUR=${DUR:-30}
OUT=${OUT:-perf-results/2026-06-10-series3-cross-uarch-perf}
mkdir -p "$OUT/raw"
CSV="$OUT/aggregate.csv"
echo "recv,proto,sysctl,iter,throughput_mbps,retx,cpu_recv_pct,cpu_send_pct,note" > "$CSV"

ssh_q() { ssh -o BatchMode=yes -o ConnectTimeout=5 "$@" ; }

# Make sure both binaries are realized + reachable on every host
echo "[setup] materializing iperf2/iperf3 on each host..."
for h in "$SENDER" "${RECVS[@]}"; do
  ssh_q root@"$h" '
    nix build --no-link --print-out-paths nixpkgs#iperf2 nixpkgs#iperf3 > /dev/null
    echo "ok $(hostname)"
  '
done

# Cache binary paths
IPERF2_BIN=$(ssh_q root@"$SENDER" 'nix eval --raw nixpkgs#iperf2.outPath')/bin/iperf
IPERF3_BIN=$(ssh_q root@"$SENDER" 'nix eval --raw nixpkgs#iperf3.outPath')/bin/iperf3
echo "[setup] IPERF2_BIN=$IPERF2_BIN"
echo "[setup] IPERF3_BIN=$IPERF3_BIN"

# Start daemons on each receiver, set perf governor on all CPUs
start_daemons() {
  local recv="$1"
  ssh_q root@"$recv" "
    pkill iperf 2>/dev/null; pkill iperf3 2>/dev/null; sleep 1
    for c in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do
      [ -w \$c ] && echo performance > \$c || true
    done
    # Open ports in nixos-fw (idempotent — error means already inserted)
    iptables -C nixos-fw -p tcp --dport 5001 -j ACCEPT 2>/dev/null || \
      iptables -I nixos-fw 1 -p tcp --dport 5001 -j ACCEPT
    iptables -C nixos-fw -p udp --dport 5001 -j ACCEPT 2>/dev/null || \
      iptables -I nixos-fw 1 -p udp --dport 5001 -j ACCEPT
    iptables -C nixos-fw -p tcp --dport 5201 -j ACCEPT 2>/dev/null || \
      iptables -I nixos-fw 1 -p tcp --dport 5201 -j ACCEPT
    iptables -C nixos-fw -p udp --dport 5201 -j ACCEPT 2>/dev/null || \
      iptables -I nixos-fw 1 -p udp --dport 5201 -j ACCEPT
    $IPERF3_BIN -s -D
    $IPERF2_BIN -s -D
    sleep 2
    pgrep -fa iperf3
    pgrep -fa iperf
  " > /dev/null 2>&1
}

stop_daemons() {
  local recv="$1"
  ssh_q root@"$recv" 'pkill iperf 2>/dev/null; pkill iperf3 2>/dev/null; sleep 1' > /dev/null 2>&1
}

set_sysctl() {
  local recv="$1" v="$2"
  ssh_q root@"$recv" "sysctl -w net.core.flow_dissector_fastpath=$v" > /dev/null 2>&1
}

# Per-cell runner
run_cell() {
  local recv="$1" proto="$2" sysctl="$3" iter="$4"
  local log="$OUT/raw/${recv}-${proto}-sysctl${sysctl}-iter${iter}.log"
  local thr=NA retx=NA cpur=NA cpus=NA note=ok

  case "$proto" in
    iperf3-tcp)
      ssh_q root@"$SENDER" "$IPERF3_BIN -c $recv -t $DUR -P 4 -i 0 -J" > "$log" 2>&1
      thr=$(python3 -c "
import json,sys
try:
    d=json.load(open('$log'))
    print(round(d['end']['sum_received']['bits_per_second']/1e6, 2))
except Exception as e:
    print('NA')
" 2>/dev/null)
      retx=$(python3 -c "
import json,sys
try:
    d=json.load(open('$log'))
    print(d['end']['sum_sent']['retransmits'])
except Exception as e:
    print('NA')
" 2>/dev/null)
      cpur=$(python3 -c "
import json
try:
    d=json.load(open('$log'))
    print(round(d['end']['cpu_utilization_percent']['remote_total'], 1))
except Exception as e:
    print('NA')
" 2>/dev/null)
      cpus=$(python3 -c "
import json
try:
    d=json.load(open('$log'))
    print(round(d['end']['cpu_utilization_percent']['host_total'], 1))
except Exception as e:
    print('NA')
" 2>/dev/null)
      ;;
    iperf3-udp-small)
      ssh_q root@"$SENDER" "$IPERF3_BIN -c $recv -u -b 0 -l 64 -t $DUR -P 4 -i 0 -J" > "$log" 2>&1
      thr=$(python3 -c "
import json
try:
    d=json.load(open('$log'))
    print(round(d['end']['sum_received']['bits_per_second']/1e6, 2))
except Exception as e:
    print('NA')
" 2>/dev/null)
      retx=$(python3 -c "
import json
try:
    d=json.load(open('$log'))
    print(d['end']['sum']['lost_packets'])
except Exception as e:
    print('NA')
" 2>/dev/null)
      cpur=$(python3 -c "
import json
try:
    d=json.load(open('$log'))
    print(round(d['end']['cpu_utilization_percent']['remote_total'], 1))
except Exception as e:
    print('NA')
" 2>/dev/null)
      cpus=$(python3 -c "
import json
try:
    d=json.load(open('$log'))
    print(round(d['end']['cpu_utilization_percent']['host_total'], 1))
except Exception as e:
    print('NA')
" 2>/dev/null)
      ;;
    iperf2-tcp)
      ssh_q root@"$SENDER" "$IPERF2_BIN -c $recv -t $DUR -P 4 -y c" > "$log" 2>&1
      # iperf2 -y c: CSV lines. Last "SUM" row col 9 = bps.
      thr=$(awk -F, '/^[0-9]{14},/ {last=$9} END{print last}' "$log")
      thr=$(python3 -c "v='$thr'; print(round(float(v)/1e6, 2) if v and v.replace('.','').isdigit() else 'NA')" 2>/dev/null)
      ;;
    iperf2-udp-small)
      ssh_q root@"$SENDER" "$IPERF2_BIN -c $recv -u -b 1G -l 64 -t $DUR -P 4 -y c" > "$log" 2>&1
      thr=$(awk -F, '/^[0-9]{14},/ {last=$9} END{print last}' "$log")
      thr=$(python3 -c "v='$thr'; print(round(float(v)/1e6, 2) if v and v.replace('.','').isdigit() else 'NA')" 2>/dev/null)
      ;;
  esac

  if [ -z "${thr:-}" ] || [ "$thr" = "NA" ]; then note=parse_fail; fi
  echo "$recv,$proto,$sysctl,$iter,${thr:-NA},${retx:-NA},${cpur:-NA},${cpus:-NA},$note" >> "$CSV"
  printf "  [%s sysctl=%d %s iter=%d] thr=%s retx=%s cpu_r=%s cpu_s=%s\n" \
    "$recv" "$sysctl" "$proto" "$iter" "${thr:-NA}" "${retx:-NA}" "${cpur:-NA}" "${cpus:-NA}"
}

# Drive the matrix
for recv in "${RECVS[@]}"; do
  echo "=========================================="
  echo "RECV=$recv"
  echo "=========================================="
  start_daemons "$recv"
  for s in "${SYSCTLS[@]}"; do
    set_sysctl "$recv" "$s"
    cur=$(ssh_q root@"$recv" 'sysctl -n net.core.flow_dissector_fastpath')
    echo "[recv=$recv sysctl=$s -> confirmed=$cur]"
    for proto in "${PROTOS[@]}"; do
      for i in $(seq 1 "$N"); do
        run_cell "$recv" "$proto" "$s" "$i"
        sleep 2
      done
    done
  done
  set_sysctl "$recv" 0
  stop_daemons "$recv"
done

echo ""
echo "=== aggregate ==="
column -t -s, "$CSV" | head -40
echo "..."
echo "wrote $CSV"
