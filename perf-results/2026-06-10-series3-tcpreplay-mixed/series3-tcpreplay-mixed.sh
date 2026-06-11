#!/bin/bash
# tcpreplay mixed-packet macro A/B
# Sender: pi5-2 replays a workload PCAP at controlled rate; receiver
# runs mpstat to capture per-CPU% during the replay window. A/B on
# sysctl=0 vs sysctl=1 on the receiver. The receiver drops packets
# at L3 (foreign IPs) but the flow_dissector runs first on the rx
# softirq path, so dissector cost is observable in receiver CPU%.

set -u
SENDER=pi5-2
SENDER_IFACE=end0
declare -A RECV_MAC=(
  [pi4-1]=e4:5f:01:42:a1:0f
  [pi3-1]=b8:27:eb:70:39:cb
)
declare -A RECV_MBPS=(
  [pi4-1]=500
  [pi3-1]=80
)
RECVS=("pi4-1" "pi3-1")
PCAPS=(broad-coverage vxlan-k8s-pure)
SYSCTLS=(0 1)
N=${N:-2}
DUR=${DUR:-15}
OUT=${OUT:-perf-results/2026-06-10-series3-tcpreplay-mixed}
mkdir -p "$OUT/raw"
CSV="$OUT/aggregate.csv"
echo "recv,pcap,sysctl,iter,mbps,recv_cpu_mean_pct,tx_packets,rx_packets,packets_loss,note" > "$CSV"

ssh_q() { ssh -o BatchMode=yes -o ConnectTimeout=5 "$@" ; }

echo "[setup] materialize tcpreplay on sender + sysstat on receivers"
ssh_q root@"$SENDER" 'nix build --no-link --print-out-paths nixpkgs#tcpreplay > /dev/null'
for h in "${RECVS[@]}"; do
  ssh_q root@"$h" 'nix build --no-link --print-out-paths nixpkgs#sysstat > /dev/null'
done

# Rewrite the PCAPs once per receiver — set dst MAC to receiver's
TCPREPLAY_BIN=$(ssh_q root@"$SENDER" 'nix eval --raw nixpkgs#tcpreplay')/bin/tcpreplay
TCPREWRITE_BIN=$(ssh_q root@"$SENDER" 'nix eval --raw nixpkgs#tcpreplay')/bin/tcprewrite

for recv in "${RECVS[@]}"; do
  mac="${RECV_MAC[$recv]}"
  for p in "${PCAPS[@]}"; do
    src=/root/replay/pcaps/$p.pcap
    dst=/root/replay/pcaps/$p-$recv.pcap
    ssh_q root@"$SENDER" "
      $TCPREWRITE_BIN \
        --enet-dmac=$mac \
        --enet-smac=2c:cf:67:31:df:b7 \
        --infile=$src \
        --outfile=$dst 2>&1 | tail -3 || echo rewrite_err
      ls -la $dst
    " > /dev/null
  done
done
echo "[setup] PCAPs rewritten"

# Per-cell runner
run_cell() {
  local recv="$1" pcap="$2" sysctl="$3" iter="$4"
  local mbps="${RECV_MBPS[$recv]}"
  local pcap_path="/root/replay/pcaps/$pcap-$recv.pcap"
  local log="$OUT/raw/${recv}-${pcap}-sysctl${sysctl}-iter${iter}"

  ssh_q root@"$recv" "sysctl -w net.core.flow_dissector_fastpath=$sysctl" > /dev/null

  # Snapshot rx_packets on receiver iface before
  local iface
  iface=$(ssh_q root@"$recv" 'ip -o -4 route get 8.8.8.8 2>/dev/null | grep -oP "dev \K\S+" | head -1')
  iface="${iface:-end0}"
  local rx_before
  rx_before=$(ssh_q root@"$recv" "cat /sys/class/net/$iface/statistics/rx_packets")

  # Kick off mpstat on receiver in background (15 1-second samples)
  ssh_q root@"$recv" "nix shell nixpkgs#sysstat -c mpstat -P ALL 1 $DUR -o JSON" \
    > "${log}.mpstat.json" 2>&1 &
  local mpstat_pid=$!

  sleep 1

  # Run tcpreplay (target rate, loop until --duration; tcpreplay 4.5.2
  # supports --duration so the rep ends cleanly)
  ssh_q root@"$SENDER" \
    "$TCPREPLAY_BIN --intf1=$SENDER_IFACE --mbps=$mbps --duration=$DUR --loop=0 --quiet $pcap_path" \
    > "${log}.replay.log" 2>&1

  wait $mpstat_pid

  local rx_after
  rx_after=$(ssh_q root@"$recv" "cat /sys/class/net/$iface/statistics/rx_packets")
  local rx_delta=$((rx_after - rx_before))

  # Parse tcpreplay tx packets
  local tx_packets
  tx_packets=$(grep -oP 'Successful packets: *\K[0-9]+' "${log}.replay.log" | tail -1)
  : "${tx_packets:=NA}"

  # Parse mpstat: avg %idle across cores in the "all" rows of "node-statistics"
  local cpu_mean
  cpu_mean=$(python3 <<PYEOF
import json
try:
    d=json.load(open('${log}.mpstat.json'))
    hosts=d['sysstat']['hosts'][0]['statistics']
    used=[]
    for sample in hosts:
        for cpu in sample['cpu-load']:
            if cpu['cpu']=='all':
                used.append(100.0 - cpu['idle'])
    print(round(sum(used)/len(used), 2) if used else 'NA')
except Exception as e:
    print('NA')
PYEOF
)

  local loss="NA"
  if [ "$tx_packets" != "NA" ] && [ -n "$rx_delta" ]; then
    loss=$((tx_packets - rx_delta))
  fi

  echo "$recv,$pcap,$sysctl,$iter,$mbps,$cpu_mean,$tx_packets,$rx_delta,$loss,ok" >> "$CSV"
  printf "  [%-6s %-15s sysctl=%d iter=%d] cpu_mean=%s tx=%s rx=%s loss=%s\n" \
    "$recv" "$pcap" "$sysctl" "$iter" "$cpu_mean" "$tx_packets" "$rx_delta" "$loss"
}

# Drive the matrix
for recv in "${RECVS[@]}"; do
  echo "=========================================="
  echo "RECV=$recv (mbps=${RECV_MBPS[$recv]})"
  echo "=========================================="
  for s in "${SYSCTLS[@]}"; do
    for p in "${PCAPS[@]}"; do
      for i in $(seq 1 "$N"); do
        run_cell "$recv" "$p" "$s" "$i"
        sleep 2
      done
    done
  done
  ssh_q root@"$recv" 'sysctl -w net.core.flow_dissector_fastpath=0' > /dev/null
done

echo ""
echo "=== aggregate ==="
column -t -s, "$CSV"
echo "wrote $CSV"
