#!/bin/bash
# Series 3 — 10-cell 1-hour real-traffic soak on the ARM pair fleet
#
# Run sequentially. Recommended invocation (so SSH disconnects don't
# kill the matrix):
#
#   nohup /tmp/series3-soak-10h.sh > /tmp/series3-soak-10h.log 2>&1 &
#   tail -f /tmp/series3-soak-10h.log
#
# Resume after partial completion: any cell whose summary.json already
# exists is skipped.  To force re-run delete the corresponding
# cells/cell-NN-*/summary.json.

set -u

# ── Configuration ──────────────────────────────────────────────
DUR=${DUR:-3600}            # per-cell duration (sec)
COOLDOWN=${COOLDOWN:-120}   # inter-cell cool-down (sec)
TEMP_GATE=${TEMP_GATE:-65}  # refuse to start a cell if receiver temp > this
OUT=${OUT:-perf-results/2026-06-10-series3-soak-10h}
mkdir -p "$OUT/cells"

# Binary paths (resolved once, used across cells)
IPERF3=/nix/store/7rsxw31cisiygg5n6976fyv8pw6l948r-iperf-3.19.1/bin/iperf3
IPERF2=/nix/store/lgwcbsnjgmr51g8cpyi8n7f0swhimwq1-iperf-2.2.1/bin/iperf
TCPREPLAY=/nix/store/wlnkx4n26sfnxwkc5hspn82bmkxw25vx-tcpreplay-4.5.2/bin/tcpreplay
VXLAN_PCAP=/root/replay/pcaps/vxlan-k8s-pure-pi3-1.pcap   # MAC-rewritten by Phase H

# Cell matrix — pipe-separated to keep awkward arrays out
# Format: NN|sender|recv|proto|sysctl
#   proto in {iperf3-tcp, iperf2-tcp, tcpreplay-vxlan}
CELLS=(
  "01|pi5-1|pi5-2|iperf3-tcp|0"
  "02|pi5-1|pi5-2|iperf3-tcp|1"
  "03|pi5-2|pi4-1|iperf3-tcp|0"
  "04|pi5-2|pi4-1|iperf3-tcp|1"
  "05|pi5-2|pi3-1|iperf3-tcp|0"
  "06|pi5-2|pi3-1|iperf3-tcp|1"
  "07|pi5-1|pi5-2|iperf2-tcp|0"
  "08|pi5-1|pi5-2|iperf2-tcp|1"
  "09|pi5-2|pi3-1|tcpreplay-vxlan|0"
  "10|pi5-2|pi3-1|tcpreplay-vxlan|1"
)

# ── Helpers ────────────────────────────────────────────────────
SSH() { ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 "$@"; }
ts()  { date -u +%FT%TZ; }
log() { echo "$(ts) $*" | tee -a "$OUT/run.log"; }

# Sidecar: 1Hz vcgencmd CSV (ship script to remote, run with nohup)
# NixOS: shebang must use env or be invoked via explicit interpreter.
start_sidecar() {
  local host="$1" remote_path="$2"
  ssh -o BatchMode=yes -o ConnectTimeout=10 root@"$host" "cat > /tmp/sidecar-runner.sh" <<'SIDECAR'
#!/usr/bin/env bash
while true; do
  ts=$(date +%s)
  temp=$(vcgencmd measure_temp 2>/dev/null | sed 's/temp=//' | tr -d "'C" || echo NA)
  freq=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null || echo NA)
  thr=$(vcgencmd get_throttled 2>/dev/null | sed 's/throttled=//' || echo NA)
  echo "$ts,$temp,$freq,$thr"
  sleep 1
done
SIDECAR
  SSH root@"$host" "chmod +x /tmp/sidecar-runner.sh; nohup bash /tmp/sidecar-runner.sh > $remote_path 2>/dev/null </dev/null & disown" > /dev/null 2>&1
}

stop_sidecar() {
  local host="$1"
  SSH root@"$host" 'pkill -f /tmp/sidecar-runner.sh 2>/dev/null' > /dev/null 2>&1 || true
}

pull_sidecar() {
  local host="$1" remote_path="$2" local_path="$3"
  SSH root@"$host" "cat $remote_path" > "$local_path" 2>/dev/null || true
}

ensure_iperf_daemons() {
  local host="$1"
  SSH root@"$host" "
    # Make sure firewall is open
    iptables -C nixos-fw -p tcp --dport 5001 -j ACCEPT 2>/dev/null || \
      iptables -I nixos-fw 1 -p tcp --dport 5001 -j ACCEPT
    iptables -C nixos-fw -p tcp --dport 5201 -j ACCEPT 2>/dev/null || \
      iptables -I nixos-fw 1 -p tcp --dport 5201 -j ACCEPT
    pgrep -x iperf3 > /dev/null || $IPERF3 -s -D > /dev/null 2>&1
    pgrep -x iperf  > /dev/null || $IPERF2 -s -D > /dev/null 2>&1
    sleep 1
  " > /dev/null 2>&1
}

receiver_temp_c() {
  local host="$1"
  SSH root@"$host" 'vcgencmd measure_temp 2>/dev/null | sed "s/temp=//" | tr -d "'\''C"' 2>/dev/null
}

# ── Per-cell runner ────────────────────────────────────────────
run_cell() {
  local nn="$1" sender="$2" recv="$3" proto="$4" sysctl="$5"
  local pair="${sender}-${recv}"
  local dir="$OUT/cells/cell-${nn}-${pair}-${proto}-sysctl${sysctl}"

  if [ -e "$dir/summary.json" ]; then
    log "[cell $nn] SKIP — summary.json already exists at $dir"
    return 0
  fi

  mkdir -p "$dir"
  log "[cell $nn] start  sender=$sender  recv=$recv  proto=$proto  sysctl=$sysctl"

  # Temperature gate
  local recv_temp
  recv_temp=$(receiver_temp_c "$recv")
  # Compare integer part only (bash can't do floating point)
  local recv_temp_int=${recv_temp%%.*}
  if [ -n "$recv_temp_int" ] && [ "$recv_temp_int" -gt "$TEMP_GATE" ]; then
    log "[cell $nn] PRE-CHECK FAIL — receiver $recv at ${recv_temp}°C > ${TEMP_GATE}°C; cooling 300s extra"
    sleep 300
  fi

  # Setup
  SSH root@"$recv"   "sysctl -w net.core.flow_dissector_fastpath=$sysctl" > /dev/null 2>&1
  SSH root@"$sender" "sysctl -w net.core.flow_dissector_fastpath=$sysctl" > /dev/null 2>&1
  ensure_iperf_daemons "$recv"

  # Sidecars (1Hz on both ends)
  start_sidecar "$sender" "/tmp/sidecar-cell${nn}-sender.csv"
  start_sidecar "$recv"   "/tmp/sidecar-cell${nn}-recv.csv"

  # Run the actual workload
  local exit_rc=0
  case "$proto" in
    iperf3-tcp)
      SSH root@"$sender" "$IPERF3 -c $recv -t $DUR -P 4 -i 1 -J" > "$dir/iperf.json" 2>&1
      exit_rc=$?
      ;;
    iperf2-tcp)
      SSH root@"$sender" "$IPERF2 -c $recv -t $DUR -P 4 -i 1 -e -y c" > "$dir/iperf.csv" 2>&1
      exit_rc=$?
      ;;
    tcpreplay-vxlan)
      # tcpreplay rate cap: pi3-1 is 100 Mbit/s USB-eth
      local mbps=80
      # mpstat on receiver in parallel, for the full duration
      SSH root@"$recv" "nix shell nixpkgs#sysstat -c mpstat -P ALL 1 $DUR -o JSON" \
        > "$dir/mpstat.json" 2>&1 &
      local mp_pid=$!
      sleep 1
      SSH root@"$sender" \
        "$TCPREPLAY --intf1=end0 --mbps=$mbps --duration=$DUR --loop=0 --quiet $VXLAN_PCAP" \
        > "$dir/replay.log.tail" 2>&1
      exit_rc=$?
      wait $mp_pid 2>/dev/null || true
      # tcpreplay output is dominated by per-packet warnings; we only keep the tail
      tail -25 "$dir/replay.log.tail" > "$dir/replay.log"
      rm -f "$dir/replay.log.tail"
      ;;
  esac

  # Tear down sidecars + pull
  stop_sidecar "$sender"
  stop_sidecar "$recv"
  pull_sidecar "$sender" "/tmp/sidecar-cell${nn}-sender.csv" "$dir/sidecar-${sender}.csv"
  pull_sidecar "$recv"   "/tmp/sidecar-cell${nn}-recv.csv"   "$dir/sidecar-${recv}.csv"

  # Restore default-off sysctl
  SSH root@"$recv"   'sysctl -w net.core.flow_dissector_fastpath=0' > /dev/null 2>&1
  SSH root@"$sender" 'sysctl -w net.core.flow_dissector_fastpath=0' > /dev/null 2>&1

  # Per-cell summary
  python3 - "$dir" "$nn" "$sender" "$recv" "$proto" "$sysctl" "$exit_rc" <<'PYEOF' || true
import json, sys, os, csv, statistics, glob, re
dir_, nn, sender, recv, proto, sysctl, exit_rc = sys.argv[1:8]

def parse_sidecar(p):
    if not os.path.exists(p): return {}
    temps=[]; thrs=set()
    with open(p) as f:
        for line in f:
            parts=line.strip().split(',')
            if len(parts)<4: continue
            try: temps.append(float(parts[1]))
            except: pass
            thrs.add(parts[3])
    return {
        "samples": len(temps),
        "max_temp": max(temps) if temps else None,
        "p95_temp": statistics.quantiles(temps, n=20)[-1] if len(temps)>=20 else (max(temps) if temps else None),
        "mean_temp": statistics.mean(temps) if temps else None,
        "throttled_observed": sorted(t for t in thrs if t and t!="0x0"),
    }

s_send = parse_sidecar(f"{dir_}/sidecar-{sender}.csv")
s_recv = parse_sidecar(f"{dir_}/sidecar-{recv}.csv")

result = {"nn":nn,"sender":sender,"recv":recv,"proto":proto,"sysctl":int(sysctl),
          "exit_rc":int(exit_rc),"sender_sidecar":s_send,"recv_sidecar":s_recv}

if proto=="iperf3-tcp":
    try:
        d=json.load(open(f"{dir_}/iperf.json"))
        if "error" in d:
            result["note"]=f"iperf3 error: {d['error']}"
        else:
            result["throughput_mbps_recv"] = d["end"]["sum_received"]["bits_per_second"]/1e6
            result["retransmits"] = d["end"]["sum_sent"]["retransmits"]
            result["cpu_recv_pct"] = d["end"]["cpu_utilization_percent"]["remote_total"]
            result["cpu_send_pct"] = d["end"]["cpu_utilization_percent"]["host_total"]
            # Per-second drift: regress per-second Mbit/s on time
            intervals = [i["sum"]["bits_per_second"]/1e6 for i in d.get("intervals",[]) if "sum" in i]
            if len(intervals) >= 60:
                # simple linear regression slope (Mbit/s per sec)
                n=len(intervals); mean_x=(n-1)/2
                mean_y=sum(intervals)/n
                num=sum((i-mean_x)*(y-mean_y) for i,y in enumerate(intervals))
                den=sum((i-mean_x)**2 for i in range(n))
                slope = num/den if den else 0
                # convert to %/hour relative to mean
                result["drift_pct_per_hour"] = 100*slope*3600/mean_y if mean_y else 0
                result["thr_p50"] = statistics.median(intervals)
                result["thr_min"] = min(intervals)
                result["thr_max"] = max(intervals)
                result["thr_stdev"] = statistics.stdev(intervals)
                result["thr_cv_pct"] = 100*result["thr_stdev"]/mean_y if mean_y else 0
    except Exception as e:
        result["note"] = f"iperf3 parse error: {e}"
elif proto=="iperf2-tcp":
    try:
        # iperf2 -y c -e: columns time,src,sport,dst,dport,txid,istart,iend,bytes,speed,...
        # final aggregate row: txid=-1, istart=0.0, iend=DUR
        rows=[r for r in csv.reader(open(f"{dir_}/iperf.csv")) if len(r)>=10 and r[0]!="time"]
        # Per-stream PER-SECOND rows: txid in {1..4}, iend-istart ~= 1.0 (not 0.0,DUR)
        per_sec_per_stream = [r for r in rows
                              if r[5] not in ("-1","") and r[6] != "0.0"
                              and (float(r[7])-float(r[6])) < 5.0]
        # Aggregate per-second across streams by start-second bucket
        bucket = {}
        for r in per_sec_per_stream:
            try:
                t=int(float(r[6]))
                bucket.setdefault(t, 0)
                bucket[t] += float(r[9])
            except: pass
        ints = [bucket[t]/1e6 for t in sorted(bucket)]
        if ints:
            mean_y = sum(ints)/len(ints)
            result["throughput_mbps_recv"] = mean_y
        # The cumulative aggregate row (txid=-1 with istart=0.0, iend ~= DUR)
        agg = [r for r in rows if r[5] == "-1" and r[6] == "0.0"]
        if agg:
            result["throughput_mbps_recv_agg"] = float(agg[-1][9])/1e6
        if len(ints) >= 60:
            n=len(ints); mean_x=(n-1)/2
            num=sum((i-mean_x)*(y-mean_y) for i,y in enumerate(ints))
            den=sum((i-mean_x)**2 for i in range(n))
            slope = num/den if den else 0
            result["drift_pct_per_hour"] = 100*slope*3600/mean_y if mean_y else 0
            result["thr_p50"] = statistics.median(ints)
            result["thr_min"] = min(ints)
            result["thr_max"] = max(ints)
            result["thr_stdev"] = statistics.stdev(ints)
            result["thr_cv_pct"] = 100*result["thr_stdev"]/mean_y if mean_y else 0
    except Exception as e:
        result["note"] = f"iperf2 parse error: {e}"
elif proto=="tcpreplay-vxlan":
    try:
        # tcpreplay tail summary
        last = open(f"{dir_}/replay.log").read()
        m=re.search(r"Successful packets:\s+(\d+)", last)
        if m: result["tx_packets"] = int(m.group(1))
        m=re.search(r"Failed packets:\s+(\d+)", last)
        if m: result["failed_packets"] = int(m.group(1))
        # mpstat: mean CPU% across all cores during the run
        d=json.load(open(f"{dir_}/mpstat.json"))
        hosts=d["sysstat"]["hosts"][0]["statistics"]
        used=[]
        for sample in hosts:
            for cpu in sample["cpu-load"]:
                if cpu["cpu"]=="all":
                    used.append(100.0-cpu["idle"])
        if used:
            result["cpu_recv_mean_pct"] = statistics.mean(used)
            result["cpu_recv_p95_pct"] = statistics.quantiles(used, n=20)[-1] if len(used)>=20 else max(used)
    except Exception as e:
        result["note"] = f"tcpreplay parse error: {e}"

# Thermal clean = no non-zero sticky bits observed beyond what we started with
# i.e. each cell's "throttled_observed" should be either empty or just the
# pre-existing historical sticky value.  Detect change-during-cell by checking
# whether the LOW 16 bits (current state) ever became non-zero.
def current_throttle_observed(thrs):
    for v in thrs:
        try:
            n=int(v,16) & 0xFFFF
            if n: return True
        except: pass
    return False

recv_change = current_throttle_observed(s_recv.get("throttled_observed", []))
send_change = current_throttle_observed(s_send.get("throttled_observed", []))
result["thermal_clean"] = not (recv_change or send_change)

json.dump(result, open(f"{dir_}/summary.json","w"), indent=2)
PYEOF

  log "[cell $nn] done   exit=$exit_rc  summary=$dir/summary.json"
  log "[cell $nn] cool-down ${COOLDOWN}s ..."
  sleep "$COOLDOWN"
}

# ── Drive ──────────────────────────────────────────────────────
log "=== series3-soak-10h start  DUR=$DUR  COOLDOWN=$COOLDOWN  cells=${#CELLS[@]} ==="
for cell in "${CELLS[@]}"; do
  IFS='|' read -r nn sender recv proto sysctl <<< "$cell"
  run_cell "$nn" "$sender" "$recv" "$proto" "$sysctl"
done
log "=== series3-soak-10h: all cells dispatched ==="

# ── Aggregate ──────────────────────────────────────────────────
python3 - "$OUT" <<'PYEOF'
import os, sys, json, csv, glob, statistics
out=sys.argv[1]
rows=[]
for sj in sorted(glob.glob(f"{out}/cells/*/summary.json")):
    try:
        d=json.load(open(sj))
    except Exception as e:
        rows.append({"summary_path":sj,"note":f"json read error: {e}"})
        continue
    rows.append(d)

# Write CSV
fields=["nn","sender","recv","proto","sysctl",
        "throughput_mbps_recv","retransmits","cpu_recv_pct",
        "thr_p50","thr_min","thr_max","thr_cv_pct","drift_pct_per_hour",
        "tx_packets","failed_packets","cpu_recv_mean_pct",
        "max_temp_recv","max_temp_send","throttled_recv","throttled_send",
        "thermal_clean","note"]
with open(f"{out}/aggregate.csv","w") as f:
    w=csv.writer(f); w.writerow(fields)
    for r in rows:
        rs=r.get("recv_sidecar",{}); ss=r.get("sender_sidecar",{})
        row=[r.get("nn"),r.get("sender"),r.get("recv"),r.get("proto"),r.get("sysctl"),
             r.get("throughput_mbps_recv"),r.get("retransmits"),r.get("cpu_recv_pct"),
             r.get("thr_p50"),r.get("thr_min"),r.get("thr_max"),r.get("thr_cv_pct"),r.get("drift_pct_per_hour"),
             r.get("tx_packets"),r.get("failed_packets"),r.get("cpu_recv_mean_pct"),
             rs.get("max_temp"),ss.get("max_temp"),
             "|".join(rs.get("throttled_observed",[])),
             "|".join(ss.get("throttled_observed",[])),
             r.get("thermal_clean"),r.get("note","")]
        w.writerow(row)
print(f"wrote {out}/aggregate.csv ({len(rows)} rows)")
PYEOF

log "=== series3-soak-10h finished ==="
