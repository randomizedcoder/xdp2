#!/nix/store/v8sa6r6q037ihghxfbwzjj4p59v2x0pv-bash-5.3p9/bin/bash
set -o errexit
set -o nounset
set -o pipefail

export PATH="/nix/store/h8x05b58m7vp5ym85h28w0skhvg25rha-openssh-10.2p1/bin:/nix/store/74sind1d6vf2bfwd7yklg8chsvzqxmmq-coreutils-9.10/bin:/nix/store/pzdalg368npikvpq4ncz2saxnz19v53k-python3-3.13.12/bin:$PATH"

set -u

# ── Configuration ──────────────────────────────────────────────
DUR=${DUR:-3600}            # per-cell duration (sec)
COOLDOWN=${COOLDOWN:-120}   # inter-cell cool-down (sec)
TEMP_GATE=${TEMP_GATE:-65}  # extra cool-down if recv temp > this
today=$(date +%Y-%m-%d)
OUT=${OUT:-perf-results/$today-series3-soak}
mkdir -p "$OUT/cells"

# Host names (override via env if your testbed differs).
PI5_1=${PI5_1:-pi5-1}
PI5_2=${PI5_2:-pi5-2}
PI4_1=${PI4_1:-pi4-1}
PI3_1=${PI3_1:-pi3-1}

# tcpreplay sender-side PCAP paths (MAC-rewritten by Phase H).
# SOURCE = original Phase H PCAP (may contain frames > MTU).
# USED   = MTU-filtered variant; oversized frames must be dropped
#          first, otherwise tcpreplay 4.5.2's --duration check is
#          unreliable when many sends fail. See bug analysis
#          below run_cell() for details.
VXLAN_PCAP_SRC=${VXLAN_PCAP_SRC:-/root/replay/pcaps/vxlan-k8s-pure-pi3-1.pcap}
VXLAN_PCAP=${VXLAN_PCAP:-/root/replay/pcaps/vxlan-k8s-pure-pi3-1-mtufit.pcap}
SENDER_MTU=${SENDER_MTU:-1500}

# Outer-timeout multiplier for tcpreplay cells (belt + braces
# over the --duration check; will kill tcpreplay if it ever
# wedges past DUR + 60 s regardless of PCAP cleanliness).
TCPRP_GUARD_SEC=$((DUR + 60))

# The 10-cell matrix.
CELLS=(
  "01|$PI5_1|$PI5_2|iperf3-tcp|0"
  "02|$PI5_1|$PI5_2|iperf3-tcp|1"
  "03|$PI5_2|$PI4_1|iperf3-tcp|0"
  "04|$PI5_2|$PI4_1|iperf3-tcp|1"
  "05|$PI5_2|$PI3_1|iperf3-tcp|0"
  "06|$PI5_2|$PI3_1|iperf3-tcp|1"
  "07|$PI5_1|$PI5_2|iperf2-tcp|0"
  "08|$PI5_1|$PI5_2|iperf2-tcp|1"
  "09|$PI5_2|$PI3_1|tcpreplay-vxlan|0"
  "10|$PI5_2|$PI3_1|tcpreplay-vxlan|1"
)

# ── Helpers ────────────────────────────────────────────────────
SSH() { ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 "$@"; }
ts()  { date -u +%FT%TZ; }
log() { echo "$(ts) $*" | tee -a "$OUT/run.log"; }

# Resolve iperf3 / iperf2 / tcpreplay store paths via nix eval
# on the sender (works because all hosts share the nixpkgs
# revision after Phase H materialisation).
IPERF3_BIN=$(SSH root@"$PI5_2" 'nix eval --raw nixpkgs#iperf3')/bin/iperf3
IPERF2_BIN=$(SSH root@"$PI5_2" 'nix eval --raw nixpkgs#iperf2')/bin/iperf
TCPRP_BIN=$(SSH root@"$PI5_2" 'nix eval --raw nixpkgs#tcpreplay')/bin/tcpreplay

log "=== series3-soak start  DUR=$DUR  COOLDOWN=$COOLDOWN  cells=${#CELLS[@]}  OUT=$OUT ==="
log "  IPERF3_BIN=$IPERF3_BIN"
log "  IPERF2_BIN=$IPERF2_BIN"
log "  TCPRP_BIN=$TCPRP_BIN"
log "  hosts: $PI5_1 $PI5_2 $PI4_1 $PI3_1"

# Sidecar: 1 Hz vcgencmd CSV on each host.  Ship the sidecar
# script via SSH heredoc; NixOS requires explicit bash invocation
# since /bin/bash isn't a thing.
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
    iptables -C nixos-fw -p tcp --dport 5001 -j ACCEPT 2>/dev/null || \
      iptables -I nixos-fw 1 -p tcp --dport 5001 -j ACCEPT
    iptables -C nixos-fw -p tcp --dport 5201 -j ACCEPT 2>/dev/null || \
      iptables -I nixos-fw 1 -p tcp --dport 5201 -j ACCEPT
    pgrep -x iperf3 > /dev/null || $IPERF3_BIN -s -D > /dev/null 2>&1
    pgrep -x iperf  > /dev/null || $IPERF2_BIN -s -D > /dev/null 2>&1
    sleep 1
  " > /dev/null 2>&1
}

receiver_temp_c() {
  local host="$1"
  # Extract digits from vcgencmd output; sed regex avoids
  # needing a literal single quote that would terminate the
  # surrounding Nix indented string.
  SSH root@"$host" "vcgencmd measure_temp 2>/dev/null | sed -E 's/temp=([0-9.]+).*/\\1/'" 2>/dev/null
}

# mpstat runner: ship a small wrapper to the receiver, run it
# under nohup so the SSH session can close without killing
# mpstat.  Output written to a known path on the receiver and
# pulled back at cell-end.
ensure_mpstat_runner() {
  local host="$1" local_path="$2" dur="$3"
  ssh -o BatchMode=yes -o ConnectTimeout=10 root@"$host" "cat > /tmp/mpstat-runner.sh" <<'MPSTAT'
#!/usr/bin/env bash
DUR="$1"
OUT="$2"
exec nix shell nixpkgs#sysstat -c mpstat -P ALL 1 "$DUR" -o JSON > "$OUT" 2>&1
MPSTAT
  SSH root@"$host" "chmod +x /tmp/mpstat-runner.sh; nohup bash /tmp/mpstat-runner.sh $dur /tmp/mpstat-cell.json > /dev/null 2>&1 </dev/null & disown" > /dev/null 2>&1
  # MPSTAT_LOCAL is consumed by stop_mpstat_runner.
  MPSTAT_LOCAL="$local_path"
  export MPSTAT_LOCAL
}

stop_mpstat_runner() {
  local host="$1"
  SSH root@"$host" 'pkill -f /tmp/mpstat-runner.sh 2>/dev/null; pkill -f "mpstat -P ALL 1" 2>/dev/null' > /dev/null 2>&1 || true
  SSH root@"$host" 'cat /tmp/mpstat-cell.json' > "$MPSTAT_LOCAL" 2>/dev/null || true
}

# Auto-prep MTU-filtered PCAP on sender if missing.  Drops
# frames > SENDER_MTU so tcpreplay 4.5.2's duration check
# (which is skipped on PF_PACKET send() failure) stays
# accurate over multi-hour runs.
ensure_mtufit_pcap() {
  local host="$1" src="$2" dst="$3" mtu="$4"
  SSH root@"$host" "
    if [ ! -e $dst ] || [ $src -nt $dst ]; then
      nix shell nixpkgs#tcpdump -c tcpdump -r $src -w $dst \"not greater $mtu\" 2>&1 | head -2
      echo PCAP filtered: \$(nix shell nixpkgs#wireshark-cli -c capinfos -c $src 2>&1 | grep \"Number of packets\") -> \$(nix shell nixpkgs#wireshark-cli -c capinfos -c $dst 2>&1 | grep \"Number of packets\")
    fi
  " 2>&1
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

  # Temp gate
  local recv_temp recv_temp_int
  recv_temp=$(receiver_temp_c "$recv")
  recv_temp_int=${recv_temp%%.*}
  if [ -n "$recv_temp_int" ] && [ "$recv_temp_int" -gt "$TEMP_GATE" ]; then
    log "[cell $nn] PRE-CHECK — receiver $recv at ${recv_temp}°C > ${TEMP_GATE}°C; cool 300 s"
    sleep 300
  fi

  # Errexit-safe: we want a transient SSH non-zero exit on any
  # SSH command in the cell body NOT to kill the whole 10-cell
  # soak.  Capture errors per-cell via $exit_rc + summary.json
  # note; let the outer driver keep going.
  set +e

  SSH root@"$recv"   "sysctl -w net.core.flow_dissector_fastpath=$sysctl" > /dev/null 2>&1
  SSH root@"$sender" "sysctl -w net.core.flow_dissector_fastpath=$sysctl" > /dev/null 2>&1
  ensure_iperf_daemons "$recv"

  start_sidecar "$sender" "/tmp/sidecar-cell${nn}-sender.csv"
  start_sidecar "$recv"   "/tmp/sidecar-cell${nn}-recv.csv"

  local exit_rc=0
  case "$proto" in
    iperf3-tcp)
      SSH root@"$sender" "$IPERF3_BIN -c $recv -t $DUR -P 4 -i 1 -J" > "$dir/iperf.json" 2>&1
      exit_rc=$?
      ;;
    iperf2-tcp)
      SSH root@"$sender" "$IPERF2_BIN -c $recv -t $DUR -P 4 -i 1 -e -y c" > "$dir/iperf.csv" 2>&1
      exit_rc=$?
      ;;
    tcpreplay-vxlan)
      local mbps=80
      # Pre-flight: drop oversized frames from the source PCAP
      # to keep tcpreplay's --duration check reliable. Idempotent;
      # only regenerates if the source is newer than the filtered.
      ensure_mtufit_pcap "$sender" "$VXLAN_PCAP_SRC" "$VXLAN_PCAP" "$SENDER_MTU"
      # mpstat captured via a long-lived nohup'd remote process
      # rather than a backgrounded ssh — the latter dropped
      # after 5-7 minutes on the original Phase I run.
      ensure_mpstat_runner "$recv" "$dir/mpstat.json" "$DUR"
      sleep 1
      # tcpreplay 4.5.2 has a known wedge: when many sends fail
      # (e.g. oversized frames > MTU), the failure path uses
      # `continue` which skips the duration check, so --duration
      # is unreliable on long runs.  Two-layer fix:
      #   1) PCAP is pre-filtered to drop frames > MTU (Phase J)
      #   2) Outer `timeout` enforces DUR + 60 s as belt+braces
      SSH root@"$sender" \
        "timeout $TCPRP_GUARD_SEC $TCPRP_BIN --intf1=end0 --mbps=$mbps --duration=$DUR --loop=0 --quiet $VXLAN_PCAP" \
        > "$dir/replay.log.tail" 2>&1
      exit_rc=$?
      stop_mpstat_runner "$recv"
      tail -25 "$dir/replay.log.tail" > "$dir/replay.log"
      rm -f "$dir/replay.log.tail"
      ;;
  esac

  stop_sidecar "$sender"
  stop_sidecar "$recv"
  pull_sidecar "$sender" "/tmp/sidecar-cell${nn}-sender.csv" "$dir/sidecar-${sender}.csv"
  pull_sidecar "$recv"   "/tmp/sidecar-cell${nn}-recv.csv"   "$dir/sidecar-${recv}.csv"

  SSH root@"$recv"   'sysctl -w net.core.flow_dissector_fastpath=0' > /dev/null 2>&1
  SSH root@"$sender" 'sysctl -w net.core.flow_dissector_fastpath=0' > /dev/null 2>&1

  python3 - "$dir" "$nn" "$sender" "$recv" "$proto" "$sysctl" "$exit_rc" <<'PYEOF' || true
import json, sys, os, csv, statistics, re
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
            intervals = [i["sum"]["bits_per_second"]/1e6 for i in d.get("intervals",[]) if "sum" in i]
            if len(intervals) >= 60:
                n=len(intervals); mean_x=(n-1)/2
                mean_y=sum(intervals)/n
                num=sum((i-mean_x)*(y-mean_y) for i,y in enumerate(intervals))
                den=sum((i-mean_x)**2 for i in range(n))
                slope = num/den if den else 0
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
        rows=[r for r in csv.reader(open(f"{dir_}/iperf.csv")) if len(r)>=10 and r[0]!="time"]
        per_sec_per_stream = [r for r in rows
                              if r[5] not in ("-1","") and r[6] != "0.0"
                              and (float(r[7])-float(r[6])) < 5.0]
        bucket = {}
        for r in per_sec_per_stream:
            try:
                t=int(float(r[6])); bucket.setdefault(t, 0); bucket[t] += float(r[9])
            except: pass
        ints = [bucket[t]/1e6 for t in sorted(bucket)]
        if ints:
            mean_y = sum(ints)/len(ints)
            result["throughput_mbps_recv"] = mean_y
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
        last = open(f"{dir_}/replay.log").read()
        m=re.search(r"Successful packets:\s+(\d+)", last)
        if m: result["tx_packets"] = int(m.group(1))
        m=re.search(r"Failed packets:\s+(\d+)", last)
        if m: result["failed_packets"] = int(m.group(1))
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

  # Restore errexit for the outer driver.
  set -e
}

# ── Drive ──────────────────────────────────────────────────────
for cell in "${CELLS[@]}"; do
  IFS='|' read -r nn sender recv proto sysctl <<< "$cell"
  run_cell "$nn" "$sender" "$recv" "$proto" "$sysctl"
done
log "=== series3-soak: all cells dispatched ==="

# ── Aggregate ──────────────────────────────────────────────────
python3 - "$OUT" <<'PYEOF'
import os, sys, json, csv, glob
out=sys.argv[1]
rows=[]
for sj in sorted(glob.glob(f"{out}/cells/*/summary.json")):
    try:
        d=json.load(open(sj))
    except Exception as e:
        rows.append({"summary_path":sj,"note":f"json read error: {e}"})
        continue
    rows.append(d)

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

log "=== series3-soak finished ==="

