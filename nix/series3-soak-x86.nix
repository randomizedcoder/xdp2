# nix/series3-soak-x86.nix
#
# Series 3 — long-running real-traffic soak for the x86 back-to-back
# pair l (generator) <-> l2 (DUT). The high-performance analogue of
# nix/series3-soak.nix (which targets the Raspberry-Pi pair fleet over
# 1 GbE); this one drives the Mellanox ConnectX-4 Lx 25 GbE link and is
# tuned to surface the flow_dissector fast-path delta on much faster
# Threadripper hosts.
#
# Differences from the Pi harness (nix/series3-soak.nix):
#   - Direction is always l -> l2, over the data-plane IP (L2_V4/L2_V6),
#     NOT the management hostname, so traffic stays on the 25 GbE link.
#   - x86 sidecar: reads /sys + /proc instead of vcgencmd (no Pi knobs),
#     keeping the SAME 4-column CSV `ts,temp,freq,throttled` so the
#     summary/aggregate Python is reused unchanged. `throttled` is a
#     synthetic 0x0/0x1 token derived from a frequency-droop check
#     (actively-cooled x86 won't thermal-throttle), preserving the
#     `thermal_clean` semantics.
#   - 12-cell matrix weighted toward CPU-bound workloads (small-packet
#     UDP, tunnelled tcpreplay) where the ~2% per-packet fast-path win
#     is observable; a 25 GbE TCP elephant is GRO/PCIe-bound and hides
#     it (kept as the no-regression control).
#   - Generator iperf/tcpreplay is `taskset`-pinned to GEN_CORES so the
#     desktop stays usable and we can prove l is not the bottleneck.
#   - No thermal gate / 300 s cool-down (irrelevant on x86).
#
# The matrix (sender=l, recv=l2 throughout):
#
#   cell  proto            ipver  sysctl  purpose
#     01  iperf3-tcp       v4     0       line-rate ref + no-regression
#     02  iperf3-tcp       v4     1
#     03  iperf3-tcp       v6     0       v6 dissect path
#     04  iperf3-tcp       v6     1
#     05  iperf3-udp       v4     0       small-packet, CPU-bound — headline
#     06  iperf3-udp       v4     1
#     07  iperf3-udp       v6     0       small-packet v6
#     08  iperf3-udp       v6     1
#     09  iperf2-tcp       v4     0       cross-check TCP stack
#     10  iperf2-tcp       v4     1
#     11  tcpreplay-vxlan  v4     0       tunnelled per-packet dissect
#     12  tcpreplay-vxlan  v4     1
#
# Usage:
#   # Default: 12 cells × 3600 s ≈ 12 h wall clock
#   L2_V4=10.10.4.5 L2_V6=fd10:10:4::5 nix run .#series3-soak-l-l2
#
#   # Smoke (validation pass): short cells
#   DUR=60 COOLDOWN=10 L2_V4=10.10.4.5 L2_V6=fd10:10:4::5 \
#     nix run .#series3-soak-l-l2
#
# Pre-conditions:
#   - root SSH from the calling host to both l and l2.
#   - BOTH l and l2 booted the series-3 patched kernel; the sysctl
#     net.core.flow_dissector_fastpath is registered (the harness
#     aborts with a clear message if absent on either host).
#   - The 25 GbE link is up (enp35s0f0np0 on both, cabled back-to-back)
#     and L2_V4 is ping-able from l.
#   - For tcpreplay cells (11, 12): l has the dst-MAC-rewritten PCAP at
#     $VXLAN_PCAP. If missing, those two cells are skipped (noted in
#     summary.json) rather than failing the run. Prepare it with:
#       tcprewrite --enet-dmac=<l2 enp35s0f0np0 MAC> \
#         --enet-smac=<l enp35s0f0np0 MAC> \
#         --infile=<source vxlan-k8s-pure.pcap> \
#         --outfile=$VXLAN_PCAP
#
# Outputs (in OUT, default perf-results/<YYYY-MM-DD>-series3-soak-l-l2/):
#   - run.log                                        master timeline
#   - series3-soak-l-l2.sh                           copy of this script
#   - cells/cell-NN-l-l2-{proto}-{ipver}-sysctl{0|1}/
#       * iperf.json / iperf.csv / replay.log / mpstat-l2.json / mpstat-l.json
#       * sidecar-l.csv  sidecar-l2.csv
#       * summary.json
#   - aggregate.csv                                  12-row table

{ pkgs }:

pkgs.writeShellApplication {
  name = "series3-soak-l-l2";

  runtimeInputs = [
    pkgs.openssh
    pkgs.coreutils
    pkgs.python3
  ];

  # SC2029: client-side $VAR expansion in ssh "..." strings is
  # intentional — we want the launcher to substitute $IPERF3_DUT,
  # $addr, $DUR, etc. before sending the command.
  # SC2064: trap-with-expanded-vars is intentional (capture $L2/$L2_DEV
  # at registration time).
  excludeShellChecks = [ "SC2029" "SC2064" ];

  text = ''
    set -u

    # ── Configuration ──────────────────────────────────────────────
    DUR=''${DUR:-3600}              # per-cell duration (sec)
    COOLDOWN=''${COOLDOWN:-30}      # inter-cell cool-down (sec)
    today=$(date +%Y-%m-%d)
    OUT=''${OUT:-perf-results/$today-series3-soak-l-l2}
    mkdir -p "$OUT/cells"

    # Hosts (SSH-reachable management names) and roles.
    L=''${L:-l}                     # generator / sender
    L2=''${L2:-l2}                  # DUT / receiver

    # Data-plane targets on the 25 GbE link (REQUIRED — traffic must go
    # over the Mellanox link, not the management interface).
    L2_V4=''${L2_V4:-}
    L2_V6=''${L2_V6:-}

    L2_DEV=''${L2_DEV:-enp35s0f0np0}   # DUT data-plane iface (cake)
    SENDER_DEV=''${SENDER_DEV:-enp35s0f0np0}  # generator iface (tcpreplay)
    LINK_RATE=''${LINK_RATE:-25Gbit}   # cake bandwidth knob
    GEN_CORES=''${GEN_CORES:-2-5}      # taskset mask for generator load
    SYSCTL_PATH=''${SYSCTL_PATH:-net.core.flow_dissector_fastpath}

    # iperf params
    TCP_PARALLEL=''${TCP_PARALLEL:-16}
    UDP_PARALLEL=''${UDP_PARALLEL:-8}
    UDP_PKTLEN=''${UDP_PKTLEN:-64}
    PORT3=''${PORT3:-5201}             # iperf3 port
    PORT2=''${PORT2:-5001}             # iperf2 port

    # tcpreplay
    VXLAN_PCAP=''${VXLAN_PCAP:-/root/replay/pcaps/vxlan-k8s-pure-l2.pcap}
    TCPRP_MBPS=''${TCPRP_MBPS:-10000}  # cap; 0 = as fast as possible
    TCPRP_GUARD_SEC=$((DUR + 60))

    if [ -z "$L2_V4" ]; then
      echo "ERROR: set L2_V4 (DUT IPv4 on the 25 GbE link, e.g. 10.10.4.5)." >&2
      echo "       Optionally set L2_V6 for the IPv6 cells." >&2
      exit 64
    fi

    # The 12-cell matrix: nn|proto|ipver|sysctl  (sender=L, recv=L2).
    CELLS=(
      "01|iperf3-tcp|v4|0"
      "02|iperf3-tcp|v4|1"
      "03|iperf3-tcp|v6|0"
      "04|iperf3-tcp|v6|1"
      "05|iperf3-udp|v4|0"
      "06|iperf3-udp|v4|1"
      "07|iperf3-udp|v6|0"
      "08|iperf3-udp|v6|1"
      "09|iperf2-tcp|v4|0"
      "10|iperf2-tcp|v4|1"
      "11|tcpreplay-vxlan|v4|0"
      "12|tcpreplay-vxlan|v4|1"
    )

    # ── Helpers ────────────────────────────────────────────────────
    SSH() { ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 "$@"; }
    ts()  { date -u +%FT%TZ; }
    log() { echo "$(ts) $*" | tee -a "$OUT/run.log"; }

    # Snapshot this script next to the results (established convention).
    cp -f "$0" "$OUT/series3-soak-l-l2.sh" 2>/dev/null || true

    # Resolve tool store paths PER host (l and l2 may be on slightly
    # different nixpkgs revisions, so do not assume a shared closure).
    IPERF3_GEN=$(SSH root@"$L"  'nix eval --raw nixpkgs#iperf3')/bin/iperf3
    IPERF3_DUT=$(SSH root@"$L2" 'nix eval --raw nixpkgs#iperf3')/bin/iperf3
    IPERF2_GEN=$(SSH root@"$L"  'nix eval --raw nixpkgs#iperf2')/bin/iperf
    IPERF2_DUT=$(SSH root@"$L2" 'nix eval --raw nixpkgs#iperf2')/bin/iperf
    TCPRP_GEN=$(SSH root@"$L"   'nix eval --raw nixpkgs#tcpreplay')/bin/tcpreplay

    # Startup guard: the patched kernel must be booted on BOTH ends so
    # the sysctl exists; A/B is meaningless otherwise.
    for h in "$L" "$L2"; do
      if ! SSH root@"$h" "sysctl -n $SYSCTL_PATH" >/dev/null 2>&1; then
        echo "ERROR: sysctl '$SYSCTL_PATH' missing on $h." >&2
        echo "       Boot the series-3 patched kernel there first." >&2
        exit 2
      fi
    done

    log "=== series3-soak-l-l2 start  DUR=$DUR  COOLDOWN=$COOLDOWN  cells=''${#CELLS[@]}  OUT=$OUT ==="
    log "  L(gen)=$L  L2(dut)=$L2  L2_DEV=$L2_DEV  LINK_RATE=$LINK_RATE  GEN_CORES=$GEN_CORES"
    log "  L2_V4=$L2_V4  L2_V6=''${L2_V6:-<unset>}"
    log "  IPERF3_GEN=$IPERF3_GEN  IPERF3_DUT=$IPERF3_DUT"

    # cake on the DUT egress; torn down once at exit.
    cleanup() {
      SSH root@"$L2" "tc qdisc del dev $L2_DEV root" >/dev/null 2>&1 || true
      SSH root@"$L"  "sysctl -w $SYSCTL_PATH=0" >/dev/null 2>&1 || true
      SSH root@"$L2" "sysctl -w $SYSCTL_PATH=0" >/dev/null 2>&1 || true
      SSH root@"$L2" "pkill iperf3 2>/dev/null; pkill iperf 2>/dev/null" >/dev/null 2>&1 || true
    }
    trap cleanup EXIT

    # x86 sidecar: 1 Hz CSV `ts,temp,freq,throttled`. temp = hottest
    # thermal zone (°C); freq = cpu0 cur freq (kHz); throttled = 0x1 if
    # freq dropped below 90% of max this sample, else 0x0 (so the
    # existing throttle-decode treats steady frequency as "clean").
    start_sidecar() {
      local host="$1" remote_path="$2"
      ssh -o BatchMode=yes -o ConnectTimeout=10 root@"$host" "cat > /tmp/sidecar-x86.sh" <<'SIDECAR'
    #!/usr/bin/env bash
    while true; do
      ts=$(date +%s)
      max=0
      for z in /sys/class/thermal/thermal_zone*/temp; do
        [ -r "$z" ] || continue
        v=$(cat "$z" 2>/dev/null) || continue
        [ "$v" -gt "$max" ] && max="$v"
      done
      temp=NA
      [ "$max" -gt 0 ] && temp=$(awk "BEGIN{printf \"%.1f\", $max/1000}")
      freq=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null || echo 0)
      mx=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null || echo 0)
      thr=0x0
      if [ "$freq" -gt 0 ] && [ "$mx" -gt 0 ] && [ "$freq" -lt $((mx*90/100)) ]; then thr=0x1; fi
      echo "$ts,$temp,$freq,$thr"
      sleep 1
    done
    SIDECAR
      SSH root@"$host" "chmod +x /tmp/sidecar-x86.sh; nohup bash /tmp/sidecar-x86.sh > $remote_path 2>/dev/null </dev/null & disown" >/dev/null 2>&1
    }

    stop_sidecar() {
      SSH root@"$1" 'pkill -f /tmp/sidecar-x86.sh 2>/dev/null' >/dev/null 2>&1 || true
    }

    pull_sidecar() {
      SSH root@"$1" "cat $2" > "$3" 2>/dev/null || true
    }

    # Open iperf firewall ports on the DUT (v4 + v6 — NixOS firewall is
    # family-specific).
    ensure_fw() {
      SSH root@"$L2" "
        for p in $PORT3 $PORT2; do
          iptables  -C nixos-fw -p tcp --dport \$p -j ACCEPT 2>/dev/null || iptables  -I nixos-fw 1 -p tcp --dport \$p -j ACCEPT
          iptables  -C nixos-fw -p udp --dport \$p -j ACCEPT 2>/dev/null || iptables  -I nixos-fw 1 -p udp --dport \$p -j ACCEPT
          ip6tables -C nixos-fw -p tcp --dport \$p -j ACCEPT 2>/dev/null || ip6tables -I nixos-fw 1 -p tcp --dport \$p -j ACCEPT
          ip6tables -C nixos-fw -p udp --dport \$p -j ACCEPT 2>/dev/null || ip6tables -I nixos-fw 1 -p udp --dport \$p -j ACCEPT
        done
      " >/dev/null 2>&1 || true
    }

    # mpstat on a host for $1=host $2=dur $3=tag (remote temp file
    # /tmp/mpstat-<tag>.json), pulled later by stop_mpstat.
    start_mpstat() {
      local host="$1" dur="$2" tag="$3"
      ssh -o BatchMode=yes -o ConnectTimeout=10 root@"$host" "cat > /tmp/mpstat-$tag.sh" <<'MPSTAT'
    #!/usr/bin/env bash
    DUR="$1"; OUT="$2"
    exec nix shell nixpkgs#sysstat -c mpstat -P ALL 1 "$DUR" -o JSON > "$OUT" 2>&1
    MPSTAT
      SSH root@"$host" "chmod +x /tmp/mpstat-$tag.sh; nohup bash /tmp/mpstat-$tag.sh $dur /tmp/mpstat-$tag.json >/dev/null 2>&1 </dev/null & disown" >/dev/null 2>&1
    }

    stop_mpstat() {
      local host="$1" tag="$2" local_path="$3"
      SSH root@"$host" "pkill -f /tmp/mpstat-$tag.sh 2>/dev/null; pkill -f 'mpstat -P ALL 1' 2>/dev/null" >/dev/null 2>&1 || true
      SSH root@"$host" "cat /tmp/mpstat-$tag.json" > "$local_path" 2>/dev/null || true
    }

    # ── Per-cell runner ────────────────────────────────────────────
    run_cell() {
      local nn="$1" proto="$2" ipver="$3" sysctl="$4"
      local dir="$OUT/cells/cell-''${nn}-l-l2-''${proto}-''${ipver}-sysctl''${sysctl}"

      if [ -e "$dir/summary.json" ]; then
        log "[cell $nn] SKIP — summary.json already exists at $dir"
        return 0
      fi
      mkdir -p "$dir"

      local addr
      if [ "$ipver" = "v6" ]; then addr="$L2_V6"; else addr="$L2_V4"; fi
      if [ -z "$addr" ]; then
        log "[cell $nn] SKIP — no $ipver address configured (L2_V6 unset)"
        python3 -c "import json,sys; json.dump({'nn':sys.argv[1],'proto':sys.argv[2],'ipver':sys.argv[3],'sysctl':int(sys.argv[4]),'note':'skipped: no '+sys.argv[3]+' address','thermal_clean':True}, open(sys.argv[5],'w'), indent=2)" "$nn" "$proto" "$ipver" "$sysctl" "$dir/summary.json"
        return 0
      fi

      log "[cell $nn] start  proto=$proto  ipver=$ipver  addr=$addr  sysctl=$sysctl"
      set +e   # one transient SSH non-zero must not kill the whole soak

      SSH root@"$L"  "sysctl -w $SYSCTL_PATH=$sysctl" >/dev/null 2>&1
      SSH root@"$L2" "sysctl -w $SYSCTL_PATH=$sysctl" >/dev/null 2>&1
      SSH root@"$L2" "tc qdisc replace dev $L2_DEV root cake bandwidth $LINK_RATE triple-isolate" >/dev/null 2>&1
      ensure_fw

      start_sidecar "$L"  "/tmp/sidecar-cell''${nn}-l.csv"
      start_sidecar "$L2" "/tmp/sidecar-cell''${nn}-l2.csv"

      local exit_rc=0
      case "$proto" in
        iperf3-tcp)
          SSH root@"$L2" "pkill iperf3 2>/dev/null; $IPERF3_DUT -s -B $addr -p $PORT3 -D" >/dev/null 2>&1
          sleep 2
          SSH root@"$L" "taskset -c $GEN_CORES $IPERF3_GEN -c $addr -p $PORT3 -t $DUR -P $TCP_PARALLEL -i 1 -J" > "$dir/iperf.json" 2>&1
          exit_rc=$?
          SSH root@"$L2" "pkill iperf3 2>/dev/null" >/dev/null 2>&1
          ;;
        iperf3-udp)
          SSH root@"$L2" "pkill iperf3 2>/dev/null; $IPERF3_DUT -s -B $addr -p $PORT3 -D" >/dev/null 2>&1
          sleep 2
          start_mpstat "$L2" "$DUR" "l2"
          start_mpstat "$L"  "$DUR" "l"
          sleep 1
          SSH root@"$L" "taskset -c $GEN_CORES $IPERF3_GEN -c $addr -p $PORT3 -u -b 0 -l $UDP_PKTLEN -P $UDP_PARALLEL -t $DUR -i 1 -J" > "$dir/iperf.json" 2>&1
          exit_rc=$?
          stop_mpstat "$L2" "l2" "$dir/mpstat-l2.json"
          stop_mpstat "$L"  "l"  "$dir/mpstat-l.json"
          SSH root@"$L2" "pkill iperf3 2>/dev/null" >/dev/null 2>&1
          ;;
        iperf2-tcp)
          SSH root@"$L2" "pkill -x iperf 2>/dev/null; $IPERF2_DUT -s -B $addr -p $PORT2 -D" >/dev/null 2>&1
          sleep 2
          SSH root@"$L" "taskset -c $GEN_CORES $IPERF2_GEN -c $addr -p $PORT2 -t $DUR -P $TCP_PARALLEL -i 1 -e -y c" > "$dir/iperf.csv" 2>&1
          exit_rc=$?
          SSH root@"$L2" "pkill -x iperf 2>/dev/null" >/dev/null 2>&1
          ;;
        tcpreplay-vxlan)
          if ! SSH root@"$L" "test -e $VXLAN_PCAP"; then
            log "[cell $nn] SKIP tcpreplay — $VXLAN_PCAP missing on $L"
            exit_rc=0
            echo "skipped: $VXLAN_PCAP missing on $L" > "$dir/replay.log"
          else
            start_mpstat "$L2" "$DUR" "l2"
            sleep 1
            SSH root@"$L" \
              "taskset -c $GEN_CORES timeout $TCPRP_GUARD_SEC $TCPRP_GEN --intf1=$SENDER_DEV --mbps=$TCPRP_MBPS --duration=$DUR --loop=0 --quiet $VXLAN_PCAP" \
              > "$dir/replay.log.tail" 2>&1
            exit_rc=$?
            stop_mpstat "$L2" "l2" "$dir/mpstat-l2.json"
            tail -25 "$dir/replay.log.tail" > "$dir/replay.log" 2>/dev/null
            rm -f "$dir/replay.log.tail"
          fi
          ;;
      esac

      stop_sidecar "$L"
      stop_sidecar "$L2"
      pull_sidecar "$L"  "/tmp/sidecar-cell''${nn}-l.csv"  "$dir/sidecar-l.csv"
      pull_sidecar "$L2" "/tmp/sidecar-cell''${nn}-l2.csv" "$dir/sidecar-l2.csv"

      SSH root@"$L"  "sysctl -w $SYSCTL_PATH=0" >/dev/null 2>&1
      SSH root@"$L2" "sysctl -w $SYSCTL_PATH=0" >/dev/null 2>&1

      python3 - "$dir" "$nn" "$L" "$L2" "$proto" "$ipver" "$sysctl" "$exit_rc" <<'PYEOF' || true
    import json, sys, os, csv, statistics, re
    dir_, nn, sender, recv, proto, ipver, sysctl, exit_rc = sys.argv[1:9]

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

    s_send = parse_sidecar(f"{dir_}/sidecar-l.csv")
    s_recv = parse_sidecar(f"{dir_}/sidecar-l2.csv")

    result = {"nn":nn,"sender":sender,"recv":recv,"proto":proto,"ipver":ipver,
              "sysctl":int(sysctl),"exit_rc":int(exit_rc),
              "sender_sidecar":s_send,"recv_sidecar":s_recv}

    def drift_block(intervals, mean_y, res):
        if len(intervals) >= 60:
            n=len(intervals); mean_x=(n-1)/2
            num=sum((i-mean_x)*(y-mean_y) for i,y in enumerate(intervals))
            den=sum((i-mean_x)**2 for i in range(n))
            slope = num/den if den else 0
            res["drift_pct_per_hour"] = 100*slope*3600/mean_y if mean_y else 0
            res["thr_p50"] = statistics.median(intervals)
            res["thr_min"] = min(intervals)
            res["thr_max"] = max(intervals)
            res["thr_stdev"] = statistics.stdev(intervals)
            res["thr_cv_pct"] = 100*res["thr_stdev"]/mean_y if mean_y else 0

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
                if intervals: drift_block(intervals, sum(intervals)/len(intervals), result)
        except Exception as e:
            result["note"] = f"iperf3-tcp parse error: {e}"
    elif proto=="iperf3-udp":
        try:
            d=json.load(open(f"{dir_}/iperf.json"))
            if "error" in d:
                result["note"]=f"iperf3 error: {d['error']}"
            else:
                summ = d["end"]["sum"]
                secs = summ.get("seconds") or 1
                result["throughput_mbps_recv"] = summ["bits_per_second"]/1e6
                result["lost_percent"] = summ.get("lost_percent")
                result["packets"] = summ.get("packets")
                result["lost_packets"] = summ.get("lost_packets")
                result["pps"] = (summ.get("packets") or 0)/secs
                result["jitter_ms"] = summ.get("jitter_ms")
                cpu = d["end"].get("cpu_utilization_percent",{})
                result["cpu_recv_pct"] = cpu.get("remote_total")
                result["cpu_send_pct"] = cpu.get("host_total")
                intervals = [i["sum"]["bits_per_second"]/1e6 for i in d.get("intervals",[]) if "sum" in i]
                if intervals: drift_block(intervals, sum(intervals)/len(intervals), result)
        except Exception as e:
            result["note"] = f"iperf3-udp parse error: {e}"
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
                drift_block(ints, mean_y, result)
            agg = [r for r in rows if r[5] == "-1" and r[6] == "0.0"]
            if agg:
                result["throughput_mbps_recv_agg"] = float(agg[-1][9])/1e6
        except Exception as e:
            result["note"] = f"iperf2 parse error: {e}"
    elif proto=="tcpreplay-vxlan":
        try:
            last = open(f"{dir_}/replay.log").read()
            if "skipped:" in last:
                result["note"] = last.strip()
            else:
                m=re.search(r"Successful packets:\s+(\d+)", last)
                if m: result["tx_packets"] = int(m.group(1))
                m=re.search(r"Failed packets:\s+(\d+)", last)
                if m: result["failed_packets"] = int(m.group(1))
            if os.path.exists(f"{dir_}/mpstat-l2.json"):
                d=json.load(open(f"{dir_}/mpstat-l2.json"))
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
      log "[cell $nn] cool-down ''${COOLDOWN}s ..."
      sleep "$COOLDOWN"
      set -e
    }

    # ── Drive ──────────────────────────────────────────────────────
    for cell in "''${CELLS[@]}"; do
      IFS='|' read -r nn proto ipver sysctl <<< "$cell"
      run_cell "$nn" "$proto" "$ipver" "$sysctl"
    done
    log "=== series3-soak-l-l2: all cells dispatched ==="

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

    fields=["nn","proto","ipver","sysctl",
            "throughput_mbps_recv","pps","lost_percent","retransmits",
            "cpu_recv_pct","cpu_send_pct","cpu_recv_mean_pct",
            "thr_p50","thr_min","thr_max","thr_cv_pct","drift_pct_per_hour",
            "tx_packets","failed_packets",
            "max_temp_recv","max_temp_send","throttled_recv","throttled_send",
            "thermal_clean","note"]
    with open(f"{out}/aggregate.csv","w") as f:
        w=csv.writer(f); w.writerow(fields)
        for r in rows:
            rs=r.get("recv_sidecar",{}); ss=r.get("sender_sidecar",{})
            row=[r.get("nn"),r.get("proto"),r.get("ipver"),r.get("sysctl"),
                 r.get("throughput_mbps_recv"),r.get("pps"),r.get("lost_percent"),r.get("retransmits"),
                 r.get("cpu_recv_pct"),r.get("cpu_send_pct"),r.get("cpu_recv_mean_pct"),
                 r.get("thr_p50"),r.get("thr_min"),r.get("thr_max"),r.get("thr_cv_pct"),r.get("drift_pct_per_hour"),
                 r.get("tx_packets"),r.get("failed_packets"),
                 rs.get("max_temp"),ss.get("max_temp"),
                 "|".join(rs.get("throttled_observed",[])),
                 "|".join(ss.get("throttled_observed",[])),
                 r.get("thermal_clean"),r.get("note","")]
            w.writerow(row)
    print(f"wrote {out}/aggregate.csv ({len(rows)} rows)")
    PYEOF

    log "=== series3-soak-l-l2 finished ==="
  '';
}
