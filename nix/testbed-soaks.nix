# Long-running TCP/UDP soak scripts for the xdp2 physical testbeds.
#
# Packages the iperf3 and iperf2 soak patterns we validated in May 2026
# (perf-results/2026-05-25/) as flake outputs. Same shape for both
# pairs (hp2-hp5-x710 i40e 10 GbE, hp1-hp3-mlx5 25 GbE) — caller passes
# the per-pair parameters as environment variables.
#
# Usage from the workstation:
#   PAIR=hp2-hp5-x710 GEN=hp2 DUT=hp5 \
#     DUT_IP4=10.10.0.5 DEV=enp1s0f0np0 BANDWIDTH=10Gbit DURATION=86400 \
#     nix run .#soak-iperf3
#
#   PAIR=hp1-hp3-mlx5 GEN=hp1 DUT=hp3 \
#     DUT_IP4=10.10.2.3 DEV=enp1s0f0np0 BANDWIDTH=25Gbit DURATION=86400 \
#     nix run .#soak-iperf2
#
# Logs land in /tmp/soak-${PAIR}-{main,snapshot}.log. Server runs in
# a held-open ssh from the launcher script (validated B.2 pattern).
#
# IPv6 mode: set DUT_IP6 instead of DUT_IP4 (and -V on iperf2). The
# launcher detects which is set.

{ pkgs, lib }:

let
  # iperf2 binary path (used by client + server). Resolved at build
  # time, baked into the launcher.
  iperf2 = "${pkgs.iperf2}/bin/iperf";

  # Helper: shell that holds env-var defaults, useful preamble.
  preamble = ''
    PAIR="''${PAIR:?must set PAIR (e.g. hp2-hp5-x710)}"
    GEN="''${GEN:?must set GEN (generator host, e.g. hp2)}"
    DUT="''${DUT:?must set DUT (DUT host, e.g. hp5)}"
    DEV="''${DEV:?must set DEV (DUT NIC, e.g. enp1s0f0np0)}"
    BANDWIDTH="''${BANDWIDTH:?must set BANDWIDTH (e.g. 10Gbit, 25Gbit)}"
    DURATION="''${DURATION:-86400}"
    SESSION_LEN="''${SESSION_LEN:-300}"

    : "''${DUT_IP4:=}"
    : "''${DUT_IP6:=}"
    if [[ -z "$DUT_IP4" && -z "$DUT_IP6" ]]; then
      echo "ERROR: set DUT_IP4 or DUT_IP6 (or both)" >&2
      exit 1
    fi

    LOG_DIR="''${LOG_DIR:-/tmp}"
    MAIN_LOG="$LOG_DIR/soak-$PAIR-main.log"
    SNAP_LOG="$LOG_DIR/soak-$PAIR-snapshot.log"

    apply_tcp_tuning() {
      local h="$1"
      ssh "root@$h" '
        sysctl -w net.ipv4.tcp_rto_min_us=5000 \
                  net.ipv4.tcp_no_metrics_save=1 \
                  net.ipv4.tcp_slow_start_after_idle=0 \
                  net.ipv4.tcp_autocorking=0
      ' >/dev/null 2>&1 && echo "$h: TCP tuned"
    }
  '';

  # iperf3 soak — uses the JSON-output pattern, single-threaded server.
  soakIperf3 = pkgs.writeShellApplication {
    name = "soak-iperf3";
    runtimeInputs = with pkgs; [ iperf3 openssh coreutils gnugrep gawk python3 ];
    # SC2029: ssh-with-local-var expansion is intentional — we want
    # the workstation to substitute $DEV, $BANDWIDTH, etc. before
    # sending the command string.
    excludeShellChecks = [ "SC2029" ];
    text = ''
      ${preamble}

      exec > >(tee "$MAIN_LOG") 2>&1
      echo "=== iperf3 soak ($PAIR) — $(date) ==="
      echo "GEN=$GEN  DUT=$DUT  DEV=$DEV  BW=$BANDWIDTH  DURATION=${"\$"}{DURATION}s"

      apply_tcp_tuning "$GEN"
      apply_tcp_tuning "$DUT"

      # Cake + server on DUT
      ssh "root@$DUT" "
        tc qdisc replace dev $DEV root cake bandwidth $BANDWIDTH triple-isolate
        pkill iperf3 2>/dev/null; sleep 1
        nix run nixpkgs#iperf3 -- -s -B ${"\$"}{DUT_IP4:-${"\$"}{DUT_IP6}} -p 5201 -D
        sleep 2
        pgrep -af iperf3 | head -2
      " | tail -3

      START=$(date +%s)
      END=$((START + DURATION))

      # Hourly snapshot collector
      (
        echo "ts hour gbits retx cake_bytes cake_drops cake_requeues rss_mb dmesg_alerts" > "$SNAP_LOG"
        HOUR=0
        while [[ $(date +%s) -lt $END ]]; do
          HOUR=$((HOUR+1))
          sleep 3600
          NOW=$(date +%s)
          GBITS=$(grep -E "^[0-9]+ +[0-9]+\.[0-9]+" "$MAIN_LOG" | tail -1 | awk '{print $2}')
          STATS=$(ssh "root@$DUT" "tc -s qdisc show dev $DEV | head -3" 2>/dev/null)
          PKTS=$(echo "$STATS" | grep -oP 'Sent.*?(\d+) pkt' | grep -oP '\d+' | head -1)
          DROPS=$(echo "$STATS" | grep -oP 'dropped \K\d+' | head -1)
          REQ=$(echo "$STATS" | grep -oP 'requeues \K\d+' | head -1)
          MEM=$(ssh "root@$DUT" "free -m | awk '/^Mem:/ {print \$3}'" 2>/dev/null)
          ALERTS=$(ssh "root@$DUT" "dmesg -t | grep -ciE 'WARN|BUG|oops|sch_cake|flow_hash|flow_dissect'" 2>/dev/null)
          echo "$NOW $HOUR ''${GBITS:-NA} NA ''${PKTS:-NA} ''${DROPS:-NA} ''${REQ:-NA} ''${MEM:-NA} ''${ALERTS:-NA}" >> "$SNAP_LOG"
          echo "[hour $HOUR] $(tail -1 "$SNAP_LOG")"
        done
      ) &
      SNAP_PID=$!

      echo ""
      echo "=== rolling iperf3 sessions ($SESSION_LEN s each, -P 16) ==="
      echo "run gbits retx ts"
      RUN=0
      while [[ $(date +%s) -lt $END ]]; do
        RUN=$((RUN+1))
        TARGET="''${DUT_IP4:-${"\$"}{DUT_IP6}}"
        OUT=$(ssh "root@$GEN" "nix run nixpkgs#iperf3 -- -c $TARGET -p 5201 -t $SESSION_LEN -P 16 -O 5 -J")
        echo "$OUT" > "$LOG_DIR/soak-$PAIR-iperf3-$RUN.json"
        python3 -c "
import json, sys, time
r = json.loads('''$OUT''')
g = r['end']['sum_received']['bits_per_second']/1e9
rx = r['end']['sum_sent']['retransmits']
print(f'$RUN {g:.3f} {rx} {int(time.time())}')
" 2>/dev/null || echo "$RUN parse-failed $(date +%s)"
        sleep 5
      done

      kill $SNAP_PID 2>/dev/null
      ssh "root@$DUT" "pkill iperf3; tc qdisc del dev $DEV root" >/dev/null 2>&1
      echo "=== soak ended $(date) ==="
    '';
  };

  # iperf2 soak — uses held-open ssh for server, parses [SUM] line.
  soakIperf2 = pkgs.writeShellApplication {
    name = "soak-iperf2";
    runtimeInputs = with pkgs; [ iperf2 openssh coreutils gnugrep gawk ];
    # SC2029: same intentional client-side expansion as iperf3 soak.
    # SC2064: trap-with-expanded-vars is intentional — we want the
    # current $SRV_SSH_PID / $IPERF / $DUT / $DEV captured at trap
    # registration time.
    excludeShellChecks = [ "SC2029" "SC2064" ];
    text = ''
      ${preamble}

      exec > >(tee "$MAIN_LOG") 2>&1
      echo "=== iperf2 soak ($PAIR) — $(date) ==="
      echo "GEN=$GEN  DUT=$DUT  DEV=$DEV  BW=$BANDWIDTH  DURATION=${"\$"}{DURATION}s"

      apply_tcp_tuning "$GEN"
      apply_tcp_tuning "$DUT"

      # Resolve iperf2 path on the hosts (binary cached identically).
      IPERF=$(ssh "root@$DUT" "nix eval --raw nixpkgs#iperf2")/bin/iperf
      echo "iperf2 binary: $IPERF"

      ssh "root@$DUT" "
        tc qdisc replace dev $DEV root cake bandwidth $BANDWIDTH triple-isolate
        pgrep -f \"$IPERF.*-s\" | xargs -r kill -9 2>/dev/null; sleep 1
        echo 'cake + prior-server-cleared'
      " | tail -1

      ssh "root@$DUT" "$IPERF -s -B ''${DUT_IP4:-${"\$"}{DUT_IP6}} -p 5202" > "$SRV_LOG" 2>&1 &
      SRV_SSH_PID=$!
      trap "kill $SRV_SSH_PID 2>/dev/null; ssh root@$DUT \"pgrep -f '$IPERF.*-s' | xargs -r kill -9 2>/dev/null; tc qdisc del dev $DEV root\" >/dev/null 2>&1" EXIT
      sleep 3
      if ! ssh "root@$DUT" "ss -tlnp 2>&1 | grep -q ':5202'"; then
        echo "ERROR: iperf2 server not listening on 5202. Aborting."
        cat "$SRV_LOG"
        exit 1
      fi
      echo "server listening on $DUT:5202 (local ssh PID $SRV_SSH_PID)"

      START=$(date +%s)
      END=$((START + DURATION))

      # Hourly snapshot (same shape as iperf3 soak)
      (
        echo "ts hour gbits cake_bytes cake_drops cake_requeues rss_mb dmesg_alerts" > "$SNAP_LOG"
        HOUR=0
        while [[ $(date +%s) -lt $END ]]; do
          HOUR=$((HOUR+1))
          sleep 3600
          NOW=$(date +%s)
          GBITS=$(grep -E "^[0-9]+ +[0-9]+\.[0-9]+" "$MAIN_LOG" | tail -1 | awk '{print $2}')
          STATS=$(ssh "root@$DUT" "tc -s qdisc show dev $DEV | head -3" 2>/dev/null)
          PKTS=$(echo "$STATS" | grep -oP 'Sent.*?(\d+) pkt' | grep -oP '\d+' | head -1)
          DROPS=$(echo "$STATS" | grep -oP 'dropped \K\d+' | head -1)
          REQ=$(echo "$STATS" | grep -oP 'requeues \K\d+' | head -1)
          MEM=$(ssh "root@$DUT" "free -m | awk '/^Mem:/ {print \$3}'" 2>/dev/null)
          ALERTS=$(ssh "root@$DUT" "dmesg -t | grep -ciE 'WARN|BUG|oops|sch_cake|flow_hash|flow_dissect'" 2>/dev/null)
          echo "$NOW $HOUR ''${GBITS:-NA} ''${PKTS:-NA} ''${DROPS:-NA} ''${REQ:-NA} ''${MEM:-NA} ''${ALERTS:-NA}" >> "$SNAP_LOG"
          echo "[hour $HOUR] $(tail -1 "$SNAP_LOG")"
        done
      ) &
      SNAP_PID=$!

      echo ""
      echo "=== rolling iperf2 sessions ($SESSION_LEN s each, -P 16) ==="
      echo "run gbits ts"
      RUN=0
      while [[ $(date +%s) -lt $END ]]; do
        RUN=$((RUN+1))
        TARGET="''${DUT_IP4:-${"\$"}{DUT_IP6}}"
        V6_FLAG=""
        if [[ -n "''${DUT_IP6:-}" && -z "''${DUT_IP4:-}" ]]; then V6_FLAG="-V"; fi
        OUT=$(ssh "root@$GEN" "$IPERF -c $TARGET -p 5202 -P 16 -t $SESSION_LEN -f m $V6_FLAG" 2>&1)
        GBITS=$(echo "$OUT" | awk '
          /^\[SUM\]/ { val=$(NF-1); unit=$NF;
            if (unit ~ /^Gbits/) print val;
            else if (unit ~ /^Mbits/) printf "%.3f", val/1000;
            else print "NA";
            exit }')
        printf "%d %s %d\n" "$RUN" "''${GBITS:-NA}" "$(date +%s)"
        sleep 5
      done

      kill $SNAP_PID 2>/dev/null
      echo "=== soak ended $(date) ==="
    '';
  };

in {
  inherit soakIperf3 soakIperf2;
}
