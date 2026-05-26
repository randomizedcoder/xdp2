#!/bin/bash
# Phase B.2: 24h iperf2 soak on patched kernel.
# Fire after B.1 completes (~22:06 PDT 2026-05-25). Do NOT launch
# while B.1 still consumes the hp1<->hp3 link.
#
# Differs from B.1 in:
#   - iperf 2.2.1 (not iperf3) - multi-threaded server, exercises
#     scheduler+TCP stack differently from iperf3's single-threaded
#     model. Catches kernel bugs iperf3 misses.
#   - Rolling 300s sessions like B.1 to allow connection cycling.
#   - Port 5202 (not 5201) to avoid clash with B.1 server if still up.
#   - Forward-only (no -d). The earlier "TCP write failed" report
#     in summaries appears to have been a fix-or-recover incident,
#     not iperf2's fault; A.1b ran 10 clean -P 16 forward sessions.
#     If we want bidirectional, run a separate -r (reverse, sequential)
#     phase rather than -d (concurrent bidirectional, historically
#     thread-bug-prone on heavy load even in modern iperf2).
#
# Output parsing: aggregate the [SUM] line ONCE per run. Earlier
# A.1b grep parsed multiple Sum lines including per-interval reports,
# inflating numbers 2-3x. Use awk on the final [SUM] only.
#
# Run pattern (matches B.1): 300s session, 5s gap, repeat for 24h.

LOG=/tmp/soak_iperf2_main.log
SNAPSHOT=/tmp/soak_iperf2_snapshot.log
DURATION=86400   # 24h
SESSION_LEN=300  # 5 min per iperf2 invocation

exec > >(tee "$LOG") 2>&1
echo "=== 24h iperf2 soak on patched kernel - started $(date) ==="

# Apply tuned TCP (idempotent; safe to re-apply)
TUNE='sysctl -w net.ipv4.tcp_rto_min_us=5000 net.ipv4.tcp_no_metrics_save=1 net.ipv4.tcp_slow_start_after_idle=0 net.ipv4.tcp_autocorking=0 >/dev/null 2>&1; echo tuned'
for h in hp1 hp3; do ssh root@$h "$TUNE" | tail -1; done

# Sanity: confirm B.1 is really gone. pgrep returns 0 if found, 1 if not;
# DON'T pipe to head — head always exits 0 even on empty input, defeating
# the check. Use pgrep's own exit code via "if ssh ... pgrep ..." directly.
if ssh root@hp1 'pgrep -x iperf3 >/dev/null'; then
    echo "ERROR: iperf3 still running on hp1 - B.1 has not finished yet. Aborting."
    exit 1
fi
if ssh root@hp3 'pgrep -x iperf3 >/dev/null'; then
    echo "ERROR: iperf3 still running on hp3 - B.1 has not finished yet. Aborting."
    exit 1
fi

# Resolve the iperf2 binary on hp3 (the nix store path is stable across
# both hosts via the binary cache). Direct binary path avoids two pitfalls:
#  - nix shell would daemonize via -D but the shell exits early, killing -D child
#  - pkill -f on the binary path is unambiguous and doesn't match the launcher
IPERF=$(ssh root@hp3 'nix eval --raw nixpkgs#iperf2' 2>/dev/null)/bin/iperf
echo "iperf2 binary: $IPERF"

# Cake + iperf2 server on hp3. Kill prior server by binary path (won't
# match this script's bash command line — different argv) before starting.
# Server runs in background of a held-open ssh from the local launcher
# (the parent script). This is the same lifecycle pattern we validated
# in the pre-soak 5x60s runs.
ssh root@hp3 "
  tc qdisc replace dev enp1s0f0np0 root cake bandwidth 25Gbit triple-isolate
  pgrep -f '${IPERF}.*-s' | xargs -r kill -9 2>/dev/null
  sleep 1
  echo 'cake + server-killed'
" 2>&1 | tail -2

# Start the persistent server in local-shell background. The ssh holds
# the connection open for the duration of the soak; the script's exit
# trap below kills it cleanly.
ssh root@hp3 "${IPERF} -s -B 10.10.2.3 -p 5202" > /tmp/soak_iperf2_srv.log 2>&1 &
SRV_SSH_PID=$!
trap "kill $SRV_SSH_PID 2>/dev/null; ssh root@hp3 \"pgrep -f '${IPERF}.*-s' | xargs -r kill -9 2>/dev/null; tc qdisc del dev enp1s0f0np0 root\" >/dev/null 2>&1" EXIT
sleep 3
# Verify server actually listening
if ! ssh root@hp3 "ss -tlnp 2>&1 | grep -q ':5202'"; then
    echo "ERROR: iperf2 server not listening on 5202. Aborting."
    cat /tmp/soak_iperf2_srv.log
    exit 1
fi
echo "iperf2 server listening on hp3:5202 (local ssh PID $SRV_SSH_PID)"

START=$(date +%s)
END=$((START + DURATION))

# Hourly snapshot collector
(
  echo "ts hour gbit_s cake_sent_pkts cake_drops cake_requeues mem_used_MB tcp_retx dmesg_alerts" > "$SNAPSHOT"
  HOUR=0
  while [ $(date +%s) -lt $END ]; do
    HOUR=$((HOUR+1))
    sleep 3600
    NOW=$(date +%s)
    # Most recent per-run summary throughput
    LAST_GBITS=$(grep -E "^[0-9]+\s+[0-9]+\.[0-9]+\s+Gbit/s" "$LOG" | tail -1 | awk '{print $2}')
    CAKE_STATS=$(ssh root@hp3 "tc -s qdisc show dev enp1s0f0np0 | head -3" 2>/dev/null)
    PKTS=$(echo "$CAKE_STATS" | grep -oP 'Sent.*?(\d+) pkt' | grep -oP '\d+' | head -1)
    DROPS=$(echo "$CAKE_STATS" | grep -oP 'dropped \K\d+' | head -1)
    REQUEUES=$(echo "$CAKE_STATS" | grep -oP 'requeues \K\d+' | head -1)
    MEM=$(ssh root@hp3 "free -m | awk '/^Mem:/ {print \$3}'" 2>/dev/null)
    TCPRTX=$(ssh root@hp3 "grep '^Tcp: [0-9]' /proc/net/snmp | tail -1 | awk '{print \$13}'" 2>/dev/null)
    DMESG_ALERTS=$(ssh root@hp3 "dmesg -t | grep -ciE 'WARN|BUG|oops|sch_cake|flow_hash'" 2>/dev/null)
    echo "$NOW $HOUR ${LAST_GBITS:-NA} ${PKTS:-NA} ${DROPS:-NA} ${REQUEUES:-NA} ${MEM:-NA} ${TCPRTX:-NA} ${DMESG_ALERTS:-NA}" >> "$SNAPSHOT"
    echo "[$(date -u +%H:%MZ) hour $HOUR] $(tail -1 "$SNAPSHOT")"
  done
) &
SNAP_PID=$!

# Rolling iperf2 sessions
echo ""
echo "=== rolling iperf2 sessions (${SESSION_LEN}s each, -P 16 forward) ==="
echo "run gbit_s ts"
RUN=0
while [ $(date +%s) -lt $END ]; do
  RUN=$((RUN+1))
  # IMPORTANT: capture the iperf2 output via ssh's stdout (NOT via
  # a redirect inside the remote command). A redirect inside the
  # quoted ssh command would write to hp1's /tmp, not locally —
  # this was the B.1 script's bug (JSONs landed on hp1, local
  # parser saw nothing).
  OUT=$(ssh root@hp1 "${IPERF} -c 10.10.2.3 -p 5202 -P 16 -t $SESSION_LEN -f m" 2>&1)
  # Parse ONLY the final [SUM] line. Without -i, iperf2 prints
  # per-thread totals + ONE final [SUM] cumulative line. (-i 0 is
  # NOT a "suppress" flag in iperf2 — it actually emits every
  # interval; tested 2026-05-24.)
  # Format example: "[SUM]   0.0-300.0 sec  ...  16384 MBytes  16.2 Gbits/sec"
  # Convert Mbits/Gbits to Gbit/s uniformly.
  GBITS=$(echo "$OUT" | awk '
    /^\[SUM\]/ {
      # Last 2 fields are <value> <unit>; unit may be Mbits/sec or Gbits/sec
      val = $(NF-1); unit = $NF;
      if (unit ~ /^Gbits/) print val;
      else if (unit ~ /^Mbits/) printf "%.3f", val/1000;
      else print "NA";
      exit
    }
  ')
  printf "%d %s %d\n" "$RUN" "${GBITS:-NA}" "$(date +%s)"
  sleep 5
done

# Cleanup
kill $SNAP_PID 2>/dev/null
# The EXIT trap (set earlier) handles iperf2 server + cake qdisc cleanup
echo "=== Soak ended $(date) ==="
