#!/bin/bash
# Fast tight-loop batch — assumes bench binary already built on HOST
# at /root/microbench/micro_flowdis_pcap (the smoke-test left it there).
# Args: HOST PATCHED BASELINE OUTDIR PCAP_DIR_LOCAL [N_RUNS] [PATTERN]
HOST=$1 PATCHED=$2 BASELINE=$3 OUTDIR=$4 PCAP_DIR=$5
N=${6:-3}
PATTERN=${7:-'*.pcap'}
mkdir -p "$OUTDIR"
# Stage PCAPs once
echo "rsync PCAPs to $HOST..."
rsync -az --include='*.pcap' --include='*/' --exclude='*' "$PCAP_DIR/" root@"$HOST":/root/microbench/pcap/
# Build bench fresh (in case)
ssh root@"$HOST" "cd /root/microbench && test -x micro_flowdis_pcap" || {
  echo "FAIL: bench binary not built. Smoke-test first."; exit 1;
}
echo "running A/B batch on $HOST..."
SUMMARY="$OUTDIR/aggregate.csv"
echo "pcap,n_packets,patched_mean_ns,patched_stdev,baseline_mean_ns,baseline_stdev,delta_ns,delta_pct,note" > "$SUMMARY"
TOTAL=0; OK=0; SKIP=0
for p in "$PCAP_DIR"/$PATTERN; do
  [ -e "$p" ] || continue
  base=$(basename "$p" .pcap)
  TOTAL=$((TOTAL+1))
  remote="/root/microbench/pcap/$(basename "$p")"
  log="$OUTDIR/runs/$base.log"
  mkdir -p "$OUTDIR/runs"
  ssh root@"$HOST" "
    cd /root/microbench
    echo '=== PATCHED ==='
    for i in \$(seq 1 $N); do
      LD_LIBRARY_PATH=$PATCHED/lib taskset -c 3 ./micro_flowdis_pcap $remote 10000000 2>&1
    done
    echo '=== BASELINE ==='
    for i in \$(seq 1 $N); do
      LD_LIBRARY_PATH=$BASELINE/lib taskset -c 3 ./micro_flowdis_pcap $remote 10000000 2>&1
    done
  " > "$log" 2>&1
  if grep -q "non-Ethernet link-layer" "$log"; then
    SKIP=$((SKIP+1))
    printf '[%3d] %-30s skip (non-Ethernet)\n' "$TOTAL" "$base"
    echo "$base,0,,,,,,,skip-non-ethernet" >> "$SUMMARY"
    continue
  fi
  result=$(python3 -c "
import re,statistics
patched=[];baseline=[];n_pkts=0;mode=None
for line in open('$log'):
    if '=== PATCHED ===' in line: mode='p';continue
    if '=== BASELINE ===' in line: mode='b';continue
    m=re.search(r'ns_per_pkt=([0-9.]+)',line)
    if not m or not mode: continue
    (patched if mode=='p' else baseline).append(float(m.group(1)))
    n=re.search(r'n_packets=(\d+)',line)
    if n and n_pkts==0: n_pkts=int(n.group(1))
if not patched or not baseline:
    print('NA,NA,NA,NA,NA,NA,NA,parse-fail')
else:
    mp=statistics.mean(patched); mb=statistics.mean(baseline)
    spd=statistics.stdev(patched) if len(patched)>1 else 0
    sbd=statistics.stdev(baseline) if len(baseline)>1 else 0
    print(f'{n_pkts},{mp:.3f},{spd:.3f},{mb:.3f},{sbd:.3f},{mp-mb:+.3f},{100*(mp-mb)/mb if mb else 0:+.2f},ok')
")
  echo "$base,$result" >> "$SUMMARY"
  OK=$((OK+1))
  printf '[%3d] %-30s %s\n' "$TOTAL" "$base" "$result"
done
echo "--- batch done: total=$TOTAL ok=$OK skip=$SKIP ---"
echo "aggregate: $SUMMARY"
