# nix/series3-pcap-microbench.nix
#
# PCAP-driven userspace libflowdis A/B harness — sibling to
# nix/series3-microbench.nix. Drives `micro_flowdis_pcap.c` against
# a PCAP file on a remote host, with patched and baseline libflowdis
# closures supplied as separate arguments.
#
# The PCAP variant lets us test the series 3 fast-path on **any**
# packet shape, not just the hardcoded eth+IPv4+TCP frame the
# original single-shape bench uses. Together with the existing
# data/pcaps/ tree and the samples/proto_audit/pcap_templates/
# corpus (300+ protocols), this gives us per-PCAP A/B evidence for:
#
#   - Non-fast-path shapes (ICMP, ARP, AppleTalk, BGP, BACnet,
#     GRE/VXLAN/IPIP/L2TP encap, SRv6, IPv6 with extension headers,
#     fragmented IPv4, ...) — should show ~0 delta + measurable
#     fall-through dispatcher cost.
#   - Mixed-traffic workload PCAPs (vlan-tcp-mix, pppoe-isp,
#     vxlan-k8s-pure, mixed-real.pcap) — should show partial gain
#     proportional to fast-path-eligible share.
#   - Controlled-ratio mix PCAPs from gen_workload_pcap.py — clean
#     linear scaling demonstration.
#
# Usage:
#   nix run .#series3-pcap-microbench -- HOST PATCHED BASELINE PCAP [N_RUNS] [OUTDIR]
#
# Examples:
#   # Run a single PCAP through pi5-2:
#   nix run .#series3-pcap-microbench -- \
#     pi5-2 \
#     /nix/store/k509xbm68zw441cpyqzl60rdv7418ask-xdp2-0.1.0 \
#     /nix/store/s2jblg2p0pjc3qpz4sds06mv9q44vk1q-xdp2-0.1.0 \
#     data/pcaps/icmp_ipv4.pcap
#
#   # Iterate over the proto_audit corpus on pi5-2:
#   for p in samples/proto_audit/pcap_templates/*.pcap; do
#     nix run .#series3-pcap-microbench -- pi5-2 PATCHED BASELINE "$p" 3
#   done
#
# Pre-conditions identical to series3-microbench: both closures
# must already exist on HOST's /nix/store (via nix-copy-closure),
# and HOST must have nix-shell available.

{ pkgs }:

let
  benchSrc = ../samples/flow_dissector/micro_flowdis_pcap.c;
in
pkgs.writeShellApplication {
  name = "series3-pcap-microbench";

  runtimeInputs = [
    pkgs.openssh
    pkgs.coreutils
    pkgs.python3
    pkgs.rsync
  ];

  text = ''
    set -u

    if [ "$#" -lt 4 ]; then
      cat <<'EOF'
    Usage: series3-pcap-microbench HOST PATCHED BASELINE PCAP [N_RUNS] [OUTDIR]

      HOST     SSH-reachable host (must have nix-shell)
      PATCHED  xdp2-with-port closure path on HOST
      BASELINE xdp2-without-port closure path on HOST
      PCAP     Path to PCAP file on the calling machine (rsync'd
               to HOST as /root/microbench/pcap/<basename>)
      N_RUNS   Number of 10M-iteration runs per variant. Default 10.
      OUTDIR   Output dir. Default
               perf-results/<YYYY-MM-DD>-series3-pcap-microbench/<HOST>/

    Env overrides:
      CPU_PIN   taskset core for bench. Default 3.
      N_ITER    Iterations per run. Default 10000000 (10 M).
      GOVERNOR  CPU governor on CPU_PIN. Default performance.

    Exit codes:
      0   bench ran + parsed
      2   PCAP had non-Ethernet link layer (skipped — informational)
      3   one of the variants failed to compile or run
    EOF
      exit 64
    fi

    HOST="$1"; PATCHED="$2"; BASELINE="$3"; PCAP="$4"
    N_RUNS="''${5:-10}"
    today="$(date +%Y-%m-%d)"
    OUTDIR="''${6:-perf-results/$today-series3-pcap-microbench/$HOST}"
    CPU_PIN="''${CPU_PIN:-3}"
    N_ITER="''${N_ITER:-10000000}"
    GOVERNOR="''${GOVERNOR:-performance}"

    pcap_base=$(basename "$PCAP" .pcap)
    mkdir -p "$OUTDIR"
    LOG="$OUTDIR/micro_flowdis_pcap_''${pcap_base}.log"

    SSH() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$@"; }

    echo "series3-pcap-microbench"
    echo "  HOST=$HOST  PCAP=$PCAP  pcap_base=$pcap_base"
    echo "  PATCHED=$PATCHED"
    echo "  BASELINE=$BASELINE"
    echo "  OUTDIR=$OUTDIR  N_RUNS=$N_RUNS  N_ITER=$N_ITER"

    # Verify closures present
    for path in "$PATCHED" "$BASELINE"; do
      if ! SSH root@"$HOST" "test -e $path/lib/libflowdis.so"; then
        echo "FAIL: $path/lib/libflowdis.so not present on $HOST"
        echo "      run: nix-copy-closure --to root@$HOST $path"
        exit 2
      fi
    done

    # Ship bench source + PCAP
    SSH root@"$HOST" 'mkdir -p /root/microbench/pcap' > /dev/null 2>&1
    rsync -az ${benchSrc} root@"$HOST":/root/microbench/micro_flowdis_pcap.c
    rsync -az "$PCAP" root@"$HOST":/root/microbench/pcap/

    REMOTE_PCAP="/root/microbench/pcap/$(basename "$PCAP")"

    # libpcap is multi-output in nixpkgs — headers in the default
    # output, the .so in the `lib` suffix. Resolve both on HOST,
    # then compile with explicit -I/-L and RPATH so LD_LIBRARY_PATH
    # only needs to override the libflowdis closure (not libpcap).
    if ! SSH root@"$HOST" "
      set -e
      cd /root/microbench
      PCAP_INC=\$(nix eval --raw 'nixpkgs#libpcap')
      PCAP_LIB=\$(nix eval --raw 'nixpkgs#libpcap.lib')
      nix shell nixpkgs#gcc -c gcc -O3 -march=native \
        -o micro_flowdis_pcap micro_flowdis_pcap.c \
        -I $PATCHED/include -I $PATCHED/include/flowdis -I \$PCAP_INC/include \
        -L $PATCHED/lib -L \$PCAP_LIB/lib \
        -lflowdis -lsiphash -lpcap \
        -Wl,-rpath,\$PCAP_LIB/lib
    " > /dev/null 2>&1; then
      echo "FAIL: micro_flowdis_pcap build on $HOST"
      exit 3
    fi

    # Run bench
    SSH root@"$HOST" "
      echo '=== $HOST  pcap=$pcap_base ==='
      if [ -n '$GOVERNOR' ]; then
        echo performance > /sys/devices/system/cpu/cpu''${CPU_PIN}/cpufreq/scaling_governor || true
      fi
      vcgencmd measure_temp 2>/dev/null || true
      cd /root/microbench
      echo === PATCHED ===
      for i in \$(seq 1 $N_RUNS); do
        LD_LIBRARY_PATH=$PATCHED/lib taskset -c $CPU_PIN ./micro_flowdis_pcap $REMOTE_PCAP $N_ITER
      done
      echo === BASELINE ===
      for i in \$(seq 1 $N_RUNS); do
        LD_LIBRARY_PATH=$BASELINE/lib taskset -c $CPU_PIN ./micro_flowdis_pcap $REMOTE_PCAP $N_ITER
      done
      vcgencmd measure_temp 2>/dev/null || true
      vcgencmd get_throttled 2>/dev/null || true
    " > "$LOG"

    # If the bench bailed because of non-Ethernet link layer, propagate
    if grep -q "skip .*non-Ethernet link-layer" "$LOG"; then
      echo "SKIP $pcap_base — non-Ethernet link layer; see $LOG"
      exit 2
    fi

    # Parse + summary
    python3 - "$LOG" "$OUTDIR/summary-''${pcap_base}.txt" "$pcap_base" <<'PYEOF'
    import re, statistics, sys
    log, summary, pcap_base = sys.argv[1], sys.argv[2], sys.argv[3]
    patched, baseline, n_pkts = [], [], None
    mode = None
    for line in open(log):
        if "=== PATCHED ===" in line: mode = "p"; continue
        if "=== BASELINE ===" in line: mode = "b"; continue
        m = re.search(r"ns_per_pkt=([0-9.]+)", line)
        if not m or not mode: continue
        v = float(m.group(1))
        (patched if mode == "p" else baseline).append(v)
        m2 = re.search(r"n_packets=(\d+)", line)
        if m2 and n_pkts is None:
            n_pkts = int(m2.group(1))
    def stats(xs):
        if not xs: return "(no samples)"
        return f"N={len(xs):3d}  mean={statistics.mean(xs):8.3f}  stdev={(statistics.stdev(xs) if len(xs)>1 else 0):6.3f}  range=[{min(xs):.2f}, {max(xs):.2f}]"
    with open(summary, "w") as f:
        f.write(f"series3-pcap-microbench summary\n  pcap: {pcap_base}\n  n_packets in pcap: {n_pkts}\n  source: {log}\n\n")
        f.write(f"patched : {stats(patched)}\n")
        f.write(f"baseline: {stats(baseline)}\n")
        if patched and baseline:
            mp, mb = statistics.mean(patched), statistics.mean(baseline)
            f.write(f"delta   : {mp-mb:+.3f} ns/pkt ({100*(mp-mb)/mb:+.2f}%)\n")
    print(open(summary).read())
    PYEOF
  '';
}
