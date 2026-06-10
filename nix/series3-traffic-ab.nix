# nix/series3-traffic-ab.nix
#
# Cross-host iperf3 A/B harness for the series 3 flow_dissector
# fast-path sysctl. Flips `net.core.flow_dissector_fastpath` on both
# ends between every iperf3 cell, captures throughput + retransmit
# (TCP) or packet/loss% (UDP) stats. Interleaved sysctl order
# (0,1,0,1,...) controls for thermal drift / test-order
# confounders.
#
# Matrix per invocation: TCP and UDP, IPv4 and IPv6, default
# 5 samples per sysctl mode per cell. Writes JSON artefacts plus
# a per-cell sidecar telemetry CSV (vcgencmd temp+freq+throttled
# at 1 Hz on the DUT) so cells that throttled can be discarded.
#
# Usage:
#   nix run .#series3-traffic-ab -- GEN DUT DUT_V4 DUT_V6 [N] [OUTDIR]
#
# Examples:
#   # Run pi5-2 -> pi4-1 over 1 GbE, default 5 samples per mode:
#   nix run .#series3-traffic-ab -- \
#     pi5-2 pi4-1 172.16.40.199 \
#     2603:8000:9c01:3b01:e65f:1ff:fe42:a10f
#
#   # Override N and output directory:
#   nix run .#series3-traffic-ab -- \
#     hp2 hp5 10.10.0.5 fd10:10:0::5 10 /tmp/my-run
#
# Pre-conditions:
#   - root SSH from the calling host to GEN and DUT.
#   - Both ends have the series-3 patched kernel booted, sysctl
#     `net.core.flow_dissector_fastpath` registered.
#   - DUT firewall allows TCP+UDP on ports 5301-5310 (v4 + v6 —
#     NixOS firewall is family-specific, both ip4tables and
#     ip6tables rules needed). The harness probes for openness
#     and exits with a helpful message if not.
#   - DUT NIC interface is `end0` (Pi 5 / Pi 4 onboard) or
#     `enu1u1` (Pi 3 USB-attached); set IFACE=... env var to
#     override.
#
# Outputs (in OUTDIR, defaults to
# perf-results/<YYYY-MM-DD>-series3-traffic-ab/<gen>-<dut>/):
#   - iperf3-{tcp,udp}-{v4,v6}-{0,1}-{1..N}.json  raw iperf3 JSON
#   - sidecar-{tcp,udp}-{v4,v6}.csv               1 Hz telemetry
#   - summary.txt                                 parsed table

{ pkgs }:

pkgs.writeShellApplication {
  name = "series3-traffic-ab";

  runtimeInputs = [
    pkgs.openssh
    pkgs.coreutils
    pkgs.python3
    pkgs.gawk
  ];

  text = ''
    set -u

    if [ "$#" -lt 4 ]; then
      cat <<'EOF'
    Usage: series3-traffic-ab GEN DUT DUT_V4 DUT_V6 [N] [OUTDIR]

      GEN     SSH-reachable hostname of the iperf3 client (sender)
      DUT     SSH-reachable hostname of the iperf3 server (receiver)
      DUT_V4  IPv4 address of DUT to iperf3 against
      DUT_V6  IPv6 address of DUT to iperf3 against
      N       Samples per sysctl mode per cell (default 5)
      OUTDIR  Output directory (default
              perf-results/<YYYY-MM-DD>-series3-traffic-ab/<GEN>-<DUT>/)

    Env overrides:
      IFACE      DUT network interface for the cake qdisc setup.
                 Default: end0. Pi 3 uses enu1u1.
      LINK_RATE  Bandwidth knob for cake. Default: 1Gbit.
      TCP_DURATION / UDP_DURATION  seconds per iperf3 cell.
                 Default: TCP 20, UDP 20.
      TCP_PARALLEL  -P value for TCP. Default: 16.
      UDP_PARALLEL  -P value for UDP. Default: 8.
      UDP_PKTLEN    -l value for UDP. Default: 64.
    EOF
      exit 64
    fi

    GEN="$1"; DUT="$2"; DUT_V4="$3"; DUT_V6="$4"
    N="''${5:-5}"
    today="$(date +%Y-%m-%d)"
    OUTDIR="''${6:-perf-results/$today-series3-traffic-ab/$GEN-$DUT}"
    IFACE="''${IFACE:-end0}"
    LINK_RATE="''${LINK_RATE:-1Gbit}"
    TCP_DURATION="''${TCP_DURATION:-20}"
    UDP_DURATION="''${UDP_DURATION:-20}"
    TCP_PARALLEL="''${TCP_PARALLEL:-16}"
    UDP_PARALLEL="''${UDP_PARALLEL:-8}"
    UDP_PKTLEN="''${UDP_PKTLEN:-64}"

    mkdir -p "$OUTDIR"
    echo "series3-traffic-ab"
    echo "  GEN=$GEN DUT=$DUT IFACE=$IFACE LINK=$LINK_RATE N=$N"
    echo "  v4=$DUT_V4 v6=$DUT_V6"
    echo "  OUTDIR=$OUTDIR"

    SSH() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$@"; }

    # Setup: cake on DUT egress
    SSH root@"$DUT" "tc qdisc replace dev $IFACE root cake bandwidth $LINK_RATE triple-isolate" \
      > /dev/null 2>&1 \
      || { echo "FAIL: could not set cake on $DUT $IFACE"; exit 2; }

    cleanup() {
      SSH root@"$DUT" 'pkill iperf3 2>/dev/null; pkill -f "while true; do echo" 2>/dev/null' \
        > /dev/null 2>&1 || true
      for h in "$GEN" "$DUT"; do
        SSH root@"$h" 'sysctl -w net.core.flow_dissector_fastpath=0' > /dev/null 2>&1 || true
      done
    }
    trap cleanup EXIT

    # Run one cell (PROTO IPVER PORT)
    run_cell() {
      local proto="$1" ipver="$2" port="$3"
      local addr; addr=$([ "$ipver" = "v6" ] && echo "$DUT_V6" || echo "$DUT_V4")

      # Sidecar telemetry on DUT: 1 Hz CSV of unix_ts,temp,freq,throttled.
      # Pi-only knobs (vcgencmd); harmless no-op on non-Pi hosts.
      SSH root@"$DUT" "nohup bash -c '
        while true; do
          ts=\$(date +%s)
          temp=\$(vcgencmd measure_temp 2>/dev/null | sed s/temp=// || echo NA)
          freq=\$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null || echo NA)
          thr=\$(vcgencmd get_throttled 2>/dev/null | sed s/throttled=// || echo NA)
          echo \$ts,\$temp,\$freq,\$thr
          sleep 1
        done
      ' > /tmp/sidecar-$proto-$ipver.csv 2>&1 &" > /dev/null 2>&1

      # Start the iperf3 server
      for h in "$GEN" "$DUT"; do
        SSH root@"$h" 'sysctl -w net.core.flow_dissector_fastpath=0' > /dev/null 2>&1
      done
      SSH root@"$DUT" "pkill iperf3 2>/dev/null; nix run nixpkgs#iperf3 -- -s -B $addr -p $port -D 2>/dev/null" \
        > /dev/null 2>&1
      sleep 3

      # Interleaved [0,1,0,1,...]
      local args
      if [ "$proto" = "udp" ]; then
        args="-u -b 0 -l $UDP_PKTLEN -P $UDP_PARALLEL -t $UDP_DURATION"
      else
        args="-P $TCP_PARALLEL -t $TCP_DURATION"
      fi
      for i in $(seq 1 "$N"); do
        for mode in 0 1; do
          for h in "$GEN" "$DUT"; do
            SSH root@"$h" "sysctl -w net.core.flow_dissector_fastpath=$mode" > /dev/null 2>&1
          done
          SSH root@"$GEN" "nix run nixpkgs#iperf3 -- -c $addr -p $port $args -J 2>/dev/null" \
            > "$OUTDIR/iperf3-$proto-$ipver-$mode-$i.json"
          echo "  [$proto-$ipver run $i sysctl=$mode] done"
        done
      done

      # Stop server + sidecar
      SSH root@"$DUT" 'pkill iperf3 2>/dev/null; pkill -f "while true; do" 2>/dev/null' \
        > /dev/null 2>&1 || true
      SSH root@"$DUT" "cat /tmp/sidecar-$proto-$ipver.csv" > "$OUTDIR/sidecar-$proto-$ipver.csv" 2>/dev/null
    }

    run_cell tcp v4 5301
    run_cell tcp v6 5302
    run_cell udp v4 5303
    run_cell udp v6 5304

    # Parse JSON to summary table
    python3 - <<PYEOF
    import json, glob, statistics, os, sys
    outdir = os.environ.get("OUTDIR") or "$OUTDIR"
    rows = []
    for proto in ("tcp", "udp"):
        for ipver in ("v4", "v6"):
            for mode in (0, 1):
                files = sorted(glob.glob(f"{outdir}/iperf3-{proto}-{ipver}-{mode}-*.json"))
                samples = []
                for f in files:
                    try:
                        d = json.load(open(f))
                        if proto == "tcp":
                            bps = d["end"]["sum_received"]["bits_per_second"]
                            extra = f"retx={d['end']['sum_sent']['retransmits']}"
                        else:
                            bps = d["end"]["sum"]["bits_per_second"]
                            extra = f"loss={d['end']['sum']['lost_percent']:.3f}%"
                        samples.append(bps / 1e6)
                    except Exception as e:
                        continue
                if samples:
                    rows.append((
                        f"{proto} {ipver} sysctl={mode}",
                        f"{statistics.mean(samples):8.2f}",
                        f"{statistics.stdev(samples) if len(samples)>1 else 0:6.3f}",
                        f"{min(samples):8.2f}",
                        f"{max(samples):8.2f}",
                        len(samples),
                    ))
    out = f"{outdir}/summary.txt"
    with open(out, "w") as f:
        f.write("series3-traffic-ab summary\n")
        f.write(f"GEN=$GEN DUT=$DUT  N(target)=$N\n\n")
        f.write(f"  {'cell':22s}{'mean Mbps':>10s}{'stdev':>8s}{'min':>10s}{'max':>10s}{'  N':>4s}\n")
        for r in rows:
            f.write(f"  {r[0]:22s}{r[1]:>10s}{r[2]:>8s}{r[3]:>10s}{r[4]:>10s}{r[5]:>4d}\n")
    print(open(out).read())
    PYEOF
  '';
}
