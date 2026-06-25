# nix/series3-cpu-bound-soak.nix
#
# Phase G of the series3 extension-patches harness. Mirrors the shape
# of series3-extensions-soak.nix but swaps the wire-saturated iperf3
# workload for kernel-pktgen-driven small-packet open-loop UDP with
# random source ports. The point is to load the receiver's
# flow_dissect path per-packet without GRO amortization, so the
# fast-path's per-call cycle saving surfaces as a measurable
# cycles_per_pkt drop in the ksoftirqd perf-stat trace AND as a
# recv_soft_pct drop in mpstat.
#
# Per scenario: 2 cells (no tcp/udp axis — pktgen is UDP only).
#   01  pktgen-rand-udp  sysctl=0
#   02  pktgen-rand-udp  sysctl=1
#
# Per pair: 7 scenarios × 2 cells = 14 cells.
# Full matrix (3 pairs):  42 cells, wall-clock ≈ 42 × (DUR + 8) sec.
#   DUR=30 (smoke):   ~25 min
#   DUR=60 (standard): ~50 min
#   DUR=300 (long):  ~3.6 h
#
# Per-cell artifacts written under
#   $OUT/$pair/$scen/cell-NN/{pktgen.log, mpstat.log, perf-stat.txt,
#                             scenario.env, rx_packets.delta}
#
# matrix.csv columns:
#   pair,scenario,cell,sysctl,dur_s,pkt_size,threads,
#   scenario_iface,scenario_mac,
#   pps_sent,pps_recv,
#   cycles,instructions,branches,branch_misses,
#   cycles_per_pkt,ins_per_pkt,branch_miss_per_pkt,
#   recv_sys_pct,recv_soft_pct,
#   rps,rfs,cake,flower,
#   kernel_has_sysctl,status
#
# Usage:
#   PAIRS=hp1-hp3 SCENARIOS=ipip DUR=30 nix run .#series3-cpu-bound-soak
#   PAIRS=pi5-pair,hp1-hp3,hp2-hp5 \
#     SCENARIOS=vlan,qinq,vxlan,mpls,ipip,gre,geneve \
#     DUR=60 nix run .#series3-cpu-bound-soak
#
# Skips:
#   - pppoe: ppp0 has no L2 MAC for pktgen; the pppoe-server side is
#     already blocked separately (perf-results/2026-06-16-pppoe-investigation.md)
#   - gtpu: needs libgtpnl userspace, blocked separately
#
# Consumers are ON by default (CONSUMER_ALL=1) because the whole
# point of Phase G is to load the dispatcher; the iperf3 phase F
# baseline already gave us the consumers-off neutral picture.

{ pkgs }:

let
  libSh = builtins.readFile ./scenarios/lib.sh;
  # Raw pktgen source — has `#!/usr/bin/env bash` so it runs on
  # the remote testbed (which doesn't have our /nix/store mounted).
  # The writeShellApplication wrapper at .#flow-dissector-pktgen-ntuple-template
  # is shellcheck-validated at build time, but its derived shebang
  # points at the builder's bash. For scp-to-peer use, we want the
  # raw .sh file; Nix path interpolation copies it into the store
  # so it's reproducible.
  pktgenSrc = ../samples/flow_dissector/pktgen_ntuple_template.sh;
in
pkgs.writeShellApplication {
  name = "series3-cpu-bound-soak";

  runtimeInputs = with pkgs; [
    openssh
    coreutils
    gawk
    jq
  ];

  excludeShellChecks = [ "SC2029" "SC1090" ];

  text = ''
    set -u

    ${libSh}

    # ── Configuration ─────────────────────────────────────────────
    PAIRS=''${PAIRS:-hp1-hp3}
    SCENARIOS=''${SCENARIOS:-vlan,qinq,vxlan,mpls,ipip,gre,geneve}
    DUR=''${DUR:-60}
    REPLICATES=''${REPLICATES:-1}
    COOLDOWN=''${COOLDOWN:-5}
    PKT_SIZE=''${PKT_SIZE:-64}
    THREADS=''${THREADS:-2}
    DPORT=''${DPORT:-5201}

    # Default consumers ON — Phase G's whole purpose is dispatcher load.
    CONSUMER_ALL=''${CONSUMER_ALL:-1}
    if [ "$CONSUMER_ALL" = "1" ]; then
      CONSUMER_RPS=''${CONSUMER_RPS:-1}
      CONSUMER_RFS=''${CONSUMER_RFS:-1}
      CONSUMER_CAKE=''${CONSUMER_CAKE:-1}
      CONSUMER_FLOWER=''${CONSUMER_FLOWER:-1}
    else
      CONSUMER_RPS=''${CONSUMER_RPS:-0}
      CONSUMER_RFS=''${CONSUMER_RFS:-0}
      CONSUMER_CAKE=''${CONSUMER_CAKE:-0}
      CONSUMER_FLOWER=''${CONSUMER_FLOWER:-0}
    fi
    CAKE_BW=''${CAKE_BW:-25Gbit}

    scenario_sysctl() {
      case "$1" in
        vlan)  echo "net.flow_dissector.vlan" ;;
        qinq)  echo "net.flow_dissector.qinq" ;;
        vxlan) echo "net.flow_dissector.vxlan_inner" ;;
        mpls)  echo "net.flow_dissector.mpls" ;;
        ipip)  echo "net.flow_dissector.ipip" ;;
        gre)   echo "net.flow_dissector.gre" ;;
        geneve)echo "net.flow_dissector.geneve_inner" ;;
        *)     echo "net.flow_dissector.eth_ip" ;;
      esac
    }

    today=$(date +%Y-%m-%d)
    OUT=''${OUT:-perf-results/$today-series3-cpu-bound-soak}
    mkdir -p "$OUT"
    matrix_csv="$OUT/matrix.csv"
    echo "pair,scenario,cell,rep,sysctl,dur_s,pkt_size,threads,scenario_iface,scenario_mac,pps_sent,pps_recv,cycles,instructions,branches,branch_misses,cycles_per_pkt,ins_per_pkt,branch_miss_per_pkt,recv_sys_pct,recv_soft_pct,rps,rfs,cake,flower,kernel_has_sysctl,status" > "$matrix_csv"

    # Pair name → L L2 IFACE underlay_L underlay_L2. Same table as
    # series3-extensions-soak.nix; testbeds/*.toml is the source of truth.
    case_pair() {
      local pair="$1"
      case "$pair" in
        l-l2)
          PAIR_L=l; PAIR_L2=l2; PAIR_IFACE=enp35s0f0np0
          PAIR_UNDERLAY_L=10.10.4.2; PAIR_UNDERLAY_L2=10.10.4.5
          ;;
        hp1-hp3)
          PAIR_L=hp1; PAIR_L2=hp3; PAIR_IFACE=enp1s0f0np0
          PAIR_UNDERLAY_L=10.10.2.1; PAIR_UNDERLAY_L2=10.10.2.3
          ;;
        hp2-hp5)
          PAIR_L=hp2; PAIR_L2=hp5; PAIR_IFACE=enp1s0f0np0
          PAIR_UNDERLAY_L=10.10.0.2; PAIR_UNDERLAY_L2=10.10.0.5
          ;;
        pi5-pair)
          PAIR_L=pi5-1; PAIR_L2=pi5-2; PAIR_IFACE=end0
          PAIR_UNDERLAY_L=172.16.40.122; PAIR_UNDERLAY_L2=172.16.40.174
          ;;
        pi5-bpif3)
          # RISC-V DUT: generator pi5-1 -> measured bpi-f3 (SpacemiT K1),
          # switched 1 GbE on the shared lab LAN; both use iface end0.
          # pktgen TX needs pi5-1 on 6.12.87 (its 6.18 bcmgenet wedges).
          PAIR_L=pi5-1; PAIR_L2=bpi-f3; PAIR_IFACE=end0
          PAIR_UNDERLAY_L=172.16.40.122; PAIR_UNDERLAY_L2=172.16.40.205
          ;;
        *) return 1 ;;
      esac
      return 0
    }

    probe_sysctl() {
      local host="$1" path="$2"
      SSH root@"$host" "sysctl -n $path" >/dev/null 2>&1
    }
    set_sysctl() {
      local host="$1" val="$2" path="$3"
      SSH root@"$host" "sysctl -w $path=$val" >/dev/null 2>&1 || true
    }

    # ── Consumer activation (same helpers as series3-extensions-soak) ──
    setup_consumers() {
      local host="$1" iface="$2"

      if [ "$CONSUMER_RPS" = "1" ]; then
        SSH root@"$host" "
          ncpu=\$(nproc)
          hex=\$(printf '%x' \$(( (1 << ncpu) - 1 )))
          for q in /sys/class/net/$iface/queues/rx-*; do
            [ -d \$q ] || continue
            echo \$hex > \$q/rps_cpus 2>/dev/null || true
          done
          if [ \"$CONSUMER_RFS\" = \"1\" ]; then
            echo 32768 > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true
            for q in /sys/class/net/$iface/queues/rx-*; do
              [ -d \$q ] || continue
              echo 2048 > \$q/rps_flow_cnt 2>/dev/null || true
            done
          fi
        " >/dev/null 2>&1 || true
      fi

      if [ "$CONSUMER_CAKE" = "1" ]; then
        SSH root@"$host" "
          tc qdisc replace dev $iface root cake bandwidth $CAKE_BW triple-isolate 2>/dev/null || true
        " >/dev/null 2>&1 || true
      fi

      if [ "$CONSUMER_FLOWER" = "1" ]; then
        SSH root@"$host" "
          tc qdisc replace dev $iface handle ffff: ingress 2>/dev/null || true
          tc filter add dev $iface ingress protocol ip   flower skip_hw action pass 2>/dev/null || true
          tc filter add dev $iface ingress protocol ipv6 flower skip_hw action pass 2>/dev/null || true
        " >/dev/null 2>&1 || true
      fi
    }

    teardown_consumers() {
      local host="$1" iface="$2"

      if [ "$CONSUMER_FLOWER" = "1" ]; then
        SSH root@"$host" "
          tc filter del dev $iface ingress 2>/dev/null
          tc qdisc del dev $iface ingress 2>/dev/null
        " >/dev/null 2>&1 || true
      fi

      if [ "$CONSUMER_CAKE" = "1" ]; then
        SSH root@"$host" "tc qdisc del dev $iface root 2>/dev/null" >/dev/null 2>&1 || true
      fi

      if [ "$CONSUMER_RPS" = "1" ]; then
        SSH root@"$host" "
          for q in /sys/class/net/$iface/queues/rx-*; do
            [ -d \$q ] || continue
            echo 0 > \$q/rps_cpus 2>/dev/null || true
            [ \"$CONSUMER_RFS\" = \"1\" ] && echo 0 > \$q/rps_flow_cnt 2>/dev/null || true
          done
        " >/dev/null 2>&1 || true
      fi
    }

    # ── pktgen helpers ───────────────────────────────────────────────
    # scp the raw pktgen script to the generator. Path comes from
    # the Nix store via path interpolation; the script has
    # #!/usr/bin/env bash so it runs on the remote without needing
    # the builder's /nix/store mounted there.
    PKTGEN_SCRIPT_LOCAL="${pktgenSrc}"
    PKTGEN_SCRIPT_REMOTE="/tmp/xdp2-pktgen-ntuple-template.sh"

    scp_pktgen() {
      local host="$1"
      scp -q -o StrictHostKeyChecking=no \
          "$PKTGEN_SCRIPT_LOCAL" "root@$host:$PKTGEN_SCRIPT_REMOTE" 2>/dev/null
      SSH root@"$host" "chmod +x $PKTGEN_SCRIPT_REMOTE" >/dev/null 2>&1 || true
    }

    pktgen_stop_remote() {
      local host="$1"
      SSH root@"$host" "$PKTGEN_SCRIPT_REMOTE stop" >/dev/null 2>&1 || true
    }

    # Read total packets sent across all pktgen device threads on
    # the generator. Per-device proc entries contain a line like
    # "  pkts-sofar: 10581688  errors: 0" while the threads run;
    # the final "Result: OK: <N>" only shows up after pgctrl stop
    # completes (and rem_device_all then deletes the entries),
    # so we read pkts-sofar mid-run and divide by DUR to get pps.
    pktgen_pkts_sent() {
      local host="$1" iface="$2"
      SSH root@"$host" "
        total=0
        for d in /proc/net/pktgen/$iface@*; do
          [ -e \$d ] || continue
          n=\$(awk '/pkts-sofar:/ {print \$2; exit}' \$d 2>/dev/null)
          [ -z \"\$n\" ] && n=0
          total=\$(( total + n ))
        done
        echo \$total
      " 2>/dev/null
    }

    # Read receiver-side packet counter from /sys; capture before/after.
    rx_packets() {
      local host="$1" iface="$2"
      SSH root@"$host" "cat /sys/class/net/$iface/statistics/rx_packets 2>/dev/null || echo 0" 2>/dev/null
    }

    # ── Per-cell run ────────────────────────────────────────────────
    # Required from scenario env: SCEN_DEV_L SCEN_V4_L SCEN_MAC_L
    #                             SCEN_DEV_DUT SCEN_V4_DUT SCEN_MAC_DUT
    run_cell() {
      local pair="$1" scen="$2" cell="$3" sysctl="$4" has_sysctl="$5" rep="$6"
      local cell_dir
      cell_dir="$OUT/$pair/$scen/cell-$(printf '%02d' "$cell")-rep$(printf '%d' "$rep")"
      mkdir -p "$cell_dir"

      local sysctl_path
      sysctl_path=$(scenario_sysctl "$scen")
      set_sysctl "$PAIR_L"  "$sysctl" "$sysctl_path"
      set_sysctl "$PAIR_L2" "$sysctl" "$sysctl_path"

      setup_consumers "$PAIR_L2" "$PAIR_IFACE"

      # Collect ksoftirqd PIDs on receiver and target perf-stat at them.
      # Linux exposes one ksoftirqd/N per CPU; pgrep '^ksoftirqd' returns
      # them all, paste -sd, joins to a comma list perf -p accepts.
      local KSOFTIRQ_PIDS
      KSOFTIRQ_PIDS=$(SSH root@"$PAIR_L2" "pgrep '^ksoftirqd' | paste -sd,") || true
      KSOFTIRQ_PIDS=''${KSOFTIRQ_PIDS:-}
      echo "ksoftirqd PIDs (L2=$PAIR_L2): $KSOFTIRQ_PIDS" > "$cell_dir/perf-stat.txt"

      # rx_packets baseline before pktgen start
      local rx_before rx_after
      rx_before=$(rx_packets "$PAIR_L2" "$PAIR_IFACE")

      # Pktgen iface selection: for vxlan/geneve the receiver mlx5 NIC
      # filters bare frames with the overlay-device MAC (since the MAC
      # isn't the NIC's unicast MAC). Target pktgen at the overlay
      # device itself so the kernel handles encap on TX. Other scenarios
      # (vlan/qinq/mpls/ipip/gre and eth_ip) emit either the underlay
      # MAC or the VLAN-inherited-from-parent MAC, both of which the
      # NIC accepts when pktgen sends from the underlay iface.
      local pktgen_iface
      case "$scen" in
        vxlan|geneve) pktgen_iface="$SCEN_DEV_DUT" ;;
        *)            pktgen_iface="$PAIR_IFACE"   ;;
      esac

      # Start pktgen on L. Pktgen returns immediately (the script
      # nohup's the blocking pgctrl start).
      SSH root@"$PAIR_L" "PKTGEN_RANDOMIZE_FLOWS=1 PKTGEN_BURST=8 \
        $PKTGEN_SCRIPT_REMOTE start $pktgen_iface $SCEN_V4_DUT $SCEN_MAC_DUT \
        --dport $DPORT --pkt-size $PKT_SIZE --threads $THREADS" \
        > "$cell_dir/pktgen.log" 2>&1 || true

      # Brief settle for pktgen to ramp.
      sleep 0.5

      # Concurrent mpstat + perf-stat on L2. nix-shell-wrap so the
      # remote doesn't need sysstat/perf pre-installed.
      SSH root@"$PAIR_L2" "nix shell nixpkgs#sysstat --command mpstat -P ALL 1 $DUR" \
        > "$cell_dir/mpstat.log" 2> "$cell_dir/mpstat.err" &
      local mpstat_pid=$!

      if [ -n "$KSOFTIRQ_PIDS" ]; then
        SSH root@"$PAIR_L2" "perf stat -p $KSOFTIRQ_PIDS \
          -e cycles,instructions,branches,branch-misses,L1-dcache-loads,L1-dcache-load-misses \
          -- sleep $DUR" \
          >> "$cell_dir/perf-stat.txt" 2>> "$cell_dir/perf-stat.txt" &
      else
        echo "WARN: no ksoftirqd PIDs found, skipping perf-stat" >> "$cell_dir/perf-stat.txt"
        sleep "$DUR" &
      fi
      local perf_pid=$!

      wait "$mpstat_pid" 2>/dev/null || true
      wait "$perf_pid"   2>/dev/null || true

      # Read counters BEFORE stopping pktgen — the stop subcommand
      # does rem_device_all which deletes the per-device proc entries.
      # Use $pktgen_iface (not PAIR_IFACE) so we read the right proc
      # entries when overlay-targeting vxlan/geneve.
      local pkts_sent pps_sent
      pkts_sent=$(pktgen_pkts_sent "$PAIR_L" "$pktgen_iface")
      pkts_sent=''${pkts_sent:-0}
      pps_sent=$(( pkts_sent / DUR ))

      pktgen_stop_remote "$PAIR_L"

      rx_after=$(rx_packets "$PAIR_L2" "$PAIR_IFACE")
      local rx_delta pps_recv
      rx_delta=$(( rx_after - rx_before ))
      pps_recv=$(( rx_delta / DUR ))
      echo "rx_before=$rx_before rx_after=$rx_after delta=$rx_delta pps=$pps_recv" \
        > "$cell_dir/rx_packets.delta"

      teardown_consumers "$PAIR_L2" "$PAIR_IFACE"

      # Parse perf-stat output. perf writes counters one-per-line in
      # the form "       N,NNN,NNN      cycles". Strip thousands
      # separators (commas may appear) and grep by event name.
      perf_val() {
        local event="$1"
        awk -v ev="$event" '
          {
            for (i=1; i<=NF; i++) {
              if ($i == ev) {
                v = $(i-1)
                gsub(",", "", v)
                print v
                exit
              }
            }
          }
        ' "$cell_dir/perf-stat.txt" 2>/dev/null
      }
      local cycles instructions branches branch_misses
      cycles=$(perf_val cycles);              cycles=''${cycles:-0}
      instructions=$(perf_val instructions);  instructions=''${instructions:-0}
      branches=$(perf_val branches);          branches=''${branches:-0}
      branch_misses=$(perf_val branch-misses); branch_misses=''${branch_misses:-0}

      # Per-packet derived metrics. Guard against pps_recv=0.
      local cycles_per_pkt ins_per_pkt branch_miss_per_pkt
      if [ "$rx_delta" -gt 0 ]; then
        cycles_per_pkt=$(awk -v c="$cycles" -v p="$rx_delta" 'BEGIN { printf "%.2f", c/p }')
        ins_per_pkt=$(awk -v c="$instructions" -v p="$rx_delta" 'BEGIN { printf "%.2f", c/p }')
        branch_miss_per_pkt=$(awk -v c="$branch_misses" -v p="$rx_delta" 'BEGIN { printf "%.4f", c/p }')
      else
        cycles_per_pkt=0
        ins_per_pkt=0
        branch_miss_per_pkt=0
      fi

      # mpstat parse (same as series3-extensions-soak).
      local recv_sys_pct recv_soft_pct
      recv_sys_pct=$(awk '$1=="Average:" && $2=="all" {print $5; exit}' "$cell_dir/mpstat.log" 2>/dev/null)
      recv_soft_pct=$(awk '$1=="Average:" && $2=="all" {print $8; exit}' "$cell_dir/mpstat.log" 2>/dev/null)
      recv_sys_pct=''${recv_sys_pct:-0.00}
      recv_soft_pct=''${recv_soft_pct:-0.00}

      local status=ok
      [ "$rx_delta" -le 0 ] && status=no-rx

      # Overlay-unsupported detection: pktgen's add_device write fails
      # on vxlan/geneve devices on most kernels ("Operation not
      # supported"). Symptom is pkts_sent=0 + tiny rx_delta + the
      # "write error" string in pktgen.log. Tag those cells so the
      # summary-report tool can filter them out of the headline table.
      case "$scen" in
        vxlan|geneve)
          if [ "$pkts_sent" -eq 0 ] \
             && grep -q "Operation not supported" "$cell_dir/pktgen.log" 2>/dev/null; then
            status=overlay-unsupported
          fi
          ;;
      esac

      printf '%s,%s,cell-%02d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$pair" "$scen" "$cell" "$rep" "$sysctl" "$DUR" "$PKT_SIZE" "$THREADS" \
        "$SCEN_DEV_DUT" "$SCEN_MAC_DUT" \
        "$pps_sent" "$pps_recv" \
        "$cycles" "$instructions" "$branches" "$branch_misses" \
        "$cycles_per_pkt" "$ins_per_pkt" "$branch_miss_per_pkt" \
        "$recv_sys_pct" "$recv_soft_pct" \
        "$CONSUMER_RPS" "$CONSUMER_RFS" "$CONSUMER_CAKE" "$CONSUMER_FLOWER" \
        "$has_sysctl" "$status" \
        >> "$matrix_csv"

      log "[$pair/$scen/cell$cell.rep$rep sysctl=$sysctl] pps_sent=$pps_sent pps_recv=$pps_recv cyc/pkt=$cycles_per_pkt ins/pkt=$ins_per_pkt recv_soft=$recv_soft_pct% status=$status"
    }

    # ── Scenario lifecycle ─────────────────────────────────────────
    run_scenario_up() {
      local pair="$1" scen="$2" out_env="$3"
      case "$scen" in
        vlan|qinq)
          OP=up L="$PAIR_L" L2="$PAIR_L2" \
            GEN_DEV="$PAIR_IFACE" DUT_DEV="$PAIR_IFACE" \
            nix run ".#netconf-$scen" > "$out_env"
          ;;
        eth_ip|vxlan|mpls|ipip|gre|geneve)
          OP=up L="$PAIR_L" L2="$PAIR_L2" \
            GEN_DEV="$PAIR_IFACE" DUT_DEV="$PAIR_IFACE" \
            GEN_UNDERLAY_V4="$PAIR_UNDERLAY_L" \
            DUT_UNDERLAY_V4="$PAIR_UNDERLAY_L2" \
            nix run ".#netconf-$scen" > "$out_env"
          ;;
        pppoe|gtpu)
          log "WARN: $scen not supported by Phase G (see header comments)"
          return 1
          ;;
        *)
          log "ERROR: unknown scenario $scen"
          return 1
          ;;
      esac
    }
    run_scenario_down() {
      local pair="$1" scen="$2"
      case "$scen" in
        vlan|qinq)
          OP=down L="$PAIR_L" L2="$PAIR_L2" \
            GEN_DEV="$PAIR_IFACE" DUT_DEV="$PAIR_IFACE" \
            nix run ".#netconf-$scen" >/dev/null 2>&1 || true
          ;;
        eth_ip|vxlan|mpls|ipip|gre|geneve)
          OP=down L="$PAIR_L" L2="$PAIR_L2" \
            GEN_DEV="$PAIR_IFACE" DUT_DEV="$PAIR_IFACE" \
            GEN_UNDERLAY_V4="$PAIR_UNDERLAY_L" \
            DUT_UNDERLAY_V4="$PAIR_UNDERLAY_L2" \
            nix run ".#netconf-$scen" >/dev/null 2>&1 || true
          ;;
      esac
    }

    # ── Main loop ──────────────────────────────────────────────────
    log "=== series3-cpu-bound-soak start  PAIRS=$PAIRS  SCENARIOS=$SCENARIOS  DUR=$DUR  PKT_SIZE=$PKT_SIZE  THREADS=$THREADS  OUT=$OUT ==="

    for pair in $(echo "$PAIRS" | tr ',' ' '); do
      if ! case_pair "$pair"; then
        log "WARN: unknown pair '$pair' — skipping"
        continue
      fi
      log "--- pair $pair: L=$PAIR_L L2=$PAIR_L2 iface=$PAIR_IFACE ---"

      has_sysctl=yes
      if ! probe_sysctl "$PAIR_L"  "net.flow_dissector.eth_ip" \
         || ! probe_sysctl "$PAIR_L2" "net.flow_dissector.eth_ip"; then
        log "WARN: net.flow_dissector.eth_ip missing on one or both hosts of $pair; cells will still run, sysctl writes best-effort"
        has_sysctl=no
      fi

      # scp pktgen script to the generator once per pair.
      scp_pktgen "$PAIR_L"

      for scen in $(echo "$SCENARIOS" | tr ',' ' '); do
        log ">>> $pair / $scen up"
        scen_env="$OUT/$pair/$scen/scenario.env"
        mkdir -p "$(dirname "$scen_env")"

        if ! run_scenario_up "$pair" "$scen" "$scen_env"; then
          log "WARN: $pair/$scen up failed; skipping"
          continue
        fi
        if ! grep -q '^L2_SCENARIO_V4=' "$scen_env" 2>/dev/null; then
          log "WARN: $pair/$scen produced no scenario.env; skipping"
          run_scenario_down "$pair" "$scen"
          continue
        fi
        if ! grep -q '^L2_SCENARIO_MAC=' "$scen_env" 2>/dev/null; then
          log "WARN: $pair/$scen emitted no L2_SCENARIO_MAC; skipping (Phase G needs a remote MAC for pktgen)"
          run_scenario_down "$pair" "$scen"
          continue
        fi

        SCEN_DEV_L=$(grep   '^L_SCENARIO_DEV='   "$scen_env" | cut -d= -f2-)
        SCEN_V4_L=$(grep    '^L_SCENARIO_V4='    "$scen_env" | cut -d= -f2-)
        SCEN_MAC_L=$(grep   '^L_SCENARIO_MAC='   "$scen_env" | cut -d= -f2-)
        SCEN_DEV_DUT=$(grep '^L2_SCENARIO_DEV='  "$scen_env" | cut -d= -f2-)
        SCEN_V4_DUT=$(grep  '^L2_SCENARIO_V4='   "$scen_env" | cut -d= -f2-)
        SCEN_MAC_DUT=$(grep '^L2_SCENARIO_MAC='  "$scen_env" | cut -d= -f2-)

        if [ -z "$SCEN_MAC_DUT" ]; then
          log "WARN: $pair/$scen L2_SCENARIO_MAC is empty; skipping"
          run_scenario_down "$pair" "$scen"
          continue
        fi

        log "[$pair/$scen] L=$SCEN_V4_L on $SCEN_DEV_L ($SCEN_MAC_L) ↔ L2=$SCEN_V4_DUT on $SCEN_DEV_DUT ($SCEN_MAC_DUT)"

        cell=1
        for sysctl in 0 1; do
          for rep in $(seq 1 "$REPLICATES"); do
            run_cell "$pair" "$scen" "$cell" "$sysctl" "$has_sysctl" "$rep"
            sleep "$COOLDOWN"
          done
          cell=$((cell + 1))
        done

        log "<<< $pair / $scen down"
        run_scenario_down "$pair" "$scen"
      done
    done

    log "=== matrix complete: $matrix_csv ==="
    column -ts, "$matrix_csv" || cat "$matrix_csv"
  '';
}
