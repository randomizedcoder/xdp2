# nix/series3-extensions-soak.nix
#
# Phase 2 of the series3 extension-patches harness. Drives the matrix
# {pair × scenario × proto × sysctl(0,1)} by composing the existing
# netconf-<scenario> scripts (nix/scenarios/) with iperf3 A/B cells in
# the spirit of series3-soak-x86.nix — slimmed to 4 cells per scenario
# rather than 12, so a full sweep completes in a tractable window for
# manual inspection.
#
# Per scenario: 4 cells
#   01  iperf3-tcp  sysctl=0
#   02  iperf3-tcp  sysctl=1
#   03  iperf3-udp  sysctl=0
#   04  iperf3-udp  sysctl=1
#
# Per pair: 4 scenarios × 4 cells = 16 cells
# Full matrix (4 pairs):           64 cells, wall-clock ≈ 64 × DUR sec
#   DUR=10 (smoke):       ~11 min
#   DUR=60 (standard):    ~64 min
#   DUR=300 (long):       ~5 h
#
# Usage:
#   PAIRS=pi5-pair SCENARIOS=vlan DUR=10 nix run .#series3-extensions-soak
#   PAIRS=l-l2,hp1-hp3,hp2-hp5,pi5-pair SCENARIOS=vlan,qinq,vxlan DUR=60 \
#     nix run .#series3-extensions-soak
#
# Skip rules baked in:
#   - Unknown pair name: log + skip
#   - netconf-<scenario> up fails (e.g. PPPoE binaries missing): log + skip
#   - Either host's sysctl path missing: cells still run, sysctl writes
#     are best-effort; matrix.csv flags kernel_has_sysctl=no for the
#     rows so downstream analysis can filter.

{ pkgs }:

let
  libSh = builtins.readFile ./scenarios/lib.sh;
in
pkgs.writeShellApplication {
  name = "series3-extensions-soak";

  runtimeInputs = with pkgs; [
    openssh
    coreutils
    jq
    python3
  ];

  # SC2029: client-side $VAR expansion inside ssh "..." strings is
  # intentional throughout — same convention as series3-soak-x86.nix.
  excludeShellChecks = [ "SC2029" "SC1090" ];

  text = ''
    set -u

    ${libSh}

    # ── Configuration ─────────────────────────────────────────────
    PAIRS=''${PAIRS:-pi5-pair}
    SCENARIOS=''${SCENARIOS:-vlan,qinq,vxlan}
    DUR=''${DUR:-60}
    COOLDOWN=''${COOLDOWN:-5}
    # Map scenario -> sysctl. The v3 series ships per-shape sysctls
    # under /proc/sys/net/flow_dissector/; toggling the right one per
    # scenario is what makes the matrix meaningful.
    scenario_sysctl() {
      case "$1" in
        vlan)  echo "net.flow_dissector.vlan" ;;
        qinq)  echo "net.flow_dissector.qinq" ;;  # auto-pulls in vlan on write of 1
        vxlan) echo "net.flow_dissector.vxlan_inner" ;;
        # Fallback / legacy paths. eth_ip is the parent series; pppoe
        # has no kernel knob yet — orchestrator runs the cells with
        # the legacy eth_ip toggle so the parent fast-path still
        # exercises.
        *)     echo "net.flow_dissector.eth_ip" ;;
      esac
    }
    PORT3=''${PORT3:-5201}
    # iperf3 warns if UDP block size > TCP MSS (typically 1398 on 1500
    # MTU, less on VXLAN overlay). Stay below to avoid stderr noise.
    UDP_PKTLEN=''${UDP_PKTLEN:-1200}
    UDP_PARALLEL=''${UDP_PARALLEL:-4}
    TCP_PARALLEL=''${TCP_PARALLEL:-4}
    today=$(date +%Y-%m-%d)
    OUT=''${OUT:-perf-results/$today-series3-extensions-soak}

    mkdir -p "$OUT"
    matrix_csv="$OUT/matrix.csv"
    # recv_sys_pct and recv_soft_pct are mpstat-derived averages across
    # all CPUs on the receiver (L2) host for the test window — captures
    # kernel softirq cost where flow_dissect actually runs. iperf3's
    # own cpu_utilization_percent measures the iperf3 process only,
    # which on wire-saturated workloads misses the fast-path saving
    # entirely; the mpstat columns are what the netdev cover-letter
    # numbers should come from.
    echo "pair,scenario,cell,proto,sysctl,dur_s,scenario_iface,scenario_v4,mbps,retransmits,recv_sys_pct,recv_soft_pct,kernel_has_sysctl,status" > "$matrix_csv"

    # Pair name → L L2 IFACE underlay_L underlay_L2
    # Hard-coded here rather than reaching into testbeds/*.toml from
    # bash; testbeds/*.toml is the source of truth for the values
    # below and they must match.
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
        *)
          return 1
          ;;
      esac
      return 0
    }

    # iperf3 / sysctl helpers — mirror series3-soak-x86.nix's pattern.
    iperf3_remote() {
      local host="$1"
      SSH root@"$host" 'nix eval --raw nixpkgs#iperf3' 2>/dev/null
    }

    open_iperf_fw() {
      local host="$1"
      SSH root@"$host" "
        iptables -C nixos-fw -p tcp --dport $PORT3 -j ACCEPT 2>/dev/null \
          || iptables -I nixos-fw 1 -p tcp --dport $PORT3 -j ACCEPT
        iptables -C nixos-fw -p udp --dport $PORT3 -j ACCEPT 2>/dev/null \
          || iptables -I nixos-fw 1 -p udp --dport $PORT3 -j ACCEPT
      " >/dev/null 2>&1 || true
    }
    close_iperf_fw() {
      local host="$1"
      SSH root@"$host" "
        iptables -D nixos-fw -p tcp --dport $PORT3 -j ACCEPT 2>/dev/null
        iptables -D nixos-fw -p udp --dport $PORT3 -j ACCEPT 2>/dev/null
      " >/dev/null 2>&1 || true
    }

    probe_sysctl() {
      local host="$1" path="$2"
      SSH root@"$host" "sysctl -n $path" >/dev/null 2>&1
    }

    set_sysctl() {
      local host="$1" val="$2" path="$3"
      SSH root@"$host" "sysctl -w $path=$val" >/dev/null 2>&1 || true
    }

    # ── Per-cell run ────────────────────────────────────────────────
    # globals from scenario env: SCEN_DEV_DUT SCEN_V4_DUT SCEN_DEV_L SCEN_V4_L
    #            (we use the DUT addr as the iperf3 target)
    run_cell() {
      local pair="$1" scen="$2" cell="$3" proto="$4" sysctl="$5" has_sysctl="$6"
      local cell_dir
      cell_dir="$OUT/$pair/$scen/cell-$(printf '%02d' "$cell")"
      mkdir -p "$cell_dir"

      local sysctl_path
      sysctl_path=$(scenario_sysctl "$scen")
      set_sysctl "$PAIR_L" "$sysctl" "$sysctl_path"
      set_sysctl "$PAIR_L2" "$sysctl" "$sysctl_path"

      local IPERF3_DUT IPERF3_GEN
      IPERF3_DUT=$(iperf3_remote "$PAIR_L2")/bin/iperf3
      IPERF3_GEN=$(iperf3_remote "$PAIR_L")/bin/iperf3

      # Daemonised one-shot server on DUT, bound to the scenario IP.
      SSH root@"$PAIR_L2" "pkill iperf3 2>/dev/null; $IPERF3_DUT -s -B $SCEN_V4_DUT -p $PORT3 -D -1" >/dev/null 2>&1 || true
      sleep 1

      local client_flags
      case "$proto" in
        tcp) client_flags="-t $DUR -P $TCP_PARALLEL -i 1 -J" ;;
        udp) client_flags="-t $DUR -u -b 0 -l $UDP_PKTLEN -P $UDP_PARALLEL -i 1 -J" ;;
        *)   client_flags="-t $DUR -i 1 -J" ;;
      esac

      # Spawn mpstat on the receiver (L2) for the duration of the test.
      # Captures per-CPU %sys + %soft averaged over the window; the
      # post-test "Average: all" row is where the kernel-CPU saving
      # signal lives. nix-shell wraps so testbed doesn't need sysstat
      # pre-installed in its NixOS config.
      SSH root@"$PAIR_L2" "nix shell nixpkgs#sysstat --command mpstat -P ALL 1 $DUR" \
        > "$cell_dir/mpstat.log" 2> "$cell_dir/mpstat.err" &
      local mpstat_pid=$!
      # Brief settle so mpstat's first sample isn't pre-iperf3-ramp idle.
      sleep 0.3

      # Keep stdout/stderr separate so iperf3's pre-JSON warnings
      # (e.g. "UDP block size … exceeds TCP MSS …") don't corrupt the
      # JSON parse below.
      SSH root@"$PAIR_L" "$IPERF3_GEN -c $SCEN_V4_DUT -p $PORT3 $client_flags" \
        > "$cell_dir/iperf3.json" 2> "$cell_dir/iperf3.err" || true

      SSH root@"$PAIR_L2" "pkill iperf3 2>/dev/null" >/dev/null 2>&1 || true

      # Wait for mpstat to finish naturally (it ran for DUR seconds).
      # Tolerate stale PID if the ssh exited early.
      wait "$mpstat_pid" 2>/dev/null || true

      local mbps retr status
      if jq -e . "$cell_dir/iperf3.json" >/dev/null 2>&1; then
        case "$proto" in
          tcp)
            mbps=$(jq -r '(.end.sum_received.bits_per_second // .end.sum.bits_per_second // 0) / 1000000' "$cell_dir/iperf3.json")
            retr=$(jq -r '.end.sum_sent.retransmits // 0' "$cell_dir/iperf3.json")
            ;;
          udp)
            mbps=$(jq -r '(.end.sum.bits_per_second // 0) / 1000000' "$cell_dir/iperf3.json")
            retr=$(jq -r '.end.sum.lost_packets // 0' "$cell_dir/iperf3.json")
            ;;
        esac
        status=ok
      else
        mbps=0; retr=0; status=fail
      fi

      # Parse mpstat "Average: all" row. Column layout on sysstat 12+:
      #   $1=Average:  $2=all  $3=%usr $4=%nice $5=%sys $6=%iowait
      #   $7=%irq $8=%soft $9=%steal $10=%guest $11=%gnice $12=%idle
      local recv_sys_pct recv_soft_pct
      recv_sys_pct=$(awk '$1=="Average:" && $2=="all" {print $5; exit}' "$cell_dir/mpstat.log" 2>/dev/null)
      recv_soft_pct=$(awk '$1=="Average:" && $2=="all" {print $8; exit}' "$cell_dir/mpstat.log" 2>/dev/null)
      recv_sys_pct=''${recv_sys_pct:-0.00}
      recv_soft_pct=''${recv_soft_pct:-0.00}

      printf '%s,%s,cell-%02d,%s,%s,%s,%s,%s,%.1f,%s,%s,%s,%s,%s\n' \
        "$pair" "$scen" "$cell" "$proto" "$sysctl" "$DUR" \
        "$SCEN_DEV_DUT" "$SCEN_V4_DUT" "$mbps" "$retr" \
        "$recv_sys_pct" "$recv_soft_pct" \
        "$has_sysctl" "$status" \
        >> "$matrix_csv"

      log "[$pair/$scen/cell$cell $proto sysctl=$sysctl] $mbps Mbps (retr=$retr, recv_sys=$recv_sys_pct%, recv_soft=$recv_soft_pct%, has_sysctl=$has_sysctl, status=$status)"
    }

    # ── Scenario lifecycle ─────────────────────────────────────────
    run_scenario_up() {
      local pair="$1" scen="$2" out_env="$3"
      case "$scen" in
        vlan|qinq|pppoe)
          OP=up L="$PAIR_L" L2="$PAIR_L2" \
            GEN_DEV="$PAIR_IFACE" DUT_DEV="$PAIR_IFACE" \
            nix run ".#netconf-$scen" > "$out_env"
          ;;
        vxlan)
          OP=up L="$PAIR_L" L2="$PAIR_L2" \
            GEN_DEV="$PAIR_IFACE" DUT_DEV="$PAIR_IFACE" \
            GEN_UNDERLAY_V4="$PAIR_UNDERLAY_L" \
            DUT_UNDERLAY_V4="$PAIR_UNDERLAY_L2" \
            nix run ".#netconf-vxlan" > "$out_env"
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
        vlan|qinq|pppoe)
          OP=down L="$PAIR_L" L2="$PAIR_L2" \
            GEN_DEV="$PAIR_IFACE" DUT_DEV="$PAIR_IFACE" \
            nix run ".#netconf-$scen" >/dev/null 2>&1 || true
          ;;
        vxlan)
          OP=down L="$PAIR_L" L2="$PAIR_L2" \
            GEN_DEV="$PAIR_IFACE" DUT_DEV="$PAIR_IFACE" \
            GEN_UNDERLAY_V4="$PAIR_UNDERLAY_L" \
            DUT_UNDERLAY_V4="$PAIR_UNDERLAY_L2" \
            nix run ".#netconf-vxlan" >/dev/null 2>&1 || true
          ;;
      esac
    }

    # ── Main loop ──────────────────────────────────────────────────
    log "=== series3-extensions-soak start  PAIRS=$PAIRS  SCENARIOS=$SCENARIOS  DUR=$DUR  OUT=$OUT ==="

    for pair in $(echo "$PAIRS" | tr ',' ' '); do
      if ! case_pair "$pair"; then
        log "WARN: unknown pair '$pair' — skipping"
        continue
      fi
      log "--- pair $pair: L=$PAIR_L L2=$PAIR_L2 iface=$PAIR_IFACE ---"

      has_sysctl=yes
      # Probe the eth_ip path (it's always-present whenever the v3
      # series is booted; the per-scenario knobs all live in the same
      # subtree). Per-scenario set_sysctl writes the right one inside
      # run_cell.
      if ! probe_sysctl "$PAIR_L" "net.flow_dissector.eth_ip" \
         || ! probe_sysctl "$PAIR_L2" "net.flow_dissector.eth_ip"; then
        log "WARN: net.flow_dissector.eth_ip missing on one or both hosts of $pair; cells will still run, sysctl writes best-effort"
        has_sysctl=no
      fi

      open_iperf_fw "$PAIR_L"
      open_iperf_fw "$PAIR_L2"

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
          continue
        fi

        # Ingest scenario-emitted vars without polluting bash globals
        # used by the orchestrator. Re-export under SCEN_*.
        SCEN_DEV_L=$(grep '^L_SCENARIO_DEV=' "$scen_env"  | cut -d= -f2-)
        SCEN_V4_L=$(grep '^L_SCENARIO_V4='   "$scen_env"  | cut -d= -f2-)
        SCEN_DEV_DUT=$(grep '^L2_SCENARIO_DEV=' "$scen_env" | cut -d= -f2-)
        SCEN_V4_DUT=$(grep '^L2_SCENARIO_V4='   "$scen_env" | cut -d= -f2-)
        log "[$pair/$scen] L=$SCEN_V4_L on $SCEN_DEV_L  ↔  L2=$SCEN_V4_DUT on $SCEN_DEV_DUT"

        cell=1
        for proto in tcp udp; do
          for sysctl in 0 1; do
            run_cell "$pair" "$scen" "$cell" "$proto" "$sysctl" "$has_sysctl"
            cell=$((cell + 1))
            sleep "$COOLDOWN"
          done
        done

        log "<<< $pair / $scen down"
        run_scenario_down "$pair" "$scen"
      done

      close_iperf_fw "$PAIR_L"
      close_iperf_fw "$PAIR_L2"
    done

    log "=== matrix complete: $matrix_csv ==="
    column -ts, "$matrix_csv" || cat "$matrix_csv"
  '';
}
