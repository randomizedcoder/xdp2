# nix/mlx5-offload-investigate.nix
#
# OFAT (one-feature-at-a-time) offload investigation harness for the
# IPIP +5.2% vs GRE -4% UDP throughput discrepancy on hp1<->hp3.
#
# For each (offload_feature, feature_state) pair, runs iperf3
# REPLICATES times under both sysctl=0 and sysctl=1, capturing
# throughput + mpstat receiver-CPU. Output is a flat CSV; pivot
# in your tool of choice.
#
# Reproduces in 1 command, with all variables declared at top of file
# and overridable via env. Designed for sharing with the kernel team:
# every wire-level decision (tunnel name, offload state, sysctl value)
# is in matrix.csv, not implied.
#
# Usage:
#   # Default: IPIP on hp1<->hp3, UDP, 30s per cell, 3 replicates,
#   # 5 OFAT toggles + baseline = 6 settings * 2 sysctls * 3 runs = 36 cells.
#   nix run .#mlx5-offload-investigate
#
#   # Same harness on GRE:
#   SCENARIO=gre nix run .#mlx5-offload-investigate
#
#   # Larger sample, longer cells:
#   DUR=60 REPLICATES=5 nix run .#mlx5-offload-investigate
#
# Tunables (env, defaults shown):
#   PAIR=hp1-hp3                    pair to test (one of the
#                                   case_pair entries below)
#   SCENARIO=ipip                   tunnel scenario (ipip|gre)
#   PROTO=udp                       iperf3 protocol (tcp|udp)
#   DUR=30                          per-cell test seconds
#   REPLICATES=3                    runs per (setting, sysctl) cell
#   FEATURES=tx,gso,gro,udp-seg,csum-ipv4   OFAT toggle set
#                                   (comma-separated keys; see
#                                   feature_ethtool_arg() below)
#   OUT=perf-results/<date>-mlx5-offload-<scenario>-<pair>/

{ pkgs }:

let
  libSh = builtins.readFile ./scenarios/lib.sh;
in
pkgs.writeShellApplication {
  name = "mlx5-offload-investigate";
  runtimeInputs = with pkgs; [ openssh coreutils jq python3 ];
  excludeShellChecks = [ "SC2029" "SC1090" ];
  text = ''
    set -u

    ${libSh}

    # ── Configuration ─────────────────────────────────────────────
    PAIR=''${PAIR:-hp1-hp3}
    SCENARIO=''${SCENARIO:-ipip}
    PROTO=''${PROTO:-udp}
    DUR=''${DUR:-30}
    REPLICATES=''${REPLICATES:-3}
    FEATURES=''${FEATURES:-tx,gso,gro,udp-seg,csum-ipv4}
    PORT3=''${PORT3:-5201}
    UDP_PKTLEN=''${UDP_PKTLEN:-1200}
    UDP_PARALLEL=''${UDP_PARALLEL:-4}
    TCP_PARALLEL=''${TCP_PARALLEL:-4}
    today=$(date +%Y-%m-%d)
    OUT=''${OUT:-perf-results/$today-mlx5-offload-$SCENARIO-$PAIR}

    # Pair name → L L2 IFACE underlay_L underlay_L2 (same as
    # series3-extensions-soak.nix; kept consistent on purpose).
    case_pair() {
      local pair="$1"
      case "$pair" in
        hp1-hp3)
          PAIR_L=hp1; PAIR_L2=hp3; PAIR_IFACE=enp1s0f0np0
          PAIR_UNDERLAY_L=10.10.2.1; PAIR_UNDERLAY_L2=10.10.2.3
          ;;
        hp2-hp5)
          PAIR_L=hp2; PAIR_L2=hp5; PAIR_IFACE=enp1s0f0np0
          PAIR_UNDERLAY_L=10.10.0.2; PAIR_UNDERLAY_L2=10.10.0.5
          ;;
        *)
          echo "ERROR: unknown pair $pair" >&2
          return 1 ;;
      esac
      return 0
    }
    case_pair "$PAIR" || exit 1

    # Map scenario → sysctl path + tunnel iface name (after netconf-X up).
    case "$SCENARIO" in
      ipip) SYSCTL=net.flow_dissector.ipip; TUN_NAME=ipip0 ;;
      gre)  SYSCTL=net.flow_dissector.gre;  TUN_NAME=gretest0 ;;
      *)    echo "ERROR: unsupported SCENARIO $SCENARIO (ipip|gre)" >&2; exit 1 ;;
    esac

    # Map FEATURE key → (ethtool -K key on/off arg) + (which iface to apply on).
    # Each entry is "key|ethtool_kw|iface_kind". iface_kind ∈ {tun,phy}
    # to mark whether we toggle on the tunnel or the physical iface.
    declare -A FEAT_ETHTOOL_KW=(
      [tx]="tx"                  # tunnel iface TX checksum offload
      [gso]="gso"                # generic segmentation offload, tunnel
      [gro]="gro"                # generic receive offload, tunnel
      [udp-seg]="tx-udp-segmentation" # tunnel
      [csum-ipv4]="tx-checksum-ip-generic" # physical iface
    )
    declare -A FEAT_IFACE_KIND=(
      [tx]=tun
      [gso]=tun
      [gro]=tun
      [udp-seg]=tun
      [csum-ipv4]=phy
    )

    feature_iface() {
      local key="$1"
      case "''${FEAT_IFACE_KIND[$key]:-}" in
        tun) echo "$TUN_NAME" ;;
        phy) echo "$PAIR_IFACE" ;;
        *)   echo "" ;;
      esac
    }

    mkdir -p "$OUT"
    matrix_csv="$OUT/matrix.csv"
    echo "pair,scenario,proto,feature,state,sysctl,run,mbps,retransmits,recv_sys_pct,recv_soft_pct,status" > "$matrix_csv"

    # ── Plumbing helpers ─────────────────────────────────────────
    set_sysctl_both() {
      local val="$1"
      SSH root@"$PAIR_L"  "sysctl -w $SYSCTL=$val" >/dev/null 2>&1 || true
      SSH root@"$PAIR_L2" "sysctl -w $SYSCTL=$val" >/dev/null 2>&1 || true
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

    iperf3_remote() {
      local host="$1"
      SSH root@"$host" 'nix eval --raw nixpkgs#iperf3' 2>/dev/null
    }

    set_feature_state() {
      # Apply one offload state (on/off) on both ends of the tunnel.
      # baseline = no override (we record the as-found state for the
      # baseline cell).
      local key="$1" state="$2"
      [ "$state" = "baseline" ] && return 0
      local kw="''${FEAT_ETHTOOL_KW[$key]:-}"
      [ -z "$kw" ] && { echo "WARN: unknown feature $key" >&2; return 1; }
      local iface_l iface_l2
      iface_l=$(feature_iface "$key")
      iface_l2=$(feature_iface "$key")
      SSH root@"$PAIR_L"  "ethtool -K $iface_l  $kw $state 2>/dev/null" >/dev/null 2>&1 || true
      SSH root@"$PAIR_L2" "ethtool -K $iface_l2 $kw $state 2>/dev/null" >/dev/null 2>&1 || true
    }

    read_feature_state() {
      # Read the current as-found ethtool state of one feature on the
      # L (sender) side. Used for the baseline cell so the CSV reflects
      # whatever the host actually has set.
      local key="$1"
      local kw="''${FEAT_ETHTOOL_KW[$key]:-}"
      [ -z "$kw" ] && { echo "?"; return; }
      local iface
      iface=$(feature_iface "$key")
      SSH root@"$PAIR_L" "ethtool -k $iface 2>/dev/null | awk -v k=\"$kw:\" '\$1==k{print \$2}'" | head -1
    }

    # ── Run one cell ─────────────────────────────────────────────
    # Records mbps + mpstat-derived recv_sys / recv_soft into matrix.csv.
    run_one_cell() {
      local feature="$1" state="$2" sysctl="$3" run_idx="$4"
      local cell_dir
      cell_dir="$OUT/cells/$feature-$state-s$sysctl-r$run_idx"
      mkdir -p "$cell_dir"

      set_sysctl_both "$sysctl"

      local IPERF3_DUT IPERF3_GEN
      IPERF3_DUT=$(iperf3_remote "$PAIR_L2")/bin/iperf3
      IPERF3_GEN=$(iperf3_remote "$PAIR_L")/bin/iperf3

      SSH root@"$PAIR_L2" "pkill iperf3 2>/dev/null; $IPERF3_DUT -s -B $TUN_V4_DUT -p $PORT3 -D -1" >/dev/null 2>&1 || true
      sleep 1

      local client_flags
      case "$PROTO" in
        tcp) client_flags="-t $DUR -P $TCP_PARALLEL -i 1 -J" ;;
        udp) client_flags="-t $DUR -u -b 0 -l $UDP_PKTLEN -P $UDP_PARALLEL -i 1 -J" ;;
        *)   client_flags="-t $DUR -i 1 -J" ;;
      esac

      SSH root@"$PAIR_L2" "nix shell nixpkgs#sysstat --command mpstat -P ALL 1 $DUR" \
        > "$cell_dir/mpstat.log" 2> "$cell_dir/mpstat.err" &
      local mpstat_pid=$!
      sleep 0.3

      SSH root@"$PAIR_L" "$IPERF3_GEN -c $TUN_V4_DUT -p $PORT3 $client_flags" \
        > "$cell_dir/iperf3.json" 2> "$cell_dir/iperf3.err" || true

      SSH root@"$PAIR_L2" "pkill iperf3 2>/dev/null" >/dev/null 2>&1 || true
      wait "$mpstat_pid" 2>/dev/null || true

      local mbps retr status
      if jq -e . "$cell_dir/iperf3.json" >/dev/null 2>&1; then
        case "$PROTO" in
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

      local recv_sys recv_soft
      recv_sys=$(awk '$1=="Average:" && $2=="all" {print $5; exit}' "$cell_dir/mpstat.log" 2>/dev/null)
      recv_soft=$(awk '$1=="Average:" && $2=="all" {print $8; exit}' "$cell_dir/mpstat.log" 2>/dev/null)
      recv_sys=''${recv_sys:-0.00}
      recv_soft=''${recv_soft:-0.00}

      printf '%s,%s,%s,%s,%s,%s,%s,%.1f,%s,%s,%s,%s\n' \
        "$PAIR" "$SCENARIO" "$PROTO" \
        "$feature" "$state" "$sysctl" "$run_idx" \
        "$mbps" "$retr" "$recv_sys" "$recv_soft" "$status" \
        >> "$matrix_csv"

      log "[$feature/$state sysctl=$sysctl run=$run_idx] $mbps Mbps (retr=$retr, recv_soft=$recv_soft%)"
    }

    # ── Main ─────────────────────────────────────────────────────
    log "=== mlx5-offload-investigate: PAIR=$PAIR SCEN=$SCENARIO PROTO=$PROTO DUR=$DUR REPLICATES=$REPLICATES OUT=$OUT ==="

    open_iperf_fw "$PAIR_L"
    open_iperf_fw "$PAIR_L2"

    # Bring up the scenario once for the entire investigation.
    scen_env="$OUT/scenario.env"
    log ">>> bring up $SCENARIO"
    OP=up L="$PAIR_L" L2="$PAIR_L2" \
      GEN_DEV="$PAIR_IFACE" DUT_DEV="$PAIR_IFACE" \
      GEN_UNDERLAY_V4="$PAIR_UNDERLAY_L" \
      DUT_UNDERLAY_V4="$PAIR_UNDERLAY_L2" \
      nix run ".#netconf-$SCENARIO" > "$scen_env"
    TUN_V4_GEN=$(grep '^L_SCENARIO_V4='  "$scen_env" | cut -d= -f2-)
    TUN_V4_DUT=$(grep '^L2_SCENARIO_V4=' "$scen_env" | cut -d= -f2-)
    log "tunnel up: $PAIR_L($TUN_V4_GEN) <-> $PAIR_L2($TUN_V4_DUT) on $TUN_NAME"

    # Baseline cell: record current as-found feature state, no toggles.
    log "--- baseline (as-found offload state) ---"
    for sysctl in 0 1; do
      for r in $(seq 1 "$REPLICATES"); do
        run_one_cell baseline asfound "$sysctl" "$r"
      done
    done

    # OFAT cells: toggle one feature at a time, off then on, replicate.
    # Reset to baseline (no toggles) between OFAT features so combinations
    # don't accumulate.
    for feature in $(echo "$FEATURES" | tr ',' ' '); do
      log "--- OFAT: feature=$feature ---"
      local_state=$(read_feature_state "$feature")
      log "as-found $feature on $PAIR_L = $local_state"

      for state in off on; do
        set_feature_state "$feature" "$state"
        for sysctl in 0 1; do
          for r in $(seq 1 "$REPLICATES"); do
            run_one_cell "$feature" "$state" "$sysctl" "$r"
          done
        done
      done

      # Restore as-found state so the next feature starts from baseline.
      if [ -n "$local_state" ] && [ "$local_state" != "?" ]; then
        set_feature_state "$feature" "$local_state"
      fi
    done

    # Tear down the scenario.
    log "<<< tearing down $SCENARIO"
    OP=down L="$PAIR_L" L2="$PAIR_L2" \
      GEN_DEV="$PAIR_IFACE" DUT_DEV="$PAIR_IFACE" \
      GEN_UNDERLAY_V4="$PAIR_UNDERLAY_L" \
      DUT_UNDERLAY_V4="$PAIR_UNDERLAY_L2" \
      nix run ".#netconf-$SCENARIO" >/dev/null 2>&1 || true

    close_iperf_fw "$PAIR_L"
    close_iperf_fw "$PAIR_L2"

    log "=== matrix complete: $matrix_csv ==="
    column -ts, "$matrix_csv" | head -80 || cat "$matrix_csv"

    # ── Auto-summary ─────────────────────────────────────────────
    # For each (feature, state), compute mean + std mbps across runs,
    # at both sysctl=0 and sysctl=1.
    log "=== summary (mean mbps ± std per cell): ==="
    python3 - <<'PYEOF' "$matrix_csv"
import csv, sys, statistics
from collections import defaultdict
rows = list(csv.DictReader(open(sys.argv[1])))
by_cell = defaultdict(list)
for r in rows:
    if r["status"] != "ok":
        continue
    k = (r["feature"], r["state"], r["sysctl"])
    by_cell[k].append((float(r["mbps"]), float(r["recv_soft_pct"])))
print(f"{'feature':<12} {'state':<8} {'sysctl':<6} {'mbps_mean':>10} {'mbps_std':>8} {'soft_mean':>10} {'n':>3}")
print("-"*68)
for k in sorted(by_cell.keys()):
    f, s, syc = k
    samples = by_cell[k]
    mbps = [m for m, _ in samples]
    soft = [s for _, s in samples]
    mean_m = statistics.mean(mbps)
    std_m  = statistics.stdev(mbps) if len(mbps) > 1 else 0.0
    mean_s = statistics.mean(soft)
    print(f"{f:<12} {s:<8} {syc:<6} {mean_m:>10.1f} {std_m:>8.1f} {mean_s:>10.2f} {len(mbps):>3}")
PYEOF
  '';
}
