# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# flow-dissector-afxdp-live — Phase 8 of the matrix plan
# (docs/flow-dissector-matrix-implementation-plan.md §12).
#
# Composes the existing flow-dissector-ntuple-template-bench (single
# load) into an offered-load sweep across [1, 2, 5, 10] Mpps and emits
# one JSON per load under the Phase-4 result tree:
#
#   <results>/<date>/<testbed>/afxdp/<load>mpps.json
#
# Usage:
#   nix run .#flow-dissector-afxdp-live -- \
#       --testbed testbeds/<name>.toml \
#       [--duration 30] [--loads 1,2,5,10] [--results <dir>]
#
# Each per-load JSON carries:
#   { offered_mpps, duration_s, target, peer, interface,
#     pps_received, drops, drops_pct, queue_util, zerocopy,
#     bench_log }
#
# Live multi-host orchestration requires ssh access to the hosts
# named in the testbed-config TOML (and hardware able to push the
# offered load). `--help` and the documented error paths work
# without hardware so the wiring can be smoke-tested via
# `nix flake check`.

{ pkgs, ntupleTemplateBench }:

pkgs.writeShellApplication {
  name = "flow-dissector-afxdp-live";

  runtimeInputs = [
    ntupleTemplateBench
    pkgs.coreutils
    pkgs.gawk
    pkgs.gnused
    pkgs.gnugrep
    pkgs.jq
  ];

  text = ''
    set -eu

    usage() {
      cat <<'USAGE'
    Usage:
      flow-dissector-afxdp-live --testbed PATH [OPTIONS]

    Options:
      --testbed PATH    testbed-config TOML (required; schema:
                        nix/testbed-config.nix). Resolves DUT, generator,
                        and the data-plane interface.
      --duration N      Per-load bench duration in seconds (default: 30).
      --loads CSV       Comma-separated offered loads in Mpps
                        (default: "1,2,5,10"). Loads above the testbed's
                        [nic].link_speed_gbps capacity are clamped with
                        a warning.
      --results DIR     Result tree root. Default: $XDP2_RESULTS_ROOT
                        or ./perf-results.
      -h, --help        Show this help.

    What this command does:
      For each offered load L in --loads:
        1. Invokes flow-dissector-ntuple-template-bench against the
           testbed's DUT and generator with PKTGEN_RATE=$((L * 1e6)).
        2. Captures the bench output and writes
           <results>/<date>/<testbed>/afxdp/<L>mpps.json with
           pps_received, drops, drops_pct, queue_util, zerocopy mode.

    Live multi-host orchestration requires ssh access to the hosts
    named in the testbed-config TOML and hardware able to drive the
    offered loads. The DUT must have the xdp2.testbed module with
    flowDirectorRules + the af_xdp_parser XDP object available.
    USAGE
    }

    TESTBED=""
    DURATION=30
    LOADS_CSV="1,2,5,10"
    RESULTS=""

    while [ $# -gt 0 ]; do
      case "$1" in
        -h|--help) usage; exit 0 ;;
        --testbed)
          [ $# -ge 2 ] || { echo "flow-dissector-afxdp-live: --testbed requires PATH" >&2; exit 2; }
          TESTBED="$2"; shift 2 ;;
        --duration)
          [ $# -ge 2 ] || { echo "flow-dissector-afxdp-live: --duration requires N" >&2; exit 2; }
          DURATION="$2"; shift 2 ;;
        --loads)
          [ $# -ge 2 ] || { echo "flow-dissector-afxdp-live: --loads requires CSV" >&2; exit 2; }
          LOADS_CSV="$2"; shift 2 ;;
        --results)
          [ $# -ge 2 ] || { echo "flow-dissector-afxdp-live: --results requires DIR" >&2; exit 2; }
          RESULTS="$2"; shift 2 ;;
        --) shift; break ;;
        *) echo "flow-dissector-afxdp-live: unknown argument '$1'" >&2; usage >&2; exit 2 ;;
      esac
    done

    if [ -z "$TESTBED" ]; then
      echo "flow-dissector-afxdp-live: --testbed is required" >&2
      usage >&2
      exit 2
    fi
    if [ ! -f "$TESTBED" ]; then
      echo "flow-dissector-afxdp-live: testbed file not found: $TESTBED" >&2
      exit 2
    fi

    # Validate --duration is a positive integer.
    case "$DURATION" in
      '''|*[!0-9]*) echo "flow-dissector-afxdp-live: --duration must be a positive integer (got '$DURATION')" >&2; exit 2 ;;
    esac
    [ "$DURATION" -gt 0 ] || { echo "flow-dissector-afxdp-live: --duration must be > 0" >&2; exit 2; }

    # Validate --loads is a CSV of positive integers.
    if ! echo "$LOADS_CSV" | grep -qE '^[1-9][0-9]*(,[1-9][0-9]*)*$'; then
      echo "flow-dissector-afxdp-live: --loads must be a comma-separated list of positive integers (got '$LOADS_CSV')" >&2
      exit 2
    fi

    # Parse the testbed-config TOML for the fields we need. Same awk
    # heuristic used by nix/physical-testbed-runner.nix.
    parse_testbed() {
      local toml=$1
      awk -v field="$2" '
        BEGIN { section=""; cur_role=""; cur_host=""; ifc="" }
        function strip(s) { gsub(/^[ \t"]+|[ \t"]+$/, "", s); return s }
        /^\s*\[testbed\]/  { section="testbed"; next }
        /^\s*\[nic\]/      { section="nic"; next }
        /^\s*\[\[hosts\]\]/ { section="hosts"; cur_role=""; cur_host=""; next }
        /^\s*\[/           { section="other"; next }
        section == "testbed" && /^\s*name\s*=/ {
          sub(/^[^=]*=[[:space:]]*/, ""); print "name=" strip($0); next
        }
        section == "nic" && /^\s*dut_iface\s*=/ {
          sub(/^[^=]*=[[:space:]]*/, ""); print "dut_iface=" strip($0); next
        }
        section == "nic" && /^\s*gen_iface\s*=/ {
          sub(/^[^=]*=[[:space:]]*/, ""); print "gen_iface=" strip($0); next
        }
        section == "nic" && /^\s*link_speed_gbps\s*=/ {
          sub(/^[^=]*=[[:space:]]*/, ""); print "link_speed_gbps=" strip($0); next
        }
        section == "hosts" && /^\s*role\s*=/ {
          sub(/^[^=]*=[[:space:]]*/, ""); cur_role=strip($0)
        }
        section == "hosts" && /^\s*hostname\s*=/ {
          sub(/^[^=]*=[[:space:]]*/, ""); cur_host=strip($0)
          if (cur_role != "" && cur_host != "") {
            print cur_role "=" cur_host
            cur_role=""; cur_host=""
          }
        }
      ' "$toml" | awk -F= -v key="$2" '$1 == key { print $2; exit }'
    }

    TESTBED_NAME=$(parse_testbed "$TESTBED" "name")
    DUT=$(parse_testbed "$TESTBED" "dut")
    GEN=$(parse_testbed "$TESTBED" "generator")
    IFC=$(parse_testbed "$TESTBED" "dut_iface")
    LINK_GBPS=$(parse_testbed "$TESTBED" "link_speed_gbps")

    if [ -z "$TESTBED_NAME" ] || [ -z "$DUT" ] || [ -z "$IFC" ]; then
      echo "flow-dissector-afxdp-live: testbed missing name/dut/dut_iface (parsed name='$TESTBED_NAME' dut='$DUT' iface='$IFC')" >&2
      exit 2
    fi
    if [ -z "$GEN" ]; then
      echo "flow-dissector-afxdp-live: testbed has no host with role='generator' — required for AF_XDP live" >&2
      exit 2
    fi

    if [ -z "$RESULTS" ]; then
      RESULTS="''${XDP2_RESULTS_ROOT:-$PWD/perf-results}"
    fi
    run_date=$(date -I)
    OUT="$RESULTS/$run_date/$TESTBED_NAME/afxdp"
    mkdir -p "$OUT"

    echo "[afxdp-live] testbed=$TESTBED_NAME dut=$DUT gen=$GEN iface=$IFC duration=''${DURATION}s loads=$LOADS_CSV link_gbps=''${LINK_GBPS:-?}" >&2
    echo "[afxdp-live] results -> $OUT" >&2

    # Cap loads against link capacity (rough: 1500-byte frames at line rate
    # = link_gbps * 1e9 / (1500 * 8) pps; round down). If we can't parse
    # link_speed_gbps, skip the cap and proceed.
    cap_mpps=""
    if [ -n "$LINK_GBPS" ]; then
      case "$LINK_GBPS" in
        '''|*[!0-9]*) ;;  # non-numeric, skip
        *) cap_mpps=$(( LINK_GBPS * 1000 / (1500 * 8) )) ;;
      esac
    fi

    overall=0
    IFS=',' read -ra LOADS <<< "$LOADS_CSV"
    for L in "''${LOADS[@]}"; do
      eff="$L"
      if [ -n "$cap_mpps" ] && [ "$L" -gt "$cap_mpps" ]; then
        echo "[afxdp-live] WARN: load ''${L}Mpps exceeds link cap ''${cap_mpps}Mpps; clamping" >&2
        eff="$cap_mpps"
      fi

      pps=$(( eff * 1000000 ))
      log="$OUT/''${L}mpps.log"
      json="$OUT/''${L}mpps.json"
      echo "[afxdp-live] -> ''${L}Mpps (pktgen rate=$pps pps), logging to $log" >&2

      bench_status=0
      RESULT_DIR="$OUT/''${L}mpps-bench" \
      PKTGEN_RATE="$pps" \
      DPORT=443 \
      QUEUE=1 \
      TEMPLATE="eth-ipv4-udp" \
        xdp2-flow-dissector-ntuple-template-bench \
          -d "$DURATION" -i "$IFC" \
          "$DUT" "$GEN" \
          > "$log" 2>&1 || bench_status=$?

      # Best-effort extraction. The bench script's stdout format is not
      # a stable contract, so we grep for the documented summary lines
      # and fall back to nulls. Downstream consumers (aggregator, CI)
      # check for nulls and report low-quality data without failing.
      pps_rx=$(grep -oE 'pps_received[: =]+[0-9]+' "$log" 2>/dev/null | tail -1 | grep -oE '[0-9]+$' || true)
      drops=$(grep -oE 'drops?[: =]+[0-9]+' "$log" 2>/dev/null | tail -1 | grep -oE '[0-9]+$' || true)
      qutil=$(grep -oE 'queue_util[: =]+[0-9.]+' "$log" 2>/dev/null | tail -1 | grep -oE '[0-9.]+$' || true)
      zc=$(grep -oE 'zerocopy[: =]+(true|false|on|off|1|0)' "$log" 2>/dev/null | tail -1 | awk -F'[: =]+' '{print $NF}' || true)

      drops_pct="null"
      if [ -n "$pps_rx" ] && [ -n "$drops" ] && [ "$pps_rx" -gt 0 ]; then
        drops_pct=$(awk -v d="$drops" -v r="$pps_rx" 'BEGIN { printf "%.4f", (d / (d + r)) * 100 }')
      fi

      jq -n \
        --arg testbed "$TESTBED_NAME" \
        --arg target "$DUT" --arg peer "$GEN" --arg iface "$IFC" \
        --argjson offered "$L" \
        --argjson duration "$DURATION" \
        --argjson exit "$bench_status" \
        --arg pps_rx "''${pps_rx:-}" \
        --arg drops "''${drops:-}" \
        --arg qutil "''${qutil:-}" \
        --arg zc "''${zc:-}" \
        --arg drops_pct "$drops_pct" \
        --arg log "$log" \
        '{
          testbed: $testbed,
          target: $target, peer: $peer, interface: $iface,
          offered_mpps: $offered, duration_s: $duration,
          bench_exit: $exit,
          pps_received: ($pps_rx | if . == "" then null else tonumber end),
          drops:        ($drops  | if . == "" then null else tonumber end),
          drops_pct:    ($drops_pct | if . == "null" then null else tonumber end),
          queue_util:   ($qutil  | if . == "" then null else tonumber end),
          zerocopy:     ($zc     | if . == "" then null else . end),
          bench_log: $log
        }' > "$json"

      if [ "$bench_status" -ne 0 ]; then
        echo "[afxdp-live] ''${L}Mpps FAILED (exit=$bench_status, see $log)" >&2
        overall=1
      fi
    done

    echo "[afxdp-live] done. JSONs in $OUT" >&2
    exit "$overall"
  '';

  meta = {
    description = "AF_XDP live offered-load sweep with per-load JSON output";
    mainProgram = "flow-dissector-afxdp-live";
  };
}
