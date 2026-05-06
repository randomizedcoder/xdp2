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

    # Cap loads against link capacity. The cap is small-frame line rate
    # (84-byte frame including preamble + IFG + FCS):
    #   Mpps_max = link_gbps * 1e9 / (84 * 8) / 1e6 = link_gbps * 125 / 84.
    # For 10 Gbps: ~14.88 Mpps (matches the 2026-04-25 D1 measurement
    # where pktgen at 64B + burst=32 + queue_map reached 14.39 Mpps =
    # ~10 GbE line rate at 64-byte frames). Larger-frame workloads may
    # legitimately fall below this cap; the cap is only a sanity bound,
    # not a frame-size-aware constraint. The previous formula assumed
    # 1500-byte frames (~0.83 Mpps cap) and integer-truncated to 0,
    # silently clamping every requested load to 0 pps.
    cap_mpps=""
    if [ -n "$LINK_GBPS" ]; then
      case "$LINK_GBPS" in
        '''|*[!0-9]*) ;;  # non-numeric, skip
        *) cap_mpps=$(( LINK_GBPS * 125 / 84 )) ;;
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

      # Best-effort extraction from the bench's per-queue table:
      #
      #   queue    | template                    |     packets |  bytes | ns/pkt |  Mpps
      #   1        | EthIpv4Udp                  |    26333552 | …      |   1139 |  0.88
      #
      # Stdout format is not a stable contract, so a missing field
      # resolves to null — downstream consumers (aggregator, CI) skip
      # null cells without failing the whole run.
      queue_line=$(grep -E '^[[:space:]]*[0-9]+[[:space:]]*\|' "$log" 2>/dev/null | grep -v '^queue ' | tail -1 || true)
      packets_rx=""
      mpps_rx=""
      if [ -n "$queue_line" ]; then
        packets_rx=$(awk -F'|' '{gsub(/[[:space:]]/, "", $3); print $3}' <<< "$queue_line")
        mpps_rx=$(awk -F'|' '{gsub(/[[:space:]]/, "", $6); print $6}' <<< "$queue_line")
        # Sanity: numeric.
        [[ "$packets_rx" =~ ^[0-9]+$ ]] || packets_rx=""
        [[ "$mpps_rx" =~ ^[0-9.]+$ ]] || mpps_rx=""
      fi
      pps_rx=""
      if [ -n "$packets_rx" ] && [ "$DURATION" -gt 0 ]; then
        pps_rx=$(( packets_rx / DURATION ))
      fi

      # Drops: offered - received. Offered = $eff Mpps × duration × 1e6.
      drops=""
      drops_pct="null"
      if [ -n "$packets_rx" ]; then
        offered_pkts=$(( eff * 1000000 * DURATION ))
        if [ "$offered_pkts" -gt "$packets_rx" ]; then
          drops=$(( offered_pkts - packets_rx ))
          drops_pct=$(awk -v d="$drops" -v o="$offered_pkts" 'BEGIN { printf "%.4f", d / o * 100 }')
        else
          drops=0
          drops_pct="0.0000"
        fi
      fi

      # Zerocopy: presence of "AF_XDP: registered in XSKMAP" + native
      # attach mode (xdpdrv, not xdpgeneric) in the log signals zero-copy.
      zc=""
      if grep -q 'XDP_MODE=xdpdrv' "$log" 2>/dev/null \
         && grep -q 'registered in XSKMAP' "$log" 2>/dev/null; then
        zc="zerocopy"
      elif grep -q 'XDP_MODE=xdpgeneric' "$log" 2>/dev/null; then
        zc="copy"
      fi

      qutil=$(grep -oE 'queue_util[: =]+[0-9.]+' "$log" 2>/dev/null | tail -1 | grep -oE '[0-9.]+$' || true)

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
