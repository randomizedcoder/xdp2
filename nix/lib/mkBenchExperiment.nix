# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# mkBenchExperiment — factory for repeatable testbed experiments.
#
# Every entry in docs/physical-testbed.md §9 Category H corresponds
# to exactly one writeShellApplication produced by this helper.
# Operator runs `nix run .#xdp2-exp-<name> -- <target> <peer>` and
# gets a self-contained, shellchecked wrapper that:
#
#   1. prints a banner + hypothesis + expected outcome,
#   2. exports the single tunable difference vs the baseline,
#   3. invokes the underlying ntuple-template-bench orchestrator,
#   4. parses xdp2-bench table output + pktgen-final-status.log,
#   5. writes perf-results/${target}/exp-<name>-${ts}/{run.log,
#      summary.json,SUMMARY.md} for cross-run comparison.
#
# Inputs:
#   name         Derivation name (also experiment id). Must match
#                ^xdp2-exp-[a-z0-9-]+$ so `nix flake show` lists
#                all experiments together.
#   description  One-paragraph hypothesis. Shown in banner + stored
#                in summary.json for provenance.
#   envVars      Attrset of env vars the experiment exports before
#                invoking the orchestrator. Exactly ONE tunable
#                difference per experiment — that's the whole point.
#   benchArgs    String passed verbatim to the orchestrator as argv
#                prefix (e.g. "-d 30 -s 64 -t 6"). Positional
#                <target> <peer> come from "$@" after these.
#   expectation  One-line prediction of the result. Stored in
#                summary.json so regressions are self-annotating.
#
# Non-goals: this helper does NOT orchestrate. It wraps. The single
# source of truth for attach/cleanup/pktgen lifecycle remains
# samples/flow_dissector/run_ntuple_template_bench.sh.

{ pkgs, ntupleTemplateBench }:

{ name
, description
, envVars ? { }
, benchArgs ? ""
, expectation ? ""
  # Optional overrides for the Deliverable-2 DPDK orchestrator path.
  # Default is today's kernel-pktgen orchestrator; D2 experiments set
  # these to the DPDK orchestrator derivation + its binary name. The
  # summary-scraping/parse logic is identical either way because
  # run_ntuple_template_bench.sh is the single source of truth and
  # only PKTGEN_SCRIPT differs between the two orchestrators.
, benchTool ? ntupleTemplateBench
, benchBin ? "xdp2-flow-dissector-ntuple-template-bench"
}:

let
  envExports = pkgs.lib.concatStringsSep "\n"
    (pkgs.lib.mapAttrsToList
      (k: v: ''export ${k}=${pkgs.lib.escapeShellArg (toString v)}'')
      envVars);
  # Short name used in the result-dir: strip the canonical
  # "xdp2-exp-" prefix so the dir is
  #   perf-results/<target>/exp-pktgen-baseline-<ts>/
  # rather than the double-prefixed
  #   perf-results/<target>/exp-xdp2-exp-pktgen-baseline-<ts>/.
  shortName = pkgs.lib.removePrefix "xdp2-exp-" name;
in
pkgs.writeShellApplication {
  inherit name;

  runtimeInputs = [
    benchTool
    pkgs.coreutils
    pkgs.gawk
    pkgs.gnugrep
    pkgs.gnused
    pkgs.jq
  ];

  text = ''
    if [[ $# -lt 2 ]]; then
      echo "Usage: ${name} <target_host> <peer_host> [extra-bench-args...]" >&2
      exit 2
    fi

    TARGET="$1"
    PEER="$2"
    shift 2

    ts=$(date +%Y%m%dT%H%M%S)
    EXP_DIR="perf-results/''${TARGET}/exp-${shortName}-''${ts}"
    mkdir -p "$EXP_DIR"

    cat <<'__BANNER__'
=== EXPERIMENT: ${name} ===
Description: ${description}
Expectation: ${expectation}
__BANNER__
    echo "Target:      $TARGET"
    echo "Peer:        $PEER"
    echo "Result dir:  $EXP_DIR"
    echo ""

    ${envExports}

    # The orchestrator always writes into perf-results/${"$"}{TARGET}/
    # ntuple-template-bench-${"$"}{ts}/; we scrape its last line of
    # "Result dir:" output to find it, then copy artefacts into our
    # experiment-scoped directory so the lab notebook has everything
    # in one place.
    BENCH_LOG="$EXP_DIR/run.log"
    set +e
    # shellcheck disable=SC2086
    ${benchBin} ${benchArgs} "$@" "$TARGET" "$PEER" \
        2>&1 | tee "$BENCH_LOG"
    rc=''${PIPESTATUS[0]}
    set -e

    BENCH_DIR=$(grep -E '^Result dir:' "$BENCH_LOG" | awk '{print $3}' | tail -1)
    if [[ -n "$BENCH_DIR" && -d "$BENCH_DIR" ]]; then
        cp -r "$BENCH_DIR"/. "$EXP_DIR"/ || true
    fi

    # Parse the template table line:
    #   queue | template | packets | bytes | ns/pkt | Mpps
    # The actual separator is "|". Only the first EthIpv4Udp line is
    # captured — we run single-queue, single-template today.
    STATS_FILE="$EXP_DIR/xdp2-bench-af-xdp-template.txt"
    PACKETS=0; BYTES=0; NS_PER_PKT=0; MPPS=0
    if [[ -f "$STATS_FILE" ]]; then
        read -r PACKETS BYTES NS_PER_PKT MPPS < <(
            awk -F'|' '
                /EthIpv4Udp/ && !seen {
                    gsub(/ /, "", $3); gsub(/ /, "", $4);
                    gsub(/ /, "", $5); gsub(/ /, "", $6);
                    print $3, $4, $5, $6;
                    seen=1;
                }
            ' "$STATS_FILE"
        )
        : "''${PACKETS:=0}" "''${BYTES:=0}" "''${NS_PER_PKT:=0}" "''${MPPS:=0}"
    fi

    # Parse pktgen-final-status.log for sent/errors totals. Sum the
    # "pkts-sofar:" lines across all per-device counters. Format:
    #   pkts-sofar: 12151333  errors: 0
    PKTGEN_LOG="$EXP_DIR/pktgen-final-status.log"
    SENT=0; ERRORS=0
    if [[ -f "$PKTGEN_LOG" ]]; then
        SENT=$(awk '/pkts-sofar:/ {s+=$2} END {print s+0}' "$PKTGEN_LOG")
        ERRORS=$(awk '/errors:/ {for(i=1;i<=NF;i++) if($i=="errors:") e+=$(i+1)} END {print e+0}' "$PKTGEN_LOG")
    fi

    DROPPED=$(( SENT - PACKETS ))
    if (( SENT > 0 )); then
        DROP_PCT=$(awk -v s="$SENT" -v d="$DROPPED" 'BEGIN{ printf "%.2f", (d/s)*100 }')
    else
        DROP_PCT="0.00"
    fi

    jq -n \
        --arg name        "${name}" \
        --arg description "${description}" \
        --arg expectation "${expectation}" \
        --arg ts          "$ts" \
        --arg target      "$TARGET" \
        --arg peer        "$PEER" \
        --argjson sent    "$SENT" \
        --argjson rx      "$PACKETS" \
        --argjson dropped "$DROPPED" \
        --arg drop_pct    "$DROP_PCT" \
        --argjson errors  "$ERRORS" \
        --argjson ns_pkt  "$NS_PER_PKT" \
        --arg mpps        "$MPPS" \
        --argjson rc      "$rc" \
        '{
            experiment: $name,
            description: $description,
            expectation: $expectation,
            timestamp: $ts,
            target: $target,
            peer: $peer,
            sent: $sent,
            rx: $rx,
            dropped: $dropped,
            drop_pct: ($drop_pct | tonumber),
            tx_errors: $errors,
            ns_per_pkt: $ns_pkt,
            mpps: ($mpps | tonumber),
            orchestrator_rc: $rc
        }' > "$EXP_DIR/summary.json"

    {
        echo "# ${name}"
        echo ""
        echo "- **ts:** $ts"
        echo "- **target / peer:** $TARGET / $PEER"
        echo "- **sent:** $SENT pkts"
        echo "- **rx:** $PACKETS pkts"
        echo "- **dropped:** $DROPPED pkts (''${DROP_PCT}%)"
        echo "- **ns/pkt:** $NS_PER_PKT"
        echo "- **Mpps:** $MPPS"
        echo "- **tx errors:** $ERRORS"
        echo "- **orchestrator rc:** $rc"
    } > "$EXP_DIR/SUMMARY.md"

    echo ""
    echo "=== EXPERIMENT RESULT: ${name} ==="
    cat "$EXP_DIR/SUMMARY.md"
    echo ""
    echo "summary.json: $EXP_DIR/summary.json"

    # Non-zero only on orchestration failure. "Result below
    # expectation" is a useful negative result, not a build error.
    exit "$rc"
  '';
}
