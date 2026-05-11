# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# flow-dissector-parity-check — Phase 17.C driver for the
# cross-parser parity gate. See
# /home/das/.claude/profiles/personal/plans/das-l-downloads-xdp2-find-name-fizzy-ocean.md
# (Phase 17 plan).
#
# What it does:
#   For each requested parser_id (default: all 15 from
#   samples/flow_dissector/parity_scope.json), invoke the appropriate
#   binary on the given pcap with --dump-meta / -D, capture per-packet
#   ParityRecord JSONL into <out>/<parser_id>.jsonl, then run
#   nix/scripts/parity-compare.py over the resulting JSONL tree to
#   surface acceptance and field disagreements.
#
# Usage:
#   nix run .#flow-dissector-parity-check -- --pcap <path> [--out DIR] \
#     [--parsers c-flowdis-usp,c-xdp2-usp,...]
#
# Exits 0 if zero unexpected disagreements; non-zero with count and
# parity-report.{md,csv} pointing at the disagreement details.

{ pkgs, xdp2Rs, flowDissectorMatrix, parityCompare }:

let
  artifacts = flowDissectorMatrix.artifacts;
in

pkgs.writeShellApplication {
  name = "flow-dissector-parity-check";

  runtimeInputs = [
    xdp2Rs.build              # provides xdp2-bench
    artifacts                 # provides benchmark + benchmark_bpf + bpf objects
    parityCompare             # provides parity-compare (Python wrapper)
    pkgs.coreutils
    pkgs.jq
    pkgs.python3
  ];

  text = ''
    set -eu

    usage() {
      cat <<'USAGE'
    Usage:
      flow-dissector-parity-check --pcap PATH [OPTIONS]

    Options:
      --pcap PATH           PCAP file (required).
      --out DIR             Output directory for per-parser JSONL +
                            parity-report.{md,csv}. Default: a temp dir.
      --parsers CSV         Comma-separated parser_ids to include.
                            Default: all 15 (c-flowdis-usp, c-xdp2-usp,
                            c-xdp2-parse-only, c-bpf-flowdis, c-bpf-xdp2,
                            c-bpf-fast, rust-graph, rust-graph-enum,
                            rust-mono, rust-mono-x4, rust-compiled,
                            rust-simd, rust-template, rust-template-simd).
      --scope PATH          Path to parity_scope.json (default in repo).
      -h, --help            This help.

    What this command does:
      1. Resolves the binary for each parser_id and invokes it on
         the pcap with the appropriate dump-meta flag, writing one
         JSONL per parser into --out.
      2. Runs nix/scripts/parity-compare.py over the tree.
      3. Exits with the comparator's status (0 = clean, 1 =
         disagreements, 2 = harness error).

    BPF parsers require CAP_BPF (root or capability). c-bpf-xdp2 is
    documented as kernel-verifier-rejected on 7.x; the driver
    synthesises its 100%-rejected JSONL without trying to load the
    object.
    USAGE
    }

    PCAP=""
    OUT=""
    PARSERS_CSV="c-flowdis-usp,c-xdp2-usp,c-xdp2-parse-only,c-xdp2-mono,c-bpf-flowdis,c-bpf-xdp2,c-bpf-fast,rust-graph,rust-graph-enum,rust-mono,rust-mono-x4,rust-compiled,rust-simd,rust-template,rust-template-simd"
    SCOPE_PATH=""

    while [ $# -gt 0 ]; do
      case "$1" in
        -h|--help) usage; exit 0 ;;
        --pcap)
          [ $# -ge 2 ] || { echo "parity-check: --pcap requires PATH" >&2; exit 2; }
          PCAP="$2"; shift 2 ;;
        --out)
          [ $# -ge 2 ] || { echo "parity-check: --out requires DIR" >&2; exit 2; }
          OUT="$2"; shift 2 ;;
        --parsers)
          [ $# -ge 2 ] || { echo "parity-check: --parsers requires CSV" >&2; exit 2; }
          PARSERS_CSV="$2"; shift 2 ;;
        --scope)
          [ $# -ge 2 ] || { echo "parity-check: --scope requires PATH" >&2; exit 2; }
          SCOPE_PATH="$2"; shift 2 ;;
        *) echo "parity-check: unknown argument '$1'" >&2; usage >&2; exit 2 ;;
      esac
    done

    if [ -z "$PCAP" ]; then
      echo "parity-check: --pcap is required" >&2
      usage >&2
      exit 2
    fi
    if [ ! -f "$PCAP" ]; then
      echo "parity-check: pcap not found: $PCAP" >&2
      exit 2
    fi

    if [ -z "$OUT" ]; then
      OUT=$(mktemp -d -t xdp2-parity-XXXX)
    fi
    mkdir -p "$OUT"

    PCAP_BASENAME=$(basename "$PCAP")
    echo "[parity-check] pcap=$PCAP out=$OUT" >&2

    # Locate static assets baked into the artifact paths.
    BPF_FLOW_KERN="${artifacts}/lib/xdp2-flow-dissector-matrix/bpf_flow.kern.o"
    BPF_FLOW_FAST="${artifacts}/lib/xdp2-flow-dissector-matrix/fast_flow.bpf.o"
    # flow_dissector.bpf.o (the c-bpf-xdp2 candidate) is verifier-rejected
    # on 7.x; the dispatch table below synthesises its records without
    # loading the object, so we don't reference it here.

    # Comma-split.
    IFS=',' read -ra PARSERS <<< "$PARSERS_CSV"

    # Dispatch per parser_id. The C userspace binary writes ALL three
    # c-* parsers' records in one invocation; we still run it once per
    # unique caller request so partial parser sets work.
    C_USERSPACE_DONE=0

    for pid in "''${PARSERS[@]}"; do
      out_file="$OUT/$pid.jsonl"
      echo "[parity-check] $pid → $out_file" >&2

      case "$pid" in
        c-flowdis-usp|c-xdp2-usp|c-xdp2-parse-only|c-xdp2-mono)
          if [ "$C_USERSPACE_DONE" -eq 0 ]; then
            # benchmark.c -D writes c-flowdis-usp + c-xdp2-usp +
            # c-xdp2-parse-only + c-xdp2-mono into one file. Split
            # by parser_id. c-xdp2-mono is the R3 monolithic-codegen
            # reference parser (samples/flow_dissector/flow_dissector_mono.h).
            tmpfile=$(mktemp)
            "${artifacts}/bin/benchmark" -c -D "$tmpfile" "$PCAP" \
                >/dev/null 2>&1 || true
            for sub in c-flowdis-usp c-xdp2-usp c-xdp2-parse-only c-xdp2-mono; do
              grep "\"parser_id\":\"$sub\"" "$tmpfile" > "$OUT/$sub.jsonl" || true
            done
            rm -f "$tmpfile"
            C_USERSPACE_DONE=1
          fi
          ;;
        c-bpf-flowdis)
          "${artifacts}/bin/benchmark_bpf" -c \
              -b "$BPF_FLOW_KERN" \
              -P c-bpf-flowdis \
              -D "$out_file" \
              "$PCAP" >/dev/null 2>&1 || \
            echo "[parity-check] WARN: c-bpf-flowdis bench failed (CAP_BPF?); empty file" >&2
          ;;
        c-bpf-xdp2)
          # Documented Way-5 N/A: the kernel verifier rejects
          # flow_dissector.bpf.o on 7.x. Synthesise one rejected
          # record per packet rather than try to load.
          npkts=$(python3 "${../nix/scripts/pcap-count.py}" "$PCAP")
          : > "$out_file"
          for ((i=0; i<npkts; i++)); do
            printf '{"schema_version":1,"pcap":"%s","packet_index":%d,"parser_id":"c-bpf-xdp2","parser_kind":"bpf","accepted":false,"reject_reason":"verifier","fields":{}}\n' \
              "$PCAP_BASENAME" "$i" >> "$out_file"
          done
          ;;
        c-bpf-fast)
          "${artifacts}/bin/benchmark_bpf" -c \
              -b "$BPF_FLOW_FAST" \
              -P c-bpf-fast \
              -D "$out_file" \
              "$PCAP" >/dev/null 2>&1 || \
            echo "[parity-check] WARN: c-bpf-fast bench failed (CAP_BPF?); empty file" >&2
          ;;
        rust-graph|rust-graph-enum|rust-mono|rust-mono-x4|\
        rust-compiled|rust-simd|rust-template|rust-template-simd)
          rust_mode="''${pid#rust-}"
          xdp2-bench --pcap "$PCAP" --mode "$rust_mode" \
            --dump-meta "$out_file" --dump-meta-only \
            >/dev/null 2>&1 || \
            echo "[parity-check] WARN: $pid bench failed; empty file" >&2
          ;;
        *)
          echo "[parity-check] WARN: unknown parser_id '$pid', skipping" >&2
          ;;
      esac
    done

    # Run the comparator over the tree.
    echo "[parity-check] running comparator over $OUT" >&2

    # The parity-compare wrapper resolves --scope to its vendored
    # default unless the caller passed --scope explicitly.
    set +e
    if [ -n "$SCOPE_PATH" ]; then
      parity-compare --scope "$SCOPE_PATH" --jsonl-dir "$OUT" --out-dir "$OUT"
    else
      parity-compare --jsonl-dir "$OUT" --out-dir "$OUT"
    fi
    rc=$?
    set -e

    echo "[parity-check] done. report: $OUT/parity-report.md (exit=$rc)" >&2
    exit "$rc"
  '';

  meta = {
    description =
      "Cross-parser parity check: run all 15 flow-dissector parsers, compare extracted FlowMeta";
    mainProgram = "flow-dissector-parity-check";
  };
}
