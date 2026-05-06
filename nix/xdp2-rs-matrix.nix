# nix/xdp2-rs-matrix.nix
#
# Unified xdp2-rs vs C-matrix benchmark harness. One command, one PCAP,
# one table — both halves of the project measured with identical
# methodology so the numbers can be laid side-by-side.
#
# Usage:
#   nix run .#flow-dissector-matrix-unified               — runs against
#       the cached workload-pcap-https-web derivation.
#   nix run .#flow-dissector-matrix-unified -- <pcap>     — runs against
#       a user-supplied PCAP.
#
# Flow:
#   1. xdp2-bench --pcap <in> --output-pcap <filtered>   (parse-filter)
#   2. benchmark (userspace, ways 1-3) on filtered pcap
#   3. benchmark_bpf (BPF, ways 4-6) on filtered pcap    (needs root)
#   4. xdp2-bench --mode <m> --pcap <filtered> --report  for
#      m in {graph, mono, compiled, template}
#   5. Merge all rows into one comparison table.
#
# Why the filter step: xdp2-bench only benchmarks packets its Rust parse
# graph handles, so measuring the C matrix on the exact same set lets
# the two columns be compared fairly. Without this step, the C matrix
# includes packets the Rust parser rejects (and vice versa if we were
# to gate on the C filter), inflating one side's throughput relative to
# the other.

{ pkgs
, xdp2Rs                        # xdp2-rs crate bundle — provides xdp2-bench
, flowDissectorMatrix           # C matrix artifacts — provides benchmark, benchmark_bpf, *.bpf.o
, workloadPcapHttpsWeb          # cached https-web workload PCAP derivation
, parityCheck                   # flow-dissector-parity-check (Phase 17.E hook)
}:

let
  lib = pkgs.lib;
  artifacts = flowDissectorMatrix.artifacts;
in

pkgs.writeShellApplication {
  name = "xdp2-flow-dissector-matrix-unified";

  runtimeInputs = [
    pkgs.coreutils
    pkgs.gnugrep
    pkgs.gawk
    pkgs.jq                     # rewriting per-cell JSON with parity fields
    xdp2Rs.build                # provides xdp2-bench
    artifacts                   # provides benchmark, benchmark_bpf
    parityCheck                 # provides flow-dissector-parity-check
  ];

  text = ''
    # shellcheck disable=SC2016
    USAGE=$(cat <<'EOF'
    Usage: xdp2-flow-dissector-matrix-unified [OPTIONS] [pcap_file]

    Runs the 6-way C matrix AND the xdp2-bench mode matrix against the
    SAME filtered PCAP. Emits one unified table.

    Arguments:
      pcap_file   Input PCAP (default: the cached https-web workload pcap)

    Options:
      -n <N>      xdp2-bench iterations per mode        (default: 100)
      -N <N>      BPF_PROG_TEST_RUN repeat count        (default: 1000)
      -c <cpu>    Pin xdp2-bench to this CPU            (default: unset)
      -j <dir>    Per-cell JSON output directory        (default: unset)
                  When set, writes <dir>/<pcap>/<mode>.json for every
                  measured (pcap, mode) cell. The text table on stdout
                  is unchanged.
      -h          This help.

    Ways 4-6 (BPF_PROG_TEST_RUN) require root / CAP_BPF.
    EOF
    )

    ITER=100
    BPF_REPEAT=1000
    CORE_PIN=""
    # JSON_OUT defaults to XDP2_MATRIX_JSON_OUT if set in the environment
    # (the orchestrator path) so the composed pipeline produces per-cell
    # JSON without needing -j forwarded through xdp2-run-on-host. The
    # explicit -j flag still wins when both are present.
    JSON_OUT="''${XDP2_MATRIX_JSON_OUT:-}"
    # XDP2_MATRIX_PARITY=1 enables the Phase 17.E hook: after the
    # matrix sweep finishes, the wrapper invokes
    # flow-dissector-parity-check on the same pcap and stamps every
    # per-cell JSON with parity_ok + parity_disagreements. Per-pcap
    # values (each pcap's cells share the same pair). Off by default
    # so the matrix runner stays cheap.
    PARITY_ENABLED="''${XDP2_MATRIX_PARITY:-0}"

    while getopts "n:N:c:j:h" opt; do
      case $opt in
        n) ITER="$OPTARG" ;;
        N) BPF_REPEAT="$OPTARG" ;;
        c) CORE_PIN="$OPTARG" ;;
        j) JSON_OUT="$OPTARG" ;;
        h) echo "$USAGE"; exit 0 ;;
        *) echo "$USAGE" >&2; exit 1 ;;
      esac
    done
    shift $((OPTIND - 1))

    # PCAP resolution order: positional arg → XDP2_MATRIX_PCAP env var →
    # cached https-web workload pcap. The env-var path lets the orchestrator
    # drive multiple PCAPs through xdp2-run-on-host (which has no per-target
    # arg forwarding).
    INPUT_PCAP="''${1:-''${XDP2_MATRIX_PCAP:-${workloadPcapHttpsWeb}/https-web.pcap}}"
    if [[ ! -f "$INPUT_PCAP" ]]; then
      echo "Error: PCAP not found: $INPUT_PCAP" >&2
      exit 1
    fi

    # Per-cell JSON setup. PCAP_BASENAME is used both as a directory
    # under JSON_OUT and as the "pcap" field of every emitted record;
    # restrict to a safe character class so filename and JSON value
    # stay corruption-free without needing jq at runtime.
    PCAP_BASENAME=$(basename "$INPUT_PCAP")
    if [[ -n "$JSON_OUT" ]]; then
      if ! [[ "$PCAP_BASENAME" =~ ^[A-Za-z0-9._-]+$ ]]; then
        echo "Error: --json-out requires PCAP basename to match [A-Za-z0-9._-]+; got '$PCAP_BASENAME'" >&2
        exit 1
      fi
      mkdir -p "$JSON_OUT/$PCAP_BASENAME"
    fi
    KERNEL_RELEASE=$(uname -r)
    XDP2_BENCH_PATH=$(command -v xdp2-bench || echo unknown)
    BUILD_HASH=$(printf '%s' "$XDP2_BENCH_PATH" | head -c 80)
    NIC_DRIVER="''${XDP2_NIC_DRIVER:-}"
    NIC_FIRMWARE="''${XDP2_NIC_FIRMWARE:-}"

    emit_cell_json() {
      local mode="$1" nspkt="$2" mpps="$3"
      [[ -z "$JSON_OUT" ]] && return 0
      local nspkt_num="''${nspkt%% *}"
      local mpps_num="''${mpps%% *}"
      [[ "$nspkt_num" =~ ^[0-9]+$ ]] || nspkt_num="null"
      [[ "$mpps_num"  =~ ^[0-9]+$ ]] || mpps_num="null"
      # parity_ok / parity_disagreements default null until the post-sweep
      # parity hook (Phase 17.E) overwrites them. Always present so
      # downstream consumers can rely on the schema being uniform.
      printf '{"mode":"%s","pcap":"%s","ns_per_pkt":%s,"mpps":%s,"iterations":%s,"build_hash":"%s","kernel":"%s","nic_driver":"%s","nic_firmware":"%s","parity_ok":null,"parity_disagreements":null}\n' \
        "$mode" "$PCAP_BASENAME" "$nspkt_num" "$mpps_num" "$ITER" \
        "$BUILD_HASH" "$KERNEL_RELEASE" "$NIC_DRIVER" "$NIC_FIRMWARE" \
        > "$JSON_OUT/$PCAP_BASENAME/$mode.json"
    }

    TMPDIR=$(mktemp -d -t xdp2-matrix-unified-XXXX)
    trap 'rm -rf "$TMPDIR"' EXIT
    FILTERED="$TMPDIR/filtered.pcap"

    BENCHMARK="${artifacts}/bin/benchmark"
    BENCHMARK_BPF="${artifacts}/bin/benchmark_bpf"
    BPF_OBJ="${artifacts}/lib/xdp2-flow-dissector-matrix/bpf_flow.kern.o"
    XDP2_BPF_OBJ="${artifacts}/lib/xdp2-flow-dissector-matrix/flow_dissector.bpf.o"
    FAST_BPF_OBJ="${artifacts}/lib/xdp2-flow-dissector-matrix/fast_flow.bpf.o"

    extract_nspkt() {
      local match
      match=$(echo "$1" | grep -oE '[0-9]+ ns/pkt' | head -1 || true)
      echo "''${match:-N/A}"
    }
    extract_mpps() {
      local match
      match=$(echo "$1" | grep -oE '[0-9]+ Mpps' | head -1 || true)
      echo "''${match:-N/A}"
    }

    echo "=== Unified xdp2-rs vs C-matrix Performance Comparison ==="
    echo "Input PCAP:           $INPUT_PCAP"
    echo "xdp2-bench iterations: $ITER"
    echo "BPF repeat count:      $BPF_REPEAT"
    if [[ -n "$CORE_PIN" ]]; then
      echo "CPU pin:               $CORE_PIN"
    fi
    echo "Artifacts:             ${artifacts}"
    echo ""

    # ─── Step 1: filter ─────────────────────────────────────────────
    # xdp2-bench parses every packet once and writes out only those the
    # Rust graph handles. The C matrix then runs on the filtered output
    # so both halves measure the same packet set.
    echo "--- Pre-filtering pcap with xdp2-bench (Rust parse filter) ---"
    XDP2_FILTER_ARGS=(--pcap "$INPUT_PCAP" --output-pcap "$FILTERED"
                      --iterations 1 --warmup 0)
    if [[ -n "$CORE_PIN" ]]; then
      XDP2_FILTER_ARGS+=(--core-pin "$CORE_PIN")
    fi
    if ! xdp2-bench "''${XDP2_FILTER_ARGS[@]}" >"$TMPDIR/filter.log" 2>&1; then
      echo "Error: xdp2-bench filter pass failed:" >&2
      cat "$TMPDIR/filter.log" >&2
      exit 1
    fi
    grep -E '^(Loaded|Filtered|Wrote)' "$TMPDIR/filter.log" || true
    echo ""

    if [[ ! -s "$FILTERED" ]]; then
      echo "Error: filtered pcap is empty — no packets passed the Rust parse filter" >&2
      exit 1
    fi

    # ─── Step 2: C userspace (ways 1-3) on filtered pcap ────────────
    echo "--- C matrix: userspace (ways 1-3) on filtered pcap ---"
    if ! USP_OUT=$("$BENCHMARK" -p -n "$ITER" "$FILTERED" 2>&1); then
      echo "Error: userspace benchmark failed" >&2
      echo "$USP_OUT" >&2
      exit 1
    fi
    echo "$USP_OUT"
    echo ""

    FLOWDIS_LINE=$(echo "$USP_OUT" | grep "^Kernel flowdis:" || true)
    XDP2_LINE=$(echo "$USP_OUT" | grep "^XDP2 parser:" || true)
    XDP2_PO_LINE=$(echo "$USP_OUT" | grep "^XDP2 parse-only:" || true)

    FLOWDIS_NSPKT=$(extract_nspkt "$FLOWDIS_LINE")
    FLOWDIS_MPPS=$(extract_mpps "$FLOWDIS_LINE")
    XDP2_NSPKT=$(extract_nspkt "$XDP2_LINE")
    XDP2_MPPS=$(extract_mpps "$XDP2_LINE")
    XDP2_PO_NSPKT=$(extract_nspkt "$XDP2_PO_LINE")
    XDP2_PO_MPPS=$(extract_mpps "$XDP2_PO_LINE")

    emit_cell_json "c-flowdis-usp"     "$FLOWDIS_NSPKT"  "$FLOWDIS_MPPS"
    emit_cell_json "c-xdp2-usp"        "$XDP2_NSPKT"     "$XDP2_MPPS"
    emit_cell_json "c-xdp2-parse-only" "$XDP2_PO_NSPKT"  "$XDP2_PO_MPPS"

    # ─── Step 3: C BPF (ways 4-6) ───────────────────────────────────
    run_bpf() {
      local label="$1" obj="$2" out_var_ns="$3" out_var_mpps="$4" json_mode="$5"
      local out line nspkt mpps
      echo "--- C matrix: $label ($(basename "$obj")) ---"
      if out=$("$BENCHMARK_BPF" -p -n "$BPF_REPEAT" -l "$label" -b "$obj" "$FILTERED" 2>&1); then
        echo "$out"
        line=$(echo "$out" | grep "^$label:" || true)
        nspkt=$(extract_nspkt "$line")
        mpps=$(extract_mpps "$line")
      else
        echo "Warning: $label failed (need root / CAP_BPF?)" >&2
        echo "$out" >&2
        nspkt="N/A"
        mpps="N/A"
      fi
      # shellcheck disable=SC2086
      printf -v "$out_var_ns"   '%s' "$nspkt"
      # shellcheck disable=SC2086
      printf -v "$out_var_mpps" '%s' "$mpps"
      emit_cell_json "$json_mode" "$nspkt" "$mpps"
      echo ""
    }

    BPF_NSPKT="N/A";      BPF_MPPS="N/A"
    XDP2_BPF_NSPKT="N/A"; XDP2_BPF_MPPS="N/A"
    FAST_BPF_NSPKT="N/A"; FAST_BPF_MPPS="N/A"

    run_bpf "Kernel BPF flowdis"  "$BPF_OBJ"       BPF_NSPKT       BPF_MPPS       "c-bpf-flowdis"
    run_bpf "XDP2 BPF parser"     "$XDP2_BPF_OBJ"  XDP2_BPF_NSPKT  XDP2_BPF_MPPS  "c-bpf-xdp2"
    run_bpf "xdp2-flow-ebpf fast" "$FAST_BPF_OBJ"  FAST_BPF_NSPKT  FAST_BPF_MPPS  "c-bpf-fast"

    # ─── Step 4: xdp2-bench modes on filtered pcap ──────────────────
    run_rust() {
      local mode="$1" out_var_ns="$2" out_var_mpps="$3"
      local args=(--pcap "$FILTERED" --iterations "$ITER" --mode "$mode")
      if [[ -n "$CORE_PIN" ]]; then
        args+=(--core-pin "$CORE_PIN")
      fi
      local out line nspkt="N/A" mpps="N/A"
      echo "--- xdp2-bench --mode $mode ---"
      if out=$(xdp2-bench "''${args[@]}" 2>&1); then
        echo "$out"
        line=$(echo "$out" | grep -E "^Rust " | head -1 || true)
        # "Rust <mode>     : NN ns/pkt,  MM Mpps"
        nspkt=$(echo "$line" | grep -oE '[0-9]+ ns/pkt' | head -1 || true)
        nspkt="''${nspkt:-N/A}"
        mpps=$(echo "$line" | grep -oE '[0-9]+ Mpps' | head -1 || true)
        mpps="''${mpps:-N/A}"
      else
        echo "Warning: xdp2-bench --mode $mode failed" >&2
        echo "$out" >&2
      fi
      # shellcheck disable=SC2086
      printf -v "$out_var_ns"   '%s' "$nspkt"
      # shellcheck disable=SC2086
      printf -v "$out_var_mpps" '%s' "$mpps"
      emit_cell_json "rust-$mode" "$nspkt" "$mpps"
      echo ""
    }

    GRAPH_NSPKT="N/A";      GRAPH_MPPS="N/A"
    GRAPH_ENUM_NSPKT="N/A"; GRAPH_ENUM_MPPS="N/A"
    MONO_NSPKT="N/A";       MONO_MPPS="N/A"
    MONOX4_NSPKT="N/A";     MONOX4_MPPS="N/A"
    COMPILED_NSPKT="N/A";   COMPILED_MPPS="N/A"
    SIMD_NSPKT="N/A";       SIMD_MPPS="N/A"
    TEMPLATE_NSPKT="N/A";   TEMPLATE_MPPS="N/A"
    TSIMD_NSPKT="N/A";      TSIMD_MPPS="N/A"

    run_rust graph         GRAPH_NSPKT      GRAPH_MPPS
    run_rust graph-enum    GRAPH_ENUM_NSPKT GRAPH_ENUM_MPPS
    run_rust mono          MONO_NSPKT       MONO_MPPS
    run_rust mono-x4       MONOX4_NSPKT     MONOX4_MPPS
    run_rust compiled      COMPILED_NSPKT   COMPILED_MPPS
    run_rust simd          SIMD_NSPKT       SIMD_MPPS
    run_rust template      TEMPLATE_NSPKT   TEMPLATE_MPPS
    run_rust template-simd TSIMD_NSPKT      TSIMD_MPPS

    # ─── Step 5: parity hook (XDP2_MATRIX_PARITY=1) ─────────────────
    # When set, runs flow-dissector-parity-check on the SAME pcap and
    # stamps parity_ok + parity_disagreements into every per-cell JSON.
    # The values are per-pcap (every cell of one pcap shares them) — by
    # design, so per-cell readers can answer "did the parsers agree on
    # this packet set?" without joining against a sibling parity file.
    if [[ "$PARITY_ENABLED" == "1" ]]; then
      if [[ -z "$JSON_OUT" ]]; then
        echo "[parity] XDP2_MATRIX_PARITY=1 set but no --json-out / XDP2_MATRIX_JSON_OUT — skipping" >&2
      else
        echo "--- Running parity check on $PCAP_BASENAME ---"
        PARITY_OUT="$TMPDIR/parity"
        mkdir -p "$PARITY_OUT"
        # Skip BPF parsers — they need CAP_BPF and aren't load-able in
        # most matrix-runner contexts (sandboxed Nix, non-root testbed
        # users). The 11 non-BPF parsers cover all the modes the
        # comparator can verify cross-language. c-bpf-xdp2 is included
        # because the driver synthesises its 100%-rejected JSONL.
        PARITY_PARSERS="c-flowdis-usp,c-xdp2-usp,c-xdp2-parse-only,c-bpf-xdp2,rust-graph,rust-graph-enum,rust-mono,rust-mono-x4,rust-compiled,rust-simd,rust-template,rust-template-simd"
        if flow-dissector-parity-check \
            --pcap "$INPUT_PCAP" \
            --out  "$PARITY_OUT" \
            --parsers "$PARITY_PARSERS" \
            > "$PARITY_OUT/driver.log" 2>&1; then
          PARITY_OK="true"
        else
          PARITY_OK="false"
        fi
        # parity-report.csv has one header row + one row per pairwise
        # disagreement (acceptance + field). Disagreement count = lines
        # minus header.  Missing report ⇒ harness error ⇒ count=null.
        PARITY_DISAGREEMENTS="null"
        if [[ -f "$PARITY_OUT/parity-report.csv" ]]; then
          local_lines=$(wc -l < "$PARITY_OUT/parity-report.csv")
          if [[ "$local_lines" =~ ^[0-9]+$ ]] && [[ "$local_lines" -ge 1 ]]; then
            PARITY_DISAGREEMENTS=$((local_lines - 1))
          else
            PARITY_DISAGREEMENTS="0"
          fi
        fi
        echo "[parity] $PCAP_BASENAME: parity_ok=$PARITY_OK parity_disagreements=$PARITY_DISAGREEMENTS"
        # Stamp every per-cell JSON for this pcap.
        for cell in "$JSON_OUT/$PCAP_BASENAME"/*.json; do
          [[ -f "$cell" ]] || continue
          jq --argjson ok "$PARITY_OK" --argjson d "$PARITY_DISAGREEMENTS" \
            '. + {parity_ok: $ok, parity_disagreements: $d}' \
            "$cell" > "$cell.tmp" && mv "$cell.tmp" "$cell"
        done
      fi
    fi

    # ─── Unified table ──────────────────────────────────────────────
    echo "================================================================="
    echo "      Unified xdp2-rs vs C-matrix Comparison (same pcap)"
    echo "================================================================="
    echo ""
    printf "%-32s | %-18s | %-9s\n" "Mode" "ns/pkt" "Mpps"
    printf -- "---------------------------------+--------------------+----------\n"
    printf "%-32s | %-18s | %-9s\n" "C kernel flowdis (usp)"     "$FLOWDIS_NSPKT" "$FLOWDIS_MPPS"
    printf "%-32s | %-18s | %-9s\n" "C XDP2 parser (usp)"        "$XDP2_NSPKT" "$XDP2_MPPS"
    printf "%-32s | %-18s | %-9s\n" "C XDP2 parse-only (usp)"    "$XDP2_PO_NSPKT" "$XDP2_PO_MPPS"
    printf "%-32s | %-18s | %-9s\n" "C kernel BPF flowdis"       "$BPF_NSPKT" "$BPF_MPPS"
    printf "%-32s | %-18s | %-9s\n" "C XDP2 BPF parser"          "$XDP2_BPF_NSPKT" "$XDP2_BPF_MPPS"
    printf "%-32s | %-18s | %-9s\n" "C xdp2-flow-ebpf fast (BPF)" "$FAST_BPF_NSPKT" "$FAST_BPF_MPPS"
    printf -- "---------------------------------+--------------------+----------\n"
    printf "%-32s | %-18s | %-9s\n" "Rust graph (dyn dispatch)"     "$GRAPH_NSPKT"      "$GRAPH_MPPS"
    printf "%-32s | %-18s | %-9s\n" "Rust graph-enum (enum match)"  "$GRAPH_ENUM_NSPKT" "$GRAPH_ENUM_MPPS"
    printf "%-32s | %-18s | %-9s\n" "Rust mono (hand-rolled)"       "$MONO_NSPKT"       "$MONO_MPPS"
    printf "%-32s | %-18s | %-9s\n" "Rust mono-x4 (sw-pipelined)"   "$MONOX4_NSPKT"     "$MONOX4_MPPS"
    printf "%-32s | %-18s | %-9s\n" "Rust compiled (monomorphized)" "$COMPILED_NSPKT"   "$COMPILED_MPPS"
    printf "%-32s | %-18s | %-9s\n" "Rust simd (AVX2 batch)"        "$SIMD_NSPKT"       "$SIMD_MPPS"
    printf "%-32s | %-18s | %-9s\n" "Rust template (fixed-offset)"  "$TEMPLATE_NSPKT"   "$TEMPLATE_MPPS"
    printf "%-32s | %-18s | %-9s\n" "Rust template-simd (AVX2)"     "$TSIMD_NSPKT"      "$TSIMD_MPPS"
    echo ""
    echo "Notes:"
    echo "  - All rows measure the SAME filtered pcap (xdp2-bench pre-filter)."
    echo "  - C usp: clock_gettime(CLOCK_MONOTONIC_RAW) around userspace loops."
    echo "  - C BPF: BPF_PROG_TEST_RUN with repeat=$BPF_REPEAT, kernel reports avg ns."
    echo "  - Rust:  timed with rdtsc-derived nanoseconds across $ITER iterations."
    echo "  - Rust 'template' mode still runs select_template_id() per packet;"
    echo "    the hardware-classified equivalent is --mode af-xdp-template"
    echo "    (see docs/ntuple-template-bench.md)."
  '';
}
