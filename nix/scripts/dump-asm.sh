#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# dump-asm — Phase A1 driver for the assembly-level analysis plan.
#
# Produces a standardized per-implementation assembly tree:
#
#   <out>/INDEX.md
#   <out>/rust-graph/parse_packet.asm
#   <out>/rust-graph-enum/parse_packet.asm
#   <out>/rust-mono/parse_packet_mono.asm
#   <out>/rust-mono-x4/bench_mono_x4.asm
#   <out>/rust-compiled/parse_packet.asm
#   <out>/rust-simd/parse_batch_avx2.asm
#   <out>/rust-template/<entry-points>.asm
#   <out>/rust-template-simd/extract_batch.asm
#   <out>/c-flowdis-usp/benchmark.asm           (one big dump; bench_flowdis loop)
#   <out>/c-xdp2-usp/benchmark.asm              (same binary; bench_xdp2 loop)
#   <out>/c-xdp2-parse-only/benchmark.asm       (same binary, parse_only loop)
#   <out>/c-bpf-flowdis/bpf_flow.kern.bpf.asm   (static llvm-objdump on .bpf.o)
#   <out>/c-bpf-xdp2/flow_dissector.bpf.asm     (static; verifier-rejected on 7.x)
#   <out>/c-bpf-fast/fast_flow.bpf.asm          (static)
#
# JITed BPF dumps (bpftool prog dump jited) are an opt-in second pass
# (--with-bpf-jit) since they need bpftool + root + the kernel to load
# the program. The static llvm-objdump pass is always run.
#
# Inputs (any may be omitted; built from the flake on demand):
#   --xdp2-rs        path to /nix/store/.../xdp2-rs-X.Y.Z (provides bin/xdp2-bench)
#   --artifacts      path to /nix/store/.../matrix-artifacts (provides bin/{benchmark,benchmark_bpf}, lib/xdp2-flow-dissector-matrix/*.bpf.o)
#   --out            output directory  (default: perf-results/asm/$(date -I))
#   --with-bpf-jit   also dump BPF JITed assembly via bpftool (requires root + bpftool on PATH; loads each program briefly)

set -euo pipefail

XDP2_RS=""
ARTIFACTS=""
OUT=""
WITH_BPF_JIT=0

usage() {
    cat <<'USAGE'
Usage: dump-asm [OPTIONS]

  --xdp2-rs PATH     Path to xdp2-rs build (provides bin/xdp2-bench).
                     Defaults: nix build --no-link --print-out-paths .#xdp2-rs
  --artifacts PATH   Path to flow-dissector-matrix-artifacts build (provides
                     bin/{benchmark,benchmark_bpf}, lib/.../*.bpf.o).
                     Defaults: nix build .#flow-dissector-matrix-artifacts
  --out DIR          Output directory. Default: perf-results/asm/$(date -I)
  --with-bpf-jit     Also dump JITed BPF asm via bpftool (needs root + bpftool;
                     loads each .bpf.o briefly).
  -h, --help         This help.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --xdp2-rs) XDP2_RS="$2"; shift 2 ;;
        --artifacts) ARTIFACTS="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --with-bpf-jit) WITH_BPF_JIT=1; shift ;;
        *) echo "dump-asm: unknown arg '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

if [ -z "$XDP2_RS" ]; then
    XDP2_RS=$(nix build --no-link --print-out-paths .#xdp2-rs 2>/dev/null | tail -1)
fi
if [ -z "$ARTIFACTS" ]; then
    ARTIFACTS=$(nix build --no-link --print-out-paths .#flow-dissector-matrix-artifacts 2>/dev/null | tail -1)
fi
[ -x "$XDP2_RS/bin/xdp2-bench"            ] || { echo "dump-asm: missing $XDP2_RS/bin/xdp2-bench" >&2; exit 2; }
[ -x "$ARTIFACTS/bin/benchmark"           ] || { echo "dump-asm: missing $ARTIFACTS/bin/benchmark" >&2; exit 2; }
[ -x "$ARTIFACTS/bin/benchmark_bpf"       ] || { echo "dump-asm: missing $ARTIFACTS/bin/benchmark_bpf" >&2; exit 2; }
BPF_DIR="$ARTIFACTS/lib/xdp2-flow-dissector-matrix"
[ -d "$BPF_DIR" ] || { echo "dump-asm: missing $BPF_DIR" >&2; exit 2; }

if [ -z "$OUT" ]; then OUT="perf-results/asm/$(date -I)"; fi
mkdir -p "$OUT"

echo "[dump-asm] xdp2-rs:    $XDP2_RS"
echo "[dump-asm] artifacts:  $ARTIFACTS"
echo "[dump-asm] out:        $OUT"
echo "[dump-asm] with-bpf-jit: $WITH_BPF_JIT"

# ─── Helpers ────────────────────────────────────────────────────────

# extract_symbols_from <output> <binary> <demangle?> <pattern1> [more...]
#   Extracts function blocks from objdump -d output of <binary>
#   (with or without -C demangle). Appends to <output>.
extract_symbols_from() {
    local out="$1" binary="$2" demangle="$3"; shift 3
    local pattern_re=""
    for p in "$@"; do
        if [ -z "$pattern_re" ]; then pattern_re="$p"
        else pattern_re="$pattern_re|$p"; fi
    done
    local objdump_args=(-d --no-show-raw-insn)
    [ "$demangle" = "1" ] && objdump_args+=(-C)
    objdump "${objdump_args[@]}" "$binary" \
      | awk -v pat="$pattern_re" '
        /^[0-9a-f]+ </ {
            in_match = 0
            sym = $0
            sub(/^[0-9a-f]+ </, "", sym)
            sub(/>:$/, "", sym)
            if (sym ~ pat) { in_match = 1; print "===== " sym " ====="; print $0; next }
        }
        in_match { print }
      ' >> "$out"
}

# dump_rust_symbol <impl_name> <pattern> [more_patterns...]
#   Dumps matching functions from xdp2-bench (demangled).
dump_rust_symbol() {
    local impl="$1"; shift
    local impl_dir="$OUT/$impl"
    mkdir -p "$impl_dir"
    local out="$impl_dir/disasm.asm"
    : > "$out"
    extract_symbols_from "$out" "$XDP2_RS/bin/xdp2-bench" 1 "$@"
    local n
    n=$(grep -c '^=====' "$out" 2>/dev/null || true)
    if [ "$n" -eq 0 ]; then
        echo "[dump-asm] WARN: no rust symbols matched for $impl (patterns: $*)" >&2
    else
        echo "[dump-asm] rust  $impl: $n symbol(s) dumped to $out"
    fi
}

# dump_c_function <impl_name> <binary_or_lib> <pattern> [more_patterns...]
#   APPENDS matching C-side function blocks to <impl>/disasm.asm.
#   Caller invokes once per (binary, library) pair the impl touches.
dump_c_function() {
    local impl="$1"; shift
    local binary="$1"; shift
    local impl_dir="$OUT/$impl"
    mkdir -p "$impl_dir"
    local out="$impl_dir/disasm.asm"
    [ -f "$out" ] || : > "$out"
    extract_symbols_from "$out" "$binary" 0 "$@"
    local n
    n=$(grep -c '^=====' "$out" 2>/dev/null || true)
    echo "[dump-asm] c     $impl: total $n symbol(s) in $out (after appending from $(basename "$binary"))"
}

# dump_bpf_static <impl_name> <bpf_object_file>
#   llvm-objdump -d on the .bpf.o file. Works even for verifier-rejected
#   programs (we never load them).
dump_bpf_static() {
    local impl="$1" obj="$2"
    local impl_dir="$OUT/$impl"
    mkdir -p "$impl_dir"
    local out="$impl_dir/static.bpf.asm"
    if ! command -v llvm-objdump >/dev/null 2>&1; then
        echo "[dump-asm] llvm-objdump not on PATH; skipping $impl" >&2
        return 0
    fi
    llvm-objdump -d "$obj" > "$out"
    echo "[dump-asm] bpf   $impl: static llvm-objdump dump at $out"
}

# dump_bpf_jited <impl_name> <bpf_object_file>
#   Loads via tiny Python helper, captures prog id, runs bpftool prog
#   dump jited, detaches. Requires root + bpftool. Only invoked under
#   --with-bpf-jit.
dump_bpf_jited() {
    local impl="$1" obj="$2"
    local impl_dir="$OUT/$impl"
    mkdir -p "$impl_dir"
    local out="$impl_dir/jited.bpf.asm"
    if [ "$WITH_BPF_JIT" -eq 0 ]; then return 0; fi
    if ! command -v bpftool >/dev/null 2>&1; then
        echo "[dump-asm] bpftool not on PATH; skipping JITed dump for $impl" >&2
        return 0
    fi
    if [ "$(id -u)" -ne 0 ]; then
        echo "[dump-asm] not root; skipping JITed dump for $impl" >&2
        return 0
    fi
    # Load the program through bpftool prog load (creates a pinned ref)
    local pin="/sys/fs/bpf/dump_asm_${impl}_$$"
    rm -f "$pin"
    if ! bpftool prog load "$obj" "$pin" 2>"$impl_dir/load.log"; then
        echo "[dump-asm] bpftool prog load FAILED for $impl (see $impl_dir/load.log; verifier-rejected?)" >&2
        return 0
    fi
    # Find prog id by listing programs and matching the pin
    local prog_id
    prog_id=$(bpftool prog show pinned "$pin" 2>/dev/null | head -1 | grep -oE '^[0-9]+' || true)
    if [ -z "$prog_id" ]; then
        echo "[dump-asm] could not find prog id for $impl" >&2
        rm -f "$pin"; return 0
    fi
    bpftool prog dump jited id "$prog_id" > "$out" 2>&1 || true
    bpftool prog dump xlated id "$prog_id" > "$impl_dir/xlated.bpf.asm" 2>&1 || true
    rm -f "$pin"
    echo "[dump-asm] bpf   $impl: JITed dump at $out"
}

# ─── Rust impls ─────────────────────────────────────────────────────

# Rust patterns: top-level entry-point parse_packet / parse_packet_mono
# functions inline at -O3 so they're not standalone symbols. Capture
# the bench::run_single_threaded driver (shared by all modes; the
# inlined per-mode bodies live inside it) PLUS the per-module
# per-protocol nodes (parse_ipv4, dispatch_ether, etc — these stay
# as separate symbols).

RUST_BENCH='^xdp2_bench::bench::run_single_threaded$|^xdp2_bench::bench::run_multi_threaded$|^xdp2_bench::runners::'

dump_rust_symbol rust-graph         "$RUST_BENCH" '^xdp2_bench::graph::' '^<xdp2_bench::graph::'
dump_rust_symbol rust-graph-enum    "$RUST_BENCH" '^xdp2_bench::graph_enum::' '^xdp2_core::enum_dispatch::engine::parse_enum'
dump_rust_symbol rust-mono          "$RUST_BENCH" '^xdp2_bench::graph_mono::'
dump_rust_symbol rust-mono-x4       "$RUST_BENCH" '^xdp2_bench::graph_mono::'
dump_rust_symbol rust-compiled      "$RUST_BENCH" '^xdp2_bench::graph_compiled::'
dump_rust_symbol rust-simd          "$RUST_BENCH" '^xdp2_bench::simd_batch::'
dump_rust_symbol rust-template      "$RUST_BENCH" '^xdp2_bench::template::' '^xdp2_bench::template_(plain|vlan|qinq|gre|ipip)::'
dump_rust_symbol rust-template-simd "$RUST_BENCH" '^xdp2_bench::template_simd::'

# ─── C impls ────────────────────────────────────────────────────────

# C impls. The benchmark binary has `main` (huge, contains all 3
# bench loops inline) and `run_flowdis` as separate symbols; the
# actual XDP2 parser entry `__xdp2_parse` and the per-protocol node
# functions live in libxdp2.so (dynamically linked). The
# kernel-flowdis port lives in libflowdis.so.

# Locate the shared libs by reading the benchmark's RPATH/dynamic
# libraries. Easier: hard-code from our known closure (artifacts depend
# on xdp2-debug). Resolve via ldd output.
LIBXDP2=$(ldd "$ARTIFACTS/bin/benchmark" | awk '/libxdp2\.so/ { print $3 }')
LIBFLOWDIS=$(ldd "$ARTIFACTS/bin/benchmark" | awk '/libflowdis\.so/ { print $3 }')
echo "[dump-asm] libxdp2:    ${LIBXDP2:-<not found>}"
echo "[dump-asm] libflowdis: ${LIBFLOWDIS:-<not found>}"

# c-flowdis-usp: bench loop in `run_flowdis` (in benchmark) + the
# kernel C dissector body in libflowdis.so.
dump_c_function c-flowdis-usp "$ARTIFACTS/bin/benchmark" '^run_flowdis$' '^main$'
[ -n "$LIBFLOWDIS" ] && dump_c_function c-flowdis-usp "$LIBFLOWDIS" \
    '^__skb_flow_dissect' '^skb_flow_dissect' '^skb_flow_dissector_init'

# c-xdp2-usp: `main` contains the bench loop; libxdp2.so contains
# __xdp2_parse + per-protocol node functions.
dump_c_function c-xdp2-usp "$ARTIFACTS/bin/benchmark" '^main$'
[ -n "$LIBXDP2" ] && dump_c_function c-xdp2-usp "$LIBXDP2" \
    '^__xdp2_parse$' '^xdp2_parse_validate_fast$' '^__xdp2_parse_fast$' \
    '^xdp2_parse_tlvs$' '^xdp2_parse_lookup_tlv$' '^xdp2_parse_flag_fields' \
    '^__xdp2_parser_'

# c-xdp2-parse-only: same C code, different bench wrapper. Same
# symbol set; different time around the loop.
dump_c_function c-xdp2-parse-only "$ARTIFACTS/bin/benchmark" '^main$'
[ -n "$LIBXDP2" ] && dump_c_function c-xdp2-parse-only "$LIBXDP2" \
    '^__xdp2_parse$' '^xdp2_parse_validate_fast$' '^__xdp2_parse_fast$' \
    '^__xdp2_parser_'

# ─── BPF impls (static) ─────────────────────────────────────────────

dump_bpf_static c-bpf-flowdis "$BPF_DIR/bpf_flow.kern.o"
dump_bpf_static c-bpf-xdp2    "$BPF_DIR/flow_dissector.bpf.o"
dump_bpf_static c-bpf-fast    "$BPF_DIR/fast_flow.bpf.o"

# ─── BPF impls (JITed; opt-in) ──────────────────────────────────────

dump_bpf_jited c-bpf-flowdis "$BPF_DIR/bpf_flow.kern.o"
dump_bpf_jited c-bpf-xdp2    "$BPF_DIR/flow_dissector.bpf.o"
dump_bpf_jited c-bpf-fast    "$BPF_DIR/fast_flow.bpf.o"

# ─── Full-binary dumps for reference ────────────────────────────────

mkdir -p "$OUT/_full"
objdump -d -C --no-show-raw-insn "$XDP2_RS/bin/xdp2-bench" > "$OUT/_full/xdp2-bench.asm"
objdump -d --no-show-raw-insn "$ARTIFACTS/bin/benchmark" > "$OUT/_full/benchmark.asm"
objdump -d --no-show-raw-insn "$ARTIFACTS/bin/benchmark_bpf" > "$OUT/_full/benchmark_bpf.asm"
echo "[dump-asm] full binaries dumped to $OUT/_full/"

# ─── INDEX.md ───────────────────────────────────────────────────────

{
  printf '# Assembly Extraction Index — %s\n\n' "$(date -Iseconds)"
  printf 'Generated by `nix/scripts/dump-asm.sh`. Per-impl directories\n'
  printf 'each contain a `disasm.asm` (Rust + C) or `static.bpf.asm` /\n'
  printf '`jited.bpf.asm` (BPF). Full-binary reference dumps in `_full/`.\n\n'
  printf 'Sources:\n- xdp2-rs:    `%s`\n- artifacts:  `%s`\n\n' "$XDP2_RS" "$ARTIFACTS"
  printf '## Per-impl files\n\n| Impl | Size | Symbols / Notes |\n|---|---:|---|\n'
  for d in "$OUT"/*/; do
    impl=$(basename "$d")
    [ "$impl" = "_full" ] && continue
    size_total=0
    syms=0
    notes=()
    for f in "$d"/*.asm; do
      [ -f "$f" ] || continue
      sz=$(wc -c < "$f" || echo 0)
      size_total=$((size_total + sz))
      n=$(grep -c '^=====' "$f" 2>/dev/null || true)
      syms=$((syms + n))
      notes+=("$(basename "$f"):$(printf '%s' "$sz" | awk '{ if ($1 > 1024) printf "%.1fK", $1/1024; else printf "%dB", $1 }')")
    done
    note_str=$(IFS=,; echo "${notes[*]}")
    printf '| `%s` | %dB | %s%s |\n' "$impl" "$size_total" "$syms symbols; " "$note_str"
  done
} > "$OUT/INDEX.md"

echo "[dump-asm] INDEX.md written to $OUT/INDEX.md"
echo "[dump-asm] done."
