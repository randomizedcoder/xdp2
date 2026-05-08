#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# run-llvm-mca — Phase A3 wrapper. Runs `llvm-mca` over each per-impl
# disasm.asm to estimate static throughput (uops/cycle, port pressure,
# IPC ceiling) on the target microarchitecture.
#
# llvm-mca expects raw assembly — not objdump output. We feed it
# the operand-only portion of the disassembly via a small awk
# preprocessor that strips line numbers, addresses, and the function
# headers added by dump-asm.sh.
#
# Usage:
#   run-llvm-mca.sh <asm-tree-dir> [--mcpu=znver1]
#   run-llvm-mca.sh <single.asm>   [--mcpu=znver1]
#
# Output:
#   <input-or-tree>/<impl>/llvm-mca.txt   (one per impl when given a tree)

set -euo pipefail

MCPU="znver1"
INPUT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --mcpu=*) MCPU="${1#--mcpu=}"; shift ;;
        --mcpu) MCPU="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# *//'
            exit 0 ;;
        *)
            if [ -z "$INPUT" ]; then INPUT="$1"
            else echo "extra arg: $1" >&2; exit 2; fi
            shift ;;
    esac
done

if [ -z "$INPUT" ]; then
    echo "usage: run-llvm-mca.sh <tree-or-file> [--mcpu=znver1]" >&2
    exit 2
fi

if ! command -v llvm-mca >/dev/null 2>&1; then
    echo "run-llvm-mca: llvm-mca not on PATH; install pkgs.llvm" >&2
    exit 2
fi

# strip_disasm_to_asm <input.asm>
#   Convert an objdump-formatted .asm file (with `===== <sym> =====`
#   separators) into raw assembly that llvm-mca can ingest. Strip
#   addresses, instruction bytes, function headers, comment lines.
#   Wraps the body in `# LLVM-MCA-BEGIN` / `# LLVM-MCA-END` so
#   llvm-mca measures the loop body alone.
strip_disasm_to_asm() {
    local in="$1"
    awk '
      /^=====/      { next }
      /^[0-9a-f]+ </ { next }   # objdump function header line
      /^[ \t]*$/    { next }
      /^Disassembly of section/ { next }
      /^[^ \t]/     { next }    # other top-level lines
      {
        # objdump line: "  401000:  mov %rax,%rbx" or
        #               "  401000:  call 8160 <strtol@plt>"
        if (match($0, /^[ \t]*[0-9a-f]+:[ \t]+(.*)$/, m)) {
          line = m[1]
          # Strip objdump symbolic annotations starting with the
          # first ` <` to end-of-line. Rust demangled names have
          # nested <> so a regex that matches balanced brackets is
          # unreliable; objdump only writes `<...>` at end-of-line
          # for control transfers, so cut from the first ` <`.
          if (match(line, /[ \t]+</)) {
            line = substr(line, 1, RSTART - 1)
          }
          # Strip trailing comments.
          sub(/[ \t]*#.*$/, "", line)
          # Drop instructions llvm-mca cannot model (control transfers
          # to absolute addresses) — replace with a nop so register
          # allocation is preserved without the syntax error.
          if (line ~ /^(call|jmp|jmpq|j[a-z]+)[ \t]+[0-9a-f]+$/) {
            # Keep it as a static branch by remapping: leave as `nop`
            # so the surrounding instructions still get resource
            # accounting from llvm-mca.
            print "nop"
            next
          }
          if (length(line) > 0) print line
        }
      }
    ' "$in"
}

run_mca_on_file() {
    local in="$1" out="$2"
    {
        echo "# llvm-mca -mcpu=$MCPU"
        echo "# input: $in"
        echo "# generated: $(date -Iseconds)"
        echo
        # Wrap the asm in MCA region markers so llvm-mca measures the
        # whole stripped body.
        printf '# LLVM-MCA-BEGIN region\n'
        strip_disasm_to_asm "$in"
        printf '# LLVM-MCA-END\n'
    } > "$in.mca-input.s"

    # llvm-mca prefers AT&T syntax (-x86-asm-syntax=att default on
    # binutils-based input). Run with -timeline to get pipeline
    # visualisation truncated to the first 40 instructions.
    if llvm-mca -mcpu="$MCPU" \
                -mtriple=x86_64-unknown-linux-gnu \
                -timeline -timeline-max-iterations=1 \
                -instruction-info -resource-pressure \
                "$in.mca-input.s" \
                > "$out" 2>"$out.err"; then
        echo "  ok   $(basename "$in") -> $out"
    else
        echo "  FAIL $(basename "$in") (see $out.err)" >&2
    fi
}

if [ -d "$INPUT" ]; then
    n=0
    for impl_dir in "$INPUT"/*/; do
        impl=$(basename "$impl_dir")
        [ "$impl" = "_full" ] && continue
        for asm in "$impl_dir"/*.asm; do
            [ -f "$asm" ] || continue
            # BPF .asm files are BPF bytecode disasm — llvm-mca won't
            # know how to model them on x86. Skip them.
            case "$(basename "$asm")" in
                static.bpf.asm|jited.bpf.asm|xlated.bpf.asm) continue ;;
            esac
            run_mca_on_file "$asm" "$impl_dir/llvm-mca.txt"
            n=$((n + 1))
            break  # one llvm-mca run per impl (whichever disasm.asm
                   # is first); BPF impls are skipped above.
        done
    done
    echo "[run-llvm-mca] done; ran on $n impls (mcpu=$MCPU)"
else
    out="${INPUT%.asm}.mca.txt"
    run_mca_on_file "$INPUT" "$out"
fi
