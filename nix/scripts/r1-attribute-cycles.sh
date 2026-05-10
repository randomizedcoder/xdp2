#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# r1-attribute-cycles.sh — bucket perf-annotate output into
# R-plan structural categories. Reads a perf-annotate.txt and an
# optional --symbol filter, emits a per-component % breakdown.
#
# Categories:
#   indirect_call    — `call *%reg` or `call *%(reg)` — R5 target
#   direct_call      — `call <fn>` (post-LTO; should be ~0 for _opt)
#   protocol_table   — linear-search lookup loop (lookup_node)
#   frame_indirect   — `mov ...,-0xXX(%rbp)` register spills
#   branch_dense     — `je/jne/jbe/ja` arms of big switches — R3 partial
#   metadata_store   — `mov` to struct field offsets (productive work)
#   load             — `mov` / `movzbl` / `movzwl` from packet/struct
#   other            — everything else
#
# Usage:
#   r1-attribute-cycles.sh PERF_ANNOTATE.txt --symbol __xdp2_parse
#   r1-attribute-cycles.sh PERF_ANNOTATE.txt --symbol __skb_flow_dissect_err
#   r1-attribute-cycles.sh PERF_ANNOTATE.txt --symbol \
#       xdp2_parser_flow_dissector_l2_xdp2_parse_etype_dispatch_node

set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 PERF_ANNOTATE.txt [--symbol NAME] [--min-pct PCT]
EOF
}

ANNOTATE=""
SYMBOL=""
MIN_PCT="0.0"

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --symbol) SYMBOL="$2"; shift 2 ;;
        --min-pct) MIN_PCT="$2"; shift 2 ;;
        *) ANNOTATE="$1"; shift ;;
    esac
done

[ -f "$ANNOTATE" ] || { echo "$0: file not found: $ANNOTATE" >&2; usage >&2; exit 2; }

# awk does the work. The function-scoping logic finds the target
# symbol header (e.g. "0000... <__skb_flow_dissect_err>:") and
# attributes every percent-bearing instruction inside it.
awk -v sym="$SYMBOL" -v minpct="$MIN_PCT" '
    BEGIN {
        # State: 0 = outside any symbol, 1 = inside target
        in_func = 0
        if (sym == "") in_func = -1  # mode -1 = scan everything
    }
    # New function symbol header. perf-annotate prefixes with
    # ":  N   " counter; actual header line looks like:
    #   "         : 5     000000000001ebe0 <__xdp2_parse>:"
    # Symbol names can contain dots (GCC .isra.0 / .constprop.0 clones).
    /<[A-Za-z_][^>]*>:[[:space:]]*$/ {
        if (in_func == 1) {
            # Already found target, now hit another function — done
            in_func = 2
        }
        if (sym != "" && index($0, "<" sym ">") > 0) {
            in_func = 1
            start = NR
        }
        next
    }
    in_func != 0 && in_func != 2 {
        # Line format: "  PCT :   OFFSET:   OPCODE   ARGS"
        # E.g.: "    5.78 :   1edec:  movzwl 0x6(%r12),%r15d"
        # Note OFFSET ends with `:` followed by spaces/tab then opcode.
        if (match($0, /^[[:space:]]*([0-9]+\.[0-9]+)[[:space:]]+:[[:space:]]+([0-9a-f]+):[[:space:]]+([a-z][a-z0-9]*)[[:space:]]+(.*)$/, m)) {
            pct = m[1] + 0
            if (pct < minpct) next
            total += pct
            count++
            op = m[3]
            args = m[4]
            cat = "other"

            # Indirect call — call *%reg or call *0xN(%reg)
            if (op == "call" && args ~ /^\*/) cat = "indirect_call"
            # Direct call — call <addr> or call SYM
            else if (op == "call") cat = "direct_call"
            # Stack/frame indirection — mov to/from -0xXX(%rbp)
            else if (op ~ /^mov/ && args ~ /-0x[0-9a-f]+\(%rbp\)/) cat = "frame_indirect"
            # Branch — conditional jumps (dense in big switch)
            else if (op ~ /^j[a-z]+$/ && op != "jmp") cat = "branch_dense"
            # Unconditional branch
            else if (op == "jmp") cat = "branch_uncond"
            # Memory load (from packet/struct)
            else if (op ~ /^mov(zb|zw|zd|sb|sw|sd)?l?$/ && args ~ /\(.*%(r[abcds][ix]|r[0-9]+|rdi|rsi)\),/) cat = "load"
            # Memory store (likely metadata field)
            else if (op ~ /^mov(b|w|l|q|ups)?$/ && args ~ /,[[:space:]]*0?x?[0-9a-f]*\(%/) cat = "store"
            # Arithmetic / test (including byte/word/long variants)
            else if (op ~ /^(add|sub|cmp|test|and|or|xor|shl|shr|sar|cmovg|sete|setb|setne|inc|dec|lea)[blwq]?$/) cat = "compute"
            # Register-to-register moves — not productive work; bucket as `other` shuffle
            else if (op ~ /^(mov|movabs)[blwq]?$/ && args ~ /^%/) cat = "regshuffle"
            # Stack push/pop (function prologue/epilogue)
            else if (op ~ /^(push|pop|ret|nop|nopl|nopw|leave|endbr64)/) cat = "prologue"

            cat_pct[cat] += pct
            cat_cnt[cat]++
            if (pct > 1.0 && cat == "other") {
                printf "OTHER %.2f%%  %s  %s\n", pct, op, args > "/dev/stderr"
            }
        }
    }
    END {
        printf "=== R1 cycle attribution"
        if (sym != "") printf " — symbol %s", sym
        printf " ===\n"
        printf "Total sample lines scored: %d  (sum: %.2f%%)\n\n", count, total
        n = asorti(cat_pct, sorted, "@val_num_desc")
        for (i = 1; i <= n; i++) {
            k = sorted[i]
            printf "  %-20s  %6.2f%%  (n=%d)\n", k, cat_pct[k], cat_cnt[k]
        }
    }
' "$ANNOTATE"
