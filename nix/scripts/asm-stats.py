#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
"""asm-stats — static-analysis pass over a disassembled .asm file.

Counts:
  total_instructions, conditional_branches, unconditional_branches,
  indirect_branches, direct_calls, indirect_calls,
  loads, stores, simd_ops, distinct_registers_touched.

Optionally prints per-symbol breakdown when the file is the output
of dump-asm.sh (which uses `===== <symbol> =====` separators).

Usage:
  asm-stats.py <file.asm> [--per-symbol]
  asm-stats.py <dir>   --csv <out.csv>
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path
from typing import NamedTuple


CONDITIONAL_BRANCHES = {
    "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jae",
    "jb", "jbe", "jc", "jnc", "jo", "jno", "js", "jns", "jp", "jnp",
    "jecxz", "jrcxz", "loop", "loope", "loopne",
}
UNCONDITIONAL_BRANCHES = {"jmp", "jmpq", "jmpl"}
DIRECT_CALLS = {"call", "callq"}
INDIRECT_HINTS = {"*"}      # objdump renders indirect: `callq *%rax`
LOAD_PREFIXES = {
    "mov", "movzbl", "movzwl", "movzx", "movsx", "movsbl", "movswl",
    "lea",
}
STORE_PREFIXES = {"mov"}    # store vs load detected by operand direction
SIMD_PREFIXES_X86 = (
    "p", "v",   # SSE/AVX integer + most AVX float
)
REGISTER_RE = re.compile(r"%(?:r|e|x?)(?:a|b|c|d)x|%r\d+[bdw]?|%rsp|%rbp|%rsi|%rdi|%rip|%xmm\d+|%ymm\d+|%zmm\d+|%[ad]l|%[ad]h|%si|%di")


class Stats(NamedTuple):
    symbol: str
    total_ins: int
    cond_branches: int
    uncond_branches: int
    indirect_branches: int
    direct_calls: int
    indirect_calls: int
    loads: int
    stores: int
    simd_ops: int
    registers: int


def is_load(operands: str) -> bool:
    # source has parentheses → memory load (intel syntax inversion not relevant in AT&T)
    if "(" not in operands:
        return False
    # AT&T: src,dst → if src has parens it's a load
    parts = operands.split(",")
    if len(parts) >= 2:
        return "(" in parts[0]
    return "(" in operands


def is_store(operands: str) -> bool:
    if "(" not in operands:
        return False
    parts = operands.split(",")
    if len(parts) >= 2:
        return "(" in parts[-1]
    return False


def parse_block(lines: list[str], symbol: str) -> Stats:
    total = cond = uncond = indir_b = direct_c = indir_c = loads = stores = simd = 0
    regs: set[str] = set()
    for line in lines:
        # Disassembly lines look like:
        #   "  401000:  mov   %rax,%rbx"
        # or with --no-show-raw-insn:
        #   "  401000:  mov %rax,%rbx"
        m = re.match(r"\s*[0-9a-f]+:\s+(\S+)\s*(.*)", line)
        if not m:
            continue
        op = m.group(1).strip()
        operands = m.group(2).strip()
        total += 1
        if op in CONDITIONAL_BRANCHES or op.startswith("j") and op[1:] in {"e","ne","z","nz","g","ge","l","le","a","ae","b","be","c","nc","o","no","s","ns","p","np","cxz"}:
            cond += 1
            continue
        if op in UNCONDITIONAL_BRANCHES:
            if "*" in operands:
                indir_b += 1
            else:
                uncond += 1
            continue
        if op in DIRECT_CALLS:
            if "*" in operands:
                indir_c += 1
            else:
                direct_c += 1
            continue
        if is_load(operands):
            loads += 1
        if is_store(operands):
            stores += 1
        if op.startswith(SIMD_PREFIXES_X86) and ("xmm" in operands or "ymm" in operands or "zmm" in operands):
            simd += 1
        for r in REGISTER_RE.findall(operands):
            regs.add(r)
    return Stats(symbol, total, cond, uncond, indir_b, direct_c, indir_c, loads, stores, simd, len(regs))


def parse_file(path: Path) -> list[Stats]:
    """Parse a dump-asm.sh output file (multiple symbols separated by
    `===== <name> =====`) into per-symbol Stats."""
    blocks: list[Stats] = []
    cur_sym = ""
    cur_lines: list[str] = []
    with path.open() as f:
        for line in f:
            if line.startswith("===== ") and line.rstrip().endswith(" ====="):
                if cur_sym:
                    blocks.append(parse_block(cur_lines, cur_sym))
                cur_sym = line[6:line.rindex(" =====")]
                cur_lines = []
            else:
                cur_lines.append(line)
    if cur_sym:
        blocks.append(parse_block(cur_lines, cur_sym))
    if not blocks:
        # Single-block file (no === separators) — treat the whole thing
        # as one symbol named after the file.
        cur_lines = path.read_text().splitlines(keepends=True)
        blocks = [parse_block(cur_lines, path.stem)]
    return blocks


def aggregate(blocks: list[Stats], impl_label: str) -> dict:
    total_ins = sum(b.total_ins for b in blocks)
    return {
        "impl": impl_label,
        "n_symbols": len(blocks),
        "total_ins": total_ins,
        "cond_branches": sum(b.cond_branches for b in blocks),
        "uncond_branches": sum(b.uncond_branches for b in blocks),
        "indirect_branches": sum(b.indirect_branches for b in blocks),
        "direct_calls": sum(b.direct_calls for b in blocks),
        "indirect_calls": sum(b.indirect_calls for b in blocks),
        "loads": sum(b.loads for b in blocks),
        "stores": sum(b.stores for b in blocks),
        "simd_ops": sum(b.simd_ops for b in blocks),
        "registers_touched": max((b.registers for b in blocks), default=0),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("path", type=Path, help="single .asm file OR directory of <impl>/disasm.asm")
    p.add_argument("--per-symbol", action="store_true",
                   help="print one row per symbol instead of aggregate")
    p.add_argument("--csv", type=Path, default=None,
                   help="when path is a directory, write aggregate CSV here")
    args = p.parse_args(argv)

    if args.path.is_file():
        blocks = parse_file(args.path)
        if args.per_symbol:
            print("symbol,total_ins,cond_branches,uncond_branches,indirect_branches,direct_calls,indirect_calls,loads,stores,simd_ops,registers")
            for b in blocks:
                print(",".join(str(getattr(b, f)) for f in b._fields))
        else:
            agg = aggregate(blocks, args.path.stem)
            for k, v in agg.items():
                print(f"{k}: {v}")
        return 0

    if not args.path.is_dir():
        print(f"error: not a file or directory: {args.path}", file=sys.stderr)
        return 2

    rows = []
    for impl_dir in sorted(args.path.iterdir()):
        if not impl_dir.is_dir() or impl_dir.name == "_full":
            continue
        asm_files = list(impl_dir.glob("*.asm"))
        if not asm_files:
            continue
        all_blocks = []
        for asm_file in asm_files:
            all_blocks.extend(parse_file(asm_file))
        rows.append(aggregate(all_blocks, impl_dir.name))

    if not rows:
        print(f"error: no .asm files found under {args.path}", file=sys.stderr)
        return 1

    if args.csv:
        with args.csv.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"wrote {args.csv} ({len(rows)} rows)")
    else:
        # Print as a tidy table.
        cols = list(rows[0].keys())
        widths = {c: max(len(c), max(len(str(r[c])) for r in rows)) for c in cols}
        line = "  ".join(c.rjust(widths[c]) for c in cols)
        print(line)
        print("  ".join("-" * widths[c] for c in cols))
        for r in rows:
            print("  ".join(str(r[c]).rjust(widths[c]) for c in cols))
    return 0


if __name__ == "__main__":
    sys.exit(main())
