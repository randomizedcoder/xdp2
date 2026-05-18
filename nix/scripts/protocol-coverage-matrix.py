#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
"""Aggregate per-protocol parity-check JSONL trees into a
(protocol × parser) coverage matrix.

Consumes the output of `flow-dissector-parity-check --pcap <p>
--out <dir>` invoked once per protocol-template pcap, laid out as:

    <jsonl-tree>/
      <protocol_id>/             # = pcap file stem (e.g. "bgp")
        c-flowdis-usp.jsonl
        c-xdp2-mono.jsonl
        ...

Renders matrix.md + matrix.csv showing each (protocol, parser) cell
labeled accepted/rejected with disagreement counts. Optional
`--bootstrap-expectations` mode writes a JSON snippet matching
current behavior, intended to be human-reviewed and merged into
`samples/flow_dissector/parity_scope.json` as the
`expected_protocol_acceptance` section.

See `/home/das/.claude/profiles/personal/plans/in-this-folder-is-fuzzy-wigderson.md`
for the design context and phase plan.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Import sibling parity-compare.py the same way parity-compare-test.py
# does (hyphenated filename can't be `import`ed directly).
_spec = importlib.util.spec_from_file_location(
    "parity_compare", HERE / "parity-compare.py"
)
_pc = importlib.util.module_from_spec(_spec)
sys.modules["parity_compare"] = _pc
_spec.loader.exec_module(_pc)

# Re-export the needed symbols for type hints + use below.
Record = _pc.Record
Schema = _pc.Schema
load_schema = _pc.load_schema
read_jsonl = _pc.read_jsonl
find_field_disagreements = _pc.find_field_disagreements
find_acceptance_disagreements = _pc.find_acceptance_disagreements
is_expected_rejection = _pc.is_expected_rejection


# Canonical parser order (matches nix/checks/parity-gate.nix:98-112).
# Used for column ordering in the rendered matrix.
CANONICAL_PARSER_ORDER = [
    "c-flowdis-usp",
    "c-xdp2-usp",
    "c-xdp2-parse-only",
    "c-xdp2-mono",
    "c-bpf-xdp2",
    "c-bpf-flowdis",
    "c-bpf-fast",
    "rust-graph",
    "rust-graph-enum",
    "rust-mono",
    "rust-mono-x4",
    "rust-compiled",
    "rust-simd",
    "rust-template",
    "rust-template-simd",
]


@dataclass
class Cell:
    """One (protocol, parser) cell in the matrix."""
    protocol: str
    parser: str
    accepted: bool              # True if any packet was accepted
    n_packets: int              # total packets in the protocol's pcap
    n_accepted: int             # packets this parser accepted
    reject_reason: str | None   # first non-null reject_reason seen
    field_disagreements: int    # times this parser is in a disagreeing pair
    expected: str               # "accept", "reject:<reason>", or "undeclared"
    classification: str         # "OK", "OK!N", "REJ-expected", "REJ-unexpected", "N/A"


def parse_expectations(scope_raw: dict) -> dict[str, dict]:
    """Return the expected_protocol_acceptance.protocols dict, or {}.

    The section is additive — old parity-scope.json files won't have it.
    """
    section = scope_raw.get("expected_protocol_acceptance") or {}
    return section.get("protocols") or {}


def expectation_for(
    expectations: dict[str, dict], protocol: str, parser: str
) -> str:
    """Look up the expected acceptance for a (protocol, parser) cell.

    Returns "accept", "reject:<reason>", or "undeclared".
    """
    proto_entry = expectations.get(protocol)
    if proto_entry is None:
        return "undeclared"
    overrides = proto_entry.get("overrides") or {}
    if parser in overrides:
        return overrides[parser]
    return proto_entry.get("default", "undeclared")


def discover_protocols(jsonl_tree: Path) -> list[str]:
    """Each subdirectory of jsonl_tree is one protocol."""
    if not jsonl_tree.is_dir():
        raise SystemExit(f"--jsonl-tree {jsonl_tree} not a directory")
    return sorted(p.name for p in jsonl_tree.iterdir() if p.is_dir())


def discover_parsers(jsonl_tree: Path, protocols: list[str]) -> list[str]:
    """Union of parser_ids seen across all protocols, sorted canonically."""
    seen: set[str] = set()
    for proto in protocols:
        for jl in (jsonl_tree / proto).glob("*.jsonl"):
            seen.add(jl.stem)
    # Canonical order first; then anything unknown alphabetical.
    ordered = [p for p in CANONICAL_PARSER_ORDER if p in seen]
    rest = sorted(p for p in seen if p not in CANONICAL_PARSER_ORDER)
    return ordered + rest


def build_cells(
    jsonl_tree: Path,
    schema: Schema,
    expectations: dict[str, dict],
    protocols: list[str],
    parsers: list[str],
) -> list[Cell]:
    """One Cell per (protocol, parser) intersection."""
    cells: list[Cell] = []
    for proto in protocols:
        proto_dir = jsonl_tree / proto
        # Read all records for this protocol — one round of JSONL load.
        all_recs: list[Record] = []
        per_parser_recs: dict[str, list[Record]] = defaultdict(list)
        for jl in proto_dir.glob("*.jsonl"):
            recs = read_jsonl(jl)
            all_recs.extend(recs)
            per_parser_recs[jl.stem].extend(recs)

        # Pre-compute disagreement attribution per parser. Done once
        # per protocol rather than per cell.
        disag_count: dict[str, int] = defaultdict(int)
        # Group by packet_index so the comparator sees aligned records.
        by_pkt: dict[int, list[Record]] = defaultdict(list)
        for r in all_recs:
            by_pkt[r.packet_index].append(r)
        for pkt_recs in by_pkt.values():
            for fd in find_field_disagreements(schema, pkt_recs):
                disag_count[fd.parser_a] += 1
                disag_count[fd.parser_b] += 1

        for parser in parsers:
            recs = per_parser_recs.get(parser, [])
            if not recs:
                # Two empty-cell sub-cases:
                #   - file missing entirely → parser not requested → N/A
                #   - file present but empty → driver tried & failed →
                #     treat as a rejected cell with reject_reason
                #     "bench-failed" so the matrix counts it.
                jl = proto_dir / f"{parser}.jsonl"
                if jl.exists():
                    classification = "REJ-undeclared"
                    reject_reason = "bench-failed"
                else:
                    classification = "N/A"
                    reject_reason = None
                cells.append(Cell(
                    protocol=proto, parser=parser,
                    accepted=False, n_packets=0, n_accepted=0,
                    reject_reason=reject_reason,
                    field_disagreements=0,
                    expected=expectation_for(expectations, proto, parser),
                    classification=classification,
                ))
                continue

            n_packets = len(recs)
            n_accepted = sum(1 for r in recs if r.accepted)
            accepted = n_accepted > 0
            reject_reason = next(
                (r.reject_reason for r in recs if not r.accepted and r.reject_reason),
                None,
            )
            field_d = disag_count.get(parser, 0)
            expected = expectation_for(expectations, proto, parser)

            # Classify the cell.
            if accepted:
                classification = "OK" if field_d == 0 else f"OK!{field_d}"
            else:
                # Rejected. Compare against expectation.
                schema_expected = is_expected_rejection(
                    schema, parser, reject_reason
                )
                if expected.startswith("reject"):
                    declared_reason = expected.split(":", 1)[1] if ":" in expected else None
                    if declared_reason and declared_reason == reject_reason:
                        classification = "REJ-expected"
                    else:
                        classification = "REJ-unexpected"
                elif schema_expected:
                    classification = "REJ-expected"
                elif expected == "undeclared":
                    classification = "REJ-undeclared"
                else:
                    classification = "REJ-unexpected"

            cells.append(Cell(
                protocol=proto, parser=parser,
                accepted=accepted, n_packets=n_packets, n_accepted=n_accepted,
                reject_reason=reject_reason,
                field_disagreements=field_d,
                expected=expected, classification=classification,
            ))
    return cells


def fmt_cell(c: Cell) -> str:
    """Render one cell as its markdown table content."""
    if c.classification == "N/A":
        return "N/A"
    if c.classification.startswith("OK"):
        return c.classification
    reason = c.reject_reason or "?"
    if c.classification == "REJ-expected":
        return f"REJ({reason})"
    if c.classification == "REJ-undeclared":
        return f"rej?({reason})"
    # REJ-unexpected: bold for visual scan.
    return f"**REJ({reason})**"


def render_md(out_path: Path, cells: list[Cell],
              protocols: list[str], parsers: list[str]) -> None:
    by_proto: dict[str, dict[str, Cell]] = defaultdict(dict)
    for c in cells:
        by_proto[c.protocol][c.parser] = c

    # Count summary stats.
    total = len(cells)
    ok = sum(1 for c in cells if c.classification == "OK")
    ok_with_disag = sum(1 for c in cells if c.classification.startswith("OK!"))
    rej_expected = sum(1 for c in cells if c.classification == "REJ-expected")
    rej_undeclared = sum(1 for c in cells if c.classification == "REJ-undeclared")
    rej_unexpected = sum(1 for c in cells if c.classification == "REJ-unexpected")
    na = sum(1 for c in cells if c.classification == "N/A")

    lines: list[str] = []
    lines.append("# Protocol Coverage Matrix")
    lines.append("")
    lines.append(
        "Generated by `nix/scripts/protocol-coverage-matrix.py` from "
        "per-protocol JSONL trees produced by `flow-dissector-parity-check`. "
        "Schema: `samples/flow_dissector/parity_scope.json` "
        "(`expected_protocol_acceptance` section)."
    )
    lines.append("")
    lines.append(f"- Protocols: **{len(protocols)}**")
    lines.append(f"- Parsers:   **{len(parsers)}**")
    lines.append(f"- Cells:     **{total}**")
    lines.append("")
    lines.append("## Cell legend")
    lines.append("")
    lines.append(
        "- `OK` — parser accepted, zero field disagreements with peers\n"
        "- `OK!N` — accepted but parser was in N disagreeing field pairs\n"
        "- `REJ(reason)` — rejected, matches an expected divergence\n"
        "- `rej?(reason)` — rejected, no declared expectation (undeclared)\n"
        "- `**REJ(reason)**` — rejected, NO expectation matches → likely bug\n"
        "- `N/A` — parser was not run on this pcap"
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- `OK`: **{ok}** ({100.0 * ok / total:.1f}%)")
    lines.append(f"- `OK!N` (with disagreements): **{ok_with_disag}**")
    lines.append(f"- `REJ-expected`: **{rej_expected}**")
    lines.append(f"- `REJ-undeclared`: **{rej_undeclared}**")
    lines.append(f"- `REJ-unexpected` ⚠️: **{rej_unexpected}**")
    lines.append(f"- `N/A`: **{na}**")
    lines.append("")
    lines.append("## Matrix")
    lines.append("")
    header = "| protocol | " + " | ".join(parsers) + " |"
    sep = "|---|" + "|".join(["---"] * len(parsers)) + "|"
    lines.append(header)
    lines.append(sep)
    for proto in protocols:
        row = [proto] + [
            fmt_cell(by_proto[proto].get(
                p,
                Cell(proto, p, False, 0, 0, None, 0, "undeclared", "N/A"),
            ))
            for p in parsers
        ]
        lines.append("| " + " | ".join(row) + " |")

    out_path.write_text("\n".join(lines) + "\n")


def render_csv(out_path: Path, cells: list[Cell]) -> None:
    with out_path.open("w", newline="") as fp:
        w = csv.writer(fp)
        w.writerow([
            "protocol", "parser", "accepted", "n_packets", "n_accepted",
            "reject_reason", "field_disagreements", "expected", "classification",
        ])
        for c in cells:
            w.writerow([
                c.protocol, c.parser, c.accepted, c.n_packets, c.n_accepted,
                c.reject_reason or "", c.field_disagreements,
                c.expected, c.classification,
            ])


def render_bootstrap(out_path: Path, cells: list[Cell],
                     protocols: list[str], parsers: list[str]) -> None:
    """Emit a JSON snippet matching observed cell behavior.

    Intended to be human-reviewed and merged into
    `samples/flow_dissector/parity_scope.json` as the
    `expected_protocol_acceptance` section.
    """
    by_proto: dict[str, dict[str, Cell]] = defaultdict(dict)
    for c in cells:
        by_proto[c.protocol][c.parser] = c

    out: dict[str, dict] = {}
    for proto in protocols:
        cells_for = by_proto[proto]
        # Bias the default toward the majority outcome.
        accepts = [p for p, c in cells_for.items() if c.accepted]
        if len(accepts) >= len(cells_for) // 2:
            default = "accept"
        else:
            default = "reject:undeclared"
        overrides: dict[str, str] = {}
        for parser in parsers:
            c = cells_for.get(parser)
            if c is None or c.classification == "N/A":
                continue
            cell_state = "accept" if c.accepted else f"reject:{c.reject_reason or 'unknown'}"
            if cell_state != default:
                overrides[parser] = cell_state
        out[proto] = {"default": default, "overrides": overrides}

    payload = {
        "expected_protocol_acceptance": {
            "doc": (
                "Per-protocol-template expected acceptance, bootstrapped "
                "from a flow-dissector-parity-check run. REVIEW BEFORE "
                "MERGING — cells that look like real bugs should be "
                "removed from 'overrides' so the matrix gates flag "
                "them. See nix/scripts/protocol-coverage-matrix.py."
            ),
            "protocols": out,
        }
    }
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate per-protocol parity JSONLs into a matrix report."
    )
    parser.add_argument("--jsonl-tree", required=True, type=Path,
                        help="Directory containing <protocol>/<parser>.jsonl files")
    parser.add_argument("--scope", required=True, type=Path,
                        help="Path to parity_scope.json")
    parser.add_argument("--out", required=True, type=Path,
                        help="Output directory; will contain matrix.{md,csv}")
    parser.add_argument(
        "--bootstrap-expectations", action="store_true",
        help="Emit scope-additions.json (observed behavior as candidate "
             "expectations) instead of strict comparison. Human-review "
             "the file then merge into parity_scope.json.",
    )
    parser.add_argument(
        "--require-expectations", action="store_true",
        help="Exit non-zero if any cell is REJ-unexpected. Off by default "
             "(report-only). Used by the smoke gate (Phase 4).",
    )
    args = parser.parse_args(argv)

    args.out.mkdir(parents=True, exist_ok=True)

    schema = load_schema(args.scope)
    scope_raw = json.loads(args.scope.read_text())
    expectations = parse_expectations(scope_raw)

    protocols = discover_protocols(args.jsonl_tree)
    parsers = discover_parsers(args.jsonl_tree, protocols)
    if not protocols:
        print(f"warning: no protocols found under {args.jsonl_tree}",
              file=sys.stderr)
        return 1

    cells = build_cells(args.jsonl_tree, schema, expectations,
                        protocols, parsers)

    render_md(args.out / "matrix.md", cells, protocols, parsers)
    render_csv(args.out / "matrix.csv", cells)
    print(f"wrote {args.out/'matrix.md'} and {args.out/'matrix.csv'} "
          f"({len(cells)} cells across {len(protocols)} protocols × "
          f"{len(parsers)} parsers)")

    if args.bootstrap_expectations:
        render_bootstrap(args.out / "scope-additions.json", cells,
                         protocols, parsers)
        print(f"wrote {args.out/'scope-additions.json'} "
              "— review then merge into parity_scope.json")

    if args.require_expectations:
        bad = [c for c in cells if c.classification == "REJ-unexpected"]
        if bad:
            print(f"FAIL: {len(bad)} REJ-unexpected cells "
                  "(see matrix.md and matrix.csv)", file=sys.stderr)
            for c in bad[:10]:
                print(f"  {c.protocol} / {c.parser}: rejected "
                      f"({c.reject_reason})", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
