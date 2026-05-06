#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
"""parity-compare — symmetric all-vs-all cross-parser parity comparator.

Walks a JSONL tree produced by xdp2-bench --dump-meta / benchmark -D /
benchmark_bpf -D, groups records by (pcap, packet_index), runs
all-pairs comparisons within each group's accepted set masked by
parity_scope.json, and emits parity-report.{md,csv}. Exits 0 if zero
unexpected disagreements; non-zero with a count otherwise.

Layout expected:

    <jsonl-dir>/<parser-id>.jsonl       (single-pcap, multi-parser run)
    <jsonl-dir>/<pcap>/<parser-id>.jsonl (multi-pcap)

Or `--jsonl <file>` may be passed as a comma-separated list.

Stdlib only (json, csv, pathlib, argparse, sys, collections, itertools).
"""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = 1


# ── schema loading + validation ──────────────────────────────────


@dataclass(frozen=True)
class ParserScope:
    parser_id: str
    kind: str  # "c" | "rust" | "bpf" | "bpf-with-fallback" | "rust-with-fallback"
    fields: frozenset[str]  # set of field names this parser populates


@dataclass(frozen=True)
class Schema:
    version: int
    field_names: frozenset[str]
    parsers: dict[str, ParserScope]
    expected_divergences: list[dict]


def load_schema(scope_path: Path) -> Schema:
    """Read parity_scope.json and resolve tier names into per-parser
    flat field sets. Raises ValueError on malformed schema."""
    raw = json.loads(scope_path.read_text())
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"schema_version mismatch: file={raw.get('schema_version')} "
            f"expected={SCHEMA_VERSION}"
        )
    field_names = frozenset(raw["field_definitions"].keys())
    tiers: dict[str, list[str]] = {
        name: list(items)
        for name, items in raw["tiers"].items()
        if name != "doc"
    }
    parsers: dict[str, ParserScope] = {}
    for parser_id, decl in raw["scopes"].items():
        flat: set[str] = set()
        for tier_name in decl["tiers"]:
            if tier_name not in tiers:
                raise ValueError(f"{parser_id}: unknown tier {tier_name!r}")
            flat.update(tiers[tier_name])
        unknown = flat - field_names
        if unknown:
            raise ValueError(
                f"{parser_id}: tier expansion references unknown fields: "
                f"{sorted(unknown)}"
            )
        parsers[parser_id] = ParserScope(
            parser_id=parser_id,
            kind=decl.get("kind", "?"),
            fields=frozenset(flat),
        )
    return Schema(
        version=raw["schema_version"],
        field_names=field_names,
        parsers=parsers,
        expected_divergences=raw.get("expected_divergences", []),
    )


# ── record I/O ───────────────────────────────────────────────────


@dataclass
class Record:
    pcap: str
    packet_index: int
    parser_id: str
    parser_kind: str
    accepted: bool
    accept_path: str | None
    reject_reason: str | None
    fields: dict[str, object]

    @classmethod
    def from_json(cls, line: str) -> "Record":
        d = json.loads(line)
        if d.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(
                f"schema_version mismatch in record: got "
                f"{d.get('schema_version')!r}"
            )
        for required in ("pcap", "packet_index", "parser_id", "parser_kind",
                         "accepted", "fields"):
            if required not in d:
                raise ValueError(f"record missing required field {required!r}")
        return cls(
            pcap=d["pcap"],
            packet_index=int(d["packet_index"]),
            parser_id=d["parser_id"],
            parser_kind=d["parser_kind"],
            accepted=bool(d["accepted"]),
            accept_path=d.get("accept_path"),
            reject_reason=d.get("reject_reason"),
            fields=dict(d["fields"]),
        )


def read_jsonl(path: Path) -> list[Record]:
    out: list[Record] = []
    with path.open() as fp:
        for lineno, line in enumerate(fp, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(Record.from_json(line))
            except (json.JSONDecodeError, ValueError) as e:
                raise ValueError(f"{path}:{lineno}: {e}") from None
    return out


# ── comparator primitives ────────────────────────────────────────


@dataclass
class FieldDisagreement:
    pcap: str
    packet_index: int
    field: str
    parser_a: str
    value_a: object
    parser_b: str
    value_b: object


def compare_pair(
    schema: Schema,
    rec_a: Record,
    rec_b: Record,
) -> list[FieldDisagreement]:
    """Compare two records on the same (pcap, packet_index). Return
    list of in-scope field disagreements. Caller is responsible for
    handling acceptance disagreements (rec_a.accepted != rec_b.accepted)
    upstream — this primitive only does field comparison when both
    records were accepted.

    Field comparison rules:
      - Skip if either parser doesn't have the field in scope.
      - Skip if the field is absent from one record's `fields` block
        (parser populated it conditionally; treated as out-of-scope
        for this packet).
      - Otherwise, compare values byte-for-byte.
    """
    if rec_a.pcap != rec_b.pcap or rec_a.packet_index != rec_b.packet_index:
        raise ValueError("compare_pair requires same (pcap, packet_index)")
    if not (rec_a.accepted and rec_b.accepted):
        return []
    scope_a = schema.parsers.get(rec_a.parser_id)
    scope_b = schema.parsers.get(rec_b.parser_id)
    if scope_a is None or scope_b is None:
        raise ValueError(f"unknown parser_id: {rec_a.parser_id} or {rec_b.parser_id}")
    intersect = scope_a.fields & scope_b.fields
    out: list[FieldDisagreement] = []
    for field in sorted(intersect):
        va = rec_a.fields.get(field, _ABSENT)
        vb = rec_b.fields.get(field, _ABSENT)
        if va is _ABSENT or vb is _ABSENT:
            continue  # parser didn't populate; skip
        if va != vb:
            out.append(FieldDisagreement(
                pcap=rec_a.pcap,
                packet_index=rec_a.packet_index,
                field=field,
                parser_a=rec_a.parser_id,
                value_a=va,
                parser_b=rec_b.parser_id,
                value_b=vb,
            ))
    return out


_ABSENT = object()


# ── full all-vs-all + cluster (Phase 17.C) ─────────────────────────


@dataclass
class AcceptanceDisagreement:
    """One parser accepted; another rejected without an expected reason."""
    pcap: str
    packet_index: int
    accepted_parser: str
    rejected_parser: str
    reject_reason: str | None


def is_expected_rejection(
    schema: Schema, parser_id: str, reject_reason: str | None
) -> bool:
    """Match a (parser, reject_reason) pair against
    parity_scope.json:expected_divergences."""
    if reject_reason is None:
        return False
    for div in schema.expected_divergences:
        ds = div.get("parsers") or [div.get("parser")]
        if parser_id in ds and div.get("reject_reason") == reject_reason:
            return True
    return False


def find_acceptance_disagreements(
    schema: Schema, recs: list[Record]
) -> list[AcceptanceDisagreement]:
    """For each (pcap, packet) group, surface rejection-with-no-expected-reason
    when at least one same-tier parser accepted."""
    out: list[AcceptanceDisagreement] = []
    accepted = [r for r in recs if r.accepted]
    if not accepted:
        return out
    for r in recs:
        if r.accepted:
            continue
        if is_expected_rejection(schema, r.parser_id, r.reject_reason):
            continue
        # Find one accepted parser to anchor the report.
        out.append(AcceptanceDisagreement(
            pcap=r.pcap,
            packet_index=r.packet_index,
            accepted_parser=accepted[0].parser_id,
            rejected_parser=r.parser_id,
            reject_reason=r.reject_reason,
        ))
    return out


def find_field_disagreements(
    schema: Schema, recs: list[Record]
) -> list[FieldDisagreement]:
    """All-pairs field comparison within accepted set; pairwise output."""
    accepted = [r for r in recs if r.accepted]
    out: list[FieldDisagreement] = []
    for a, b in itertools.combinations(accepted, 2):
        out.extend(compare_pair(schema, a, b))
    return out


@dataclass
class FieldCluster:
    """Per-(pcap, packet, field), group parsers into agreement clusters."""
    pcap: str
    packet_index: int
    field: str
    clusters: list[tuple[object, list[str]]]  # value → parser_ids


def cluster_field(
    pcap: str, packet_index: int, field: str, recs: list[Record]
) -> FieldCluster | None:
    """Return None if all parsers agree (or only 0/1 parsers populated F)."""
    by_value: dict = defaultdict(list)
    for r in recs:
        if not r.accepted:
            continue
        if field not in r.fields:
            continue
        # Use a hashable representation of the value (handle dict/list).
        v = r.fields[field]
        key = json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else v
        by_value[key].append(r.parser_id)
    if len(by_value) <= 1:
        return None
    clusters = [(json.loads(k) if isinstance(k, str) and (k.startswith("{") or k.startswith("[")) else k, sorted(v))
                for k, v in by_value.items()]
    # Sort largest cluster first.
    clusters.sort(key=lambda c: -len(c[1]))
    return FieldCluster(pcap=pcap, packet_index=packet_index,
                        field=field, clusters=clusters)


# ── report rendering ──────────────────────────────────────────────


def render_report_md(
    schema: Schema,
    by_pkt: dict[tuple[str, int], list[Record]],
    field_diffs: list[FieldDisagreement],
    accept_diffs: list[AcceptanceDisagreement],
    out_path: Path,
) -> None:
    pcaps = sorted({k[0] for k in by_pkt.keys()})
    parsers_seen = sorted({r.parser_id for recs in by_pkt.values() for r in recs})

    lines: list[str] = []
    lines.append("# Cross-Parser Parity Report")
    lines.append("")
    lines.append("Generated by `nix/scripts/parity-compare.py` from "
                 "JSONL records emitted by `xdp2-bench --dump-meta` / "
                 "`benchmark -D` / `benchmark_bpf -D`. Schema: "
                 "`samples/flow_dissector/parity_scope.json`.")
    lines.append("")
    lines.append(f"- PCAPs:    {len(pcaps)} ({', '.join(pcaps[:5])}{'…' if len(pcaps)>5 else ''})")
    lines.append(f"- Parsers:  {len(parsers_seen)} "
                 f"({', '.join(parsers_seen)})")
    lines.append(f"- Packets:  {len(by_pkt)} (pcap × packet_index groups)")
    lines.append(f"- Acceptance disagreements: **{len(accept_diffs)}**")
    lines.append(f"- Field disagreements: **{len(field_diffs)}** (pairwise rows)")
    lines.append("")

    # Acceptance matrix per (pcap, parser)
    lines.append("## Acceptance matrix (accepted / total per pcap × parser)")
    lines.append("")
    accept_count: dict = defaultdict(lambda: [0, 0])  # (pcap, parser) → [acc, total]
    reject_reasons: dict = defaultdict(Counter)
    for (pcap, _), recs in by_pkt.items():
        for r in recs:
            accept_count[(pcap, r.parser_id)][1] += 1
            if r.accepted:
                accept_count[(pcap, r.parser_id)][0] += 1
            elif r.reject_reason:
                reject_reasons[(pcap, r.parser_id)][r.reject_reason] += 1
    header = ["pcap"] + parsers_seen
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "|".join("---" for _ in header) + "|")
    for pcap in pcaps:
        row = [pcap]
        for p in parsers_seen:
            acc, tot = accept_count.get((pcap, p), [0, 0])
            cell = f"{acc}/{tot}" if tot else "—"
            row.append(cell)
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")

    # Field disagreements grouped
    if field_diffs:
        lines.append("## Field disagreements (pairwise, in-scope)")
        lines.append("")
        lines.append(f"Total rows: **{len(field_diffs)}**. "
                     "Grouped by `(parser_a, parser_b, field)` then by "
                     "`(pcap, value_a, value_b)` for cluster-style reading.")
        lines.append("")
        groups: dict = Counter()
        for d in field_diffs:
            groups[(d.parser_a, d.parser_b, d.field)] += 1
        lines.append("| Pair | Field | # |")
        lines.append("|---|---|---:|")
        for (a, b, f), n in groups.most_common(50):
            lines.append(f"| {a} vs {b} | {f} | {n} |")
        lines.append("")

        # Sample disagreements (first 20 rows verbatim)
        lines.append("### Sample (first 20 disagreements)")
        lines.append("")
        lines.append("| pcap | pkt | field | parser_a | value_a | parser_b | value_b |")
        lines.append("|---|---:|---|---|---|---|---|")
        for d in field_diffs[:20]:
            lines.append(
                f"| {d.pcap} | {d.packet_index} | {d.field} | "
                f"{d.parser_a} | `{d.value_a}` | "
                f"{d.parser_b} | `{d.value_b}` |"
            )
        lines.append("")
    else:
        lines.append("## Field disagreements")
        lines.append("")
        lines.append("**Zero in-scope field disagreements across all "
                     "compared pairs.** Every parser produces identical "
                     "extracted output for every accepted packet within "
                     "the shared scope tier.")
        lines.append("")

    # Acceptance disagreements detail
    if accept_diffs:
        lines.append("## Acceptance disagreements")
        lines.append("")
        lines.append("Cases where one parser accepted but another rejected "
                     "without a documented expected reason. Each row is one "
                     "(pcap, packet) where `rejected_parser` had no "
                     "matching `expected_divergences` entry in `parity_scope.json`.")
        lines.append("")
        lines.append("| pcap | pkt | accepted_parser (anchor) | rejected_parser | reject_reason |")
        lines.append("|---|---:|---|---|---|")
        for a in accept_diffs[:50]:
            lines.append(
                f"| {a.pcap} | {a.packet_index} | {a.accepted_parser} | "
                f"{a.rejected_parser} | "
                f"{a.reject_reason or '(none)'} |"
            )
        lines.append("")
        if len(accept_diffs) > 50:
            lines.append(f"...and {len(accept_diffs) - 50} more.")

    # Rejection-reason distribution (counts the documented vs unexpected splits)
    lines.append("## Rejection reason distribution")
    lines.append("")
    by_parser_rr: dict = defaultdict(Counter)
    for (pcap, _), recs in by_pkt.items():
        for r in recs:
            if not r.accepted and r.reject_reason:
                by_parser_rr[r.parser_id][r.reject_reason] += 1
    if not by_parser_rr:
        lines.append("(no rejections)")
    else:
        lines.append("| parser_id | reject_reason | count | expected? |")
        lines.append("|---|---|---:|:-:|")
        for parser_id in sorted(by_parser_rr.keys()):
            for reason, n in by_parser_rr[parser_id].most_common():
                exp = "✓" if is_expected_rejection(schema, parser_id, reason) else "✗"
                lines.append(f"| {parser_id} | {reason} | {n} | {exp} |")
    lines.append("")

    out_path.write_text("\n".join(lines) + "\n")


def render_report_csv(
    field_diffs: list[FieldDisagreement],
    accept_diffs: list[AcceptanceDisagreement],
    out_path: Path,
) -> None:
    with out_path.open("w", newline="") as fp:
        w = csv.writer(fp)
        w.writerow([
            "kind", "pcap", "packet_index", "field",
            "parser_a", "value_a", "parser_b", "value_b",
            "reject_reason", "severity",
        ])
        for d in field_diffs:
            w.writerow([
                "field", d.pcap, d.packet_index, d.field,
                d.parser_a, json.dumps(d.value_a) if isinstance(d.value_a, (dict, list)) else d.value_a,
                d.parser_b, json.dumps(d.value_b) if isinstance(d.value_b, (dict, list)) else d.value_b,
                "", "unexpected",
            ])
        for a in accept_diffs:
            w.writerow([
                "accept", a.pcap, a.packet_index, "",
                a.accepted_parser, "true",
                a.rejected_parser, "false",
                a.reject_reason or "", "unexpected",
            ])


# ── CLI driver ─────────────────────────────────────────────────────


def collect_jsonl_files(jsonl_dir: Path) -> list[Path]:
    """Find all *.jsonl files under jsonl_dir (recursive)."""
    if not jsonl_dir.is_dir():
        return [] if not jsonl_dir.is_file() else [jsonl_dir]
    return sorted(jsonl_dir.rglob("*.jsonl"))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--scope", type=Path,
                   default=Path("samples/flow_dissector/parity_scope.json"))
    p.add_argument("--jsonl-dir", type=Path,
                   help="Directory tree containing *.jsonl files")
    p.add_argument("--jsonl", action="append", default=[],
                   help="Specific JSONL file (may be repeated)")
    p.add_argument("--out-dir", type=Path, default=None,
                   help="Output directory for parity-report.{md,csv} "
                        "(default: --jsonl-dir or current directory)")
    p.add_argument("--validate-only", action="store_true",
                   help="Validate schema + JSONL shape only; no comparison")
    args = p.parse_args(argv)

    try:
        schema = load_schema(args.scope)
    except (OSError, ValueError) as e:
        print(f"error: cannot load schema {args.scope}: {e}", file=sys.stderr)
        return 2
    print(f"Loaded schema v{schema.version}: "
          f"{len(schema.parsers)} parsers, "
          f"{len(schema.field_names)} fields, "
          f"{len(schema.expected_divergences)} expected divergences",
          file=sys.stderr)

    # Collect JSONL files
    files: list[Path] = []
    if args.jsonl_dir:
        files.extend(collect_jsonl_files(args.jsonl_dir))
    files.extend(Path(p) for p in args.jsonl)

    if not files:
        print("error: no JSONL files found (pass --jsonl-dir or --jsonl)",
              file=sys.stderr)
        return 2

    # Read all records
    all_recs: list[Record] = []
    for f in files:
        try:
            all_recs.extend(read_jsonl(f))
        except (OSError, ValueError) as e:
            print(f"error: reading {f}: {e}", file=sys.stderr)
            return 2

    if args.validate_only:
        print(f"validate-only: {len(all_recs)} records OK across {len(files)} files",
              file=sys.stderr)
        return 0

    # Group by (pcap, packet_index)
    by_pkt: dict = defaultdict(list)
    for r in all_recs:
        by_pkt[(r.pcap, r.packet_index)].append(r)

    # All-pairs field comparison + acceptance gate
    all_field: list[FieldDisagreement] = []
    all_accept: list[AcceptanceDisagreement] = []
    for recs in by_pkt.values():
        all_field.extend(find_field_disagreements(schema, recs))
        all_accept.extend(find_acceptance_disagreements(schema, recs))

    # Report output
    out_dir = args.out_dir or args.jsonl_dir or Path(".")
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / "parity-report.md"
    csv_path = out_dir / "parity-report.csv"
    render_report_md(schema, by_pkt, all_field, all_accept, md_path)
    render_report_csv(all_field, all_accept, csv_path)
    print(f"wrote {md_path} and {csv_path}", file=sys.stderr)

    total_unexpected = len(all_field) + len(all_accept)
    print(f"  records: {len(all_recs)}", file=sys.stderr)
    print(f"  packet groups: {len(by_pkt)}", file=sys.stderr)
    print(f"  field disagreements: {len(all_field)}", file=sys.stderr)
    print(f"  acceptance disagreements: {len(all_accept)}", file=sys.stderr)
    print(f"  unexpected total: {total_unexpected}", file=sys.stderr)

    return 0 if total_unexpected == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
