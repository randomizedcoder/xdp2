#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
"""parity-compare — symmetric all-vs-all cross-parser parity comparator.

Phase 17.A is a SKELETON: it loads `parity_scope.json`, ingests JSONL
records produced by `xdp2-bench --dump-meta` / `benchmark -D` /
`benchmark_bpf -D`, validates each line's shape, and exposes a
`compare_pair()` primitive that the (Phase 17.C) driver uses to do the
full pairwise comparison + cluster reporting + report rendering.

Usage (Phase 17.C):
    parity-compare --scope samples/flow_dissector/parity_scope.json \
                   --jsonl-dir <dir>/<pcap>/<parser-id>.jsonl \
                   --out parity-report.{md,csv}

For now (17.A) only the API + unit tests below.

Stdlib only (json, csv, pathlib, argparse, sys).
"""

from __future__ import annotations

import argparse
import json
import sys
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


# ── CLI entry (skeleton; Phase 17.C will flesh out) ───────────────


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--scope", type=Path,
                   default=Path("samples/flow_dissector/parity_scope.json"))
    p.add_argument("--jsonl-dir", type=Path,
                   help="Directory tree <pcap>/<parser-id>.jsonl")
    p.add_argument("--out", type=Path, default=Path("parity-report.md"))
    p.add_argument("--validate-only", action="store_true",
                   help="Validate schema + JSONL shape only; no comparison")
    args = p.parse_args(argv)

    schema = load_schema(args.scope)
    print(f"Loaded schema v{schema.version}: "
          f"{len(schema.parsers)} parsers, "
          f"{len(schema.field_names)} fields, "
          f"{len(schema.expected_divergences)} expected divergences",
          file=sys.stderr)

    if args.validate_only:
        return 0

    if args.jsonl_dir is None:
        print("error: --jsonl-dir required (or pass --validate-only)",
              file=sys.stderr)
        return 2

    print("error: full comparator not implemented yet (Phase 17.C). "
          "Phase 17.A delivers the schema + skeleton + unit tests.",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
