#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
"""Runtime reader for data/pcap-manifest.toml.

Used at flake-eval time by nix/checks/parity-gate.nix via
`builtins.fromTOML` directly, but this script provides a CLI for
runtime consumers (shells, ad-hoc queries) that don't want to
parse TOML inline.

Examples:
  load-pcap-manifest.py --gate parity_gate
      → one line per pcap path included in the parity_gate gate
  load-pcap-manifest.py --gate parity_gate --json
      → JSON array of {key, path, category, ...}
  load-pcap-manifest.py --excluded-from parity_gate
      → one line per pcap excluded from parity_gate (path + reason)
  load-pcap-manifest.py --validate
      → check that every manifest path exists on disk; exit non-zero
        on any missing file
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path

DEFAULT_MANIFEST = Path(__file__).resolve().parents[2] / "data/pcap-manifest.toml"


def load(path: Path) -> dict:
    raw = tomllib.loads(path.read_text())
    if raw.get("schema_version") != 1:
        raise ValueError(
            f"unexpected schema_version {raw.get('schema_version')} in {path}"
        )
    return raw


def entries(raw: dict) -> list[dict]:
    """Return manifest entries as a list of dicts with a 'key' field."""
    out = []
    for k, v in raw.get("pcap", {}).items():
        e = dict(v); e["key"] = k
        out.append(e)
    return sorted(out, key=lambda e: e["key"])


def included(entries_: list[dict], gate: str) -> list[dict]:
    return [e for e in entries_ if gate in e.get("included_in", [])]


def excluded(entries_: list[dict], gate: str) -> list[dict]:
    return [e for e in entries_ if gate in e.get("excluded_from", [])]


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    p.add_argument("--repo-root", type=Path,
                   help="Resolve relative paths against this directory. "
                        "Default: parent of --manifest.")
    p.add_argument("--gate", metavar="NAME",
                   help="List pcaps INCLUDED in <NAME>")
    p.add_argument("--excluded-from", metavar="NAME",
                   help="List pcaps EXCLUDED from <NAME>")
    p.add_argument("--json", action="store_true",
                   help="Emit JSON instead of one-line-per-pcap")
    p.add_argument("--validate", action="store_true",
                   help="Check every manifest path exists; exit 1 on missing")
    args = p.parse_args(argv)

    raw = load(args.manifest)
    es = entries(raw)

    repo_root = args.repo_root or args.manifest.resolve().parent.parent

    if args.validate:
        missing = []
        for e in es:
            p_ = (repo_root / e["path"]).resolve()
            if not p_.exists():
                missing.append((e["key"], str(p_)))
        if missing:
            print(f"FAIL: {len(missing)} manifest path(s) missing on disk:",
                  file=sys.stderr)
            for k, p_ in missing:
                print(f"  {k}: {p_}", file=sys.stderr)
            return 1
        print(f"OK: {len(es)} manifest paths all present.")
        return 0

    if args.gate:
        rows = included(es, args.gate)
    elif args.excluded_from:
        rows = excluded(es, args.excluded_from)
    else:
        rows = es

    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for e in rows:
            p_ = (repo_root / e["path"]).resolve()
            if args.excluded_from:
                reason = e.get("excluded_reason", "")
                print(f"{p_}\t{reason}")
            else:
                print(p_)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
