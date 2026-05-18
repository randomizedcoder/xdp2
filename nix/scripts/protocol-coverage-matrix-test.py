#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
"""Unit tests for protocol-coverage-matrix.py (Phase 1).

Builds a synthetic jsonl-tree with 3 fake protocols × 2 parsers,
runs the aggregator end-to-end, and asserts the rendered matrix
contains the expected cell classifications.
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "protocol-coverage-matrix.py"

# Minimal parity_scope.json the matrix tool needs to load. Matches the
# schema_version + structure of samples/flow_dissector/parity_scope.json.
MINIMAL_SCOPE = {
    "schema_version": 1,
    "field_definitions": {
        "ip_proto": {"type": "u8"},
        "sport":    {"type": "u16"},
        "dport":    {"type": "u16"},
    },
    "tiers": {
        "bpf_flow_keys": ["ip_proto", "sport", "dport"],
    },
    "scopes": {
        "c-xdp2-mono":   {"tiers": ["bpf_flow_keys"], "tunnel_behavior": "inner"},
        "c-flowdis-usp": {"tiers": ["bpf_flow_keys"], "tunnel_behavior": "outer"},
    },
    "expected_divergences": [],
    "expected_protocol_acceptance": {
        "doc": "test fixture",
        "protocols": {
            "tcp_v4": {"default": "accept", "overrides": {}},
            "bgp":    {"default": "accept", "overrides": {}},
            # arp: undeclared by design — exercise that path
        }
    }
}


def write_jsonl(path: Path, records: list[dict]) -> None:
    """Write JSONL records (each prepended with schema_version=1)."""
    lines = []
    for r in records:
        r = dict(r); r["schema_version"] = 1
        lines.append(json.dumps(r))
    path.write_text("\n".join(lines) + "\n")


def build_tree(root: Path) -> None:
    """Fixture: 3 protocols × 2 parsers, hand-crafted cells.

      tcp_v4: both parsers accept, agree on all fields            -> OK / OK
      bgp:    both parsers accept, disagree on ip_proto           -> OK!1 / OK!1
      arp:    flowdis rejects (parse-error), mono accepts         -> N/A / OK
    """
    pcap = "fixture.pcap"

    def rec(parser_id, kind, accepted, fields, reject_reason=None, pkt=0):
        return {
            "pcap": pcap,
            "packet_index": pkt,
            "parser_id": parser_id,
            "parser_kind": kind,
            "accepted": accepted,
            "fields": fields,
            "reject_reason": reject_reason,
            "accept_path": None,
        }

    # tcp_v4: both agree
    d = root / "tcp_v4"; d.mkdir(parents=True)
    write_jsonl(d / "c-flowdis-usp.jsonl", [
        rec("c-flowdis-usp", "c", True, {"ip_proto": 6, "sport": 80, "dport": 443}),
    ])
    write_jsonl(d / "c-xdp2-mono.jsonl", [
        rec("c-xdp2-mono", "c", True, {"ip_proto": 6, "sport": 80, "dport": 443}),
    ])

    # bgp: both accept, disagree on ip_proto
    d = root / "bgp"; d.mkdir(parents=True)
    write_jsonl(d / "c-flowdis-usp.jsonl", [
        rec("c-flowdis-usp", "c", True, {"ip_proto": 6, "sport": 179, "dport": 12345}),
    ])
    write_jsonl(d / "c-xdp2-mono.jsonl", [
        rec("c-xdp2-mono", "c", True, {"ip_proto": 99, "sport": 179, "dport": 12345}),
    ])

    # arp: flowdis rejects (no parser file), mono accepts
    d = root / "arp"; d.mkdir(parents=True)
    write_jsonl(d / "c-flowdis-usp.jsonl", [
        rec("c-flowdis-usp", "c", False, {}, reject_reason="parse-error"),
    ])
    write_jsonl(d / "c-xdp2-mono.jsonl", [
        rec("c-xdp2-mono", "c", True, {"ip_proto": 0}),
    ])


def run_matrix(jsonl_tree: Path, scope: Path, out: Path,
               extra_args: list[str] | None = None) -> int:
    cmd = [
        sys.executable, str(SCRIPT),
        "--jsonl-tree", str(jsonl_tree),
        "--scope", str(scope),
        "--out", str(out),
    ] + (extra_args or [])
    cp = subprocess.run(cmd, capture_output=True, text=True)
    if cp.returncode != 0:
        print(cp.stdout); print(cp.stderr, file=sys.stderr)
    return cp.returncode


def main() -> int:
    failures = 0
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        scope = td / "scope.json"
        scope.write_text(json.dumps(MINIMAL_SCOPE))
        tree = td / "jsonl-tree"; build_tree(tree)
        out = td / "report"

        # ── basic run ────────────────────────────────────────────
        rc = run_matrix(tree, scope, out)
        if rc != 0:
            print(f"FAIL: basic run exited {rc}", file=sys.stderr)
            return 1

        md = (out / "matrix.md").read_text()
        csv_text = (out / "matrix.csv").read_text()

        # tcp_v4: both OK
        if "| tcp_v4 | OK | OK |" not in md:
            print(f"FAIL: tcp_v4 row not 'OK | OK'; md=\n{md}", file=sys.stderr)
            failures += 1
        # bgp: both should have OK!1 (one disagreement on ip_proto)
        if "| bgp | OK!1 | OK!1 |" not in md:
            print(f"FAIL: bgp row not 'OK!1 | OK!1'; md=\n{md}", file=sys.stderr)
            failures += 1
        # arp: flowdis rejects with parse-error (rej? = undeclared); mono OK
        if "| arp | rej?(parse-error) | OK |" not in md:
            print(f"FAIL: arp row not 'rej?(parse-error) | OK'; md=\n{md}",
                  file=sys.stderr)
            failures += 1

        # CSV sanity
        if "tcp_v4,c-flowdis-usp,True" not in csv_text:
            print(f"FAIL: tcp_v4/c-flowdis-usp row missing from csv",
                  file=sys.stderr)
            failures += 1

        # ── bootstrap mode ──────────────────────────────────────
        out2 = td / "report-bootstrap"
        rc = run_matrix(tree, scope, out2, ["--bootstrap-expectations"])
        if rc != 0:
            print(f"FAIL: bootstrap run exited {rc}", file=sys.stderr)
            failures += 1
        boot = json.loads((out2 / "scope-additions.json").read_text())
        protocols = boot["expected_protocol_acceptance"]["protocols"]
        if set(protocols) != {"tcp_v4", "bgp", "arp"}:
            print(f"FAIL: bootstrap protocols {set(protocols)} != "
                  "{'tcp_v4', 'bgp', 'arp'}", file=sys.stderr)
            failures += 1
        # arp default should be 'accept' (mono accepts; majority)
        if protocols["arp"]["default"] != "accept":
            print(f"FAIL: bootstrap arp default {protocols['arp']['default']} "
                  "!= 'accept'", file=sys.stderr)
            failures += 1
        if "c-flowdis-usp" not in protocols["arp"]["overrides"]:
            print(f"FAIL: bootstrap arp.overrides missing c-flowdis-usp",
                  file=sys.stderr)
            failures += 1

        # ── --require-expectations: should fail because arp's flowdis
        #     reject_reason isn't declared
        out3 = td / "report-strict"
        rc = run_matrix(tree, scope, out3, ["--require-expectations"])
        # arp.c-flowdis-usp is REJ-undeclared (not REJ-unexpected), so
        # the gate shouldn't fail on it. tcp_v4 + bgp + arp/mono are all OK.
        # Test passes if rc==0.
        if rc != 0:
            print(f"FAIL: --require-expectations exited {rc}, "
                  "expected 0 (no REJ-unexpected)", file=sys.stderr)
            failures += 1

    if failures:
        print(f"\n{failures} test failure(s)", file=sys.stderr)
        return 1
    print("All tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
