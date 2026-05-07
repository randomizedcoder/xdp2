#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
"""extract-afxdp-cell — re-extract per-cell metrics from saved bench logs.

The flow-dissector-afxdp-live wrapper's inline awk extraction only handles
the per-queue table format emitted by `--mode af-xdp-template`. The other
AF_XDP modes (af-xdp / af-xdp-mono / af-xdp-graph-enum) emit a different
single-line format:

  AF_XDP Results (<iface> queue <N>, parser=<label>):
    Packets:  26334063
    Duration: 30.00s
    1139 ns/pkt,  0.9 Mpps
    36867.7 MB received

This script walks one or more existing 10mpps.log files, extracts numbers
from whichever format is present, and rewrites the sibling 10mpps.json
with pps_received / drops / drops_pct / zerocopy / mode / frame_size_b
populated.

Usage:
  extract-afxdp-cell.py <results_dir>

Walks <results_dir>/<mode>/<size>b/<L>mpps.log and updates the matching
10mpps.json in-place (preserving keys that didn't need re-extraction).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


# Per-queue table format used by --mode af-xdp-template:
#   queue    | template            | packets   | bytes  | ns/pkt | Mpps
#   -------- | ------------------- | --------- | ------ | ------ | ----
#   1        | EthIpv4Udp          | 26333552  | …      | 1139   | 0.88
TABLE_ROW = re.compile(
    r"^\s*\d+\s*\|\s*\S.*?\|\s*(\d+)\s*\|\s*\d+\s*\|\s*(\d+)\s*\|\s*([\d.]+)\s*$"
)

# Single-mode AF_XDP output (af-xdp / af-xdp-mono / af-xdp-graph-enum):
#   AF_XDP Results (<iface> queue <N>, parser=<label>):
#     Packets:  26334063
#     Duration: 30.00s
#     1139 ns/pkt,  0.9 Mpps
SINGLE_PACKETS = re.compile(r"^\s*Packets:\s*(\d+)\s*$")
SINGLE_RATE = re.compile(r"^\s*(\d+)\s*ns/pkt,\s*([\d.]+)\s*Mpps\s*$")


def parse_log(log_path: Path) -> dict:
    """Return {packets, ns_per_pkt, mpps, zerocopy} extracted from the log.

    Missing fields default to None so the caller can decide whether to
    overwrite existing JSON values.
    """
    out = {
        "packets": None,
        "ns_per_pkt": None,
        "mpps": None,
        "zerocopy": None,
    }
    if not log_path.exists():
        return out

    saw_xskmap = False
    saw_xdpdrv = False
    saw_xdpgeneric = False

    with log_path.open() as f:
        for line in f:
            # Detect zerocopy from the rx setup lines.
            if "registered in XSKMAP" in line:
                saw_xskmap = True
            if "XDP_MODE=xdpdrv" in line:
                saw_xdpdrv = True
            if "XDP_MODE=xdpgeneric" in line:
                saw_xdpgeneric = True

            # Try the per-queue table format first.
            m = TABLE_ROW.match(line)
            if m and out["packets"] is None:
                out["packets"] = int(m.group(1))
                out["ns_per_pkt"] = int(m.group(2))
                out["mpps"] = float(m.group(3))
                continue

            # Fall back to the single-mode format.
            m = SINGLE_PACKETS.match(line)
            if m and out["packets"] is None:
                out["packets"] = int(m.group(1))
                continue
            m = SINGLE_RATE.match(line)
            if m and out["ns_per_pkt"] is None:
                out["ns_per_pkt"] = int(m.group(1))
                out["mpps"] = float(m.group(2))
                continue

    if saw_xdpdrv and saw_xskmap:
        out["zerocopy"] = "zerocopy"
    elif saw_xdpgeneric:
        out["zerocopy"] = "copy"
    return out


def update_cell_json(json_path: Path, log_path: Path, duration_s: int) -> bool:
    """Update json_path's pps_received / drops / drops_pct / zerocopy
    from log_path. Returns True if the JSON was updated."""
    if not json_path.exists():
        return False

    extracted = parse_log(log_path)
    if extracted["packets"] is None:
        return False

    with json_path.open() as f:
        data = json.load(f)

    pps_rx = extracted["packets"] // duration_s if duration_s > 0 else None
    data["pps_received"] = pps_rx
    data["mpps_received"] = extracted["mpps"]
    data["ns_per_pkt"] = extracted["ns_per_pkt"]

    # drops calculated against the requested offered load, same convention
    # as the inline wrapper. offered_mpps already in JSON.
    offered_mpps = data.get("offered_mpps")
    if isinstance(offered_mpps, (int, float)) and pps_rx is not None:
        offered_pkts = int(offered_mpps * 1_000_000 * duration_s)
        if offered_pkts > extracted["packets"]:
            drops = offered_pkts - extracted["packets"]
            data["drops"] = drops
            data["drops_pct"] = round(drops / offered_pkts * 100.0, 4)
        else:
            data["drops"] = 0
            data["drops_pct"] = 0.0

    if extracted["zerocopy"] is not None:
        data["zerocopy"] = extracted["zerocopy"]

    with json_path.open("w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    return True


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("results_dir", type=Path,
                   help="afxdp results root, e.g. perf-results/2026-05-06/hp2-hp5-x710/afxdp")
    args = p.parse_args(argv)

    if not args.results_dir.is_dir():
        print(f"error: not a directory: {args.results_dir}", file=sys.stderr)
        return 2

    n_updated = 0
    n_seen = 0
    for json_path in args.results_dir.rglob("*mpps.json"):
        log_path = json_path.with_suffix(".log")
        # Read duration from JSON if present; default 30.
        try:
            with json_path.open() as f:
                d = json.load(f)
            duration = int(d.get("duration_s", 30))
        except Exception:
            duration = 30
        n_seen += 1
        if update_cell_json(json_path, log_path, duration):
            n_updated += 1
            print(f"updated: {json_path}")
        else:
            print(f"skipped: {json_path} (no parsable bench output in {log_path.name})", file=sys.stderr)

    print(f"\nupdated {n_updated} of {n_seen} cell JSONs")
    return 0 if n_updated > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
