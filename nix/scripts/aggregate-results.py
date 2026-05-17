#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
"""aggregate-results — walk a Phase-5 result tree, emit summary.{md,csv}.

Walks `--results <dir>` for JSONs matching the Phase-5 schema
(see nix/xdp2-rs-matrix.nix), groups by (testbed, host, pcap, mode),
computes mean/median/p95/95% CI of `ns_per_pkt`, and emits:

  <out>/summary.md       per-(testbed,pcap) tables, columns=hosts
  <out>/summary.csv      flat row-per-cell
  <out>/regressions.md   only when --baseline is given

Path-inference heuristic for testbed/host (Phase-4 layout):

  <results>/<date>/<testbed>/<host>/<target>-<ts>/<pcap>/<mode>.json

If the path doesn't match, falls back to testbed=host="unknown" and
warns once.

Stdlib only: json, csv, statistics, pathlib, argparse.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path

# Canonical mode order — controls row order in summary.md. Modes not in
# this list sort alphabetically after and get a "(unknown)" tag.
CANONICAL_MODES = [
    "c-flowdis-usp",
    "c-xdp2-usp",
    "c-xdp2-parse-only",
    "c-xdp2-mono",
    "c-bpf-flowdis",
    "c-bpf-xdp2",
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

CSV_COLUMNS = [
    "testbed", "host", "pcap", "mode",
    "n_iter", "n_replicates",
    "ns_per_pkt_mean", "ns_per_pkt_median", "ns_per_pkt_p95",
    "ns_per_pkt_ci95_lo", "ns_per_pkt_ci95_hi",
    "mpps_median",
    # Phase 17.E: per-pcap parity attestation (every cell of one pcap
    # carries the same pair). null when XDP2_MATRIX_PARITY=0.
    "parity_ok", "parity_disagreements",
    "build_hash", "kernel", "nic_driver", "nic_firmware",
]


def infer_testbed_host(json_path: Path, results_root: Path) -> tuple[str, str]:
    """Walk path components above the JSON to find host/testbed.

    Layout: <results_root>/<date>/<testbed>/<host>/<target-ts>/<pcap>/<mode>.json
    The component immediately above the pcap directory is <target-ts>;
    the one above that is <host>; one above that is <testbed>.
    """
    try:
        rel = json_path.relative_to(results_root)
    except ValueError:
        return ("unknown", "unknown")
    parts = rel.parts
    # Need at least: <date>/<testbed>/<host>/<target-ts>/<pcap>/<mode>.json
    if len(parts) >= 6:
        return (parts[-5], parts[-4])
    return ("unknown", "unknown")


def parse_cell_json(path: Path) -> dict | None:
    try:
        with path.open() as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"warning: skipping {path}: {exc}", file=sys.stderr)
        return None
    if "mode" not in data or "pcap" not in data:
        print(f"warning: {path} missing mode/pcap; skipping", file=sys.stderr)
        return None
    return data


def collect(results_root: Path) -> dict:
    """Return {(testbed, host, pcap, mode): [record, ...]}."""
    grouped: dict = defaultdict(list)
    warned_unknown = False
    for json_path in results_root.rglob("*.json"):
        # Skip our own outputs and the orchestrator's run-index sibling.
        # (xdp2-run-on-host writes INDEX.json one level above the cell
        # tree; rglob picks it up but it has no mode/pcap fields.)
        if json_path.name in {"summary.json", "INDEX.json"}:
            continue
        record = parse_cell_json(json_path)
        if record is None:
            continue
        testbed, host = infer_testbed_host(json_path, results_root)
        if testbed == "unknown" and not warned_unknown:
            print(
                f"warning: {json_path} does not match the Phase-4 result-tree "
                "layout; using testbed=host='unknown'",
                file=sys.stderr,
            )
            warned_unknown = True
        record["_testbed"] = testbed
        record["_host"] = host
        key = (testbed, host, record["pcap"], record["mode"])
        grouped[key].append(record)
    return grouped


def cell_stats(records: list[dict]) -> dict:
    """Compute mean/median/p95/CI95 over ns_per_pkt across replicate runs."""
    nspkts = [
        r["ns_per_pkt"]
        for r in records
        if isinstance(r.get("ns_per_pkt"), (int, float))
    ]
    mppss = [
        r["mpps"]
        for r in records
        if isinstance(r.get("mpps"), (int, float))
    ]
    n_iter = max((r.get("iterations", 0) or 0) for r in records) if records else 0

    # Parity is per-pcap (every cell of one pcap shares the same pair),
    # so picking the first non-null value across replicates is correct.
    # If a record predates Phase 17.E, the field is missing → None.
    parity_ok = None
    parity_disagreements = None
    for r in records:
        v = r.get("parity_ok")
        if v is not None and parity_ok is None:
            parity_ok = bool(v)
        v = r.get("parity_disagreements")
        if v is not None and parity_disagreements is None and isinstance(v, int):
            parity_disagreements = v
        if parity_ok is not None and parity_disagreements is not None:
            break

    out = {
        "n_iter": n_iter,
        "n_replicates": len(nspkts),
        "ns_per_pkt_mean": None,
        "ns_per_pkt_median": None,
        "ns_per_pkt_p95": None,
        "ns_per_pkt_ci95_lo": None,
        "ns_per_pkt_ci95_hi": None,
        "mpps_median": statistics.median(mppss) if mppss else None,
        "parity_ok": parity_ok,
        "parity_disagreements": parity_disagreements,
    }
    if not nspkts:
        return out
    out["ns_per_pkt_mean"] = statistics.mean(nspkts)
    out["ns_per_pkt_median"] = statistics.median(nspkts)
    if len(nspkts) >= 2:
        # 95% CI from sample stdev. Use t-ish 1.96 approximation; the
        # alternative (statistics.NormalDist) only fits when sample
        # mean is treated as the population estimate, which is fine
        # for our small-N regression purpose.
        sd = statistics.stdev(nspkts)
        sem = sd / math.sqrt(len(nspkts))
        half = 1.96 * sem
        out["ns_per_pkt_ci95_lo"] = out["ns_per_pkt_mean"] - half
        out["ns_per_pkt_ci95_hi"] = out["ns_per_pkt_mean"] + half
    if len(nspkts) >= 5:
        # quantiles with n=20 gives 5%/10%/.../95% breakpoints; index 18 is p95.
        out["ns_per_pkt_p95"] = statistics.quantiles(nspkts, n=20)[18]
    else:
        out["ns_per_pkt_p95"] = max(nspkts)
    return out


def fmt_num(x, ndigits: int = 1) -> str:
    if x is None:
        return "—"
    if isinstance(x, float) and not math.isfinite(x):
        return "—"
    if isinstance(x, float):
        return f"{x:.{ndigits}f}"
    return str(x)


def mode_sort_key(mode: str):
    """Canonical modes in their listed order; unknowns sorted alphabetically after."""
    if mode in CANONICAL_MODES:
        return (0, CANONICAL_MODES.index(mode))
    return (1, mode)


def write_csv(out_path: Path, grouped: dict, stats_by_cell: dict) -> None:
    rows = []
    for key, records in grouped.items():
        testbed, host, pcap, mode = key
        s = stats_by_cell[key]
        sample = records[0]
        # parity_ok renders as "true"/"false"/"" (not "—"/"None") so it
        # round-trips cleanly through csv.DictReader on the regression path.
        if s["parity_ok"] is True:
            parity_ok_str = "true"
        elif s["parity_ok"] is False:
            parity_ok_str = "false"
        else:
            parity_ok_str = ""
        if isinstance(s["parity_disagreements"], int):
            parity_d_str = str(s["parity_disagreements"])
        else:
            parity_d_str = ""
        rows.append({
            "testbed": testbed,
            "host": host,
            "pcap": pcap,
            "mode": mode,
            "n_iter": s["n_iter"],
            "n_replicates": s["n_replicates"],
            "ns_per_pkt_mean": fmt_num(s["ns_per_pkt_mean"], 2),
            "ns_per_pkt_median": fmt_num(s["ns_per_pkt_median"], 2),
            "ns_per_pkt_p95": fmt_num(s["ns_per_pkt_p95"], 2),
            "ns_per_pkt_ci95_lo": fmt_num(s["ns_per_pkt_ci95_lo"], 2),
            "ns_per_pkt_ci95_hi": fmt_num(s["ns_per_pkt_ci95_hi"], 2),
            "mpps_median": fmt_num(s["mpps_median"], 2),
            "parity_ok": parity_ok_str,
            "parity_disagreements": parity_d_str,
            "build_hash": sample.get("build_hash", ""),
            "kernel": sample.get("kernel", ""),
            "nic_driver": sample.get("nic_driver", ""),
            "nic_firmware": sample.get("nic_firmware", ""),
        })
    rows.sort(key=lambda r: (r["testbed"], r["host"], r["pcap"], mode_sort_key(r["mode"])))
    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def write_md(out_path: Path, grouped: dict, stats_by_cell: dict, min_iter: int) -> None:
    # Group by (testbed, pcap); rows = mode, columns = host.
    by_pcap: dict = defaultdict(lambda: defaultdict(dict))
    hosts_per_pcap: dict = defaultdict(set)
    modes_per_pcap: dict = defaultdict(set)
    low_n_count = 0
    for key, _records in grouped.items():
        testbed, host, pcap, mode = key
        s = stats_by_cell[key]
        by_pcap[(testbed, pcap)][mode][host] = s
        hosts_per_pcap[(testbed, pcap)].add(host)
        modes_per_pcap[(testbed, pcap)].add(mode)
        if s["n_iter"] and s["n_iter"] < min_iter:
            low_n_count += 1

    lines = [
        "# Flow-Dissector Matrix Summary",
        "",
        "Generated by `flow-dissector-matrix-aggregate`. Methodology:",
        "win = CI-disjoint ns/pkt; otherwise = noise.",
        "",
    ]
    if low_n_count:
        lines.append(
            f"⚠ {low_n_count} cell(s) below `--min-iterations {min_iter}`; "
            "marked `(low-N)`."
        )
        lines.append("")

    for (testbed, pcap) in sorted(by_pcap.keys()):
        cell = by_pcap[(testbed, pcap)]
        hosts = sorted(hosts_per_pcap[(testbed, pcap)])
        modes = sorted(modes_per_pcap[(testbed, pcap)], key=mode_sort_key)
        lines.append(f"## {testbed} — `{pcap}`")
        lines.append("")
        header = ["Mode", *hosts]
        lines.append("| " + " | ".join(header) + " |")
        lines.append("|" + "|".join("---" for _ in header) + "|")
        for mode in modes:
            row = [mode + (" (unknown)" if mode not in CANONICAL_MODES else "")]
            for host in hosts:
                s = cell.get(mode, {}).get(host)
                if s is None or s["ns_per_pkt_median"] is None:
                    row.append("—")
                    continue
                ns = fmt_num(s["ns_per_pkt_median"], 1)
                mpps = fmt_num(s["mpps_median"], 1)
                tag = ""
                if s["n_iter"] and s["n_iter"] < min_iter:
                    tag = " (low-N)"
                if s.get("parity_ok") is False:
                    d = s.get("parity_disagreements")
                    tag += f" (parity-fail{f', {d}' if isinstance(d, int) else ''})"
                row.append(f"{ns} ns/pkt ({mpps} Mpps){tag}")
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")

    out_path.write_text("\n".join(lines))


def parse_baseline(path: Path) -> dict:
    """Return {(testbed,host,pcap,mode): row} keyed for join. Reject non-numeric medians."""
    rows = {}
    with path.open() as f:
        reader = csv.DictReader(f)
        for r in reader:
            try:
                med = float(r["ns_per_pkt_median"])
                lo = float(r.get("ns_per_pkt_ci95_lo") or "nan")
                hi = float(r.get("ns_per_pkt_ci95_hi") or "nan")
            except (KeyError, ValueError):
                raise ValueError(
                    f"baseline incomplete: row {r!r} has non-numeric "
                    "ns_per_pkt_median or CI columns. Promote a real "
                    "summary.csv before invoking --baseline."
                )
            key = (r["testbed"], r["host"], r["pcap"], r["mode"])
            # parity_ok: "true"/"false"/"" — None means "baseline pre-dates
            # Phase 17.E or parity was off"; only an explicit true→false
            # flip is a regression.
            parity_raw = r.get("parity_ok", "")
            if parity_raw == "true":
                parity_ok = True
            elif parity_raw == "false":
                parity_ok = False
            else:
                parity_ok = None
            rows[key] = {
                "median": med,
                "ci95_lo": lo if math.isfinite(lo) else None,
                "ci95_hi": hi if math.isfinite(hi) else None,
                "parity_ok": parity_ok,
            }
    return rows


def write_regressions(
    out_path: Path,
    stats_by_cell: dict,
    baseline: dict,
    threshold_pct: float,
) -> int:
    """Return total regression count (perf + parity).

    Two independent regression checks per cell:
      1. ns/pkt: magnitude > threshold AND CI-disjoint.
      2. parity: baseline=True → new=False (only that direction; None on
         either side is "no signal" — pre-Phase-17.E baselines never
         flag).

    Both kinds are emitted into the same regressions.md table with a
    `kind` column so a maintainer reading the report can see which
    half tripped.
    """
    perf_regressions = []
    parity_regressions = []
    n_compared = 0
    for key, s in stats_by_cell.items():
        b = baseline.get(key)
        if b is None:
            continue
        n_compared += 1
        # ── perf regression ──────────────────────────────────────
        if s["ns_per_pkt_median"] is not None:
            new_med = s["ns_per_pkt_median"]
            base_med = b["median"]
            if base_med > 0:
                delta_pct = (new_med - base_med) / base_med * 100.0
                if delta_pct > threshold_pct:
                    new_lo = s["ns_per_pkt_ci95_lo"]
                    base_hi = b["ci95_hi"]
                    if not (new_lo is not None and base_hi is not None and new_lo <= base_hi):
                        perf_regressions.append((key, new_med, base_med, delta_pct))
        # ── parity regression ────────────────────────────────────
        # Only flag the explicit true→false flip. None on either side
        # is silent (baseline pre-dates Phase 17.E, or parity was off
        # for this run).
        if b.get("parity_ok") is True and s.get("parity_ok") is False:
            parity_regressions.append((key, s.get("parity_disagreements")))

    total = len(perf_regressions) + len(parity_regressions)

    lines = ["# Regressions", ""]
    if total == 0:
        lines.append(
            f"No regressions detected (threshold={threshold_pct}%, N={n_compared})."
        )
    else:
        lines.append(
            f"⚠ {total} REGRESSION(s) detected "
            f"(threshold={threshold_pct}%, N={n_compared}; "
            f"{len(perf_regressions)} perf, {len(parity_regressions)} parity)."
        )
        lines.append("")
        lines.append("| Kind | Testbed | Host | PCAP | Mode | New ns/pkt | Baseline | Δ% / disagreements |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for key, new_med, base_med, delta_pct in perf_regressions:
            t, h, p, m = key
            lines.append(
                f"| perf | {t} | {h} | {p} | {m} | {fmt_num(new_med, 2)} | "
                f"{fmt_num(base_med, 2)} | {fmt_num(delta_pct, 1)} |"
            )
        for key, disagreements in parity_regressions:
            t, h, p, m = key
            d_str = str(disagreements) if isinstance(disagreements, int) else "—"
            lines.append(
                f"| parity | {t} | {h} | {p} | {m} | — | — | {d_str} |"
            )
    out_path.write_text("\n".join(lines) + "\n")
    return total


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate Phase-5 per-cell JSONs into summary tables.",
    )
    parser.add_argument("--results", required=True, type=Path,
                        help="root of the Phase-5 result tree to aggregate")
    parser.add_argument("--out", type=Path, default=None,
                        help="output directory (default: --results)")
    parser.add_argument("--baseline", type=Path, default=None,
                        help="baseline CSV to diff against; produces regressions.md")
    parser.add_argument("--threshold-pct", type=float, default=10.0,
                        help="regression threshold in percent (default: 10)")
    parser.add_argument("--min-iterations", type=int, default=30,
                        help="annotate cells with iterations < N as (low-N)")
    parser.add_argument("--fail-on-regression", action="store_true",
                        help="exit non-zero when regressions are detected")
    args = parser.parse_args(argv)

    results_root = args.results.resolve()
    if not results_root.is_dir():
        print(f"error: --results {results_root} is not a directory", file=sys.stderr)
        return 2
    out_dir = (args.out or args.results).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    grouped = collect(results_root)
    if not grouped:
        print(f"error: no Phase-5 cell JSONs found under {results_root}", file=sys.stderr)
        return 1

    stats_by_cell = {key: cell_stats(records) for key, records in grouped.items()}

    write_csv(out_dir / "summary.csv", grouped, stats_by_cell)
    write_md(out_dir / "summary.md", grouped, stats_by_cell, args.min_iterations)
    print(f"wrote {out_dir/'summary.csv'} and {out_dir/'summary.md'}")

    n_regressions = 0
    if args.baseline:
        baseline = parse_baseline(args.baseline)
        n_regressions = write_regressions(
            out_dir / "regressions.md",
            stats_by_cell,
            baseline,
            args.threshold_pct,
        )
        print(f"wrote {out_dir/'regressions.md'} ({n_regressions} regression(s))")
        if args.fail_on_regression and n_regressions > 0:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
