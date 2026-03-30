#!/usr/bin/env python3
"""Compare proto-audit JSON output against a committed baseline.

Exit 0 if no Gold-tier regressions, exit 1 otherwise.
Reports new protocols, removed protocols, and tier changes.
"""

import argparse
import json
import sys


def load_json(path):
    with open(path) as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(description='Proto-audit regression check')
    parser.add_argument('--baseline', required=True, help='Path to baseline JSON')
    parser.add_argument('--current', required=True, help='Path to current JSON')
    parser.add_argument('--strict', action='store_true',
                        help='Fail on any regression (not just Gold-tier)')
    args = parser.parse_args()

    baseline = load_json(args.baseline)
    current = load_json(args.current)

    # Build lookup maps
    base_map = {}
    for entry in baseline:
        base_map[entry['protocol']] = entry

    curr_map = {}
    for entry in current:
        curr_map[entry['protocol']] = entry

    # Detect changes
    new_protos = set(curr_map.keys()) - set(base_map.keys())
    removed_protos = set(base_map.keys()) - set(curr_map.keys())

    regressions = []
    improvements = []

    tier_order = {'Gold': 0, 'Silver': 1, 'Bronze': 2, 'Unvalidated': 3}

    for proto in sorted(set(base_map.keys()) & set(curr_map.keys())):
        b = base_map[proto]
        c = curr_map[proto]

        b_tier = b.get('validation_tier', 'Unvalidated')
        c_tier = c.get('validation_tier', 'Unvalidated')

        b_agree = b.get('fields_agree', 0)
        c_agree = c.get('fields_agree', 0)

        b_mismatch = b.get('fields_mismatch', 0)
        c_mismatch = c.get('fields_mismatch', 0)

        # Tier regression
        if tier_order.get(c_tier, 4) > tier_order.get(b_tier, 4):
            regressions.append({
                'protocol': proto,
                'type': 'tier_regression',
                'was': b_tier,
                'now': c_tier,
            })

        # Field agreement regression
        if c_agree < b_agree:
            regressions.append({
                'protocol': proto,
                'type': 'agreement_decrease',
                'was': b_agree,
                'now': c_agree,
            })

        # New mismatches
        if c_mismatch > b_mismatch:
            regressions.append({
                'protocol': proto,
                'type': 'new_mismatches',
                'was': b_mismatch,
                'now': c_mismatch,
            })

        # Improvement
        if tier_order.get(c_tier, 4) < tier_order.get(b_tier, 4):
            improvements.append({
                'protocol': proto,
                'type': 'tier_improvement',
                'was': b_tier,
                'now': c_tier,
            })

    # Report
    print(f"Proto-Audit Regression Report")
    print(f"  Baseline: {len(base_map)} protocols")
    print(f"  Current:  {len(curr_map)} protocols")
    print()

    if new_protos:
        print(f"  New protocols ({len(new_protos)}):")
        for p in sorted(new_protos)[:20]:
            print(f"    + {p}")
        if len(new_protos) > 20:
            print(f"    ... and {len(new_protos) - 20} more")
        print()

    if removed_protos:
        print(f"  Removed protocols ({len(removed_protos)}):")
        for p in sorted(removed_protos)[:20]:
            print(f"    - {p}")
        print()

    if improvements:
        print(f"  Improvements ({len(improvements)}):")
        for imp in improvements[:20]:
            print(f"    ↑ {imp['protocol']}: {imp['was']} → {imp['now']}")
        print()

    gold_regressions = [r for r in regressions
                        if base_map.get(r['protocol'], {}).get('validation_tier') == 'Gold']

    if regressions:
        print(f"  Regressions ({len(regressions)}, {len(gold_regressions)} Gold-tier):")
        for reg in regressions[:30]:
            is_gold = base_map.get(reg['protocol'], {}).get('validation_tier') == 'Gold'
            marker = " [GOLD]" if is_gold else ""
            print(f"    ↓ {reg['protocol']}: {reg['type']} ({reg['was']} → {reg['now']}){marker}")
        print()

    if not regressions:
        print("  No regressions detected. ✓")
        return 0

    if args.strict and regressions:
        print(f"  FAIL: {len(regressions)} regressions detected (--strict mode)")
        return 1

    if gold_regressions:
        print(f"  FAIL: {len(gold_regressions)} Gold-tier regressions detected")
        return 1

    print(f"  WARN: {len(regressions)} non-Gold regressions (acceptable)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
