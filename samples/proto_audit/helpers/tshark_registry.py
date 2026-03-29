#!/usr/bin/env python3
"""Generate a JSON registry from tshark metadata for proto-audit auto-discovery.

Runs:
  tshark -G protocols  → list of (short_name, long_name, filter_name)
  tshark -G decodes    → parent→child decode tables with dispatch values
  tshark -G fields     → field counts per protocol (for size estimation)

Outputs tshark_registry.json.
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict


def run_tshark(tshark_bin, *args):
    """Run tshark with the given -G arguments and return stdout lines."""
    cmd = [tshark_bin] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        print(f"tshark {' '.join(args)} failed: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().split('\n')


def parse_protocols(tshark_bin):
    """Parse `tshark -G protocols` output.

    Each line is tab-separated: long_name, short_name, filter_name
    """
    lines = run_tshark(tshark_bin, '-G', 'protocols')
    protocols = {}
    for line in lines:
        if not line.strip():
            continue
        parts = line.split('\t')
        if len(parts) < 3:
            continue
        long_name, short_name, filter_name = parts[0], parts[1], parts[2]
        # Use filter_name as the key (most stable identifier)
        protocols[filter_name] = {
            'short_name': short_name,
            'long_name': long_name,
            'filter_name': filter_name,
            'field_count': 0,
        }
    return protocols


def parse_decodes(tshark_bin):
    """Parse `tshark -G decodes` output.

    Each line is tab-separated: decode_table, value, protocol_short_name
    Some lines have additional columns we can ignore.
    """
    lines = run_tshark(tshark_bin, '-G', 'decodes')
    decode_tables = defaultdict(list)
    for line in lines:
        if not line.strip():
            continue
        parts = line.split('\t')
        if len(parts) < 3:
            continue
        table_name = parts[0]
        value = parts[1]
        proto_filter = parts[2]
        # Only keep entries with numeric-looking values (hex or decimal)
        if value and (value.isdigit() or value.startswith('0x') or value.startswith('0X')):
            decode_tables[table_name].append({
                'value': value,
                'protocol': proto_filter,
            })
    return dict(decode_tables)


def parse_fields(tshark_bin, protocols):
    """Parse `tshark -G fields` to capture field metadata per protocol.

    Each line is tab-separated:
      P lines: P, long_name, short_name, filter_name
      F lines: F, description, filter_name, ft_type, parent_proto, base, bitmask, blurb
    """
    lines = run_tshark(tshark_bin, '-G', 'fields')
    current_proto = None
    proto_fields = defaultdict(list)
    field_counts = defaultdict(int)
    for line in lines:
        if not line.strip():
            continue
        parts = line.split('\t')
        if not parts:
            continue
        if parts[0] == 'P':
            # Protocol header line in -G fields: P, long_name, filter_name
            if len(parts) >= 3:
                current_proto = parts[2]  # filter_name
        elif parts[0] == 'F' and current_proto:
            field_counts[current_proto] += 1
            if len(parts) >= 7:
                field_entry = {
                    'description': parts[1] if len(parts) > 1 else '',
                    'filter_name': parts[2] if len(parts) > 2 else '',
                    'ft_type': parts[3] if len(parts) > 3 else '',
                    'parent_proto': parts[4] if len(parts) > 4 else '',
                    'base': parts[5] if len(parts) > 5 else '',
                    'bitmask': parts[6] if len(parts) > 6 else '0',
                }
                proto_fields[current_proto].append(field_entry)

    # Merge counts and fields into protocol records
    for filter_name, count in field_counts.items():
        if filter_name in protocols:
            protocols[filter_name]['field_count'] = count
            protocols[filter_name]['fields'] = proto_fields.get(filter_name, [])


def main():
    parser = argparse.ArgumentParser(description='Generate tshark protocol registry')
    parser.add_argument('--tshark', default='tshark', help='Path to tshark binary')
    parser.add_argument('--output', required=True, help='Output JSON file path')
    args = parser.parse_args()

    print(f"Scanning tshark protocols...", file=sys.stderr)
    protocols = parse_protocols(args.tshark)
    print(f"  Found {len(protocols)} protocols", file=sys.stderr)

    print(f"Scanning decode tables...", file=sys.stderr)
    decode_tables = parse_decodes(args.tshark)
    print(f"  Found {len(decode_tables)} decode tables", file=sys.stderr)

    print(f"Parsing fields per protocol...", file=sys.stderr)
    parse_fields(args.tshark, protocols)

    registry = {
        'protocols': protocols,
        'decode_tables': decode_tables,
    }

    with open(args.output, 'w') as f:
        json.dump(registry, f, indent=2)

    print(f"Wrote {len(protocols)} protocols to {args.output}", file=sys.stderr)


if __name__ == '__main__':
    main()
