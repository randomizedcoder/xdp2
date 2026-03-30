#!/usr/bin/env python3
"""Parse IANA registry CSVs into unified JSON for proto-audit.

Produces:
  - protocol_numbers.json: IP protocol numbers (IPv4/IPv6 next-header)
  - ethertypes.json: IEEE 802 EtherType values
  - service_ports.json: TCP/UDP/SCTP service name + port assignments
"""

import argparse
import csv
import json
import sys


def parse_protocol_numbers(path):
    """Parse IANA protocol-numbers-1.csv."""
    entries = {}
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            decimal = row.get('Decimal', '').strip()
            keyword = row.get('Keyword', '').strip()
            protocol = row.get('Protocol', '').strip()

            if not decimal or not keyword:
                continue

            # Handle ranges like "143-252"
            if '-' in decimal:
                continue

            try:
                num = int(decimal)
            except ValueError:
                continue

            entries[str(num)] = {
                'number': num,
                'keyword': keyword,
                'description': protocol,
            }
    return entries


def parse_ethertypes(path):
    """Parse IANA ieee-802-numbers-1.csv (EtherType values)."""
    entries = {}
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Column names vary; try common patterns
            ethertype = None
            description = ''
            for key in row:
                val = row[key].strip()
                if 'type' in key.lower() or 'number' in key.lower():
                    if val.startswith('0x') or val.startswith('0X'):
                        try:
                            ethertype = int(val, 16)
                        except ValueError:
                            pass
                    elif val.isdigit():
                        try:
                            ethertype = int(val)
                        except ValueError:
                            pass
                if 'description' in key.lower() or 'exp' in key.lower():
                    description = val

            if ethertype is not None:
                entries[str(ethertype)] = {
                    'ethertype': ethertype,
                    'hex': f'0x{ethertype:04X}',
                    'description': description,
                }
    return entries


def parse_service_names(path):
    """Parse IANA service-name-port-numbers.csv (truncated to common ports)."""
    entries = {}
    with open(path, newline='', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row.get('Service Name', '').strip()
            port = row.get('Port Number', '').strip()
            proto = row.get('Transport Protocol', '').strip()
            description = row.get('Description', '').strip()

            if not name or not port or not proto:
                continue

            # Handle port ranges
            if '-' in port:
                continue

            try:
                port_num = int(port)
            except ValueError:
                continue

            # Only well-known + registered ports (0-49151)
            if port_num > 49151:
                continue

            key = f'{port_num}/{proto}'
            entries[key] = {
                'name': name,
                'port': port_num,
                'protocol': proto,
                'description': description,
            }
    return entries


def main():
    parser = argparse.ArgumentParser(description='Parse IANA registry CSVs')
    parser.add_argument('--protocol-numbers', required=True)
    parser.add_argument('--ethertypes', required=True)
    parser.add_argument('--service-names', required=True)
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()

    protos = parse_protocol_numbers(args.protocol_numbers)
    print(f'Parsed {len(protos)} IP protocol numbers', file=sys.stderr)
    with open(f'{args.output_dir}/protocol_numbers.json', 'w') as f:
        json.dump(protos, f, indent=2)

    ethers = parse_ethertypes(args.ethertypes)
    print(f'Parsed {len(ethers)} EtherType values', file=sys.stderr)
    with open(f'{args.output_dir}/ethertypes.json', 'w') as f:
        json.dump(ethers, f, indent=2)

    services = parse_service_names(args.service_names)
    print(f'Parsed {len(services)} service port assignments', file=sys.stderr)
    with open(f'{args.output_dir}/service_ports.json', 'w') as f:
        json.dump(services, f, indent=2)

    # Write combined summary
    summary = {
        'protocol_numbers_count': len(protos),
        'ethertypes_count': len(ethers),
        'service_ports_count': len(services),
    }
    with open(f'{args.output_dir}/summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    print(f'IANA registries parsed successfully', file=sys.stderr)


if __name__ == '__main__':
    main()
