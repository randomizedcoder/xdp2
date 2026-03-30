#!/usr/bin/env python3
"""Summarize protocol coverage from a directory of PDML XML files.

Produces a JSON summary with:
- Total unique dissector names
- Per-protocol: field count, PCAP sources, byte sizes observed
- Coverage matrix: which PCAPs contain which protocols
"""

import argparse
import json
import os
import xml.etree.ElementTree as ET
from collections import defaultdict


def main():
    parser = argparse.ArgumentParser(description="Summarize PDML corpus")
    parser.add_argument("--pdml-dir", required=True, help="Directory of PDML XML files")
    parser.add_argument("--output", required=True, help="Output JSON file")
    args = parser.parse_args()

    # proto_name → { fields: set, pcaps: set, sizes: list }
    proto_data = defaultdict(lambda: {"fields": set(), "pcaps": set(), "sizes": []})
    skip_protos = {"frame", "data", "_ws.malformed", "fake-field-wrapper", ""}
    pcap_count = 0
    parse_errors = 0

    for f in sorted(os.listdir(args.pdml_dir)):
        if not f.endswith(".xml"):
            continue
        pcap_name = f.rsplit(".", 1)[0]
        pcap_count += 1
        try:
            tree = ET.parse(os.path.join(args.pdml_dir, f))
            for proto in tree.iter("proto"):
                name = proto.get("name", "")
                if name in skip_protos:
                    continue

                info = proto_data[name]
                info["pcaps"].add(pcap_name)

                size = proto.get("size", "")
                if size and size.isdigit():
                    info["sizes"].append(int(size))

                for field in proto.findall("field"):
                    fname = field.get("name", "")
                    if fname and fname != name:
                        info["fields"].add(fname)
        except Exception:
            parse_errors += 1

    # Build output
    protocols = {}
    for name, info in sorted(proto_data.items()):
        sizes = info["sizes"]
        protocols[name] = {
            "field_count": len(info["fields"]),
            "pcap_count": len(info["pcaps"]),
            "pcaps": sorted(info["pcaps"]),
            "min_bytes": min(sizes) if sizes else 0,
            "max_bytes": max(sizes) if sizes else 0,
        }

    summary = {
        "protocol_count": len(protocols),
        "pcap_file_count": pcap_count,
        "parse_errors": parse_errors,
        "protocols": protocols,
        "protocol_names": sorted(protocols.keys()),
    }
    with open(args.output, "w") as out:
        json.dump(summary, out, indent=2)
    print(f"Total unique dissectors in corpus: {len(protocols)}")
    print(f"PCAP files processed: {pcap_count} ({parse_errors} errors)")

    # Top protocols by coverage
    by_coverage = sorted(protocols.items(), key=lambda x: x[1]["pcap_count"], reverse=True)
    print("\nTop 20 protocols by PCAP coverage:")
    for name, info in by_coverage[:20]:
        print(f"  {name:<30} {info['pcap_count']:>3} PCAPs, {info['field_count']:>4} fields")


if __name__ == "__main__":
    main()
