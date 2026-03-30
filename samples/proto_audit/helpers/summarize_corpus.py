#!/usr/bin/env python3
"""Summarize protocol coverage from a directory of PDML XML files."""

import argparse
import json
import os
import xml.etree.ElementTree as ET


def main():
    parser = argparse.ArgumentParser(description="Summarize PDML corpus")
    parser.add_argument("--pdml-dir", required=True, help="Directory of PDML XML files")
    parser.add_argument("--output", required=True, help="Output JSON file")
    args = parser.parse_args()

    protos = set()
    for f in os.listdir(args.pdml_dir):
        if not f.endswith(".xml"):
            continue
        try:
            tree = ET.parse(os.path.join(args.pdml_dir, f))
            for proto in tree.iter("proto"):
                name = proto.get("name", "")
                skip = ("frame", "data", "_ws.malformed", "")
                if name and name not in skip:
                    protos.add(name)
        except Exception:
            pass

    summary = {"protocol_count": len(protos), "protocols": sorted(protos)}
    with open(args.output, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Total unique dissectors in corpus: {len(protos)}")


if __name__ == "__main__":
    main()
