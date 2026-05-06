#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
"""pcap-count — count packets in a libpcap-format file.

Used by flow-dissector-parity-check (Phase 17.C) to size the
synthesized rejected-record list for c-bpf-xdp2 (verifier-rejected;
no actual run, but we still need one ParityRecord per packet).
"""

import struct
import sys


def count(path: str) -> int:
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        return 0
    n = 0
    off = 24
    while off + 16 <= len(data):
        incl_len = struct.unpack("<I", data[off + 8 : off + 12])[0]
        off += 16 + incl_len
        n += 1
        if n > 1_000_000:
            break
    return n


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: pcap-count <pcap-path>", file=sys.stderr)
        sys.exit(2)
    print(count(sys.argv[1]))
