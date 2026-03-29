#!/usr/bin/env python3
"""Scan Linux kernel UAPI headers for protocol struct definitions.

Scans include/uapi/linux/*.h for `struct *hdr` / `struct *_header` patterns.
Outputs kernel_registry.json with struct name, header file, estimated field count.
"""

import argparse
import json
import os
import re
import sys


# Regex to match struct definitions that look like protocol headers
STRUCT_RE = re.compile(
    r'struct\s+(\w+(?:hdr|_header|_hdr))\s*\{([^}]*)\}',
    re.DOTALL,
)

# Additional known protocol struct patterns (not ending in hdr/header)
EXTRA_STRUCT_RE = re.compile(
    r'struct\s+(in6_addr|in_addr|sock(?:addr(?:_in6?|_ll)?)|ethhdr|arphdr|can_frame|canfd_frame|canxl_frame)\s*\{([^}]*)\}',
    re.DOTALL,
)

# Match field declarations inside structs
FIELD_RE = re.compile(
    r'(?:__be(?:16|32|64)|__le(?:16|32|64)|__u8|__u16|__u32|__u64|__s8|__s16|__s32|__s64|unsigned\s+\w+|u_?int\d+_t)\s+\w+',
)


def scan_header(filepath, relpath):
    """Scan a single header file for protocol structs."""
    try:
        content = open(filepath).read()
    except (IOError, UnicodeDecodeError):
        return []

    results = []
    for regex in [STRUCT_RE, EXTRA_STRUCT_RE]:
        for m in regex.finditer(content):
            struct_name = m.group(1)
            body = m.group(2)
            field_count = len(FIELD_RE.findall(body))
            if field_count > 0:
                results.append({
                    'struct_name': struct_name,
                    'header': relpath,
                    'field_count': field_count,
                })
    return results


def scan_kernel_tree(kernel_src):
    """Scan the entire kernel UAPI include tree."""
    structs = {}
    uapi_dir = os.path.join(kernel_src, 'include', 'uapi')
    if not os.path.isdir(uapi_dir):
        # Try without uapi prefix
        uapi_dir = os.path.join(kernel_src, 'include')

    for dirpath, _, filenames in os.walk(uapi_dir):
        for fn in filenames:
            if not fn.endswith('.h'):
                continue
            filepath = os.path.join(dirpath, fn)
            # Relative path from include/uapi/ for consistency
            relpath = os.path.relpath(filepath, os.path.join(kernel_src, 'include', 'uapi'))
            if relpath.startswith('..'):
                relpath = os.path.relpath(filepath, os.path.join(kernel_src, 'include'))

            for entry in scan_header(filepath, relpath):
                name = entry['struct_name']
                if name not in structs or entry['field_count'] > structs[name]['field_count']:
                    structs[name] = entry

    return structs


def main():
    parser = argparse.ArgumentParser(description='Scan kernel UAPI headers for protocol structs')
    parser.add_argument('--kernel-src', required=True, help='Path to kernel source tree')
    parser.add_argument('--output', required=True, help='Output JSON file path')
    args = parser.parse_args()

    print(f"Scanning kernel headers in {args.kernel_src}...", file=sys.stderr)
    structs = scan_kernel_tree(args.kernel_src)
    print(f"  Found {len(structs)} protocol structs", file=sys.stderr)

    with open(args.output, 'w') as f:
        json.dump(structs, f, indent=2)

    print(f"Wrote {len(structs)} structs to {args.output}", file=sys.stderr)


if __name__ == '__main__':
    main()
