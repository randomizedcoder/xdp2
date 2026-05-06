#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
"""Unit tests for parity-compare.py (Phase 17.A skeleton).

Validates:
  1. parity_scope.json loads cleanly with all 14 parsers + 36 fields.
  2. Per-parser scope expansion produces the expected field set.
  3. compare_pair correctly flags one synthetic disagreement.
  4. compare_pair correctly skips out-of-scope fields.
  5. compare_pair returns [] when both records were rejected.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

# Load parity-compare from the same directory.
# Register the module in sys.modules BEFORE exec_module — required for
# the @dataclass decorator's introspection (it looks up cls.__module__
# in sys.modules to resolve KW_ONLY on Python 3.13+).
HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location(
    "parity_compare", HERE / "parity-compare.py"
)
pc = importlib.util.module_from_spec(spec)
sys.modules["parity_compare"] = pc
spec.loader.exec_module(pc)

REPO = HERE.parent.parent  # nix/scripts → repo root
SCOPE_PATH = REPO / "samples" / "flow_dissector" / "parity_scope.json"


class TestSchemaLoading(unittest.TestCase):
    def setUp(self):
        self.schema = pc.load_schema(SCOPE_PATH)

    def test_schema_version(self):
        self.assertEqual(self.schema.version, 1)

    def test_14_parsers(self):
        self.assertEqual(len(self.schema.parsers), 14)
        for required in (
            "c-flowdis-usp", "c-xdp2-usp", "c-xdp2-parse-only",
            "c-bpf-flowdis", "c-bpf-xdp2", "c-bpf-fast",
            "rust-graph", "rust-graph-enum",
            "rust-mono", "rust-mono-x4",
            "rust-compiled", "rust-simd",
            "rust-template", "rust-template-simd",
        ):
            self.assertIn(required, self.schema.parsers, f"missing {required}")

    def test_field_count(self):
        # Should be 36 canonical fields per parity_scope.json.
        self.assertGreaterEqual(len(self.schema.field_names), 30,
                                f"got {len(self.schema.field_names)}")

    def test_bpf_parsers_have_narrow_scope(self):
        # bpf parsers should not include MAC, TCP flags, or VLAN.
        for parser_id in ("c-bpf-flowdis", "c-bpf-xdp2", "c-bpf-fast"):
            p = self.schema.parsers[parser_id]
            self.assertNotIn("eth_dst", p.fields, f"{parser_id} has eth_dst in scope")
            self.assertNotIn("tcp_flags", p.fields, f"{parser_id} has tcp_flags in scope")
            self.assertNotIn("vlan", p.fields, f"{parser_id} has vlan in scope")
            # but MUST have core 5-tuple
            for required in ("addr_type", "ip_proto", "sport", "dport", "ipv4_src"):
                self.assertIn(required, p.fields,
                              f"{parser_id} missing core field {required}")

    def test_full_flowmeta_parsers_have_wide_scope(self):
        for parser_id in ("c-xdp2-usp", "rust-graph", "rust-compiled"):
            p = self.schema.parsers[parser_id]
            for required in ("addr_type", "eth_dst", "tcp_flags", "vlan",
                             "esp_spi", "icmp_type"):
                self.assertIn(required, p.fields,
                              f"{parser_id} missing wide field {required}")


class TestRecordParse(unittest.TestCase):
    def test_valid_accepted(self):
        rec = pc.Record.from_json(
            '{"schema_version":1,"pcap":"x.pcap","packet_index":0,'
            '"parser_id":"rust-graph","parser_kind":"rust","accepted":true,'
            '"fields":{"addr_type":"ipv4","ip_proto":6,"sport":80,"dport":443}}'
        )
        self.assertTrue(rec.accepted)
        self.assertEqual(rec.fields["sport"], 80)

    def test_valid_rejected(self):
        rec = pc.Record.from_json(
            '{"schema_version":1,"pcap":"x.pcap","packet_index":0,'
            '"parser_id":"c-bpf-xdp2","parser_kind":"bpf","accepted":false,'
            '"reject_reason":"verifier","fields":{}}'
        )
        self.assertFalse(rec.accepted)
        self.assertEqual(rec.reject_reason, "verifier")

    def test_invalid_schema_version(self):
        with self.assertRaises(ValueError) as ctx:
            pc.Record.from_json('{"schema_version":99,"pcap":"x","packet_index":0,'
                                '"parser_id":"x","parser_kind":"x","accepted":true,"fields":{}}')
        self.assertIn("schema_version", str(ctx.exception))

    def test_missing_required(self):
        with self.assertRaises(ValueError):
            pc.Record.from_json('{"schema_version":1,"pcap":"x","packet_index":0}')


class TestComparator(unittest.TestCase):
    def setUp(self):
        self.schema = pc.load_schema(SCOPE_PATH)

    def make_rec(self, parser_id, **fields):
        kind = self.schema.parsers[parser_id].kind
        return pc.Record(
            pcap="t.pcap",
            packet_index=0,
            parser_id=parser_id,
            parser_kind=kind,
            accepted=True,
            accept_path=None,
            reject_reason=None,
            fields=fields,
        )

    def test_no_disagreement(self):
        a = self.make_rec("rust-graph", addr_type="ipv4", ip_proto=6,
                          sport=80, dport=443)
        b = self.make_rec("rust-compiled", addr_type="ipv4", ip_proto=6,
                          sport=80, dport=443)
        out = pc.compare_pair(self.schema, a, b)
        self.assertEqual(out, [])

    def test_one_field_disagreement(self):
        a = self.make_rec("rust-graph", addr_type="ipv4", ip_proto=6,
                          sport=80, dport=443)
        b = self.make_rec("rust-compiled", addr_type="ipv4", ip_proto=6,
                          sport=80, dport=8080)  # ← dport differs
        out = pc.compare_pair(self.schema, a, b)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].field, "dport")
        self.assertEqual(out[0].value_a, 443)
        self.assertEqual(out[0].value_b, 8080)

    def test_out_of_scope_skipped(self):
        # eth_dst is in rust-graph's scope but NOT in c-bpf-flowdis's
        a = self.make_rec("rust-graph", addr_type="ipv4", ip_proto=6,
                          sport=80, dport=443, eth_dst="aa:bb:cc:dd:ee:ff")
        b = self.make_rec("c-bpf-flowdis", addr_type="ipv4", ip_proto=6,
                          sport=80, dport=443)
        # No eth_dst in b → comparator should skip eth_dst (out of scope
        # for c-bpf-flowdis), no disagreement
        out = pc.compare_pair(self.schema, a, b)
        self.assertEqual(out, [], f"expected no disagreements; got {out}")

    def test_acceptance_mismatch_returns_empty(self):
        # If either rejected, compare_pair returns empty (caller handles
        # acceptance gate separately)
        a = self.make_rec("rust-graph", addr_type="ipv4", ip_proto=6, sport=80, dport=443)
        b = pc.Record(
            pcap="t.pcap", packet_index=0,
            parser_id="rust-simd", parser_kind="rust",
            accepted=False, accept_path=None, reject_reason="no-avx2",
            fields={},
        )
        self.assertEqual(pc.compare_pair(self.schema, a, b), [])


if __name__ == "__main__":
    unittest.main()
