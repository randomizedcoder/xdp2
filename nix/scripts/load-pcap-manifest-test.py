#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
"""Unit tests for load-pcap-manifest.py."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "load-pcap-manifest.py"
MANIFEST = HERE.parents[1] / "data/pcap-manifest.toml"

# Load the script as a module so we can call its helpers directly
# (it has a hyphenated filename so plain `import` won't work).
spec = importlib.util.spec_from_file_location("loader", SCRIPT)
loader = importlib.util.module_from_spec(spec)
sys.modules["loader"] = loader
spec.loader.exec_module(loader)


class TestManifest(unittest.TestCase):
    """Exercises against the in-repo manifest."""

    def setUp(self):
        self.raw = loader.load(MANIFEST)
        self.entries = loader.entries(self.raw)

    def test_schema_version(self):
        self.assertEqual(self.raw["schema_version"], 1)

    def test_every_entry_has_path_and_category(self):
        for e in self.entries:
            self.assertIn("path", e, f"{e['key']}: missing path")
            self.assertIn("category", e, f"{e['key']}: missing category")

    def test_every_entry_is_in_or_excluded(self):
        for e in self.entries:
            has_inc = bool(e.get("included_in"))
            has_exc = bool(e.get("excluded_from"))
            self.assertTrue(
                has_inc or has_exc,
                f"{e['key']}: declares neither included_in nor excluded_from"
            )

    def test_every_excluded_entry_has_reason(self):
        for e in self.entries:
            if e.get("excluded_from"):
                self.assertIn(
                    "excluded_reason", e,
                    f"{e['key']}: excluded_from set but no excluded_reason"
                )

    def test_parity_gate_count(self):
        # Today's parity-gate corpus is exactly 22 pcaps. Changes to
        # this count are a contract change that should be reviewed.
        inc = loader.included(self.entries, "parity_gate")
        self.assertEqual(
            len(inc), 22,
            f"parity_gate count drifted: {len(inc)} != 22. "
            "Update this test only if intentionally changing the gate."
        )


class TestManifestCli(unittest.TestCase):
    def test_validate_passes(self):
        cp = subprocess.run(
            [sys.executable, str(SCRIPT), "--validate"],
            capture_output=True, text=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)

    def test_gate_emits_one_path_per_line(self):
        cp = subprocess.run(
            [sys.executable, str(SCRIPT), "--gate", "parity_gate"],
            capture_output=True, text=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        lines = [l for l in cp.stdout.splitlines() if l]
        self.assertEqual(len(lines), 22)
        for l in lines:
            self.assertTrue(l.endswith(".pcap"), l)

    def test_json_round_trip(self):
        cp = subprocess.run(
            [sys.executable, str(SCRIPT), "--gate", "parity_gate", "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        rows = json.loads(cp.stdout)
        self.assertEqual(len(rows), 22)
        self.assertTrue(all("key" in r and "path" in r for r in rows))

    def test_validate_fails_on_missing_path(self):
        # Synthesize a tiny manifest with a bogus path; --validate
        # should exit non-zero.
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            m = td / "manifest.toml"
            m.write_text(
                'schema_version = 1\n'
                '[pcap.bogus]\n'
                'path = "data/pcaps/does-not-exist.pcap"\n'
                'category = "test"\n'
                'included_in = ["parity_gate"]\n'
            )
            (td / "data" / "pcaps").mkdir(parents=True)
            cp = subprocess.run(
                [sys.executable, str(SCRIPT), "--manifest", str(m),
                 "--repo-root", str(td), "--validate"],
                capture_output=True, text=True,
            )
            self.assertNotEqual(cp.returncode, 0)
            self.assertIn("missing", cp.stderr)


if __name__ == "__main__":
    unittest.main()
