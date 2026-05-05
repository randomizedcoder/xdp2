# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# afxdp-live-smoke — Phase 8 wiring check.
#
# Pure-Nix `runCommand` that builds flow-dissector-afxdp-live and
# asserts:
#   1. `--help` exits 0 with the documented flag set.
#   2. Missing `--testbed` errors with a clear message.
#   3. Bogus `--testbed` path errors before any orchestration.
#   4. Bogus `--duration` / `--loads` values are rejected.
#   5. A testbed missing a generator host fails with the documented
#      "no host with role='generator'" message.
#
# This is a wiring check, not a behavioral one. Live AF_XDP
# orchestration requires hardware and is exercised in a hardware
# session.

{ pkgs, lib, afxdpLive }:

pkgs.runCommand "afxdp-live-smoke"
{
  nativeBuildInputs = [ afxdpLive pkgs.gnugrep pkgs.coreutils ];
} ''
  set -eu

  # --- --help ----------------------------------------------------
  flow-dissector-afxdp-live --help > help.txt
  for flag in '--testbed' '--duration' '--loads' '--results' '--help'; do
    grep -q -- "$flag" help.txt \
      || { echo "afxdp-live --help missing $flag"; cat help.txt; exit 1; }
  done

  # --- missing --testbed ----------------------------------------
  if flow-dissector-afxdp-live > miss.out 2> miss.err; then
    echo "afxdp-live with no args should have failed"; exit 1
  fi
  grep -q -- '--testbed is required' miss.err \
    || { echo "missing-testbed message wrong"; cat miss.err; exit 1; }

  # --- bogus testbed path ---------------------------------------
  if flow-dissector-afxdp-live --testbed /no/such/file.toml \
       > bad.out 2> bad.err; then
    echo "afxdp-live with bogus testbed should have failed"; exit 1
  fi
  grep -q 'testbed file not found' bad.err \
    || { echo "bad-path message wrong"; cat bad.err; exit 1; }

  # --- duration validation --------------------------------------
  cat > tb-good.toml <<'TOML'
  [testbed]
  name = "tb-good"

  [[hosts]]
  role = "dut"
  hostname = "d1"

  [[hosts]]
  role = "generator"
  hostname = "g1"

  [nic]
  driver = "i40e"
  dut_iface = "enp1s0f0"
  gen_iface = "enp1s0f1"
  link_speed_gbps = 10
  TOML

  if flow-dissector-afxdp-live --testbed tb-good.toml --duration foo \
       > dur.out 2> dur.err; then
    echo "afxdp-live with non-integer duration should have failed"; exit 1
  fi
  grep -q -- '--duration must be a positive integer' dur.err \
    || { echo "bad-duration message wrong"; cat dur.err; exit 1; }

  if flow-dissector-afxdp-live --testbed tb-good.toml --duration 0 \
       > dur0.out 2> dur0.err; then
    echo "afxdp-live with --duration 0 should have failed"; exit 1
  fi
  grep -q -- '--duration must be > 0' dur0.err \
    || { echo "duration-zero message wrong"; cat dur0.err; exit 1; }

  # --- loads validation -----------------------------------------
  if flow-dissector-afxdp-live --testbed tb-good.toml --loads "1,abc,5" \
       > loads.out 2> loads.err; then
    echo "afxdp-live with bad loads should have failed"; exit 1
  fi
  grep -q -- '--loads must be a comma-separated list of positive integers' loads.err \
    || { echo "bad-loads message wrong"; cat loads.err; exit 1; }

  # --- testbed missing generator --------------------------------
  cat > tb-no-gen.toml <<'TOML'
  [testbed]
  name = "tb-no-gen"

  [[hosts]]
  role = "dut"
  hostname = "d1"

  [nic]
  driver = "i40e"
  dut_iface = "enp1s0f0"
  link_speed_gbps = 10
  TOML

  if flow-dissector-afxdp-live --testbed tb-no-gen.toml \
       > nogen.out 2> nogen.err; then
    echo "afxdp-live without generator should have failed"; exit 1
  fi
  grep -q "no host with role='generator'" nogen.err \
    || { echo "missing-generator message wrong"; cat nogen.err; exit 1; }

  echo ok > $out
''
