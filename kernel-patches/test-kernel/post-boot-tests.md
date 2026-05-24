# Post-boot validation tests on hp5

To run after the patched kernel (`7.1.0-rc4-flowdis-pppoe`) is
running on hp5.

## 0. Sanity check that the new kernel is running

```bash
ssh root@hp5 'uname -r'
# Expected: 7.1.0-rc4-flowdis-pppoe (or close — the suffix
#          encodes our local version tag)

ssh root@hp5 'grep flow_hash_from_keys_small /proc/kallsyms'
# Expected: lines for flow_hash_from_keys_small and _seed variant
```

If `uname -r` still shows 7.0.1, the reboot didn't pick up the new
generation — either the GRUB selection went to the old one, or
nixos-rebuild boot didn't activate as expected.

## 1. Series 1 — sch_cake selftests (TC)

```bash
# Copy the tc-testing harness from the source tree to a working dir
ssh root@hp5 'mkdir -p /tmp/tc-test && \
  rsync -a /tmp/net-next-build/tools/testing/selftests/tc-testing/ \
            /tmp/tc-test/'

# Run the cake.json selftest
ssh root@hp5 'cd /tmp/tc-test && \
  python3 tdc.py -e -f tc-tests/qdiscs/cake.json 2>&1 | tail -30'

# Run the cake_mq.json selftest (multi-queue cake — added with the
# 2026 cake_mq merge)
ssh root@hp5 'cd /tmp/tc-test && \
  python3 tdc.py -e -f tc-tests/qdiscs/cake_mq.json 2>&1 | tail -30'
```

**Expected**: all tests pass. Both files exercise cake's user-visible
behavior (qdisc add/del/change, parameter validation). Our patch
doesn't change user-visible behavior, so they should pass identically
to the unpatched kernel baseline.

## 2. Series 2 — BPF flow_dissector verifier load test

We already validated this on hp5's running 7.0.1 kernel
(2026-05-23). Repeating on the patched 7.1.0-rc4 kernel:

```bash
ssh root@hp5 '
  # Build the patched bpf_flow.bpf.o (if not already from the
  # combined build)
  cd ~/xdp2 && nix develop --command bash -c "
    clang -target bpf -O2 -g -Wall \
      -I /tmp/net-next-build/tools/testing/selftests/bpf \
      -I /tmp/net-next-build/tools/testing/selftests/bpf/tools/include \
      -I /tmp/net-next-build/tools/include \
      -I /tmp/net-next-build/tools/include/uapi \
      -c /tmp/net-next-build/tools/testing/selftests/bpf/progs/bpf_flow.c \
      -o /tmp/bpf_flow.bpf.o
  "

  # Load all programs into the patched-kernel BPF subsystem
  rm -rf /sys/fs/bpf/test_flow_v2 2>/dev/null
  mkdir -p /sys/fs/bpf/test_flow_v2
  bpftool prog loadall /tmp/bpf_flow.bpf.o /sys/fs/bpf/test_flow_v2 \
    type flow_dissector
  ls /sys/fs/bpf/test_flow_v2/
  # Expected: _dissect, flow_dissector_0 through flow_dissector_6
  # (flow_dissector_6 is PROG(PPPOE))

  # Cleanup
  for p in /sys/fs/bpf/test_flow_v2/*; do bpftool prog unpin "$p" 2>/dev/null; done
  rmdir /sys/fs/bpf/test_flow_v2 2>/dev/null
'
```

**Expected**: 7 sub-programs loaded successfully. BPF verifier accepts
PROG(PPPOE). No errors.

## 3. Functional sch_cake test (real interface)

Set up a cake qdisc on a dummy interface, push traffic through it,
verify host-load accounting still works:

```bash
ssh root@hp5 '
  # Create a dummy interface for the test
  ip link add testcake0 type dummy 2>/dev/null
  ip link set testcake0 up

  # Apply cake qdisc with the dual-source-host flow mode
  # (this is the mode that uses host_keys hashes — patch 3 target)
  tc qdisc replace dev testcake0 root cake \
    bandwidth 100mbit \
    flowblind                    # disable host accounting; baseline
  tc qdisc show dev testcake0

  # Now enable triple-isolate (uses dsthost_hash + srchost_hash)
  tc qdisc replace dev testcake0 root cake \
    bandwidth 100mbit \
    triple-isolate
  tc qdisc show dev testcake0
  tc -s qdisc show dev testcake0   # should show queue stats

  # Inject some traffic via packet-gen to exercise the hash path
  # (10k packets, multiple flow tuples)
  modprobe pktgen
  # ... pktgen config ... (skip for now if pktgen not set up)

  # Cleanup
  tc qdisc del dev testcake0 root
  ip link del testcake0
'
```

**Expected**: cake qdisc accepts triple-isolate mode (which exercises
host_keys hashing). `tc -s qdisc show` reports sensible stats. No
kernel oops, no warnings in dmesg.

## 4. dmesg sanity check

```bash
ssh root@hp5 'dmesg -t | grep -iE "WARN|BUG|oops|trace|RIP" | head -20'
```

**Expected**: no new warnings since boot related to flow_dissector,
sch_cake, or bpf_flow.

## 5. Document the results

Append to `kernel-patches/test-kernel/runtime-validation.md` (to be
created from the test outputs):

- uname -r output
- /proc/kallsyms confirmation of patched symbols
- cake.json + cake_mq.json result (pass/fail count + any FAILED lines)
- bpftool prog loadall output
- functional sch_cake test outcome
- dmesg sanity check

This becomes the "runtime validated on hp5 (Zen 1)" evidence we cite
in both series' cover letters.

## After tests: restore baseline kernel

Once the tests are complete and the results captured:

```bash
# On workstation: revert the configuration.nix diff (restore
# pkgs.linuxPackages_latest)
cd /home/das/nixos/hp/hp5
$EDITOR configuration.nix    # restore the original kernelPackages line

# Sync + rebuild
make sync
ssh root@hp5 'cd /home/das/nixos/hp/hp5 && sudo nixos-rebuild boot --flake .'

# User-triggered reboot (your call)
# ssh root@hp5 reboot
```

After reboot, hp5 is back on `pkgs.linuxPackages_latest` (7.0.1 or
whatever nixpkgs ships as latest by then).
