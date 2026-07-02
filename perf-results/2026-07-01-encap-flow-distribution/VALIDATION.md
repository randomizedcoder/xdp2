# Validation: inner-stripped method == real descent output

The flow-distribution study computes the "inner-descent" hash by feeding the
**inner frame alone** (`*.inner.pcap`) to the unmodified userspace dissector.
This is only valid if that equals what the actual kernel inner-descent patch
produces. This note argues the equivalence and validates it at runtime.

## The equivalence argument

The kernel `vxlan_inner` descent, on a matching packet:
1. sets `key_control->flags |= FLOW_DIS_ENCAPSULATION`, and
2. dispatches the **inner** Eth/IP/L4 into the fast-path, which overwrites
   `key_basic` (n_proto, ip_proto), `key_addrs` (inner src/dst), and `key_ports`
   (inner sport/dport) with the inner-flow values.

`flow_hash_from_keys()` hashes exactly `basic + addrs + ports` (the consumer
audit, `../2026-05-23-flow-keys-consumer-audit/findings.md`, confirms these are
the CL0 fields; `FLOW_DIS_ENCAPSULATION` and any tunnel keyid are **not** in the
hashed region for the standard `flow_keys_dissector`). Dissecting the inner frame
standalone produces the same `basic/addrs/ports`. Therefore
`flow_hash_from_keys(descent) == flow_hash_from_keys(inner-frame)`.

## Runtime validation

A **compile-gated** VXLAN descent was added to
`src/lib/flowdis/flow_dissector.c` (`#ifdef FLOWDIS_INNER_DESCENT`, `case
IPPROTO_UDP` matching dport 4789 → descend into inner Ethernet). The default
build is unchanged (byte-identical to mainline); the flag turns on real descent
in the same dissector that computes the real hash.

Build + run:
```sh
nix develop --command bash -c '
  export CFLAGS="-DFLOWDIS_INNER_DESCENT"
  make -C src/lib/flowdis && make -C src/test/parser'
# descent build on the OVERLAY pcap vs the unmodified build on the INNER pcap:
test_parser -i pcap,pcaps/vxlan-fixedsport.pcap       -c flowdis -o text -H  # descent
test_parser -i pcap,pcaps/vxlan-fixedsport.inner.pcap -c flowdis -o text -H  # stripped
# the two hash= streams must be identical.
```

## Result — PASS (2026-07-01)

Built `test_parser` with the descent enabled (`CPATH=$PWD/src/include`, the local
`config.mk` being stale) and compared, per packet:
- descent build on the **overlay** pcap (descent fires), vs
- the build on the **inner-stripped** pcap.

```
vxlan-fixedsport   : 20000/20000 packets, hash streams IDENTICAL  ✓
vxlan-kernelsport  : 20000/20000 packets, hash streams IDENTICAL  ✓
```

The real descent produces **byte-identical flow hashes** to dissecting the inner
frame standalone — the inner-stripped method used throughout this study is exact.
VXLAN is the representative case; Geneve descent is structurally identical (inner
Ethernet), and GTP-U differs only in carrying a naked inner IP (no inner
Ethernet). The descent code is retained compile-gated (`FLOWDIS_INNER_DESCENT`,
off by default → the normal build is byte-identical to mainline) so this check is
re-runnable.

Note: the earlier `siphash/siphash.h not found` build error was a stale-config.mk
include-path issue affecting the *unmodified* file too (it aborts at line 77,
before the descent code at ~line 1834); `CPATH=$PWD/src/include` resolves it.
