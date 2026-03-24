[Back to Summary](../SUMMARY.md)

## Correctness Methodology

The benchmark compares flowdis and xdp2 on every packet, classifying results
into three categories:

- **Match**: All fields agree (addr_type, ip_proto, addresses, ports, flow_label,
  fragment flags, ARP/TIPC fields, GRE keyid)
- **Mismatch**: Any field disagrees — indicates a parser bug
- **Tunnel extended**: Flowdis sees outer UDP to port 4789 (VXLAN) or 6081
  (Geneve), while xdp2 follows the tunnel and extracts inner flow keys. This is
  not a bug — it demonstrates xdp2's extended tunnel-following capability.
- **XDP2 only**: Protocols that xdp2 parses successfully but flowdis does not
  support. After the multi-graph expansion, this includes ~30 protocols:
  LLDP, STP, PBB, TRILL, HSR/PRP, NSH, CFM, EtherCAT, PROFINET, AoE, NC-SI,
  CAN, CAN FD, CAN XL, Phonet, IEEE 802.15.4, ATM MPOA, IPX, AppleTalk,
  X.25, DSA, EDSA, RoCE v1/v2 (IBoE/BTH), and others. These are not
  mismatches — they demonstrate xdp2's broader protocol coverage. The Nix test
  suite (test 25d) explicitly verifies that xdp2-only protocols are detected
  in combinatorial PCAPs.

### Flowdis AH/ESP/L2TP Fixes

The flowdis userspace port (`libflowdis`) lacked handlers for three IPsec/L2TP
protocols. Without handlers, `__skb_flow_dissect_ports()` would read garbage
bytes from these headers as ports:

| Protocol | Fix | Effect |
|---|---|---|
| AH (proto 51) | Chain through AH header to inner proto | Correct inner ports extracted |
| ESP (proto 50) | Leaf handler, skip port extraction | No garbage SPI-as-ports |
| L2TP (proto 115) | Leaf handler, skip port extraction | No garbage session_id-as-ports |

Port comparison is also skipped when `ip_proto` is ESP or L2TP, since flowdis
may have residual port bytes from AH→ESP/L2TP chaining while xdp2 correctly
reports zero ports for these leaf protocols.

### Comparison Skip Rules

Two additional skip rules handle cases where xdp2 extracts data that flowdis
does not:

- **First-fragment ports:** When `is_first_frag` and flowdis reports ports
  `0:0`, skip port comparison. xdp2 extracts actual ports from the first
  fragment; flowdis returns zeroes.
- **TIPC keys behind encapsulation:** When flowdis reports TIPC key `0x0`,
  skip TIPC key comparison. Flowdis does not extract TIPC keys behind some
  encapsulations (VLAN, PPPoE), while xdp2 extracts the actual key.

These are not bugs in either parser -- they are cases where xdp2 provides
strictly more information than flowdis.

### Keyid Comparison

The benchmark registers `FLOW_DISSECTOR_KEY_GRE_KEYID` with flowdis to extract
GRE key values. Keyid comparison is only performed when both parsers extracted a
non-zero keyid (GRE with key bit set). For ESP SPI and L2TP session_id, xdp2
extracts the keyid but flowdis does not (leaf handlers skip extraction), so
these are not compared.
