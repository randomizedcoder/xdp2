# Does WireGuard exercise the flow dissector? (yes — heavily)

**Date**: 2026-06-25
**Question**: WireGuard is hugely popular; does its traffic go through the
kernel flow dissector, so the series-3 fast-path helps it?

## Short answer

**Yes — WireGuard traffic drives the flow dissector roughly once per
packet, and every call is the `eth_ip` shape the fast-path optimises.**
The dominant caller is the **qdisc (cake/fq)** classifying the encrypted
WireGuard *transport* packets (eth + IP + UDP) — exactly the QoS path
series-3 targets, and ubiquitous on real WireGuard servers/gateways.

## Evidence

### 1. Source (net-next): WireGuard forces a dissect on the inner packet

`drivers/net/wireguard/send.c`, `encrypt_packet()`:

```c
/* Force hash calculation before encryption so that flow analysis is
 * consistent over the inner packet. */
skb_get_hash(skb);
```

So WireGuard deliberately calls `skb_get_hash()` on the plaintext inner
packet before encryption. The inner on an L3 `wg0` tunnel is bare IP
(`skb->protocol = ETH_P_IP/IPV6`) → the eth_ip fast-path shape. (For
*locally-generated* TCP the inner skb hash is often already socket-cached,
so this particular call may return cached; the qdisc path below dominates
regardless, and *forwarded* traffic — the gateway case — is not cached.)

### 2. Empirical: bpftrace on a live WireGuard sender (pi5-2, Cortex-A76)

Tunnel pi5-2 ↔ pi4-1, `iperf3` over `wg0` at **902 Mbit/s** (1 GbE),
`cake` qdisc on the physical egress (`end0`). `kprobe:__skb_flow_dissect`:

- **1,111,528 dissector calls in 10 s** (~110 k/s, ≈ once per wire packet)
  for a single 902 Mbit/s flow. The dissector is **not** cached away.

Stack attribution (`kstack`, 6 s flow) — who calls it:

| call path | dissects | what |
|---|---:|---|
| `cake_enqueue` → `dev_qdisc_enqueue` → `__dev_queue_xmit` | 493,218 | **cake qdisc** classifying the outer encrypted UDP on TX |
| `tcf_classify` → `tc_run` | 85,453 | tc classifier on TX |
| `get_rps_cpu` → `napi_complete_done` | 66,841 | RPS steering on RX |
| `get_rps_cpu` → `gro_receive_skb` | 18,656 | RPS/GRO on RX |

All of these dissect **eth + IP + UDP** (the WireGuard transport) or bare
IP (the inner) — i.e. the **eth_ip fast-path shape**.

### 3. Per-call saving = the eth_ip microbench

Every one of those calls is the shape measured in
`../2026-06-25-series3-allshapes-microbench/`: eth_ip fast-path is
**~−47% (x86) to ~−50% (ARM/RISC-V)** of dissector cost. So on a busy
WireGuard server/gateway running cake/fq, the fast-path halves the
per-packet dissector cost across 100% of traffic.

## Honest caveats

- **The dissector is a small fraction of WireGuard's per-packet cost** —
  ChaCha20-Poly1305 dominates (hundreds of ns–µs/pkt). Halving a
  ~10–100 ns dissect is real but is not a 50% WireGuard-throughput win.
- **Macro CPU A/B at 1 GbE is below noise**: toggling
  `net.flow_dissector.eth_ip` on the sender during the 902 Mbit/s flow
  showed no clean softirq/sys delta — the per-call saving is small
  relative to crypto and spread across cores, and 1 GbE doesn't saturate
  the CPU. The win is per-packet and scales with pps: it matters on a
  10/25/40 GbE WireGuard concentrator pushing Mpps through cake/fq, where
  the dissector is called millions of times per second.
- **Where it clearly helps**: WireGuard servers/gateways doing software
  QoS (cake/fq — extremely common) or RPS without hardware rxhash. That
  is precisely the consumer scenario series-3 was built around.

## Bottom line for the cover letter

WireGuard's encrypted transport is the eth_ip shape, and real WireGuard
deployments run it through cake/fq, which calls the flow dissector on
**every** packet (measured: ~1.1 M calls for a single 902 Mbit/s flow).
The series-3 fast-path applies directly and cuts that ~50% on x86, ARM,
and RISC-V — a per-packet saving across the entire (and very large)
WireGuard install base, most visibly on high-pps concentrators.
