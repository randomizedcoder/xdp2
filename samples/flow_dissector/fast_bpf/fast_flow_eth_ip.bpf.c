// SPDX-License-Identifier: GPL-2.0
//
// fast_flow_eth_ip: the base object of the per-encapsulation
// xdp2-flow-ebpf menu — plain eth + IPv4/IPv6 + {TCP,UDP,ICMP}, no
// encapsulation. This is the common inner every other menu object also
// carries; loaded on its own it fast-paths untagged IP traffic and
// returns BPF_FLOW_DISSECTOR_CONTINUE for everything else.
//
// The inner extractors + jmp_table live in fast_flow_inner.h, shared
// verbatim by every fast_flow_<encap>.bpf.c so the 5-tuple logic has a
// single source of truth. See kernel-patches/series6-common-case/
// ebpf-menu.md.
//
// Portability: Linux >= 5.1 (BPF_FLOW_DISSECTOR_CONTINUE), libbpf >= 0.7
// (bpf_tail_call_static). See fast_flow.bpf.c for the CO-RE rationale.
//

#include "fast_flow_inner.h"

/* ─── Entry: plain-IP signature match + tail-call dispatch ──────────────
 *
 * The kernel (or BPF_PROG_TEST_RUN) pre-sets keys->n_proto from the
 * Ethernet header and keys->nhoff = ETH_HLEN before calling us, so we
 * begin at L3. Fast-path gate for IPv4: IHL=5 (no options) AND no
 * fragmentation. IPv6: no extension headers (nexthdr is a fast-path L4).
 * Anything else -> slow path.
 */
SEC("flow_dissector")
int _dissect(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 nhoff = keys->nhoff;

	/* Bound nhoff so the verifier can prove data + nhoff + sizeof(hdr)
	 * stays in-bounds inside the dispatcher. */
	if (nhoff > 128)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	/* No encapsulation to unwrap: keys->nhoff already at L3, n_proto is
	 * the L3 ethertype. Straight to the shared inner dispatch. */
	return fast_dispatch_l3(skb, data, data_end, nhoff, keys->n_proto);
}

char _license[] SEC("license") = "GPL";
