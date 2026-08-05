// SPDX-License-Identifier: GPL-2.0
//
// fast_flow_geneve: UDP-tunnel inner-flow descent for Geneve. Outer eth +
// IPv4/IPv6 + UDP dst port 6081 + a plain Geneve header (version 0, no
// options, not OAM, proto_type == ETH_P_TEB) + inner Ethernet → descend to
// the inner IP 5-tuple. Non-Geneve UDP (and outer TCP) keep the outer
// 5-tuple.
//
// Changes the hash for Geneve traffic (per-inner-flow fairness for cloud
// overlays) — a deliberate operator choice, so load it only where port
// 6081 is Geneve by policy. Mirrors series5-descent patch 02's
// flow_dissect_geneve_inner_ok(); oracle is the descent-patched C
// dissector. Geneve with TLV options (opt_len > 0) defers to the slow
// path. See kernel-patches/series6-common-case/ebpf-menu.md.
//

#include "fast_flow_inner.h"

#ifndef ETH_P_TEB
#define ETH_P_TEB 0x6558
#endif
#define GENEVE_UDP_PORT	6081

SEC("flow_dissector")
int _dissect(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 nhoff = keys->nhoff;
	__be16 proto = keys->n_proto;
	int udp_off, inner;
	__u8 *u;
	__be16 ieth;

	if (nhoff > 128)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	udp_off = fast_outer_udp_off(data, data_end, nhoff, proto);
	if (udp_off < 0)
		return fast_dispatch_l3(skb, data, data_end, nhoff, proto);

	u = data + udp_off;

	/* Need udphdr(8) + genevehdr(8) + inner ETH_HLEN(14). */
	if ((void *)(u + 30) > data_end)
		goto outer;
	if (*(__be16 *)(u + 2) != bpf_htons(GENEVE_UDP_PORT))	/* dst port */
		goto outer;

	/* genevehdr at u+8: byte0 = ver(2)|opt_len(6); byte1 bit7 = OAM;
	 * proto_type at u+10. Require ver 0, no options, not OAM, TEB.
	 */
	if ((u[8] >> 6) != 0)			/* version != 0 */
		goto outer;
	if ((u[8] & 0x3f) != 0)			/* opt_len != 0 (has TLVs) */
		goto outer;
	if (u[9] & 0x80)			/* OAM frame */
		goto outer;
	if (*(__be16 *)(u + 10) != bpf_htons(ETH_P_TEB))	/* proto_type */
		goto outer;

	/* inner Ethernet h_proto at udp + 8(udp) + 8(geneve) + 12 */
	ieth = *(__be16 *)(u + 28);
	if (ieth != bpf_htons(ETH_P_IP) && ieth != bpf_htons(ETH_P_IPV6))
		goto outer;

	inner = udp_off + 30;			/* udp + geneve + inner eth */
	if (inner > 128)
		goto outer;

	keys->is_encap = 1;
	keys->nhoff = inner;
	keys->n_proto = ieth;
	return fast_dispatch_l3(skb, data, data_end, inner, ieth);

outer:
	return fast_dispatch_l3(skb, data, data_end, nhoff, proto);
}

char _license[] SEC("license") = "GPL";
