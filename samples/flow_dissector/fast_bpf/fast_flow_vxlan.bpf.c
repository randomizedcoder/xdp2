// SPDX-License-Identifier: GPL-2.0
//
// fast_flow_vxlan: UDP-tunnel inner-flow descent for VXLAN (RFC 7348).
// Outer eth + IPv4/IPv6 + UDP dst port 4789 + a plain VXLAN header
// (I flag set, all other flag bits zero) + inner Ethernet → descend to
// the inner IP 5-tuple. Non-VXLAN UDP (and outer TCP) keep the outer
// 5-tuple.
//
// This DELIBERATELY CHANGES the hash for VXLAN traffic — the whole point:
// without descent, every inner flow between two VTEPs collapses onto the
// outer 5-tuple, so RSS/RPS/fq/cake pin them to one bucket and east-west
// overlay traffic reorders under load. Load this object on a netns where
// port 4789 is VXLAN by policy. Mirrors series5-descent patch 01's
// flow_dissect_vxlan_inner_ok(); its oracle is the descent-patched C
// dissector (the in-tree BPF dissector does not descend UDP tunnels).
// See kernel-patches/series6-common-case/ebpf-menu.md.
//

#include "fast_flow_inner.h"

#ifndef ETH_P_TEB
#define ETH_P_TEB 0x6558
#endif
#define VXLAN_UDP_PORT	4789
#define VXLAN_HF_VNI	0x08000000u	/* I flag set, all other bits zero */

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

	/* Need udphdr(8) + vxlanhdr(8) + inner ETH_HLEN(14). */
	if ((void *)(u + 30) > data_end)
		goto outer;
	if (*(__be16 *)(u + 2) != bpf_htons(VXLAN_UDP_PORT))	/* dst port */
		goto outer;
	if (*(__be32 *)(u + 8) != bpf_htonl(VXLAN_HF_VNI))	/* vx_flags */
		goto outer;

	/* inner Ethernet h_proto is at udp + 8(udp) + 8(vxlan) + 12 */
	ieth = *(__be16 *)(u + 28);
	if (ieth != bpf_htons(ETH_P_IP) && ieth != bpf_htons(ETH_P_IPV6))
		goto outer;

	inner = udp_off + 30;			/* udp + vxlan + inner eth */
	if (inner > 128)
		goto outer;

	keys->is_encap = 1;
	keys->nhoff = inner;
	keys->n_proto = ieth;
	return fast_dispatch_l3(skb, data, data_end, inner, ieth);

outer:
	/* Outer UDP but not a descendable VXLAN packet → outer 5-tuple. */
	return fast_dispatch_l3(skb, data, data_end, nhoff, proto);
}

char _license[] SEC("license") = "GPL";
