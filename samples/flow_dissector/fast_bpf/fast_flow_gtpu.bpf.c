// SPDX-License-Identifier: GPL-2.0
//
// fast_flow_gtpu: UDP-tunnel inner-flow descent for GTP-U (mobile core).
// Outer eth + IPv4/IPv6 + UDP dst port 2152 + a GTPv1 G-PDU header
// (version 1, PT=1, no optional flags, type=0xFF) → descend directly to
// the inner IP 5-tuple (GTP-U carries no inner Ethernet). Non-GTP-U UDP
// (and outer TCP) keep the outer 5-tuple.
//
// This is the sharpest descent case: GTP-U has no outer source-port
// entropy, so on the mobile-core data path millions of subscriber flows
// ride one tunnel between two endpoints and collapse onto a single hash
// bucket without descent. Load this where port 2152 is GTP-U by policy.
// Mirrors series5-descent patch 03's flow_dissect_gtpu_inner_ok(); oracle
// is the descent-patched C dissector. GTPv0/GTP'/extension-header/N-PDU/
// sequence variants defer to the slow path. See
// kernel-patches/series6-common-case/ebpf-menu.md.
//

#include "fast_flow_inner.h"

#define GTP1U_PORT	2152
#define GTP_TPDU	0xff	/* G-PDU message type */

SEC("flow_dissector")
int _dissect(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 nhoff = keys->nhoff;
	__be16 proto = keys->n_proto;
	int udp_off, inner;
	__u8 *u, *ipver;
	__be16 ieth;

	if (nhoff > 128)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	udp_off = fast_outer_udp_off(data, data_end, nhoff, proto);
	if (udp_off < 0)
		return fast_dispatch_l3(skb, data, data_end, nhoff, proto);

	u = data + udp_off;

	/* Need udphdr(8) + gtp1_header(8) + at least the inner IP version. */
	if ((void *)(u + 17) > data_end)
		goto outer;
	if (*(__be16 *)(u + 2) != bpf_htons(GTP1U_PORT))	/* dst port */
		goto outer;

	/* gtp1_header at u+8: byte0 = flags (version<<5 | PT<<4 | E|S|PN),
	 * byte1 = message type. Require GTPv1, PT=1, no optional flags,
	 * type = G-PDU.
	 */
	if (((u[8] >> 5) & 0x7) != 1)		/* version != 1 */
		goto outer;
	if (!(u[8] & 0x10))			/* PT bit clear (GTP') */
		goto outer;
	if (u[8] & 0x07)			/* E/S/PN optional flags set */
		goto outer;
	if (u[9] != GTP_TPDU)			/* not a G-PDU */
		goto outer;

	inner = udp_off + 16;			/* udp(8) + gtp1(8), no inner eth */
	if (inner > 128)
		goto outer;

	/* GTP-U carries no ethertype — infer inner IP version. */
	ipver = data + inner;
	if ((void *)(ipver + 1) > data_end)
		goto outer;
	if ((*ipver >> 4) == 4)
		ieth = bpf_htons(ETH_P_IP);
	else if ((*ipver >> 4) == 6)
		ieth = bpf_htons(ETH_P_IPV6);
	else
		goto outer;

	keys->is_encap = 1;
	keys->nhoff = inner;
	keys->n_proto = ieth;
	return fast_dispatch_l3(skb, data, data_end, inner, ieth);

outer:
	return fast_dispatch_l3(skb, data, data_end, nhoff, proto);
}

char _license[] SEC("license") = "GPL";
