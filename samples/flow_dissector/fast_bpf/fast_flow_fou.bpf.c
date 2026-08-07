// SPDX-License-Identifier: GPL-2.0
//
// fast_flow_fou: UDP-tunnel inner-flow descent for direct Foo-over-UDP
// (FOU). Outer eth + IPv4/IPv6 + UDP at the configured FOU port → the UDP
// payload IS the inner packet (no encapsulation header) → descend to the
// inner IP 5-tuple.
//
// Direct FOU is bare and **the inner protocol is not on the wire** — in
// kernel it comes from the fou module's per-netns port→protocol table. A
// standalone BPF object can't reach that table, so this object (a) takes
// the port as a load-time policy choice (set FOU_UDP_PORT to your FOU
// port) and (b) handles the common case where FOU carries IP by inferring
// the inner IP version from the first nibble (as GTP-U does). A FOU tunnel
// carrying a non-IP inner protocol is not fast-pathed here. Mirrors
// series5-descent patch 04's flow_dissect_fou_inner_ok() (inner right
// after UDP); oracle is the descent-patched C dissector. See
// kernel-patches/series6-common-case/ebpf-menu.md.
//

#include "fast_flow_inner.h"

#ifndef FOU_UDP_PORT
#define FOU_UDP_PORT	5555	/* policy: set to your FOU port */
#endif

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

	/* Need udphdr(8) + the inner IP version nibble. */
	if ((void *)(u + 9) > data_end)
		goto outer;
	if (*(__be16 *)(u + 2) != bpf_htons(FOU_UDP_PORT))	/* dst port */
		goto outer;

	inner = udp_off + 8;			/* bare: inner IP right after UDP */
	if (inner > 128)
		goto outer;

	/* Inner protocol not on the wire — infer IP version from the nibble. */
	ipver = u + 8;
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
