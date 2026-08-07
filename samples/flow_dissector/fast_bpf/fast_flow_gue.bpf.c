// SPDX-License-Identifier: GPL-2.0
//
// fast_flow_gue: UDP-tunnel inner-flow descent for GUE (Generic UDP
// Encapsulation, Tom Herbert's). Outer eth + IPv4/IPv6 + UDP at the
// configured GUE port + a version-0 GUE data header → descend to the
// inner IP 5-tuple. GUE is self-describing: guehdr.proto_ctype gives the
// inner IP protocol (IPIP → IPv4, IPV6 → IPv6).
//
// GUE has NO well-known UDP port — in-kernel the fou module's per-netns
// table maps a port to a GUE tunnel. A standalone BPF object can't reach
// that table, so the port is a load-time policy choice: set GUE_UDP_PORT
// to your deployment's port (default below is a placeholder). Mirrors
// series5-descent patch 04's flow_dissect_gue_inner_ok(); oracle is the
// descent-patched C dissector. Only version-0 data messages with no
// control/flags/options and an IPIP/IPv6 inner are handled. See
// kernel-patches/series6-common-case/ebpf-menu.md.
//

#include "fast_flow_inner.h"

#ifndef GUE_UDP_PORT
#define GUE_UDP_PORT	6080	/* policy: set to your GUE port */
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
	__u8 *u;
	__be16 ieth;

	if (nhoff > 128)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	udp_off = fast_outer_udp_off(data, data_end, nhoff, proto);
	if (udp_off < 0)
		return fast_dispatch_l3(skb, data, data_end, nhoff, proto);

	u = data + udp_off;

	/* Need udphdr(8) + guehdr(4) + the inner IP version nibble. */
	if ((void *)(u + 13) > data_end)
		goto outer;
	if (*(__be16 *)(u + 2) != bpf_htons(GUE_UDP_PORT))	/* dst port */
		goto outer;

	/* guehdr at u+8: byte0 = version(2)|control(1)|hlen(5); byte1 =
	 * proto_ctype; bytes2-3 = flags. Require version 0, no control, no
	 * options (hlen 0), no flags.
	 */
	if ((u[8] >> 6) != 0)			/* version != 0 */
		goto outer;
	if (u[8] & 0x20)			/* control message */
		goto outer;
	if (u[8] & 0x1f)			/* hlen != 0 (has options) */
		goto outer;
	if (u[10] || u[11])			/* flags != 0 */
		goto outer;

	if (u[9] == IPPROTO_IPIP)		/* proto_ctype */
		ieth = bpf_htons(ETH_P_IP);
	else if (u[9] == IPPROTO_IPV6)
		ieth = bpf_htons(ETH_P_IPV6);
	else
		goto outer;

	inner = udp_off + 12;			/* udp(8) + guehdr(4, hlen 0) */
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
