// SPDX-License-Identifier: GPL-2.0
//
// fast_flow_pppoe: per-encapsulation menu object for PPPoE session
// packets (ETH_P_PPP_SES) carrying IPv4/IPv6, descending to the inner IP
// 5-tuple, plus the plain-IP inner.
//
// The in-tree BPF dissector has no PPPoE case and DROPS such packets; this
// object closes that gap. Its parity oracle is therefore the
// series2-patched bpf_flow.kern.o (kernel-patches/series2-bpf-pppoe/),
// which adds the matching PPPoE arm. The PPP-protocol mapping
// (PPP_IP -> IPv4, PPP_IPV6 -> IPv6) mirrors series2 and the kernel C
// dissector's is_pppoe_ses_hdr_valid(). See
// kernel-patches/series6-common-case/ebpf-menu.md.
//

#include "fast_flow_inner.h"

#ifndef ETH_P_PPP_SES
#define ETH_P_PPP_SES 0x8864
#endif

#define PPP_IP		0x0021	/* PPP protocol: IPv4 */
#define PPP_IPV6	0x0057	/* PPP protocol: IPv6 */
#define PPPOE_SES_HLEN	8	/* 6-byte PPPoE session hdr + 2-byte PPP proto */

SEC("flow_dissector")
int _dissect(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 nhoff = keys->nhoff;
	__be16 proto = keys->n_proto;

	if (nhoff > 128)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	if (proto == bpf_htons(ETH_P_PPP_SES)) {
		__u8 *hdr = data + nhoff;

		if ((void *)(hdr + PPPOE_SES_HLEN) > data_end)
			return BPF_FLOW_DISSECTOR_CONTINUE;

		/* Validate the PPPoE session header: ver=1, type=1, code=0
		 * (hdr[0]=0x11, hdr[1]=0x00) — mirrors is_pppoe_ses_hdr_valid()
		 * and series2. */
		if (hdr[0] != 0x11 || hdr[1] != 0x00)
			return BPF_FLOW_DISSECTOR_CONTINUE;

		/* PPP protocol field at offset 6 selects the inner L3. */
		__be16 ppp = *(__be16 *)(hdr + 6);
		__be16 inner_proto;

		if (ppp == bpf_htons(PPP_IP))
			inner_proto = bpf_htons(ETH_P_IP);
		else if (ppp == bpf_htons(PPP_IPV6))
			inner_proto = bpf_htons(ETH_P_IPV6);
		else
			return BPF_FLOW_DISSECTOR_CONTINUE;

		__u32 inner = nhoff + PPPOE_SES_HLEN;

		if (inner > 128)
			return BPF_FLOW_DISSECTOR_CONTINUE;

		keys->nhoff = inner;
		keys->n_proto = inner_proto;
		return fast_dispatch_l3(skb, data, data_end, inner, inner_proto);
	}

	/* Superset: also fast-path plain IP. */
	return fast_dispatch_l3(skb, data, data_end, nhoff, proto);
}

char _license[] SEC("license") = "GPL";
