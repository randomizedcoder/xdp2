// SPDX-License-Identifier: GPL-2.0
//
// fast_flow_ipip: per-encapsulation menu object for the IP-in-IP family
// with an IPv4 outer — IPIP (4-in-4) and 6in4 (IPv6-in-IPv4) — descending
// to the inner IP 5-tuple, plus the plain-IP inner. Mirrors the kernel BPF
// dissector's IPPROTO_IPIP / IPPROTO_IPV6 encap arms
// (kern_bpf/bpf_flow.c parse_ip_proto).
//
// Outer-IPv6 tunnels (4in6 / 6in6) defer to the slow path for now: they
// need flow-label-stop handling to stay byte-identical under
// FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL. See
// kernel-patches/series6-common-case/ebpf-menu.md.
//

#include "fast_flow_inner.h"

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

	/* Plain IPv6 → inner dispatch (outer-IPv6 tunnels deferred). */
	if (proto == bpf_htons(ETH_P_IPV6))
		return fast_dispatch_l3(skb, data, data_end, nhoff, proto);

	if (proto != bpf_htons(ETH_P_IP))
		return BPF_FLOW_DISSECTOR_CONTINUE;

	struct iphdr *iph = data + nhoff;

	if ((void *)(iph + 1) > data_end)
		return BPF_FLOW_DISSECTOR_CONTINUE;
	if (iph->ihl != 5)
		return BPF_FLOW_DISSECTOR_CONTINUE;
	if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
		return BPF_FLOW_DISSECTOR_CONTINUE;

	__be16 inner_proto;

	if (iph->protocol == IPPROTO_IPIP)
		inner_proto = bpf_htons(ETH_P_IP);      /* 4-in-4 */
	else if (iph->protocol == IPPROTO_IPV6)
		inner_proto = bpf_htons(ETH_P_IPV6);    /* 6in4 */
	else
		/* Not an IP-in-IP outer → plain IPv4 fast path. */
		return fast_dispatch_l3(skb, data, data_end, nhoff, proto);

	__u32 inner = nhoff + 20;

	if (inner > 128)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	keys->is_encap = 1;
	keys->nhoff = inner;
	keys->n_proto = inner_proto;
	return fast_dispatch_l3(skb, data, data_end, inner, inner_proto);
}

char _license[] SEC("license") = "GPL";
