// SPDX-License-Identifier: GPL-2.0
//
// fast_flow_mpls: per-encapsulation menu object for a single MPLS label
// followed by IPv4/IPv6, descending to the inner IP 5-tuple, plus the
// plain-IP inner.
//
// NOTE: this deliberately goes BEYOND the in-tree BPF dissector, whose
// MPLS handler (kern_bpf/bpf_flow.c PROG(MPLS)) is a stub that validates a
// label and returns with no inner 5-tuple. fast_flow_mpls extracts the
// inner flow, so its parity oracle is the in-kernel C flow_dissector's
// single-label MPLS behaviour (cf. series5 patch 05), NOT bpf_flow.kern.o.
// Only single-label stacks (bottom-of-stack bit set) are fast-pathed;
// multi-label stacks defer. Inner IP type is inferred from the first
// nibble after the label (MPLS carries no ethertype). See
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

	if (proto == bpf_htons(ETH_P_MPLS_UC) ||
	    proto == bpf_htons(ETH_P_MPLS_MC)) {
		__u8 *label = data + nhoff;

		if ((void *)(label + 4) > data_end)
			return BPF_FLOW_DISSECTOR_CONTINUE;

		/* Single label only: the bottom-of-stack bit (label[2] bit0)
		 * must be set. Multi-label stacks defer to the slow path. */
		if (!(label[2] & 0x01))
			return BPF_FLOW_DISSECTOR_CONTINUE;

		__u32 inner = nhoff + 4;

		if (inner > 128)
			return BPF_FLOW_DISSECTOR_CONTINUE;

		__u8 *ipver = data + inner;

		if ((void *)(ipver + 1) > data_end)
			return BPF_FLOW_DISSECTOR_CONTINUE;

		__be16 inner_proto;

		/* MPLS carries no ethertype — infer inner IP version. */
		if ((*ipver >> 4) == 4)
			inner_proto = bpf_htons(ETH_P_IP);
		else if ((*ipver >> 4) == 6)
			inner_proto = bpf_htons(ETH_P_IPV6);
		else
			return BPF_FLOW_DISSECTOR_CONTINUE;

		keys->nhoff = inner;
		keys->n_proto = inner_proto;
		return fast_dispatch_l3(skb, data, data_end, inner, inner_proto);
	}

	/* Superset: also fast-path plain IP. */
	return fast_dispatch_l3(skb, data, data_end, nhoff, proto);
}

char _license[] SEC("license") = "GPL";
