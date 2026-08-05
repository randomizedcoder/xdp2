// SPDX-License-Identifier: GPL-2.0
//
// fast_flow_qinq: per-encapsulation menu object for 802.1AD + 802.1Q
// double-tagged (QinQ) traffic over IPv4/IPv6 + {TCP,UDP,ICMP}, and also
// single 802.1Q and plain IP. Load this on a netns carrying QinQ.
//
// Mirrors the kernel BPF dissector's double-tag rule
// (kern_bpf/bpf_flow.c PROG(VLAN)): outer 802.1AD must wrap an inner
// 802.1Q; triple-tagging is unsupported. See
// kernel-patches/series6-common-case/ebpf-menu.md.
//

#include "fast_flow_inner.h"

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

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

	/* Outer 802.1AD service tag: the kernel accepts only 802.1AD+802.1Q,
	 * so require an inner 802.1Q customer tag. */
	if (proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan = data + nhoff;

		if ((void *)(vlan + 1) > data_end)
			return BPF_FLOW_DISSECTOR_CONTINUE;
		if (vlan->h_vlan_encapsulated_proto != bpf_htons(ETH_P_8021Q))
			return BPF_FLOW_DISSECTOR_CONTINUE;
		nhoff += sizeof(*vlan);
		proto = bpf_htons(ETH_P_8021Q);
	}

	/* Inner (or single) 802.1Q tag → unwrap to the L3 ethertype. */
	if (proto == bpf_htons(ETH_P_8021Q)) {
		struct vlan_hdr *vlan = data + nhoff;

		if ((void *)(vlan + 1) > data_end)
			return BPF_FLOW_DISSECTOR_CONTINUE;
		proto = vlan->h_vlan_encapsulated_proto;
		nhoff += sizeof(*vlan);
		/* No triple-tagging (matches the kernel). */
		if (proto == bpf_htons(ETH_P_8021Q) ||
		    proto == bpf_htons(ETH_P_8021AD))
			return BPF_FLOW_DISSECTOR_CONTINUE;
	}

	keys->nhoff = nhoff;
	keys->n_proto = proto;
	return fast_dispatch_l3(skb, data, data_end, nhoff, proto);
}

char _license[] SEC("license") = "GPL";
