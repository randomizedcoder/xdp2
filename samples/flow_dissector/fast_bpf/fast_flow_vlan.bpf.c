// SPDX-License-Identifier: GPL-2.0
//
// fast_flow_vlan: per-encapsulation menu object for single-tagged
// 802.1Q VLAN over IPv4/IPv6 + {TCP,UDP,ICMP}, plus the plain-IP inner.
// Load this on a netns whose traffic is single-VLAN-tagged. QinQ
// (double-tagged) traffic defers to the slow path here — use
// fast_flow_qinq for that.
//
// Mirrors the kernel BPF dissector's in-place VLAN unwrap
// (kern_bpf/bpf_flow.c PROG(VLAN)): advance nhoff past the tag, rewrite
// n_proto to the inner ethertype, then dispatch. See
// kernel-patches/series6-common-case/ebpf-menu.md.
//

#include "fast_flow_inner.h"

/* <linux/if_vlan.h> is kernel-internal; declare the wire format inline. */
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

	/* Single 802.1Q tag → unwrap to inner ethertype + advance L3. If the
	 * inner ethertype is itself a VLAN tag (QinQ), fast_dispatch_l3 sees a
	 * non-IP proto and returns CONTINUE — the slow path (or fast_flow_qinq)
	 * handles double-tagging. */
	if (proto == bpf_htons(ETH_P_8021Q)) {
		struct vlan_hdr *vlan = data + nhoff;

		if ((void *)(vlan + 1) > data_end)
			return BPF_FLOW_DISSECTOR_CONTINUE;
		proto = vlan->h_vlan_encapsulated_proto;
		nhoff += sizeof(*vlan);
		keys->nhoff = nhoff;
		keys->n_proto = proto;
	}

	return fast_dispatch_l3(skb, data, data_end, nhoff, proto);
}

char _license[] SEC("license") = "GPL";
