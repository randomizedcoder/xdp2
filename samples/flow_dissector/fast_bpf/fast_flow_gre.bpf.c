// SPDX-License-Identifier: GPL-2.0
//
// fast_flow_gre: per-encapsulation menu object for plain (version-0) GRE
// over IPv4, descending to the inner IP 5-tuple, plus the plain-IP inner.
// Handles the optional GRE checksum/key/sequence fields and Transparent
// Ethernet Bridging (TEB) inner Ethernet, mirroring the kernel BPF
// dissector's GRE arm (kern_bpf/bpf_flow.c parse_ip_proto IPPROTO_GRE).
// Non-zero GRE versions (e.g. PPTP) defer to the slow path.
//
// See kernel-patches/series6-common-case/ebpf-menu.md.
//

#include "fast_flow_inner.h"

struct gre_hdr {
	__be16 flags;
	__be16 proto;
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

	/* Plain IPv6 (no GRE outer handled for v6 here) → inner dispatch. */
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

	/* Not GRE → plain IPv4 fast path. */
	if (iph->protocol != IPPROTO_GRE)
		return fast_dispatch_l3(skb, data, data_end, nhoff, proto);

	/* GRE: outer IPv4 (20B) + GRE header. */
	__u32 greoff = nhoff + 20;
	struct gre_hdr *gre = data + greoff;

	if ((void *)(gre + 1) > data_end)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	__u16 gflags = bpf_ntohs(gre->flags);

	/* Only inspect standard version-0 GRE. */
	if (gflags & 0x0007)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	__u32 inner = greoff + 4;      /* flags + proto */
	if (gflags & 0x8000)           /* checksum present (+ reserved1) */
		inner += 4;
	if (gflags & 0x2000)           /* key present */
		inner += 4;
	if (gflags & 0x1000)           /* sequence present */
		inner += 4;

	__be16 iproto = gre->proto;

	/* Transparent Ethernet Bridging: an inner Ethernet header follows. */
	if (iproto == bpf_htons(ETH_P_TEB)) {
		struct ethhdr *eth = data + inner;

		if ((void *)(eth + 1) > data_end)
			return BPF_FLOW_DISSECTOR_CONTINUE;
		iproto = eth->h_proto;
		inner += sizeof(*eth);
	}

	if (inner > 128)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	keys->is_encap = 1;
	keys->nhoff = inner;
	keys->n_proto = iproto;
	return fast_dispatch_l3(skb, data, data_end, inner, iproto);
}

char _license[] SEC("license") = "GPL";
