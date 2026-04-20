// SPDX-License-Identifier: GPL-2.0
/*
 * BPF flow dissector using XDP2 declarative parser framework.
 *
 * This demonstrates that xdp2's declarative parser can replace the
 * kernel's ~2100 lines of hand-written flow dissector C code. The
 * parser graph is defined in parser.c (~150 lines) and compiled by
 * xdp2-compiler into the generated parser.xdp.h.
 *
 * Program type: BPF_PROG_TYPE_FLOW_DISSECTOR
 * Context: struct __sk_buff with skb->flow_keys
 * Output: writes to struct bpf_flow_keys
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/mpls.h>
#include <linux/ppp_defs.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp2/bpf.h"
#include "xdp2/bpf_maps.h"
#include "xdp2/parser_metadata.h"

/* Generated parser from xdp2-compiler */
#include "parser.xdp.h"

/* Per-CPU storage for parser context */
struct flow_dissector_ctx {
	struct xdp2_xdp_ctx ctx;
	struct xdp2_metadata_all frame[1];
};

/* BTF-described map (libbpf >= 1.0). The legacy bpf_elf_map/SEC("maps")
 * form was rejected by libbpf 1.x. PIN_GLOBAL_NS pinning under
 * /sys/fs/bpf/tc/globals isn't used by the BPF_PROG_TEST_RUN loader;
 * if a future integration path needs pinning, use libbpf's pin_path
 * API in the loader rather than reinstating the legacy section. */
XDP2_MAP_PERCPU_ARRAY(ctx_map, __u32, struct flow_dissector_ctx, 2);

static __always_inline struct flow_dissector_ctx *get_ctx(void)
{
	__u32 key = 1;

	return bpf_map_lookup_elem(&ctx_map, &key);
}

/* vlan_hdr is provided by xdp2/proto_defs/ethernet/proto_vlan.h via parser.xdp.h */

/* Handle VLAN tags: strip 802.1Q/802.1AD, update nhoff/thoff/n_proto */
static __always_inline int handle_vlan(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct vlan_hdr *vlan;

	/* Handle 802.1AD (outer tag) */
	if (keys->n_proto == bpf_htons(ETH_P_8021AD)) {
		vlan = data + keys->thoff;
		if ((void *)(vlan + 1) > data_end)
			return BPF_DROP;

		if (vlan->h_vlan_encapsulated_proto !=
		    bpf_htons(ETH_P_8021Q))
			return BPF_DROP;

		keys->nhoff += sizeof(*vlan);
		keys->thoff += sizeof(*vlan);
	}

	/* Handle 802.1Q (inner tag) */
	vlan = data + keys->thoff;
	if ((void *)(vlan + 1) > data_end)
		return BPF_DROP;

	keys->nhoff += sizeof(*vlan);
	keys->thoff += sizeof(*vlan);

	/* Reject triple tagging */
	if (vlan->h_vlan_encapsulated_proto == bpf_htons(ETH_P_8021AD) ||
	    vlan->h_vlan_encapsulated_proto == bpf_htons(ETH_P_8021Q))
		return BPF_DROP;

	keys->n_proto = vlan->h_vlan_encapsulated_proto;

	return -1; /* Continue processing with new n_proto */
}

/* Handle MPLS: validate header and return BPF_OK */
static __always_inline int handle_mpls(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct mpls_label *mpls;

	mpls = data + keys->thoff;
	if ((void *)(mpls + 1) > data_end)
		return BPF_DROP;

	return BPF_OK;
}

/* Translate xdp2 metadata to bpf_flow_keys */
static __always_inline void translate_metadata(struct xdp2_metadata_all *frame,
					       struct bpf_flow_keys *keys)
{
	/* Address type and addresses */
	switch (frame->addr_type) {
	case XDP2_ADDR_TYPE_IPV4:
		keys->addr_proto = ETH_P_IP;
		keys->ipv4_src = frame->addrs.v4.saddr;
		keys->ipv4_dst = frame->addrs.v4.daddr;
		break;
	case XDP2_ADDR_TYPE_IPV6:
		keys->addr_proto = ETH_P_IPV6;
		__builtin_memcpy(&keys->ipv6_src, &frame->addrs.v6.saddr,
				 sizeof(keys->ipv6_src));
		__builtin_memcpy(&keys->ipv6_dst, &frame->addrs.v6.daddr,
				 sizeof(keys->ipv6_dst));
		break;
	case XDP2_ADDR_TYPE_TIPC:
		/* TIPC doesn't map to bpf_flow_keys addr_proto */
		break;
	default:
		break;
	}

	/* IP protocol */
	keys->ip_proto = frame->ip_proto;

	/* Ports */
	keys->sport = frame->port_pair.sport;
	keys->dport = frame->port_pair.dport;

	/* Fragment info */
	if (frame->is_fragment) {
		keys->is_frag = true;
		if (frame->first_frag)
			keys->is_first_frag = true;
	}

	/* IPv6 flow label */
	keys->flow_label = frame->flow_label;
}

SEC("flow_dissector")
int _dissect(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct flow_dissector_ctx *parser_ctx;
	const void *hdr;
	int rc;

	/* Handle VLAN tags inline */
	if (keys->n_proto == bpf_htons(ETH_P_8021Q) ||
	    keys->n_proto == bpf_htons(ETH_P_8021AD)) {
		rc = handle_vlan(skb);
		if (rc >= 0)
			return rc;
		/* Reload data pointers after VLAN processing */
		data_end = (void *)(long)skb->data_end;
		data = (void *)(long)skb->data;
	}

	/* Handle MPLS inline */
	if (keys->n_proto == bpf_htons(ETH_P_MPLS_UC) ||
	    keys->n_proto == bpf_htons(ETH_P_MPLS_MC))
		return handle_mpls(skb);

	/* Handle ARP inline — validate header and return OK */
	if (keys->n_proto == bpf_htons(ETH_P_ARP)) {
		void *arp = data + keys->thoff;

		if (arp + sizeof(struct arphdr) > data_end)
			return BPF_DROP;
		return BPF_OK;
	}

	/* Handle TIPC inline — validate basic header (4 x __be32) */
	if (keys->n_proto == bpf_htons(ETH_P_TIPC)) {
		void *tipc = data + keys->thoff;

		if (tipc + 16 > data_end)
			return BPF_DROP;
		return BPF_OK;
	}

	/* Handle PPPoE inline — strip PPPoE header and continue to IP */
	if (keys->n_proto == bpf_htons(ETH_P_PPP_SES)) {
		struct pppoe_hdr {
			__u8 vertype;
			__u8 code;
			__be16 sid;
			__be16 length;
			__be16 protocol;
		} __attribute__((packed));

		struct pppoe_hdr *pppoe = data + keys->thoff;
		__be16 ppp_proto;

		if ((void *)(pppoe + 1) > data_end)
			return BPF_DROP;
		keys->thoff += sizeof(*pppoe);
		keys->nhoff += sizeof(*pppoe);
		ppp_proto = pppoe->protocol;
		if (ppp_proto == bpf_htons(PPP_IP))
			keys->n_proto = bpf_htons(ETH_P_IP);
		else if (ppp_proto == bpf_htons(PPP_IPV6))
			keys->n_proto = bpf_htons(ETH_P_IPV6);
		else
			return BPF_FLOW_DISSECTOR_CONTINUE;
		/* Reload data pointers and fall through to IP/IPv6 */
		data_end = (void *)(long)skb->data_end;
		data = (void *)(long)skb->data;
	}

	/* Only handle IP and IPv6 via the xdp2 parser */
	if (keys->n_proto != bpf_htons(ETH_P_IP) &&
	    keys->n_proto != bpf_htons(ETH_P_IPV6))
		return BPF_FLOW_DISSECTOR_CONTINUE;

	/* Get per-CPU parser context */
	parser_ctx = get_ctx();
	if (!parser_ctx)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	/* Initialize parser context */
	__builtin_memset(parser_ctx->frame, 0,
			 sizeof(struct xdp2_metadata_all));
	parser_ctx->ctx.frame_num = 0;
	parser_ctx->ctx.next = CODE_IGNORE;
	parser_ctx->ctx.metadata = parser_ctx->frame;
	parser_ctx->ctx.parser = xdp2_parser_flow_dissector;

	/* Start parsing at L3 (thoff points past Ethernet/VLAN) */
	hdr = data + keys->thoff;
	if (hdr >= data_end)
		return BPF_DROP;

	/* Invoke the xdp2 parser on raw packet data */
	rc = XDP2_PARSE_XDP(xdp2_parser_flow_dissector, &parser_ctx->ctx,
			    &hdr, data_end, false, 0);

	if (rc != XDP2_OKAY && rc != XDP2_STOP_OKAY &&
	    rc != XDP2_STOP_UNKNOWN_PROTO)
		return BPF_DROP;

	/* Translate xdp2 metadata -> bpf_flow_keys */
	translate_metadata(parser_ctx->frame, keys);

	/* Update thoff to point past parsed headers */
	if (hdr > data && hdr <= data_end)
		keys->thoff = (__u16)(hdr - data);

	return BPF_OK;
}

char __license[] SEC("license") = "GPL";
