/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * flow_dissector_mono.h — hand-written R3 reference for the
 * monolithic parser shape.
 *
 * This is the GROUND TRUTH that the R3 codegen template
 * (mono_parser.template.c) should learn to emit. One function with
 * goto-state transitions covering eth(ertype) + ipv4 + ipv6 + tcp +
 * udp + icmp. Falls through to STOP_OKAY on non-matching protocols.
 *
 * The xdp2_parser_flow_dissector_l2 entry point is documented as
 * starting at the 2-byte ethertype (the benchmark advances past the
 * 12-byte MAC pair before calling). Same calling convention here.
 *
 * Covers the common-path 5-tuple flow_keys extraction. R3 phase 2
 * extends this to handle vlan / qinq / mpls / gre / ipv6_eh /
 * encap layers; phase 3 reaches feature-parity with the existing
 * _opt path and becomes the kernel-flowdis-shape codegen output.
 */

#ifndef XDP2_FLOW_DISSECTOR_MONO_H
#define XDP2_FLOW_DISSECTOR_MONO_H

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "xdp2/parser.h"
#include "xdp2/parser_metadata.h"

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

/* Mono entry function for xdp2_parser_flow_dissector_l2_mono.
 *
 * Signature matches XDP2_PARSER_OPT / XDP2_PARSER_MONO:
 *   (parser, hdr, len, metadata, ctrl, flags)
 *
 * `hdr` points at the ethertype field (after the 12-byte MAC pair),
 * matching the calling convention of the existing
 * xdp2_parser_flow_dissector_l2 / _opt variant.
 */
static inline int xdp2_parser_flow_dissector_l2_mono_entry(
	const struct xdp2_parser *parser, void *hdr, size_t len,
	void *metadata, struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	struct xdp2_metadata_all *_meta = metadata;
	const __u8 *p = hdr;
	__u8 ip_proto;

	(void)parser;
	(void)ctrl;
	(void)flags;

	/* etype_dispatch_node: read 2-byte ethertype */
	if (__builtin_expect(len < 2, 0))
		return XDP2_STOP_LENGTH;
	{
		__be16 etype = *(const __be16 *)p;
		_meta->eth_proto = etype;
		p += 2;
		len -= 2;

		switch (etype) {
		case __cpu_to_be16(ETH_P_IP):
			goto parse_ipv4;
		case __cpu_to_be16(ETH_P_IPV6):
			goto parse_ipv6;
		default:
			return XDP2_STOP_OKAY;
		}
	}

parse_ipv4: {
	const struct iphdr *iph = (const struct iphdr *)p;
	size_t ihl;

	if (__builtin_expect(len < sizeof(struct iphdr), 0))
		return XDP2_STOP_LENGTH;
	if (__builtin_expect(iph->version != 4, 0))
		return XDP2_STOP_FAIL;
	ihl = (size_t)iph->ihl << 2;
	if (__builtin_expect(ihl < sizeof(struct iphdr) || len < ihl, 0))
		return XDP2_STOP_LENGTH;

	_meta->addr_type = XDP2_ADDR_TYPE_IPV4;
	_meta->addrs.v4.saddr = iph->saddr;
	_meta->addrs.v4.daddr = iph->daddr;
	_meta->ip_proto = iph->protocol;

	/* fragment / first_frag flags */
	{
		__be16 frag_off = iph->frag_off;
		__u16 host_frag = __be16_to_cpu(frag_off);
		_meta->is_fragment = !!(host_frag & 0x3FFF);
		_meta->first_frag = !(host_frag & 0x1FFF);
		if (_meta->is_fragment && !_meta->first_frag)
			return XDP2_STOP_OKAY;
	}

	ip_proto = iph->protocol;
	p += ihl;
	len -= ihl;
	goto dispatch_l4;
}

parse_ipv6: {
	const struct ipv6hdr *ip6h = (const struct ipv6hdr *)p;

	if (__builtin_expect(len < sizeof(struct ipv6hdr), 0))
		return XDP2_STOP_LENGTH;

	_meta->addr_type = XDP2_ADDR_TYPE_IPV6;
	_meta->addrs.v6.saddr = ip6h->saddr;
	_meta->addrs.v6.daddr = ip6h->daddr;
	_meta->ip_proto = ip6h->nexthdr;
	ip_proto = ip6h->nexthdr;

	p += sizeof(struct ipv6hdr);
	len -= sizeof(struct ipv6hdr);
	goto dispatch_l4;
}

dispatch_l4:
	switch (ip_proto) {
	case IPPROTO_TCP:
		goto parse_tcp;
	case IPPROTO_UDP:
		goto parse_udp;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		goto parse_icmp;
	default:
		return XDP2_STOP_OKAY;
	}

parse_tcp: {
	const struct tcphdr *th = (const struct tcphdr *)p;

	if (__builtin_expect(len < sizeof(struct tcphdr), 0))
		return XDP2_STOP_LENGTH;
	_meta->port16[0] = th->source;
	_meta->port16[1] = th->dest;
	return XDP2_STOP_OKAY;
}

parse_udp: {
	const struct udphdr *uh = (const struct udphdr *)p;

	if (__builtin_expect(len < sizeof(struct udphdr), 0))
		return XDP2_STOP_LENGTH;
	_meta->port16[0] = uh->source;
	_meta->port16[1] = uh->dest;
	return XDP2_STOP_OKAY;
}

parse_icmp:
	if (__builtin_expect(len < 4, 0))
		return XDP2_STOP_LENGTH;
	_meta->icmp.type = p[0];
	_meta->icmp.code = p[1];
	return XDP2_STOP_OKAY;
}

/* Declare the mono parser. The parse-graph dispatch in
 * xdp2_parse() routes XDP2_MONOLITHIC straight to the entry
 * function below; root_node is etype_dispatch_node only for
 * config-introspection purposes (it isn't used at runtime). */
XDP2_PARSER_MONO(xdp2_parser_flow_dissector_l2_mono,
		 "XDP2 flow dissector (L2) — mono reference",
		 etype_dispatch_node,
		 xdp2_parser_flow_dissector_l2_mono_entry,
		 (.metameta_size = 0,
		  .frame_size = sizeof(struct xdp2_metadata_all),
		  .max_frames = 0
		 ));

#endif /* XDP2_FLOW_DISSECTOR_MONO_H */
