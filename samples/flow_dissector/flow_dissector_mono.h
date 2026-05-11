/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * flow_dissector_mono.h — hand-written R3 reference for the
 * monolithic parser shape.
 *
 * This is the GROUND TRUTH that the R3 codegen template
 * (mono_parser.template.c) should learn to emit. One function with
 * goto-state transitions covering eth(ertype) + vlan / qinq + mpls +
 * ipv4 + ipv6 (with extension headers) + tcp + udp + icmp + GRE +
 * IPIP / 6in4 / 6to4. Falls through to STOP_OKAY on protocols not
 * yet wired in.
 *
 * The xdp2_parser_flow_dissector_l2 entry point is documented as
 * starting at the 2-byte ethertype (the benchmark advances past the
 * 12-byte MAC pair before calling). Same calling convention here.
 *
 * Phase 1 covered eth → ipv4/v6 → tcp/udp/icmp.
 * Phase 2 (this file) adds encap-layer coverage: vlan/qinq, mpls,
 * ipv6 extension headers, gre, ipip/ipv6ip (4-in-4, 6-in-4, 6to4).
 * Phase 3 will replace this hand-written file with codegen.
 */

#ifndef XDP2_FLOW_DISSECTOR_MONO_H
#define XDP2_FLOW_DISSECTOR_MONO_H

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_vlan.h>
#include <linux/mpls.h>
#include "xdp2/parser.h"
#include "xdp2/parser_metadata.h"
#include "xdp2/proto_defs/ip/proto_ipv4.h"  /* ip_is_fragment(), IP_OFFSET */
#include "xdp2/proto_defs/ip/proto_ipv6.h"  /* ip6_flowlabel(), IPV6_FLOWLABEL_MASK */
#include "xdp2/proto_defs/ip/proto_icmp.h"  /* icmp_has_id() */

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#ifndef ETH_P_MPLS_UC
#define ETH_P_MPLS_UC	0x8847
#endif
#ifndef ETH_P_MPLS_MC
#define ETH_P_MPLS_MC	0x8848
#endif
#ifndef ETH_P_PPP_SES
#define ETH_P_PPP_SES	0x8864
#endif

/* PPP protocol type field values (RFC 1661 §2) */
#define XDP2_MONO_PPP_IP   0x0021
#define XDP2_MONO_PPP_IPV6 0x0057

/* IPv6 extension-header next-header values (RFC 8200) */
#define XDP2_MONO_IPV6_NH_HBH       0    /* Hop-by-hop */
#define XDP2_MONO_IPV6_NH_ROUTING   43
#define XDP2_MONO_IPV6_NH_FRAGMENT  44
#define XDP2_MONO_IPV6_NH_DSTOPTS   60
#define XDP2_MONO_IPV6_NH_AH        51   /* IPsec auth header */
#define XDP2_MONO_IPV6_NH_MOBILITY  135
#define XDP2_MONO_IPV6_NH_HIP       139
#define XDP2_MONO_IPV6_NH_SHIM6     140

/* Sentinel: keep encap loops bounded so a hostile packet can't make
 * the parser walk forever. Matches XDP2_PARSER_DEFAULT_MAX_ENCAPS. */
#define XDP2_MONO_MAX_ENCAPS 4
#define XDP2_MONO_MAX_VLAN   2

/* Generic ipv6_opt_hdr layout: u8 nexthdr; u8 hdrlen (in 8-byte units,
 * not counting the first 8); u8 data[6+8*hdrlen]. Same shape for
 * HBH, routing, dstopts. */
struct xdp2_mono_ipv6_opt {
	__u8 nexthdr;
	__u8 hdrlen;
};

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
	__u8 ip_proto = 0;
	__be16 etype;
	int encap_depth = 0;
	int vlan_count = 0;

	(void)parser;
	(void)ctrl;
	(void)flags;

	/* etype_dispatch_node: read 2-byte ethertype.
	 * Note: c-xdp2-usp's etype_dispatch_node only reads for dispatch
	 * and doesn't set eth_proto; we match that behavior so the parity
	 * comparator sees identical outputs. eth_proto IS set by encap
	 * paths (vlan / mpls / pppoe) on the way down, which is the same
	 * place the OPT path sets it via the proto-specific metadata
	 * extractors. */
	if (__builtin_expect(len < 2, 0))
		return XDP2_STOP_LENGTH;
	etype = *(const __be16 *)p;
	p += 2;
	len -= 2;

dispatch_etype:
	switch (etype) {
	case __cpu_to_be16(ETH_P_IP):
		goto parse_ipv4;
	case __cpu_to_be16(ETH_P_IPV6):
		goto parse_ipv6;
	case __cpu_to_be16(ETH_P_8021Q):
	case __cpu_to_be16(ETH_P_8021AD):
		goto parse_vlan;
	case __cpu_to_be16(ETH_P_MPLS_UC):
	case __cpu_to_be16(ETH_P_MPLS_MC):
		goto parse_mpls;
	case __cpu_to_be16(ETH_P_PPP_SES):
		goto parse_pppoe;
	default:
		return XDP2_STOP_OKAY;
	}

parse_pppoe: {
	/* PPPoE session frame (RFC 2516 §4): 1 byte ver/type, 1 byte code,
	 * 2 bytes session_id, 2 bytes length = 6 bytes total. Then PPP
	 * frame (RFC 1661): 2 bytes protocol type, then payload. So we
	 * need 6+2=8 bytes before we can dispatch on PPP proto. */
	__u16 ppp_proto;

	if (__builtin_expect(len < 6 + 2, 0))
		return XDP2_STOP_LENGTH;
	ppp_proto = ((__u16)p[6] << 8) | p[7];
	p += 6 + 2;
	len -= 6 + 2;
	switch (ppp_proto) {
	case XDP2_MONO_PPP_IP:
		etype = __cpu_to_be16(ETH_P_IP);
		goto parse_ipv4;
	case XDP2_MONO_PPP_IPV6:
		etype = __cpu_to_be16(ETH_P_IPV6);
		goto parse_ipv6;
	default:
		return XDP2_STOP_OKAY;
	}
}

parse_vlan: {
	/* 4-byte VLAN header: 2 bytes TCI + 2 bytes inner ethertype */
	const struct vlan_hdr *vlan;
	__u16 tci;

	if (__builtin_expect(len < sizeof(struct vlan_hdr), 0))
		return XDP2_STOP_LENGTH;
	vlan = (const struct vlan_hdr *)p;
	tci = ntohs(vlan->h_vlan_TCI);

	if (vlan_count < XDP2_MONO_MAX_VLAN) {
		int idx = _meta->vlan_count;
		if (idx >= XDP2_MAX_VLAN_CNT)
			idx = XDP2_MAX_VLAN_CNT - 1;
		else
			_meta->vlan_count = idx + 1;
		_meta->vlan[idx].id = tci & VLAN_VID_MASK;
		_meta->vlan[idx].priority =
			(tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
		_meta->vlan[idx].tpid = etype;
	}
	vlan_count++;

	etype = vlan->h_vlan_encapsulated_proto;
	p += sizeof(struct vlan_hdr);
	len -= sizeof(struct vlan_hdr);
	goto dispatch_etype;
}

parse_mpls: {
	/* Walk MPLS label stack until bottom-of-stack (BoS bit).
	 * Match XDP2_METADATA_TEMP_mpls semantics: record fields of
	 * the FIRST label seen. Then sniff the next nibble at p to
	 * dispatch into IPv4 or IPv6 (RFC 3032 has no protocol field
	 * after MPLS; flow dissectors peek). */
	const struct mpls_label *mpls;
	__u32 entry, label;
	bool first = true;

	while (1) {
		if (__builtin_expect(len < sizeof(struct mpls_label), 0))
			return XDP2_STOP_LENGTH;
		mpls = (const struct mpls_label *)p;
		entry = ntohl(mpls->entry);
		label = (entry & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT;
		if (first) {
			_meta->mpls.label = label;
			_meta->mpls.ttl =
				(entry & MPLS_LS_TTL_MASK) >> MPLS_LS_TTL_SHIFT;
			_meta->mpls.tc =
				(entry & MPLS_LS_TC_MASK) >> MPLS_LS_TC_SHIFT;
			_meta->mpls.bos =
				(entry & MPLS_LS_S_MASK) >> MPLS_LS_S_SHIFT;
			first = false;
		}
		p += sizeof(struct mpls_label);
		len -= sizeof(struct mpls_label);
		if (entry & MPLS_LS_S_MASK)
			break;
	}
	/* Peek IP version nibble */
	if (__builtin_expect(len < 1, 0))
		return XDP2_STOP_OKAY;
	if ((p[0] >> 4) == 4) {
		etype = __cpu_to_be16(ETH_P_IP);
		goto parse_ipv4;
	}
	if ((p[0] >> 4) == 6) {
		etype = __cpu_to_be16(ETH_P_IPV6);
		goto parse_ipv6;
	}
	return XDP2_STOP_OKAY;
}

parse_ipv4: {
	const struct iphdr *iph = (const struct iphdr *)p;
	size_t ihl;

	if (__builtin_expect(len < sizeof(struct iphdr), 0))
		return XDP2_STOP_LENGTH;
	if (__builtin_expect(iph->version != 4, 0))
		return XDP2_STOP_UNKNOWN_PROTO;
	ihl = (size_t)iph->ihl << 2;
	if (__builtin_expect(ihl < sizeof(struct iphdr) || len < ihl, 0))
		return XDP2_STOP_LENGTH;

	_meta->l3_off = (__u16)((const __u8 *)iph - (const __u8 *)hdr);
	_meta->addr_type = XDP2_ADDR_TYPE_IPV4;
	_meta->addrs.v4.saddr = iph->saddr;
	_meta->addrs.v4.daddr = iph->daddr;
	_meta->ip_proto = iph->protocol;

	/* fragment / first_frag flags — match XDP2_METADATA_TEMP_ipv4
	 * semantics: both fields are only set when the packet IS a
	 * fragment (parser_metadata.h:385-389). Non-fragmented packets
	 * leave both at the memset-zero default. */
	if (ip_is_fragment(iph)) {
		_meta->is_fragment = 1;
		_meta->first_frag = !(iph->frag_off & htons(IP_OFFSET));
		if (!_meta->first_frag)
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

	_meta->l3_off = (__u16)((const __u8 *)ip6h - (const __u8 *)hdr);
	_meta->addr_type = XDP2_ADDR_TYPE_IPV6;
	_meta->addrs.v6.saddr = ip6h->saddr;
	_meta->addrs.v6.daddr = ip6h->daddr;
	_meta->ip_proto = ip6h->nexthdr;
	_meta->flow_label = ntohl(ip6_flowlabel(ip6h));
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
	case IPPROTO_GRE:
		goto parse_gre;
	case IPPROTO_IPIP:
		/* 4-in-4: outer carries inner IPv4 */
		if (++encap_depth > XDP2_MONO_MAX_ENCAPS)
			return XDP2_STOP_ENCAP_DEPTH;
		goto parse_ipv4;
	case IPPROTO_IPV6:
		/* 6-in-4 / 6-in-6: outer carries inner IPv6 */
		if (++encap_depth > XDP2_MONO_MAX_ENCAPS)
			return XDP2_STOP_ENCAP_DEPTH;
		goto parse_ipv6;
	case XDP2_MONO_IPV6_NH_HBH:
	case XDP2_MONO_IPV6_NH_ROUTING:
	case XDP2_MONO_IPV6_NH_DSTOPTS:
	case XDP2_MONO_IPV6_NH_MOBILITY:
	case XDP2_MONO_IPV6_NH_HIP:
	case XDP2_MONO_IPV6_NH_SHIM6:
		goto parse_ipv6_eh;
	case XDP2_MONO_IPV6_NH_FRAGMENT:
		goto parse_ipv6_frag;
	case XDP2_MONO_IPV6_NH_AH:
		goto parse_ah;
	default:
		return XDP2_STOP_OKAY;
	}

parse_ipv6_eh: {
	/* Variable-length IPv6 option header: nexthdr + hdrlen (units
	 * of 8 bytes, not counting first 8). Loop bound by encap_depth
	 * to defend against malicious chains. */
	const struct xdp2_mono_ipv6_opt *eh;
	size_t hlen;

	if (__builtin_expect(len < sizeof(struct xdp2_mono_ipv6_opt), 0))
		return XDP2_STOP_LENGTH;
	eh = (const struct xdp2_mono_ipv6_opt *)p;
	hlen = ((size_t)eh->hdrlen + 1) << 3;
	if (__builtin_expect(len < hlen, 0))
		return XDP2_STOP_LENGTH;
	ip_proto = eh->nexthdr;
	p += hlen;
	len -= hlen;
	goto dispatch_l4;
}

parse_ipv6_frag: {
	/* Fragment header: nexthdr + reserved + fragment_offset(13)+flags */
	if (__builtin_expect(len < 8, 0))
		return XDP2_STOP_LENGTH;
	ip_proto = p[0];
	{
		__u16 off = (__u16)(p[2]) << 8 | p[3];
		_meta->is_fragment = 1;
		_meta->first_frag = !(off & 0xFFF8);
		if (!_meta->first_frag)
			return XDP2_STOP_OKAY;
	}
	p += 8;
	len -= 8;
	goto dispatch_l4;
}

parse_ah: {
	/* IPsec AH: nexthdr + hdrlen (units of 4 bytes, not counting
	 * first 2 = -2). hdrlen=4 means total 24 bytes. */
	if (__builtin_expect(len < 12, 0))
		return XDP2_STOP_LENGTH;
	ip_proto = p[0];
	{
		size_t ah_len = ((size_t)p[1] + 2) << 2;
		if (__builtin_expect(len < ah_len, 0))
			return XDP2_STOP_LENGTH;
		p += ah_len;
		len -= ah_len;
	}
	goto dispatch_l4;
}

parse_gre: {
	/* RFC 1701 / 2784 GRE. First 2 bytes = flags + version. Next 2
	 * bytes = protocol_type (same encoding as ethertype). For v0
	 * (no PPTP/L2TP-style), we just skip the header (variable len)
	 * and dispatch on protocol. */
	__u16 flags;
	__u16 ver;
	__be16 proto;
	size_t gre_len;

	if (__builtin_expect(len < 4, 0))
		return XDP2_STOP_LENGTH;
	if (++encap_depth > XDP2_MONO_MAX_ENCAPS)
		return XDP2_STOP_ENCAP_DEPTH;
	flags = (__u16)p[0] << 8 | p[1];
	ver = flags & 0x7;
	if (ver != 0)
		return XDP2_STOP_OKAY;  /* PPTP v1 — bail */
	proto = *(const __be16 *)(p + 2);
	gre_len = 4;
	/* Optional fields: checksum (4), key (4), seq (4) — each adds
	 * 4 bytes when its flag bit is set in `flags`. */
	if (flags & 0x8000) gre_len += 4;   /* checksum + reserved */
	if (flags & 0x2000) gre_len += 4;   /* key */
	if (flags & 0x1000) gre_len += 4;   /* sequence */
	if (__builtin_expect(len < gre_len, 0))
		return XDP2_STOP_LENGTH;
	p += gre_len;
	len -= gre_len;
	etype = proto;
	goto dispatch_etype;
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
	/* Match XDP2_METADATA_TEMP_icmp: for types that have id/seq
	 * (echo/echo-reply/timestamp/etc.), capture id (or 1 sentinel
	 * if id == 0). For other types, leave id at zero.
	 *
	 * The metadata field is stored in NETWORK byte order (matches
	 * `frame->icmp.id = icmp->un.echo.id` in parser_metadata.h:693
	 * — un.echo.id is __be16 stored verbatim). The parity dump
	 * applies ntohs() before emitting JSON. */
	if (icmp_has_id(p[0])) {
		__be16 id_be = *(const __be16 *)(p + 4);
		_meta->icmp.id = id_be ? id_be : htons(1);
	}
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
