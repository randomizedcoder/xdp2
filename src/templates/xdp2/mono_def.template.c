<!--(if 0)-->
// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/*
 * Copyright (c) 2026 Anthropic. R3 phase 3 — monolithic-codegen
 * template. Generates a single function with goto-state transitions
 * per parser graph, matching the shape of the R3.1+R3.2 hand-written
 * reference at samples/flow_dissector/flow_dissector_mono.h.
 *
 * Phase-3 scope (this template):
 *   - One function per parser root.
 *   - One goto label per parse_node, with a length check at entry.
 *   - Each node calls proto_def->ops.extract_metadata + ops.handler
 *     (kept INDIRECT for now — devirt is R5 territory).
 *   - Next-proto dispatch via ops.next_proto + switch with goto
 *     targets per out-edge.
 *
 * Phase-4 follow-ups:
 *   - Devirtualise ops callbacks into inline metadata stores driven
 *     by metadata_transfers + next_proto_info from the R2 IR.
 *   - Hardcoded eth+ipv4+l4 fast-path emit at function entry.
 *   - TLV / flag_fields walkers (currently mono-eligibility
 *     validator rejects parsers using these).
 *
 * Selected per parser via XDP2_PARSER_MONO() macro
 * (src/include/xdp2/parser.h) + XDP2_MONOLITHIC parser_type
 * (src/include/xdp2/parser_types.h). Generated when the input file
 * has the .mono.c output extension.
 */
<!--(end)-->

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* R3.3.6: this TU includes the user's parser.c only to pull in
 * parse_node + proto_def static-const definitions. The user-level
 * XDP2_PARSER macro is gated on XDP2_PARSERS_SKIP (defined here
 * before parser.h is parsed), so the user's XDP2_PARSER(...) calls
 * in parser.c expand to nothing — parser.p.c is the canonical TU
 * that owns those base parser structs / pointers. The codegen-only
 * XDP2_PARSER_MONO macro is unaffected and still emits the _mono-
 * suffixed structs the template generates at the bottom of this
 * file. */
#define XDP2_PARSERS_SKIP 1
#include "xdp2/parser.h"
#include "xdp2/proto_defs_define.h"
#include "xdp2/compiler_helpers.h"
#include "@!filename!@"

/* check_pkt_len: shared length-check helper. Same as c_def.template.c
 * — could be inlined per node-block but kept as a static-inline so
 * the goto-state body stays readable. The compiler folds it. */
static inline __unused() __attribute__((always_inline)) int
	__mono_check_pkt_len(const void *hdr,
			     const struct xdp2_proto_def *pnode,
			     size_t len, ssize_t *hlen)
{
	*hlen = pnode->min_len;

	if (len < *hlen)
		return XDP2_STOP_LENGTH;

	if (pnode->ops.len) {
		*hlen = pnode->ops.len(hdr, len);
		if (len < *hlen)
			return XDP2_STOP_LENGTH;
		if (*hlen < pnode->min_len)
			return *hlen < 0 ? *hlen : XDP2_STOP_LENGTH;
	}

	return XDP2_OKAY;
}

<!--(for root in roots)-->
/* ───────────────────────────────────────────────────────────────────
 * Mono entry function for parser '@!root['parser_name']!@'.
 * Root node: @!root['node_name']!@
 * ─────────────────────────────────────────────────────────────────── */

/* Forward-declare the parser-graph nodes so the goto labels can
 * reference them. (The actual parse_node structs are declared in
 * the included @!filename!@ via XDP2_MAKE_PARSE_NODE macros.) */

static __unused() __attribute__((always_inline)) int
	@!root['parser_name']!@_xdp2_parse_mono(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, struct xdp2_ctrl_data *ctrl,
		unsigned int flags)
{
	void *frame = (char *)metadata + parser->config.metameta_size;
	ssize_t hlen;
	int ret;
	int type;

	(void)flags;
	(void)frame;

	<!--(if root['parser_name'] == 'xdp2_parser_flow_dissector_l2')-->
	/* R3.4.1 + R3.4.5 fast-path: straight-line extractors for the
	 * common eth+ipv{4,6}+{tcp,udp,icmp,icmpv6} chains. Inlined at
	 * the top of the mono entry function. Sidesteps the parse graph
	 * entirely on a chain match; on miss, falls through to the
	 * goto-state body below. Each chain mirrors the metadata writes
	 * produced by the slow-path *_metadata functions so c-xdp2-mono
	 * stays parity-identical to c-xdp2-usp on chain hits.
	 *
	 * Hardcoded to the L2 parser; R3.4.4 will generalise via a
	 * XDP2_FAST_PATH_CHAIN annotation in the parser source. */
	{
		const unsigned char *p = (const unsigned char *)hdr;
		/* R3.4.1: eth+ipv4+{tcp,udp,icmp} */
		if (len >= 30 &&
		    p[0] == 0x08 && p[1] == 0x00 && p[2] == 0x45 &&
		    (p[8] & 0x3f) == 0 && p[9] == 0 && (p[8] & 0x20) == 0) {
			unsigned char ip_proto = p[11];
			if (ip_proto == 6 || ip_proto == 17 || ip_proto == 1) {
				struct xdp2_metadata_all *_meta = metadata;
				_meta->addr_type = XDP2_ADDR_TYPE_IPV4;
				_meta->l3_off = 2;
				_meta->ip_proto = ip_proto;
				memcpy(&_meta->addrs.v4_addrs[0], p + 14, 4);
				memcpy(&_meta->addrs.v4_addrs[1], p + 18, 4);
				if (ip_proto == 1) {
					_meta->icmp.type = p[22];
					_meta->icmp.code = p[23];
					if (icmp_has_id(p[22])) {
						__be16 id_be = *(const __be16 *)(p + 26);
						_meta->icmp.id = id_be ? id_be : htons(1);
					}
				} else {
					memcpy(&_meta->port16[0], p + 22, 4);
				}
				return XDP2_STOP_OKAY;
			}
		}
		/* R3.4.5: eth+ipv6+{tcp,udp,icmpv6}. IPv6 header is 40
		 * bytes (fixed); extension-header chains bail because the
		 * next_proto check below excludes them. p[2..3] = version+TC,
		 * p[8] = next_header (= L4 proto when no EH). */
		if (len >= 62 && p[0] == 0x86 && p[1] == 0xDD &&
		    (p[2] >> 4) == 6) {
			unsigned char nexthdr = p[8];
			if (nexthdr == 6 || nexthdr == 17 || nexthdr == 58) {
				struct xdp2_metadata_all *_meta = metadata;
				_meta->addr_type = XDP2_ADDR_TYPE_IPV6;
				_meta->l3_off = 2;
				_meta->ip_proto = nexthdr;
				/* flow_label = bottom 20 bits of the first
				 * 32-bit word (matches ip6_flowlabel +
				 * ntohl in parser_metadata.h). */
				__be32 flow_word = *(const __be32 *)(p + 2);
				_meta->flow_label = ntohl(flow_word) & 0x000FFFFF;
				memcpy(&_meta->addrs.v6_addrs[0], p + 10, 16);
				memcpy(&_meta->addrs.v6_addrs[1], p + 26, 16);
				if (nexthdr == 58) {
					/* ICMPv6 — same icmp_has_id sentinel
					 * shape as ICMPv4; id_be at +46 (ICMPv6
					 * header byte 4-5). */
					_meta->icmp.type = p[42];
					_meta->icmp.code = p[43];
					if (icmp_has_id(p[42])) {
						__be16 id_be = *(const __be16 *)(p + 46);
						_meta->icmp.id = id_be ? id_be : htons(1);
					}
				} else {
					/* TCP/UDP: src+dst ports at L4 offset 0. */
					memcpy(&_meta->port16[0], p + 42, 4);
				}
				return XDP2_STOP_OKAY;
			}
		}
		/* R3.4.5b: eth+8021Q+ipv4+{tcp,udp,icmp}. Single VLAN tag
		 * (4-byte 8021Q header at +2). VLAN metadata uses the
		 * XDP2_METADATA_TEMP_vlan_set_tpid shape from
		 * parser_metadata.h:660 — vlan[0].id, .priority, .tpid,
		 * and vlan_count++. Inner ethertype must be ETH_P_IP; IPv4
		 * logic mirrors R3.4.1 with offsets +4 to skip the VLAN tag. */
		if (len >= 34 && p[0] == 0x81 && p[1] == 0x00 &&
		    p[4] == 0x08 && p[5] == 0x00 && p[6] == 0x45 &&
		    (p[12] & 0x3f) == 0 && p[13] == 0 && (p[12] & 0x20) == 0) {
			unsigned char ip_proto = p[15];
			if (ip_proto == 6 || ip_proto == 17 || ip_proto == 1) {
				struct xdp2_metadata_all *_meta = metadata;
				/* VLAN metadata. TCI in network byte order:
				 * p[2] = priority(3)|dei(1)|VID_hi(4),
				 * p[3] = VID_lo(8). Slow path does
				 * ntohs(tci) & VLAN_VID_MASK for .id and
				 * (ntohs(tci) >> 13) for .priority. */
				unsigned short tci = (p[2] << 8) | p[3];
				_meta->vlan[0].id = tci & 0x0FFF;
				_meta->vlan[0].priority = tci >> 13;
				_meta->vlan[0].tpid = 0x8100;  /* ETH_P_8021Q */
				_meta->vlan_count = 1;
				/* IPv4 metadata (R3.4.1 logic, offsets +4). */
				_meta->addr_type = XDP2_ADDR_TYPE_IPV4;
				_meta->l3_off = 6;  /* etype(2) + vlan(4) */
				_meta->ip_proto = ip_proto;
				memcpy(&_meta->addrs.v4_addrs[0], p + 18, 4);
				memcpy(&_meta->addrs.v4_addrs[1], p + 22, 4);
				if (ip_proto == 1) {
					_meta->icmp.type = p[26];
					_meta->icmp.code = p[27];
					if (icmp_has_id(p[26])) {
						__be16 id_be = *(const __be16 *)(p + 30);
						_meta->icmp.id = id_be ? id_be : htons(1);
					}
				} else {
					memcpy(&_meta->port16[0], p + 26, 4);
				}
				return XDP2_STOP_OKAY;
			}
		}
		/* R3.4.5c: eth+8021Q+ipv6+{tcp,udp,icmpv6}. Mirrors R3.4.5b's
		 * VLAN handling and R3.4.5a's IPv6 handling, with IPv6 offsets
		 * shifted by +4 to skip the VLAN tag. Min len = 14 + 4 + 40 +
		 * 4 = 62 (eth + vlan + ipv6 + L4 ports/icmp). */
		if (len >= 66 && p[0] == 0x81 && p[1] == 0x00 &&
		    p[4] == 0x86 && p[5] == 0xDD && (p[6] >> 4) == 6) {
			unsigned char nexthdr = p[12];
			if (nexthdr == 6 || nexthdr == 17 || nexthdr == 58) {
				struct xdp2_metadata_all *_meta = metadata;
				/* VLAN metadata (same as R3.4.5b). */
				unsigned short tci = (p[2] << 8) | p[3];
				_meta->vlan[0].id = tci & 0x0FFF;
				_meta->vlan[0].priority = tci >> 13;
				_meta->vlan[0].tpid = 0x8100;  /* ETH_P_8021Q */
				_meta->vlan_count = 1;
				/* IPv6 metadata (R3.4.5a logic, offsets +4). */
				_meta->addr_type = XDP2_ADDR_TYPE_IPV6;
				_meta->l3_off = 6;  /* etype(2) + vlan(4) */
				_meta->ip_proto = nexthdr;
				__be32 flow_word = *(const __be32 *)(p + 6);
				_meta->flow_label = ntohl(flow_word) & 0x000FFFFF;
				memcpy(&_meta->addrs.v6_addrs[0], p + 14, 16);
				memcpy(&_meta->addrs.v6_addrs[1], p + 30, 16);
				if (nexthdr == 58) {
					/* ICMPv6 — same id-sentinel as ICMPv4;
					 * type/code at +46, id at +50. */
					_meta->icmp.type = p[46];
					_meta->icmp.code = p[47];
					if (icmp_has_id(p[46])) {
						__be16 id_be = *(const __be16 *)(p + 50);
						_meta->icmp.id = id_be ? id_be : htons(1);
					}
				} else {
					/* TCP/UDP: src+dst ports at L4 offset 0. */
					memcpy(&_meta->port16[0], p + 46, 4);
				}
				return XDP2_STOP_OKAY;
			}
		}
	}
	/* Fast-path miss — fall through to the standard graph body. */
	<!--(end)-->

	goto label_@!root['node_name']!@;

	<!--(for node in graph)-->

label_@!node!@: {
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node *)&@!node!@;
	const struct xdp2_proto_def *proto_def = parse_node->proto_def;

	ctrl->var.last_node = parse_node;

	ret = __mono_check_pkt_len(hdr, proto_def, len, &hlen);
	if (ret != XDP2_OKAY)
		return ret;

		<!--(if graph[node]['mt_full_coverage'])-->
			<!--(for t in graph[node]['metadata_transfers'])-->
	/* R3.3.4 devirt: @!t['name']!@ */
	memcpy((char *)metadata + @!t['dst_off']!@ / 8,
	       (const char *)hdr + @!t['src_off']!@ / 8,
	       @!t['length']!@ / 8);
			<!--(end)-->
		<!--(else)-->
	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(hdr, hlen, metadata,
						 frame, ctrl);
		<!--(end)-->

	if (parse_node->ops.handler) {
		ret = parse_node->ops.handler(hdr, hlen, metadata,
					      frame, ctrl);
		if (ret != XDP2_OKAY)
			return ret;
	}

		<!--(if len(graph[node]['out_edges']) != 0)-->
			<!--(if graph[node]['npi_simple'])-->
	/* R3.3.5 devirt: inline next_proto load.
	 * Eligibility (precomputed as npi_simple in template.cpp): the
	 * LLVM IR analysis described a byte-aligned full-mask 8/16/32-
	 * bit load with no scaled offset. That shape is the entire
	 * computation a hand-coded simple ops.next_proto would do (e.g.
	 * `return iph->protocol;` is exactly byte 9 of the IP header).
	 * Anything more complex — partial mask, shift, keyin lookup,
	 * conditional branch — leaves npi_simple=False and falls back
	 * to the indirect call below. */
	type = @!graph[node]['npi_expr']!@;
			<!--(else)-->
	type = proto_def->ops.next_proto_keyin ?
		proto_def->ops.next_proto_keyin(hdr,
				ctrl->key.keys[parse_node->key_sel]) :
		proto_def->ops.next_proto(hdr);

	if (type < 0)
		return type;
			<!--(end)-->

	if (!proto_def->overlay) {
		hdr = (char *)hdr + hlen;
		len -= hlen;
	}

	switch (type) {
			<!--(for edge_target in graph[node]['out_edges'])-->
	case @!edge_target['macro_name']!@:
		goto label_@!edge_target['target']!@;
			<!--(end)-->
	}
			<!--(if len(graph[node]['wildcard_proto_node']) != 0)-->
	goto label_@!graph[node]['wildcard_proto_node']!@;
			<!--(else)-->
	return parse_node->unknown_ret;
			<!--(end)-->
		<!--(else)-->
			<!--(if len(graph[node]['wildcard_proto_node']) != 0)-->
	if (!proto_def->overlay) {
		hdr = (char *)hdr + hlen;
		len -= hlen;
	}
	goto label_@!graph[node]['wildcard_proto_node']!@;
			<!--(else)-->
	return XDP2_STOP_OKAY;
			<!--(end)-->
		<!--(end)-->
}
	<!--(end)-->
}

/* Mono parser declaration. The runtime dispatch in xdp2_parse()
 * routes XDP2_MONOLITHIC to parser_entry_point directly. */
XDP2_PARSER_MONO(
	@!root['parser_name']!@_mono,
	"",
	@!root['node_name']!@,
	@!root['parser_name']!@_xdp2_parse_mono,
	(
		.max_nodes = @!root['max_nodes']!@,
		.max_encaps = @!root['max_encaps']!@,
		.max_frames = @!root['max_frames']!@,
		.metameta_size = @!root['metameta_size']!@,
		.frame_size = @!root['frame_size']!@,
		.num_counters = @!root['num_counters']!@,
		.num_keys = @!root['num_keys']!@,
		<!--(if root['okay_node'] != '')-->
		.okay_node = &@!root['okay_node']!@.pn,
		<!--(end)-->
		<!--(if root['fail_node'] != '')-->
		.fail_node = &@!root['fail_node']!@.pn,
		<!--(end)-->
		<!--(if root['atencap_node'] != '')-->
		.atencap_node = &@!root['atencap_node']!@.pn,
		<!--(end)-->
	)
);

<!--(end)-->
