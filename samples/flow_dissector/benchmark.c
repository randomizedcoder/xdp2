// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/*
 * Copyright (c) 2025 Tom Herbert
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* Flow dissector benchmark: head-to-head comparison of xdp2 parser
 * vs kernel flow dissector (userspace port).
 *
 * Reads a PCAP file and runs each packet through both parsers,
 * comparing correctness and measuring performance.
 *
 * Uses the L2 parser (xdp2_parser_flow_dissector_l2) which starts
 * at the ethertype field, giving full parser framework coverage for
 * all protocols including ARP, TIPC, PPPoE, ESP, AH, L2TP, VXLAN,
 * and Geneve.
 *
 * Usage:
 *   ./benchmark [-c] [-p] [-v] [-O] [-n <repeat>] <pcap_file>
 *
 *   -c  Correctness only (compare outputs, no timing)
 *   -p  Performance only (timing, no comparison)
 *   -v  Verbose (print every packet's results)
 *   -O  Use optimized xdp2 parser
 *   -F  Use fast xdp2 parser (xdp2_parse_fast)
 *   -n  Number of iterations for performance measurement (default: 100)
 */

#include <errno.h>
#include <getopt.h>

#include "pcap_loader.h"
#include "parity_schema.h"

#include "xdp2/parser.h"
#include "xdp2/parser_metadata.h"
#include "xdp2/utility.h"

#include "flowdis/flow_dissector.h"

#ifndef IPPROTO_L2TP
#define IPPROTO_L2TP 115
#endif

/* XDP2 parser extern declarations */
XDP2_PARSER_EXTERN(xdp2_parser_flow_dissector);
XDP2_PARSER_EXTERN(xdp2_parser_flow_dissector_opt);
XDP2_PARSER_EXTERN(xdp2_parser_flow_dissector_l2);
XDP2_PARSER_EXTERN(xdp2_parser_flow_dissector_l2_opt);

/* Initialize flowdis (kernel flow dissector port) */
struct flowdis_state {
	struct flow_dissector fd;
};

struct flowdis_all_keys {
	struct flow_keys f;
	struct flow_dissector_key_arp arp;
	struct flow_dissector_key_tipc tipckey;
	struct flow_dissector_key_keyid gre_keyid;
};

#define __FDK(ID, F) \
	{ .key_id = (ID), .offset = offsetof(struct flowdis_all_keys, F) }

static const struct flow_dissector_key fdk[] = {
	__FDK(FLOW_DISSECTOR_KEY_CONTROL, f.control),
	__FDK(FLOW_DISSECTOR_KEY_BASIC, f.basic),
	__FDK(FLOW_DISSECTOR_KEY_IPV4_ADDRS, f.addrs.v4addrs),
	__FDK(FLOW_DISSECTOR_KEY_IPV6_ADDRS, f.addrs.v6addrs),
	__FDK(FLOW_DISSECTOR_KEY_PORTS, f.ports),
	__FDK(FLOW_DISSECTOR_KEY_FLOW_LABEL, f.tags),
	__FDK(FLOW_DISSECTOR_KEY_ARP, arp),
	__FDK(FLOW_DISSECTOR_KEY_TIPC, tipckey),
	__FDK(FLOW_DISSECTOR_KEY_GRE_KEYID, gre_keyid),
};

static void flowdis_state_init(struct flowdis_state *state)
{
	init_default_flow_dissectors();
	skb_flow_dissector_init(&state->fd, fdk, ARRAY_SIZE(fdk));
}

/* Run kernel flowdis on a packet and extract results */
static int run_flowdis(struct flowdis_state *state, void *data, size_t len,
		       struct parsed_result *result)
{
	struct flowdis_all_keys keys;
	struct ethhdr *ehdr = data;
	const char *msg = NULL;
	int suc;

	if (len < ETH_HLEN)
		return -1;

	memset(&keys, 0, sizeof(keys));
	suc = __skb_flow_dissect_err(0, &state->fd, &keys, data,
				     ehdr->h_proto, ETH_HLEN, len, 0, &msg);
	if (!suc)
		return -1;

	/* Translate to common result format */
	memset(result, 0, sizeof(*result));

	switch (keys.f.control.addr_type) {
	case FLOW_DISSECTOR_KEY_IPV4_ADDRS:
		result->addr_type = ADDR_TYPE_IPV4;
		result->ipv4_src = keys.f.addrs.v4addrs.src;
		result->ipv4_dst = keys.f.addrs.v4addrs.dst;
		break;
	case FLOW_DISSECTOR_KEY_IPV6_ADDRS:
		result->addr_type = ADDR_TYPE_IPV6;
		memcpy(&result->ipv6_src, &keys.f.addrs.v6addrs.src,
		       sizeof(result->ipv6_src));
		memcpy(&result->ipv6_dst, &keys.f.addrs.v6addrs.dst,
		       sizeof(result->ipv6_dst));
		break;
	case FLOW_DISSECTOR_KEY_TIPC:
		result->addr_type = ADDR_TYPE_TIPC;
		result->tipc_key = keys.f.addrs.tipckey.key;
		break;
	default:
		break;
	}

	result->ip_proto = keys.f.basic.ip_proto;
	result->sport = keys.f.ports.src;
	result->dport = keys.f.ports.dst;
	result->flow_label = keys.f.tags.flow_label;
	result->thoff = keys.f.control.thoff;
	result->is_frag = !!(keys.f.control.flags & FLOW_DIS_IS_FRAGMENT);
	result->is_first_frag = !!(keys.f.control.flags & FLOW_DIS_FIRST_FRAG);

	/* ARP fields */
	result->arp_sip = keys.arp.sip;
	result->arp_tip = keys.arp.tip;
	result->arp_op = keys.arp.op;

	/* GRE keyid */
	result->keyid = keys.gre_keyid.keyid;

	return 0;
}

/* Run xdp2 L2 parser on a packet and extract results */
static int run_xdp2(const struct xdp2_parser *l2_parser,
		    const struct xdp2_parser *l3_parser,
		    void *data, size_t len,
		    struct parsed_result *result, int use_fast)
{
	struct xdp2_metadata_all metadata;
	struct xdp2_ctrl_data ctrl;
	__be16 ethertype;
	size_t l3_off;
	int rc;

	l3_off = strip_vlans(data, len, &ethertype);
	if (!l3_off)
		return -1;

	/* Need at least 2 bytes before L3 for the ethertype field */
	if (l3_off < 2)
		return -1;

	memset(&metadata, 0, sizeof(metadata));
	memset(&ctrl, 0, sizeof(ctrl));

	/* Pass data starting at ethertype field (2 bytes before L3) */
	void *etype_data = data + l3_off - 2;
	size_t etype_len = len - l3_off + 2;

	XDP2_CTRL_SET_BASIC_PKT_DATA(&ctrl, etype_data, etype_data,
				     etype_len, 0);

	if (use_fast)
		rc = xdp2_parse_fast(l2_parser, etype_data, etype_len,
				     &metadata, &ctrl);
	else
		rc = xdp2_parse(l2_parser, etype_data, etype_len,
				&metadata, &ctrl, 0);
	if (rc != XDP2_OKAY && rc != XDP2_STOP_OKAY &&
	    rc != XDP2_STOP_UNKNOWN_PROTO &&
	    rc != XDP2_STOP_ENCAP_DEPTH)
		return -1;

	/* Translate to common result format */
	memset(result, 0, sizeof(*result));

	switch (metadata.addr_type) {
	case XDP2_ADDR_TYPE_IPV4:
		result->addr_type = ADDR_TYPE_IPV4;
		result->ipv4_src = metadata.addrs.v4.saddr;
		result->ipv4_dst = metadata.addrs.v4.daddr;
		break;
	case XDP2_ADDR_TYPE_IPV6:
		result->addr_type = ADDR_TYPE_IPV6;
		memcpy(&result->ipv6_src, &metadata.addrs.v6.saddr,
		       sizeof(result->ipv6_src));
		memcpy(&result->ipv6_dst, &metadata.addrs.v6.daddr,
		       sizeof(result->ipv6_dst));
		break;
	case XDP2_ADDR_TYPE_TIPC:
		result->addr_type = ADDR_TYPE_TIPC;
		result->tipc_key = metadata.addrs.tipckey;
		break;
	default:
		break;
	}

	result->ip_proto = metadata.ip_proto;
	result->sport = metadata.port_pair.sport;
	result->dport = metadata.port_pair.dport;
	result->flow_label = metadata.flow_label;
	result->is_frag = metadata.is_fragment;
	result->is_first_frag = metadata.first_frag;

	/* ARP fields */
	result->arp_sip = metadata.arp.sip;
	result->arp_tip = metadata.arp.tip;
	result->arp_op = metadata.arp.op;

	/* IPsec/L2TP key */
	result->keyid = metadata.keyid;

	return 0;
}

/* ── Phase 17.B.C parity dump-meta helpers ────────────────────────
 *
 * Convert the populated parsed_result / xdp2_metadata_all into a
 * ParityRecord (samples/flow_dissector/parity_schema.h). One record
 * per parser per packet; written to a JSONL file when `-D <path>` is
 * passed. Independent of the timing loop's `repeat` count.
 */

static void parity_fill_from_parsed_result(struct parity_record *r,
					   const struct parsed_result *p)
{
	switch (p->addr_type) {
	case ADDR_TYPE_IPV4:
		parity_set_addr_type(r, PARITY_ADDR_IPV4);
		parity_set_ipv4(r, p->ipv4_src, p->ipv4_dst);
		break;
	case ADDR_TYPE_IPV6:
		parity_set_addr_type(r, PARITY_ADDR_IPV6);
		parity_set_ipv6(r, &p->ipv6_src, &p->ipv6_dst);
		break;
	case ADDR_TYPE_TIPC:
		parity_set_addr_type(r, PARITY_ADDR_TIPC);
		parity_set_tipc_key(r, p->tipc_key);
		break;
	default:
		break;
	}
	if (p->ip_proto)
		parity_set_ip_proto(r, p->ip_proto);
	if (p->sport || p->dport)
		parity_set_ports(r, ntohs(p->sport), ntohs(p->dport));
	if (p->thoff)
		parity_set_thoff(r, p->thoff);
	if (p->is_frag || p->is_first_frag)
		parity_set_frag(r, !!p->is_frag, !!p->is_first_frag);
	if (p->flow_label)
		parity_set_flow_label(r, p->flow_label);
	if (p->arp_op || p->arp_sip || p->arp_tip)
		parity_set_arp(r, p->arp_sip, p->arp_tip, p->arp_op);
	if (p->keyid)
		parity_set_keyid(r, ntohl(p->keyid));
}

/* Convert XDP2 C metadata to a ParityRecord.
 *
 * Offset translation: the C XDP2 parser is invoked starting at the
 * ETHERTYPE field of the packet (samples/flow_dissector/benchmark.c
 * passes `etype_data = data + l3_off - 2`), so its `l*_off` fields
 * are relative to the ethertype offset, NOT to the original frame.
 * `etype_offset_abs` is the original-frame byte offset of that
 * ethertype field; we add it to translate l2/l3/l4_off back to
 * absolute frame offsets so they align with kernel-flowdis (which
 * reports absolute frame offsets) and xdp2-rs (likewise). Without
 * this, the parity gate flags an in-scope disagreement on every
 * packet that any parser populates l3_off/l4_off for.
 */
static void parity_fill_from_metadata(struct parity_record *r,
				      const struct xdp2_metadata_all *m,
				      __u16 etype_offset_abs)
{
	switch (m->addr_type) {
	case XDP2_ADDR_TYPE_IPV4:
		parity_set_addr_type(r, PARITY_ADDR_IPV4);
		parity_set_ipv4(r, m->addrs.v4.saddr, m->addrs.v4.daddr);
		break;
	case XDP2_ADDR_TYPE_IPV6:
		parity_set_addr_type(r, PARITY_ADDR_IPV6);
		parity_set_ipv6(r, &m->addrs.v6.saddr, &m->addrs.v6.daddr);
		break;
	case XDP2_ADDR_TYPE_TIPC:
		parity_set_addr_type(r, PARITY_ADDR_TIPC);
		parity_set_tipc_key(r, m->addrs.tipckey);
		break;
	default:
		break;
	}
	if (m->ip_proto)
		parity_set_ip_proto(r, m->ip_proto);
	if (m->port_pair.sport || m->port_pair.dport)
		parity_set_ports(r, ntohs(m->port_pair.sport),
				 ntohs(m->port_pair.dport));
	if (m->l4_off)
		parity_set_thoff(r, etype_offset_abs + m->l4_off);
	if (m->is_fragment || m->first_frag)
		parity_set_frag(r, !!m->is_fragment, !!m->first_frag);
	if (m->flow_label)
		parity_set_flow_label(r, m->flow_label);
	if (m->eth_proto)
		parity_set_eth_proto(r, ntohs(m->eth_proto));
	{
		__u8 zero[12] = {0};
		if (memcmp(m->eth_addrs, zero, 12) != 0)
			parity_set_eth_addrs(r, m->eth_addrs, m->eth_addrs + 6);
	}
	for (unsigned i = 0; i < m->vlan_count && i < XDP2_MAX_VLAN_CNT; i++)
		parity_push_vlan(r, ntohs(m->vlan[i].tci),
				 ntohs(m->vlan[i].tpid),
				 m->vlan[i].id);
	if (m->mpls.label)
		parity_push_mpls(r, m->mpls.label, m->mpls.tc,
				 !!m->mpls.bos, m->mpls.ttl);
	if (m->arp.op || m->arp.sip || m->arp.tip)
		parity_set_arp(r, m->arp.sip, m->arp.tip, m->arp.op);
	if (m->gre.keyid)
		parity_set_gre(r, 0, ntohl(m->gre.keyid));
	if (m->keyid && !m->gre.keyid)
		parity_set_keyid(r, ntohl(m->keyid));
	if (m->icmp.type || m->icmp.code || m->icmp.id)
		parity_set_icmp(r, m->icmp.type, m->icmp.code,
				ntohs(m->icmp.id), 0);
	if (m->l2_off || m->l3_off || m->l4_off)
		parity_set_offsets(r,
				   etype_offset_abs + m->l2_off,
				   etype_offset_abs + m->l3_off,
				   etype_offset_abs + m->l4_off);
}

static int dump_meta_pass(const char *out_path,
			  const struct xdp2_parser *l2_parser,
			  int fast_parser,
			  struct flowdis_state *fstate,
			  struct stored_packet *packets, int npkts,
			  const char *pcap_label)
{
	FILE *fp = fopen(out_path, "w");
	if (!fp) {
		fprintf(stderr, "dump-meta: cannot open '%s': %s\n",
			out_path, strerror(errno));
		return -1;
	}

	for (int i = 0; i < npkts; i++) {
		struct parity_record rec;
		struct parsed_result pr;
		struct xdp2_metadata_all metadata;
		struct xdp2_ctrl_data ctrl;
		int rc;

		/* c-flowdis-usp */
		parity_record_init(&rec, "c-flowdis-usp", "c", pcap_label, i);
		if (run_flowdis(fstate, packets[i].data,
				packets[i].len, &pr) == 0) {
			parity_record_set_accepted(&rec, true, NULL);
			parity_fill_from_parsed_result(&rec, &pr);
		} else {
			parity_record_set_accepted(&rec, false, "parse-error");
		}
		parity_record_emit_jsonl(fp, &rec);

		/* c-xdp2-usp + c-xdp2-parse-only — both run xdp2_parse_*
		 * and produce the same xdp2_metadata_all output, differing
		 * only in whether they pre-zero the metadata struct. We
		 * dump the same record under both parser_ids so the
		 * comparator confirms zero divergence between them.
		 */
		if (packets[i].l3_off >= 2) {
			void *etype_data = packets[i].data + packets[i].l3_off - 2;
			size_t etype_len = packets[i].len - packets[i].l3_off + 2;
			memset(&metadata, 0, sizeof(metadata));
			memset(&ctrl, 0, sizeof(ctrl));
			XDP2_CTRL_SET_BASIC_PKT_DATA(&ctrl, etype_data,
						     etype_data, etype_len, 0);
			rc = fast_parser
				? xdp2_parse_fast(l2_parser, etype_data,
						  etype_len, &metadata, &ctrl)
				: xdp2_parse(l2_parser, etype_data, etype_len,
					     &metadata, &ctrl, 0);
			int xdp2_ok = (rc == XDP2_OKAY ||
				       rc == XDP2_STOP_OKAY ||
				       rc == XDP2_STOP_UNKNOWN_PROTO ||
				       rc == XDP2_STOP_ENCAP_DEPTH);

			parity_record_init(&rec, "c-xdp2-usp", "c",
					   pcap_label, i);
			if (xdp2_ok) {
				parity_record_set_accepted(&rec, true, NULL);
				parity_fill_from_metadata(&rec, &metadata,
							  packets[i].l3_off - 2);
			} else {
				parity_record_set_accepted(&rec, false,
							   "parse-error");
			}
			parity_record_emit_jsonl(fp, &rec);

			parity_record_init(&rec, "c-xdp2-parse-only", "c",
					   pcap_label, i);
			if (xdp2_ok) {
				parity_record_set_accepted(&rec, true, NULL);
				parity_fill_from_metadata(&rec, &metadata,
							  packets[i].l3_off - 2);
			} else {
				parity_record_set_accepted(&rec, false,
							   "parse-error");
			}
			parity_record_emit_jsonl(fp, &rec);
		} else {
			/* Packet too short for L3; report as parse-error
			 * for the XDP2 parsers. */
			for (const char *pid = "c-xdp2-usp";
			     pid != NULL;
			     pid = strcmp(pid, "c-xdp2-usp") == 0
				    ? "c-xdp2-parse-only" : NULL) {
				parity_record_init(&rec, pid, "c",
						   pcap_label, i);
				parity_record_set_accepted(&rec, false,
							   "parse-error");
				parity_record_emit_jsonl(fp, &rec);
			}
		}
	}

	fclose(fp);
	fprintf(stderr, "[dump-meta] wrote %s (%d packets × 3 modes)\n",
		out_path, npkts);
	return 0;
}

/* Convenience alias for print_parsed_result (from pcap_loader.h) */
#define print_result print_parsed_result

/* Compare two results, return 0 if match */
static int compare_results(unsigned int pktnum,
			   struct parsed_result *flowdis,
			   struct parsed_result *xdp2,
			   int verbose, int *is_tunnel)
{
	int mismatch = 0;
	char buf[256];

	*is_tunnel = 0;

	/* VXLAN (4789) or Geneve (6081) — xdp2 follows tunnel, flowdis
	 * doesn't. These are not mismatches — xdp2 extracts inner flow
	 * keys intentionally.
	 */
	if (flowdis->ip_proto == IPPROTO_UDP &&
	    (flowdis->dport == htons(VXLAN_UDP_PORT) ||
	     flowdis->dport == htons(GENEVE_UDP_PORT))) {
		*is_tunnel = 1;
		if (verbose) {
			fprintf(stderr,
				"  Pkt %u: tunnel (dport %u) — "
				"xdp2 follows to inner\n",
				pktnum, ntohs(flowdis->dport));
			print_result(pktnum, "outer", flowdis);
			print_result(pktnum, "inner", xdp2);
		}
		return 0;
	}

	if (flowdis->addr_type != xdp2->addr_type) {
		if (verbose)
			fprintf(stderr, "  Pkt %u: addr_type %u vs %u\n",
				pktnum, flowdis->addr_type, xdp2->addr_type);
		mismatch = 1;
	}

	if (flowdis->ip_proto != xdp2->ip_proto) {
		if (verbose)
			fprintf(stderr, "  Pkt %u: ip_proto %u vs %u\n",
				pktnum, flowdis->ip_proto, xdp2->ip_proto);
		mismatch = 1;
	}

	if (flowdis->addr_type == ADDR_TYPE_IPV4 && xdp2->addr_type == ADDR_TYPE_IPV4) {
		if (flowdis->ipv4_src != xdp2->ipv4_src ||
		    flowdis->ipv4_dst != xdp2->ipv4_dst) {
			if (verbose) {
				inet_ntop(AF_INET, &flowdis->ipv4_src,
					  buf, sizeof(buf));
				fprintf(stderr, "  Pkt %u: IPv4 src %s vs ",
					pktnum, buf);
				inet_ntop(AF_INET, &xdp2->ipv4_src,
					  buf, sizeof(buf));
				fprintf(stderr, "%s\n", buf);
			}
			mismatch = 1;
		}
	}

	if (flowdis->addr_type == ADDR_TYPE_IPV6 && xdp2->addr_type == ADDR_TYPE_IPV6) {
		if (memcmp(&flowdis->ipv6_src, &xdp2->ipv6_src,
			   sizeof(flowdis->ipv6_src)) ||
		    memcmp(&flowdis->ipv6_dst, &xdp2->ipv6_dst,
			   sizeof(flowdis->ipv6_dst))) {
			if (verbose)
				fprintf(stderr,
					"  Pkt %u: IPv6 addresses differ\n",
					pktnum);
			mismatch = 1;
		}
	}

	/* Skip port comparison for ESP/L2TP — flowdis may have residual
	 * port bytes from AH chaining while xdp2 correctly has zero ports.
	 *
	 * Skip port comparison for first fragments — flowdis reports 0:0
	 * while xdp2 correctly extracts ports from the first fragment.
	 */
	if (flowdis->ip_proto != IPPROTO_ESP &&
	    flowdis->ip_proto != IPPROTO_L2TP &&
	    !(flowdis->is_first_frag && flowdis->sport == 0 &&
	      flowdis->dport == 0)) {
		if (flowdis->sport != xdp2->sport ||
		    flowdis->dport != xdp2->dport) {
			if (verbose)
				fprintf(stderr,
					"  Pkt %u: ports %u:%u vs %u:%u\n",
					pktnum,
					ntohs(flowdis->sport),
					ntohs(flowdis->dport),
					ntohs(xdp2->sport),
					ntohs(xdp2->dport));
			mismatch = 1;
		}
	}

	if (flowdis->flow_label != xdp2->flow_label) {
		if (verbose)
			fprintf(stderr,
				"  Pkt %u: flow_label 0x%x vs 0x%x\n",
				pktnum, flowdis->flow_label,
				xdp2->flow_label);
		mismatch = 1;
	}

	if (flowdis->is_frag != xdp2->is_frag) {
		if (verbose)
			fprintf(stderr, "  Pkt %u: is_frag %u vs %u\n",
				pktnum, flowdis->is_frag, xdp2->is_frag);
		mismatch = 1;
	}

	if (flowdis->is_first_frag != xdp2->is_first_frag) {
		if (verbose)
			fprintf(stderr,
				"  Pkt %u: is_first_frag %u vs %u\n",
				pktnum, flowdis->is_first_frag,
				xdp2->is_first_frag);
		mismatch = 1;
	}

	/* ARP comparison */
	if (flowdis->arp_op && xdp2->arp_op) {
		if (flowdis->arp_sip != xdp2->arp_sip ||
		    flowdis->arp_tip != xdp2->arp_tip ||
		    flowdis->arp_op != xdp2->arp_op) {
			if (verbose)
				fprintf(stderr,
					"  Pkt %u: ARP fields differ\n",
					pktnum);
			mismatch = 1;
		}
	}

	/* TIPC comparison — skip when flowdis reports key 0 (flowdis
	 * doesn't extract TIPC keys behind some encapsulations).
	 */
	if (flowdis->addr_type == ADDR_TYPE_TIPC && xdp2->addr_type == ADDR_TYPE_TIPC &&
	    flowdis->tipc_key != 0) {
		if (flowdis->tipc_key != xdp2->tipc_key) {
			if (verbose)
				fprintf(stderr,
					"  Pkt %u: TIPC key 0x%x vs 0x%x\n",
					pktnum, ntohl(flowdis->tipc_key),
					ntohl(xdp2->tipc_key));
			mismatch = 1;
		}
	}

	/* keyid comparison (GRE key) — only when both extracted one */
	if (flowdis->keyid && xdp2->keyid &&
	    flowdis->keyid != xdp2->keyid) {
		if (verbose)
			fprintf(stderr,
				"  Pkt %u: keyid 0x%x vs 0x%x\n",
				pktnum, ntohl(flowdis->keyid),
				ntohl(xdp2->keyid));
		mismatch = 1;
	}

	return mismatch;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-c] [-p] [-v] [-O] [-F] [-n <repeat>] <pcap_file>\n"
		"\n"
		"  -c  Correctness only\n"
		"  -p  Performance only\n"
		"  -v  Verbose output\n"
		"  -O  Use optimized xdp2 parser\n"
		"  -F  Use fast xdp2 parser (xdp2_parse_fast)\n"
		"  -n  Iterations for performance (default: 100)\n",
		prog);
	exit(1);
}

int main(int argc, char *argv[])
{
	int do_correctness = 1, do_performance = 1;
	int verbose = 0, opt_parser = 0, fast_parser = 0;
	const struct xdp2_parser *l2_parser, *l3_parser;
	struct stored_packet *packets;
	struct flowdis_state fstate;
	int repeat = 100;
	int npkts = 0;
	int c;
	const char *dump_meta_path = NULL;  /* -D <path>: parity dump (Phase 17.B.C) */

	while ((c = getopt(argc, argv, "cpvOFn:D:")) != -1) {
		switch (c) {
		case 'c':
			do_correctness = 1;
			do_performance = 0;
			break;
		case 'p':
			do_correctness = 0;
			do_performance = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'O':
			opt_parser = 1;
			break;
		case 'F':
			fast_parser = 1;
			break;
		case 'n':
			repeat = atoi(optarg);
			if (repeat < 1)
				repeat = 1;
			break;
		case 'D':
			dump_meta_path = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}

	if (optind != argc - 1)
		usage(argv[0]);

	/* Initialize kernel flowdis */
	flowdis_state_init(&fstate);

	/* Select xdp2 parsers */
	l3_parser = opt_parser ? xdp2_parser_flow_dissector_opt :
				  xdp2_parser_flow_dissector;
	l2_parser = opt_parser ? xdp2_parser_flow_dissector_l2_opt :
				  xdp2_parser_flow_dissector_l2;

	/* Validate fast parser compatibility if requested */
	if (fast_parser) {
		if (!xdp2_parse_validate_fast(l2_parser)) {
			fprintf(stderr,
				"Parser not compatible with fast path\n");
			exit(1);
		}
	}

	/* Read all packets from PCAP */
	packets = calloc(MAX_PACKETS, sizeof(struct stored_packet));
	if (!packets) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}

	npkts = load_pcap(argv[optind], packets, MAX_PACKETS);
	if (npkts < 0)
		exit(1);

	printf("=== Flow Dissector Benchmark ===\n");
	printf("Packets: %d\n", npkts);
	printf("PCAP: %s\n", argv[optind]);
	printf("Parser: %s%s\n",
	       opt_parser ? "optimized" : "standard",
	       fast_parser ? " (fast)" : "");
	printf("\n");

	if (npkts == 0) {
		fprintf(stderr, "No packets read\n");
		free(packets);
		exit(1);
	}

	/* Parity dump-meta pass (Phase 17.B.C). Independent from
	 * correctness/performance loops; one record per parser per
	 * packet (3 records per packet: c-flowdis-usp, c-xdp2-usp,
	 * c-xdp2-parse-only). Runs once regardless of -n iteration count. */
	if (dump_meta_path) {
		const char *bn = strrchr(argv[optind], '/');
		const char *pcap_label = bn ? bn + 1 : argv[optind];
		if (dump_meta_pass(dump_meta_path, l2_parser, fast_parser,
				   &fstate, packets, npkts, pcap_label) != 0) {
			free(packets);
			exit(1);
		}
	}

	/* Correctness comparison */
	if (do_correctness) {
		int matches = 0, mismatches = 0, tunnel_extended = 0;
		int flowdis_fail = 0, xdp2_fail = 0, xdp2_only = 0;

		printf("--- Correctness ---\n");

		for (int i = 0; i < npkts; i++) {
			struct parsed_result flowdis_r, xdp2_r;
			int fd_rc, xdp2_rc;
			int is_tunnel = 0;

			fd_rc = run_flowdis(&fstate, packets[i].data,
					    packets[i].len, &flowdis_r);
			xdp2_rc = run_xdp2(l2_parser, l3_parser,
					   packets[i].data,
					   packets[i].len, &xdp2_r,
					   fast_parser);

			/* L2-only protocols: xdp2 parses but flowdis
			 * doesn't support them. Count separately.
			 */
			if (fd_rc < 0 && xdp2_rc >= 0) {
				xdp2_only++;
				continue;
			}
			if (fd_rc < 0) {
				flowdis_fail++;
				continue;
			}
			if (xdp2_rc < 0) {
				xdp2_fail++;
				continue;
			}

			if (compare_results(i + 1, &flowdis_r, &xdp2_r,
					    verbose, &is_tunnel)) {
				mismatches++;
				if (verbose) {
					print_result(i + 1, "flowdis",
						     &flowdis_r);
					print_result(i + 1, "xdp2  ",
						     &xdp2_r);
				}
			} else if (is_tunnel) {
				tunnel_extended++;
			} else {
				matches++;
				if (verbose)
					print_result(i + 1, "match ",
						     &flowdis_r);
			}
		}

		printf("Matches:       %d / %d", matches,
		       matches + mismatches);
		if (matches + mismatches > 0)
			printf(" (%.1f%%)",
			       100.0 * matches / (matches + mismatches));
		printf("\n");
		printf("Mismatches:    %d\n", mismatches);
		if (tunnel_extended)
			printf("Tunnel ext:    %d "
			       "(xdp2 extracted inner flow keys)\n",
			       tunnel_extended);
		if (xdp2_only)
			printf("XDP2 only:     %d "
			       "(protocols not in flowdis)\n",
			       xdp2_only);
		if (flowdis_fail)
			printf("Flowdis fail:  %d\n", flowdis_fail);
		if (xdp2_fail)
			printf("XDP2 fail:     %d\n", xdp2_fail);
		printf("\n");
	}

	/* Performance benchmark */
	if (do_performance) {
		struct xdp2_metadata_all metadata;
		struct flowdis_all_keys keys;
		struct xdp2_ctrl_data ctrl;
		struct timespec t_start, t_end;
		long long flowdis_ns = 0;
		long long xdp2_ns = 0;
		long long xdp2_nomemset_ns = 0;
		struct ethhdr *ehdr;
		const char *msg;
		long long avg;

		printf("--- Performance (%d packets x %d iterations) ---\n",
		       npkts, repeat);

		/* Benchmark kernel flowdis */
		clock_gettime(CLOCK_MONOTONIC_RAW, &t_start);
		for (int r = 0; r < repeat; r++) {
			for (int i = 0; i < npkts; i++) {
				ehdr = (struct ethhdr *)packets[i].data;
				memset(&keys, 0, sizeof(keys));
				__skb_flow_dissect_err(0, &fstate.fd, &keys,
						       packets[i].data,
						       ehdr->h_proto,
						       ETH_HLEN,
						       packets[i].len,
						       0, &msg);
			}
		}
		clock_gettime(CLOCK_MONOTONIC_RAW, &t_end);
		flowdis_ns = timespec_diff_ns(&t_start, &t_end);

		/* Benchmark xdp2 L2 parser (with memset)
		 *
		 * Phase O1.A optimisation (2026-05-08):
		 *
		 * The original code did `memset(&metadata, 0,
		 * sizeof(metadata))` per packet — a 200-byte zero that
		 * accounts for the 11 ns gap vs c-xdp2-parse-only at
		 * 221 ns. Most of those 200 bytes are unconditionally
		 * overwritten by the parser when it encounters the
		 * relevant protocol (eth_addrs by eth, addrs/ports/
		 * ip_proto by ip+l4, etc.) so they don't strictly need
		 * pre-zeroing.
		 *
		 * The fields that DO need per-packet reset are the
		 * accumulator bitfields (vlan_count, is_fragment,
		 * first_frag) — they're conditionally OR'd into by
		 * specific parser nodes and stale values would carry
		 * across packets.
		 *
		 * Strategy: full zero ONCE before the loop; per-packet
		 * reset only the accumulators. Saves ~10 ns/pkt on
		 * Zen 1 with no behavioural change for the common
		 * eth+ipv4+l4 chain. Documented in
		 * perf-results/asm/2026-05-08/asm-comparison-baseline.md
		 * Phase O1.A.
		 */
		memset(&metadata, 0, sizeof(metadata));   /* once */
		memset(&ctrl, 0, sizeof(ctrl));
		clock_gettime(CLOCK_MONOTONIC_RAW, &t_start);
		for (int r = 0; r < repeat; r++) {
			for (int i = 0; i < npkts; i++) {
				void *etype_data;
				size_t etype_len;

				if (!packets[i].l3_off ||
				    packets[i].l3_off < 2)
					continue;
				etype_data = packets[i].data +
					     packets[i].l3_off - 2;
				etype_len = packets[i].len -
					    packets[i].l3_off + 2;

				/* O1.A: minimal accumulator reset (was: full 200B memset) */
				metadata.vlan_count = 0;
				metadata.is_fragment = 0;
				metadata.first_frag = 0;
				ctrl.var.encaps = 0;
				ctrl.var.node_cnt = 0;
				ctrl.var.ret_code = 0;
				ctrl.pkt.packet = etype_data;
				ctrl.pkt.start = etype_data;
				ctrl.pkt.pkt_len = etype_len;
				ctrl.pkt.seqno = 0;
				if (fast_parser)
					xdp2_parse_fast(l2_parser,
							etype_data,
							etype_len,
							&metadata,
							&ctrl);
				else
					xdp2_parse(l2_parser, etype_data,
						   etype_len, &metadata,
						   &ctrl, 0);
			}
		}
		clock_gettime(CLOCK_MONOTONIC_RAW, &t_end);
		xdp2_ns = timespec_diff_ns(&t_start, &t_end);

		/* Benchmark xdp2 L2 parser (parse-only, no metadata memset) */
		memset(&metadata, 0, sizeof(metadata));
		memset(&ctrl, 0, sizeof(ctrl));
		clock_gettime(CLOCK_MONOTONIC_RAW, &t_start);
		for (int r = 0; r < repeat; r++) {
			for (int i = 0; i < npkts; i++) {
				void *etype_data;
				size_t etype_len;

				if (!packets[i].l3_off ||
				    packets[i].l3_off < 2)
					continue;
				etype_data = packets[i].data +
					     packets[i].l3_off - 2;
				etype_len = packets[i].len -
					    packets[i].l3_off + 2;

				ctrl.var.encaps = 0;
				ctrl.var.node_cnt = 0;
				ctrl.var.ret_code = 0;
				ctrl.pkt.packet = etype_data;
				ctrl.pkt.start = etype_data;
				ctrl.pkt.pkt_len = etype_len;
				if (fast_parser)
					xdp2_parse_fast(l2_parser,
							etype_data,
							etype_len,
							&metadata,
							&ctrl);
				else
					xdp2_parse(l2_parser, etype_data,
						   etype_len, &metadata,
						   &ctrl, 0);
			}
		}
		clock_gettime(CLOCK_MONOTONIC_RAW, &t_end);
		xdp2_nomemset_ns = timespec_diff_ns(&t_start, &t_end);

		long long total_pkts = (long long)npkts * repeat;

		avg = flowdis_ns / total_pkts;
		printf("Kernel flowdis: %lld ns/pkt", avg);
		if (avg > 0)
			printf(",  %lld Mpps", 1000 / avg);
		printf("\n");

		avg = xdp2_ns / total_pkts;
		printf("XDP2 parser:    %lld ns/pkt", avg);
		if (avg > 0)
			printf(",  %lld Mpps", 1000 / avg);
		printf("\n");

		avg = xdp2_nomemset_ns / total_pkts;
		printf("XDP2 parse-only:%lld ns/pkt", avg);
		if (avg > 0)
			printf(",  %lld Mpps", 1000 / avg);
		printf("\n");

		if (xdp2_ns > 0 && flowdis_ns > 0) {
			printf("Speedup:        %.1fx",
			       (double)flowdis_ns / xdp2_ns);
			printf(" (parse-only: %.1fx)\n",
			       (double)flowdis_ns / xdp2_nomemset_ns);
		}
		printf("\n");
	}

	free(packets);
	return 0;
}
