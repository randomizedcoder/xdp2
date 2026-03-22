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

#include <arpa/inet.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "xdp2/pcap.h"
#include "xdp2/parser.h"
#include "xdp2/parser_metadata.h"
#include "xdp2/utility.h"

#include "flowdis/flow_dissector.h"

/* XDP2 parser extern declarations */
XDP2_PARSER_EXTERN(xdp2_parser_flow_dissector);
XDP2_PARSER_EXTERN(xdp2_parser_flow_dissector_opt);

#define MAXPKT 65536
#define MAX_PACKETS 100000

/* Stored packet for repeated benchmark runs */
struct stored_packet {
	__u8 data[MAXPKT];
	size_t len;
	size_t l3_off;	/* Pre-computed L3 offset (past Ethernet + VLANs) */
};

/* Per-packet results for comparison */
struct parsed_result {
	__u8 addr_type;		/* 0=none, 1=IPv4, 2=IPv6 */
	__u8 ip_proto;
	__be32 ipv4_src, ipv4_dst;
	struct in6_addr ipv6_src, ipv6_dst;
	__be16 sport, dport;
	__u32 flow_label;
	__u16 thoff;
	__u8 is_frag;
	__u8 is_first_frag;
};

static long long timespec_diff_ns(struct timespec *start, struct timespec *end)
{
	return (end->tv_sec - start->tv_sec) * 1000000000LL +
	       (end->tv_nsec - start->tv_nsec);
}

/* Initialize flowdis (kernel flow dissector port) */
struct flowdis_state {
	struct flow_dissector fd;
};

struct flowdis_all_keys {
	struct flow_keys f;
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
		result->addr_type = 1;
		result->ipv4_src = keys.f.addrs.v4addrs.src;
		result->ipv4_dst = keys.f.addrs.v4addrs.dst;
		break;
	case FLOW_DISSECTOR_KEY_IPV6_ADDRS:
		result->addr_type = 2;
		memcpy(&result->ipv6_src, &keys.f.addrs.v6addrs.src,
		       sizeof(result->ipv6_src));
		memcpy(&result->ipv6_dst, &keys.f.addrs.v6addrs.dst,
		       sizeof(result->ipv6_dst));
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

	return 0;
}

/* Strip VLAN tags from packet, return offset to L3 header.
 * Handles 802.1Q and 802.1AD (QinQ) double-tagged frames.
 */
static size_t strip_vlans(void *data, size_t len, __be16 *ethertype)
{
	struct ethhdr *ehdr = data;
	size_t offset = ETH_HLEN;
	__be16 proto;

	if (len < ETH_HLEN)
		return 0;

	proto = ehdr->h_proto;

	/* Strip up to 2 VLAN tags */
	for (int i = 0; i < 2; i++) {
		if (proto != htons(ETH_P_8021Q) &&
		    proto != htons(ETH_P_8021AD))
			break;
		if (offset + 4 > len)
			return 0;
		/* VLAN TCI (2 bytes) + encapsulated proto (2 bytes) */
		proto = *(__be16 *)(data + offset + 2);
		offset += 4;
	}

	*ethertype = proto;
	return offset;
}

/* Run xdp2 parser on a packet and extract results */
static int run_xdp2(const struct xdp2_parser *parser, void *data, size_t len,
		    struct parsed_result *result, int use_fast)
{
	struct xdp2_metadata_all metadata;
	struct xdp2_ctrl_data ctrl;
	__be16 ethertype;
	void *l3_data;
	size_t l3_off;
	size_t l3_len;
	int rc;

	l3_off = strip_vlans(data, len, &ethertype);
	if (!l3_off)
		return -1;

	/* Only handle IP and IPv6 */
	if (ethertype != htons(ETH_P_IP) && ethertype != htons(ETH_P_IPV6))
		return -1;

	memset(&metadata, 0, sizeof(metadata));
	memset(&ctrl, 0, sizeof(ctrl));
	l3_data = data + l3_off;
	l3_len = len - l3_off;

	XDP2_CTRL_SET_BASIC_PKT_DATA(&ctrl, l3_data, l3_data, l3_len, 0);

	if (use_fast)
		rc = xdp2_parse_fast(parser, l3_data, l3_len,
				     &metadata, &ctrl);
	else
		rc = xdp2_parse(parser, l3_data, l3_len,
				&metadata, &ctrl, 0);
	if (rc != XDP2_OKAY && rc != XDP2_STOP_OKAY &&
	    rc != XDP2_STOP_UNKNOWN_PROTO &&
	    rc != XDP2_STOP_ENCAP_DEPTH)
		return -1;

	/* Translate to common result format */
	memset(result, 0, sizeof(*result));

	switch (metadata.addr_type) {
	case XDP2_ADDR_TYPE_IPV4:
		result->addr_type = 1;
		result->ipv4_src = metadata.addrs.v4.saddr;
		result->ipv4_dst = metadata.addrs.v4.daddr;
		break;
	case XDP2_ADDR_TYPE_IPV6:
		result->addr_type = 2;
		memcpy(&result->ipv6_src, &metadata.addrs.v6.saddr,
		       sizeof(result->ipv6_src));
		memcpy(&result->ipv6_dst, &metadata.addrs.v6.daddr,
		       sizeof(result->ipv6_dst));
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

	return 0;
}

/* Compare two results, return 0 if match */
static int compare_results(unsigned int pktnum,
			   struct parsed_result *flowdis,
			   struct parsed_result *xdp2,
			   int verbose)
{
	int mismatch = 0;
	char buf[256];

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

	if (flowdis->addr_type == 1 && xdp2->addr_type == 1) {
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

	if (flowdis->addr_type == 2 && xdp2->addr_type == 2) {
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

	if (flowdis->sport != xdp2->sport ||
	    flowdis->dport != xdp2->dport) {
		if (verbose)
			fprintf(stderr,
				"  Pkt %u: ports %u:%u vs %u:%u\n",
				pktnum,
				ntohs(flowdis->sport), ntohs(flowdis->dport),
				ntohs(xdp2->sport), ntohs(xdp2->dport));
		mismatch = 1;
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

	return mismatch;
}

static void print_result(unsigned int pktnum, const char *label,
			 struct parsed_result *r)
{
	char sbuf[INET6_ADDRSTRLEN], dbuf[INET6_ADDRSTRLEN];

	printf("  [%s] Pkt %u: ", label, pktnum);
	switch (r->addr_type) {
	case 1:
		inet_ntop(AF_INET, &r->ipv4_src, sbuf, sizeof(sbuf));
		inet_ntop(AF_INET, &r->ipv4_dst, dbuf, sizeof(dbuf));
		printf("IPv4 %s:%u -> %s:%u proto=%u",
		       sbuf, ntohs(r->sport), dbuf, ntohs(r->dport),
		       r->ip_proto);
		break;
	case 2:
		inet_ntop(AF_INET6, &r->ipv6_src, sbuf, sizeof(sbuf));
		inet_ntop(AF_INET6, &r->ipv6_dst, dbuf, sizeof(dbuf));
		printf("IPv6 %s:%u -> %s:%u proto=%u fl=0x%x",
		       sbuf, ntohs(r->sport), dbuf, ntohs(r->dport),
		       r->ip_proto, r->flow_label);
		break;
	default:
		printf("unknown addr_type=%u", r->addr_type);
		break;
	}
	if (r->is_frag)
		printf(" FRAG%s", r->is_first_frag ? "(first)" : "");
	printf("\n");
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
	const struct xdp2_parser *parser;
	struct stored_packet *packets;
	struct flowdis_state fstate;
	struct xdp2_pcap_file *pf;
	int repeat = 100;
	int npkts = 0;
	int c;

	while ((c = getopt(argc, argv, "cpvOFn:")) != -1) {
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
		default:
			usage(argv[0]);
		}
	}

	if (optind != argc - 1)
		usage(argv[0]);

	/* Initialize kernel flowdis */
	flowdis_state_init(&fstate);

	/* Select xdp2 parser */
	parser = opt_parser ? xdp2_parser_flow_dissector_opt :
			      xdp2_parser_flow_dissector;

	/* Validate fast parser compatibility if requested */
	if (fast_parser) {
		if (!xdp2_parse_validate_fast(parser)) {
			fprintf(stderr,
				"Parser not compatible with fast path\n");
			exit(1);
		}
	}

	/* Read all packets from PCAP */
	pf = xdp2_pcap_init(argv[optind]);
	if (!pf) {
		fprintf(stderr, "Failed to open PCAP: %s\n", argv[optind]);
		exit(1);
	}

	packets = calloc(MAX_PACKETS, sizeof(struct stored_packet));
	if (!packets) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}

	while (npkts < MAX_PACKETS) {
		size_t plen;
		ssize_t len;
		__be16 etype;

		len = xdp2_pcap_readpkt(pf, packets[npkts].data,
					MAXPKT, &plen);
		if (len < 0)
			break;
		packets[npkts].len = plen;
		/* Pre-compute L3 offset (strip Ethernet + VLANs) */
		packets[npkts].l3_off = strip_vlans(packets[npkts].data,
						    plen, &etype);
		npkts++;
	}
	xdp2_pcap_close(pf);

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

	/* Correctness comparison */
	if (do_correctness) {
		int matches = 0, mismatches = 0;
		int flowdis_fail = 0, xdp2_fail = 0;

		printf("--- Correctness ---\n");

		for (int i = 0; i < npkts; i++) {
			struct parsed_result flowdis_r, xdp2_r;
			int fd_rc, xdp2_rc;

			fd_rc = run_flowdis(&fstate, packets[i].data,
					    packets[i].len, &flowdis_r);
			xdp2_rc = run_xdp2(parser, packets[i].data,
					   packets[i].len, &xdp2_r,
					   fast_parser);

			if (fd_rc < 0) {
				flowdis_fail++;
				continue;
			}
			if (xdp2_rc < 0) {
				xdp2_fail++;
				continue;
			}

			if (compare_results(i + 1, &flowdis_r, &xdp2_r,
					    verbose)) {
				mismatches++;
				if (verbose) {
					print_result(i + 1, "flowdis",
						     &flowdis_r);
					print_result(i + 1, "xdp2  ",
						     &xdp2_r);
				}
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

		/* Benchmark xdp2 parser (with memset) */
		memset(&ctrl, 0, sizeof(ctrl));
		clock_gettime(CLOCK_MONOTONIC_RAW, &t_start);
		for (int r = 0; r < repeat; r++) {
			for (int i = 0; i < npkts; i++) {
				void *l3_data;
				size_t l3_len;

				if (!packets[i].l3_off)
					continue;
				l3_data = packets[i].data + packets[i].l3_off;
				l3_len = packets[i].len - packets[i].l3_off;

				memset(&metadata, 0, sizeof(metadata));
				ctrl.var.encaps = 0;
				ctrl.var.node_cnt = 0;
				ctrl.var.ret_code = 0;
				ctrl.pkt.packet = l3_data;
				ctrl.pkt.start = l3_data;
				ctrl.pkt.pkt_len = l3_len;
				ctrl.pkt.seqno = 0;
				if (fast_parser)
					xdp2_parse_fast(parser, l3_data,
							l3_len, &metadata,
							&ctrl);
				else
					xdp2_parse(parser, l3_data, l3_len,
						   &metadata, &ctrl, 0);
			}
		}
		clock_gettime(CLOCK_MONOTONIC_RAW, &t_end);
		xdp2_ns = timespec_diff_ns(&t_start, &t_end);

		/* Benchmark xdp2 parser (parse-only, no metadata memset) */
		memset(&metadata, 0, sizeof(metadata));
		memset(&ctrl, 0, sizeof(ctrl));
		clock_gettime(CLOCK_MONOTONIC_RAW, &t_start);
		for (int r = 0; r < repeat; r++) {
			for (int i = 0; i < npkts; i++) {
				void *l3_data;
				size_t l3_len;

				if (!packets[i].l3_off)
					continue;
				l3_data = packets[i].data + packets[i].l3_off;
				l3_len = packets[i].len - packets[i].l3_off;

				ctrl.var.encaps = 0;
				ctrl.var.node_cnt = 0;
				ctrl.var.ret_code = 0;
				ctrl.pkt.packet = l3_data;
				ctrl.pkt.start = l3_data;
				ctrl.pkt.pkt_len = l3_len;
				if (fast_parser)
					xdp2_parse_fast(parser, l3_data,
							l3_len, &metadata,
							&ctrl);
				else
					xdp2_parse(parser, l3_data, l3_len,
						   &metadata, &ctrl, 0);
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
