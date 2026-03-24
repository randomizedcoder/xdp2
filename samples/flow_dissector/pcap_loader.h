/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD */
/*
 * pcap_loader.h — Shared PCAP loading and packet storage utilities
 *
 * Extracted from benchmark.c for reuse by benchmark_bpf.c.
 * Provides packet storage, VLAN stripping, PCAP loading, and
 * timing helpers.
 */

#ifndef __SAMPLES_FLOW_DISSECTOR_PCAP_LOADER_H__
#define __SAMPLES_FLOW_DISSECTOR_PCAP_LOADER_H__

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "xdp2/pcap.h"

#define MAXPKT 65536
#define MAX_PACKETS 500000

/* Stored packet for repeated benchmark runs */
struct stored_packet {
	__u8 data[MAXPKT];
	size_t len;
	size_t l3_off;	/* Pre-computed L3 offset (past Ethernet + VLANs) */
};

/* Per-packet results for comparison */
/* Address type constants for parsed_result */
#define ADDR_TYPE_NONE	0
#define ADDR_TYPE_IPV4	1
#define ADDR_TYPE_IPV6	2
#define ADDR_TYPE_TIPC	3

/* Well-known tunnel UDP destination ports */
#define VXLAN_UDP_PORT	4789
#define GENEVE_UDP_PORT	6081

struct parsed_result {
	__u8 addr_type;
	__u8 ip_proto;
	__be32 ipv4_src, ipv4_dst;
	struct in6_addr ipv6_src, ipv6_dst;
	__be16 sport, dport;
	__u32 flow_label;
	__u16 thoff;
	__u8 is_frag;
	__u8 is_first_frag;
	/* ARP fields */
	__u32 arp_sip, arp_tip;
	__u8 arp_op;
	/* TIPC fields */
	__be32 tipc_key;
	/* IPsec/L2TP key */
	__be32 keyid;
};

static inline long long timespec_diff_ns(struct timespec *start,
					 struct timespec *end)
{
	return (end->tv_sec - start->tv_sec) * 1000000000LL +
	       (end->tv_nsec - start->tv_nsec);
}

/* Strip VLAN tags from packet, return offset to L3 header.
 * Handles 802.1Q and 802.1AD (QinQ) double-tagged frames.
 */
static inline size_t strip_vlans(void *data, size_t len, __be16 *ethertype)
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

/* Load all packets from a PCAP file into the packets array.
 * Returns the number of packets loaded, or -1 on error.
 */
static inline int load_pcap(const char *path, struct stored_packet *packets,
			    int max_packets)
{
	struct xdp2_pcap_file *pf;
	int npkts = 0;

	pf = xdp2_pcap_init(path);
	if (!pf) {
		fprintf(stderr, "Failed to open PCAP: %s\n", path);
		return -1;
	}

	while (npkts < max_packets) {
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

	return npkts;
}

/* Print a parsed_result in human-readable format */
static inline void print_parsed_result(unsigned int pktnum, const char *label,
				       struct parsed_result *r)
{
	char sbuf[INET6_ADDRSTRLEN], dbuf[INET6_ADDRSTRLEN];

	printf("  [%s] Pkt %u: ", label, pktnum);
	switch (r->addr_type) {
	case ADDR_TYPE_IPV4:
		inet_ntop(AF_INET, &r->ipv4_src, sbuf, sizeof(sbuf));
		inet_ntop(AF_INET, &r->ipv4_dst, dbuf, sizeof(dbuf));
		printf("IPv4 %s:%u -> %s:%u proto=%u",
		       sbuf, ntohs(r->sport), dbuf, ntohs(r->dport),
		       r->ip_proto);
		break;
	case ADDR_TYPE_IPV6:
		inet_ntop(AF_INET6, &r->ipv6_src, sbuf, sizeof(sbuf));
		inet_ntop(AF_INET6, &r->ipv6_dst, dbuf, sizeof(dbuf));
		printf("IPv6 %s:%u -> %s:%u proto=%u fl=0x%x",
		       sbuf, ntohs(r->sport), dbuf, ntohs(r->dport),
		       r->ip_proto, r->flow_label);
		break;
	case ADDR_TYPE_TIPC:
		printf("TIPC key=0x%x", ntohl(r->tipc_key));
		break;
	default:
		if (r->arp_op)
			printf("ARP op=%u sip=0x%x tip=0x%x",
			       r->arp_op, r->arp_sip, r->arp_tip);
		else
			printf("unknown addr_type=%u", r->addr_type);
		break;
	}
	if (r->is_frag)
		printf(" FRAG%s", r->is_first_frag ? "(first)" : "");
	if (r->keyid)
		printf(" keyid=0x%x", ntohl(r->keyid));
	printf("\n");
}

#endif /* __SAMPLES_FLOW_DISSECTOR_PCAP_LOADER_H__ */
