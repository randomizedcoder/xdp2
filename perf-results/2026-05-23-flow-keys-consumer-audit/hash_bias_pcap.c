/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-or-later */
/*
 * Phase 3 follow-on (pcap edition) — hash distribution bias test
 * on real-world traffic.
 *
 * Reads a pcap file, extracts IPv4 5-tuples (TCP and UDP only),
 * hashes each two ways:
 *   - full   : siphash over a kernel-flow_keys-shaped 40-B region
 *              (zero-padded for the cold fields)
 *   - small  : siphash over a packed 16-B 5-tuple region
 *
 * Buckets each hash into K=256 and K=4096, reports chi-squared
 * against uniform.
 *
 * Companion to hash_bias.c which used synthetic uniform tuples.
 * The synthetic test confirmed both regions give equivalent
 * distribution on uniform input; this test does the same on
 * real (typically heavy-tailed) traffic.
 *
 * Usage:
 *   gcc -O2 -I ../../src/include hash_bias_pcap.c \
 *       -L../../src/lib/siphash -lsiphash -lpcap -lm \
 *       -o hash_bias_pcap
 *   LD_LIBRARY_PATH=../../src/lib/siphash \
 *       ./hash_bias_pcap /path/to/some.pcap
 */

#define _GNU_SOURCE
#include <linux/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <netinet/in.h>
#include <pcap.h>

#include "siphash/siphash.h"

struct full_v4_region {
	__u8   ip_proto;
	__u8   _pad0;
	__be16 n_proto;
	__u32  flow_label;
	__u64  vlan;
	__u64  cvlan;
	__be32 keyid;
	__be16 sport;
	__be16 dport;
	__u32  icmp;
	__be32 saddr;
	__be32 daddr;
} __attribute__((packed, aligned(8)));

struct small_v4_region {
	__u8   ip_proto;
	__u8   _pad0;
	__u8   _pad1;
	__u8   _pad2;
	__be16 sport;
	__be16 dport;
	__be32 saddr;
	__be32 daddr;
} __attribute__((packed, aligned(8)));

#define K256  256
#define K4096 4096

static void
chi_squared(const char *label, const uint32_t *bins, int k, uint64_t n)
{
	double expected = (double)n / k;
	double chi2 = 0.0;
	uint32_t mn = bins[0], mx = bins[0];

	for (int i = 0; i < k; i++) {
		double d = (double)bins[i] - expected;
		chi2 += d * d / expected;
		if (bins[i] < mn) mn = bins[i];
		if (bins[i] > mx) mx = bins[i];
	}
	double mean = (double)n / k;
	printf("  %-32s  chi2=%10.2f  (df=%d)  mean=%6.1f  min=%5u  max=%5u\n",
	       label, chi2, k - 1, mean, mn, mx);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <pcap>\n", argv[0]);
		return 2;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *p = pcap_open_offline(argv[0] /*dummy*/, errbuf);
	p = pcap_open_offline(argv[1], errbuf);
	if (!p) {
		fprintf(stderr, "pcap_open_offline(%s): %s\n", argv[1], errbuf);
		return 1;
	}

	siphash_key_t key = {{ 0xdeadbeefcafebabeULL, 0x0123456789abcdefULL }};
	struct full_v4_region full = {0};
	struct small_v4_region small = {0};
	full.n_proto = htons(0x0800);

	uint32_t *bins256_full   = calloc(K256,  sizeof(uint32_t));
	uint32_t *bins256_small  = calloc(K256,  sizeof(uint32_t));
	uint32_t *bins4096_full  = calloc(K4096, sizeof(uint32_t));
	uint32_t *bins4096_small = calloc(K4096, sizeof(uint32_t));

	struct pcap_pkthdr *hdr;
	const u_char *data;
	int rc;
	uint64_t n_pkts = 0, n_v4_l4 = 0;
	int dl = pcap_datalink(p);

	while ((rc = pcap_next_ex(p, &hdr, &data)) == 1) {
		n_pkts++;

		/* Skip ethernet header */
		size_t off = 0;
		if (dl == DLT_EN10MB) {
			if (hdr->caplen < 14) continue;
			__u16 etype = ntohs(*(const __u16 *)(data + 12));
			off = 14;
			/* skip a single VLAN tag for the simple cases */
			if (etype == 0x8100) {
				if (hdr->caplen < 18) continue;
				etype = ntohs(*(const __u16 *)(data + 16));
				off = 18;
			}
			if (etype != 0x0800) continue; /* IPv4 only */
		} else if (dl == DLT_RAW) {
			off = 0;
		} else {
			continue;
		}

		/* Parse IPv4 */
		if (hdr->caplen < off + 20) continue;
		__u8 ver_ihl = data[off];
		if ((ver_ihl >> 4) != 4) continue;
		size_t ihl = (ver_ihl & 0x0f) * 4;
		if (hdr->caplen < off + ihl + 4) continue;
		__u8 proto = data[off + 9];
		if (proto != 6 && proto != 17) continue; /* TCP/UDP only */

		__be32 saddr, daddr;
		memcpy(&saddr, data + off + 12, 4);
		memcpy(&daddr, data + off + 16, 4);

		/* Ports */
		__be16 sport, dport;
		memcpy(&sport, data + off + ihl, 2);
		memcpy(&dport, data + off + ihl + 2, 2);

		full.ip_proto = proto;
		full.sport = sport;
		full.dport = dport;
		full.saddr = saddr;
		full.daddr = daddr;

		small.ip_proto = proto;
		small.sport = sport;
		small.dport = dport;
		small.saddr = saddr;
		small.daddr = daddr;

		__u64 h_full  = __siphash_aligned(&full,  sizeof(full),  &key);
		__u64 h_small = __siphash_aligned(&small, sizeof(small), &key);

		bins256_full [h_full  & (K256  - 1)]++;
		bins256_small[h_small & (K256  - 1)]++;
		bins4096_full [h_full  & (K4096 - 1)]++;
		bins4096_small[h_small & (K4096 - 1)]++;
		n_v4_l4++;
	}
	pcap_close(p);

	printf("pcap: %s\n", argv[1]);
	printf("packets read: %lu; IPv4 TCP/UDP packets hashed: %lu\n",
	       (unsigned long)n_pkts, (unsigned long)n_v4_l4);

	if (n_v4_l4 == 0) {
		printf("no IPv4 TCP/UDP packets in pcap; nothing to test\n");
		return 0;
	}

	printf("full region: %zu B, small region: %zu B\n",
	       sizeof(full), sizeof(small));
	printf("\n[A] K=256 (low 8 bits):\n");
	chi_squared("full   40-B region", bins256_full,  K256, n_v4_l4);
	chi_squared("small  16-B region", bins256_small, K256, n_v4_l4);

	printf("\n[B] K=4096 (low 12 bits):\n");
	chi_squared("full   40-B region", bins4096_full,  K4096, n_v4_l4);
	chi_squared("small  16-B region", bins4096_small, K4096, n_v4_l4);

	free(bins256_full);
	free(bins256_small);
	free(bins4096_full);
	free(bins4096_small);
	return 0;
}
