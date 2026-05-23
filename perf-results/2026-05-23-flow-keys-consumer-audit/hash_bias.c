/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-or-later */
/*
 * Phase 3 follow-on — hash distribution bias test.
 *
 * Generates N synthetic IPv4 5-tuples with random src/dst
 * addresses and ports. Hashes each two ways:
 *  - "full" : siphash over a 40-B kernel-flow_keys-shaped buffer
 *             with zeros in tags/vlan/cvlan/keyid/icmp + populated
 *             basic/ports/v4_addrs (today's behavior on TCP/IPv4)
 *  - "small": siphash over a 16-B 5-tuple-only buffer
 *             (basic.ip_proto + ports + v4_addrs, packed)
 *
 * Buckets each hash into K=256 and K=4096 bins and computes
 * chi-squared against a uniform distribution.
 *
 * Question: does the smaller region hash give *worse* distribution
 * than the full one? Prediction (from siphash properties): no,
 * both should be statistically uniform — siphash is a PRF and
 * is unaffected by input length for distribution purposes.
 * The full region just wastes cycles hashing zeros.
 */

#define _GNU_SOURCE
#include <linux/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "siphash/siphash.h"

/* Full v4 hash region (40 B aligned) — basic/tags/vlan/cvlan/keyid/ports/icmp/v4_addrs */
struct full_v4_region {
	__u8   ip_proto;          /* basic.ip_proto */
	__u8   _pad0;
	__be16 n_proto;
	__u32  flow_label;        /* tags.flow_label */
	__u64  vlan;              /* vlan (8 B) */
	__u64  cvlan;             /* cvlan (8 B) */
	__be32 keyid;
	__be16 sport;
	__be16 dport;
	__u32  icmp;
	__be32 saddr;
	__be32 daddr;
} __attribute__((packed, aligned(8)));

/* Small 5-tuple region (16 B) — packed */
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

#define N_FLOWS  100000
#define K256     256
#define K4096    4096

static uint64_t rng_state = 0xdeadbeefcafebabeULL;

static __u32 rng_next(void)
{
	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state ^= rng_state >> 27;
	return (__u32)((rng_state * 2685821657736338717ULL) >> 32);
}

static void
chi_squared(const char *label, const uint32_t *bins, int k, int n)
{
	double expected = (double)n / k;
	double chi2 = 0.0;
	uint32_t mn = bins[0], mx = bins[0];
	double sum_sq = 0.0;

	for (int i = 0; i < k; i++) {
		double d = (double)bins[i] - expected;
		chi2 += d * d / expected;
		if (bins[i] < mn) mn = bins[i];
		if (bins[i] > mx) mx = bins[i];
		sum_sq += (double)bins[i] * bins[i];
	}
	/* Stddev of bin counts */
	double mean = (double)n / k;
	double var = (sum_sq / k) - (mean * mean);
	double stddev = sqrt(var);

	printf("  %-32s  chi2=%9.2f  (df=%d)  mean=%6.1f  stddev=%5.2f  min=%5u  max=%5u\n",
	       label, chi2, k - 1, mean, stddev, mn, mx);
}

int main(void)
{
	siphash_key_t key = {{ 0xdeadbeefcafebabeULL, 0x0123456789abcdefULL }};
	struct full_v4_region full = {0};
	struct small_v4_region small = {0};

	uint32_t *bins256_full   = calloc(K256,  sizeof(uint32_t));
	uint32_t *bins256_small  = calloc(K256,  sizeof(uint32_t));
	uint32_t *bins4096_full  = calloc(K4096, sizeof(uint32_t));
	uint32_t *bins4096_small = calloc(K4096, sizeof(uint32_t));

	printf("hash bias test — %d synthetic IPv4 5-tuples\n", N_FLOWS);
	printf("full region: %zu B, small region: %zu B\n",
	       sizeof(full), sizeof(small));
	printf("Compare chi-squared. Df = K-1 (255 or 4095).\n");
	printf("Uniform: chi2 ~ df with stddev ~ sqrt(2*df).\n\n");

	/* Constant fields */
	full.ip_proto    = 6;
	full.n_proto     = __builtin_bswap16(0x0800);
	small.ip_proto   = 6;

	for (int i = 0; i < N_FLOWS; i++) {
		__be32 sa = rng_next();
		__be32 da = rng_next();
		__be16 sp = (__be16)rng_next();
		__be16 dp = (__be16)rng_next();

		full.saddr = sa;  full.daddr = da;
		full.sport = sp;  full.dport = dp;
		small.saddr = sa; small.daddr = da;
		small.sport = sp; small.dport = dp;

		__u64 h_full  = __siphash_aligned(&full,  sizeof(full),  &key);
		__u64 h_small = __siphash_aligned(&small, sizeof(small), &key);

		bins256_full [h_full  & (K256  - 1)]++;
		bins256_small[h_small & (K256  - 1)]++;
		bins4096_full [h_full  & (K4096 - 1)]++;
		bins4096_small[h_small & (K4096 - 1)]++;
	}

	printf("[A] K=256 (low 8 bits) — RSS-style indirection table:\n");
	chi_squared("full   40-B region", bins256_full,  K256, N_FLOWS);
	chi_squared("small  16-B region", bins256_small, K256, N_FLOWS);

	printf("\n[B] K=4096 (low 12 bits) — larger bucket count:\n");
	chi_squared("full   40-B region", bins4096_full,  K4096, N_FLOWS);
	chi_squared("small  16-B region", bins4096_small, K4096, N_FLOWS);

	free(bins256_full);
	free(bins256_small);
	free(bins4096_full);
	free(bins4096_small);
	return 0;
}
