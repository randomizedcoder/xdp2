/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-or-later */
/*
 * Phase 3 microbench — flow_hash_from_keys cost breakdown.
 *
 * Goal: answer "if the hash region shrank, how much faster would
 *       flow_hash_from_keys() be?"
 *
 * Measures:
 *  - __flow_hash_consistentify() cost (alone, no siphash)
 *  - siphash over a fixed-size buffer (no consistentify)
 *  - combined: consistentify + siphash (the full hot path)
 *
 * Sweep:
 *  - region sizes: 16, 24, 40, 56, 64, 72 bytes (multiples-of-8
 *    that bracket today's v4 (40 B) and v6 (64 B) and a hypothetical
 *    5-tuple-only layout (24 B))
 *  - addr_type: IPv4 / IPv6
 *
 * NOT a kernel benchmark — runs in userspace against the same
 * siphash impl XDP2 already ships (src/lib/siphash/siphash.c,
 * adapted from kernel lib/siphash.c). The relative costs
 * (consistentify vs siphash, N B vs N+M B) are
 * microarchitecture-portable for the trend; absolute cycles
 * differ between cores.
 */

#define _GNU_SOURCE
#include <linux/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <time.h>
#include <x86intrin.h>

#include "siphash/siphash.h"

/* ---- kernel flow_keys mirror (relevant part) ---- */
struct fk_control {
	__u16 thoff;
	__u16 addr_type;
	__u32 flags;
};
struct fk_basic {
	__be16 n_proto;
	__u8   ip_proto;
	__u8   padding;
};
struct fk_tags { __u32 flow_label; };
struct fk_vlan {
	__be16 vlan_tpid;
	__be16 vlan_dei_pcp;
	__be16 vlan_id;
	__be16 _reserved;
};
struct fk_keyid { __be32 keyid; };
struct fk_ports {
	union { __be32 ports; struct { __be16 src, dst; }; };
};
struct fk_icmp {
	__u8 type;
	__u8 code;
	__u16 id;
};
struct fk_v4 { __be32 src, dst; };
struct fk_v6 { __u8 src[16]; __u8 dst[16]; };
struct fk_addrs {
	union { struct fk_v4 v4; struct fk_v6 v6; } u;
};

#define FK_KEY_IPV4 1
#define FK_KEY_IPV6 2

struct flow_keys {
	struct fk_control control;
	struct fk_basic   basic __attribute__((aligned(SIPHASH_ALIGNMENT)));
	struct fk_tags    tags;
	struct fk_vlan    vlan;
	struct fk_vlan    cvlan;
	struct fk_keyid   keyid;
	struct fk_ports   ports;
	struct fk_icmp    icmp;
	struct fk_addrs   addrs;  /* must be last */
};

#define FK_HASH_OFFSET offsetof(struct flow_keys, basic)

/* ---- ported helpers ---- */
static inline const void *fk_hash_start(const struct flow_keys *fl)
{
	return &fl->basic;
}

static inline size_t fk_hash_length(const struct flow_keys *fl)
{
	size_t diff = FK_HASH_OFFSET + sizeof(fl->addrs);
	switch (fl->control.addr_type) {
	case FK_KEY_IPV4: diff -= sizeof(fl->addrs.u.v4); break;
	case FK_KEY_IPV6: diff -= sizeof(fl->addrs.u.v6); break;
	}
	return sizeof(*fl) - diff;
}

static inline void fk_consistentify(struct flow_keys *fl)
{
	switch (fl->control.addr_type) {
	case FK_KEY_IPV4:
		if ((__u32)fl->addrs.u.v4.dst < (__u32)fl->addrs.u.v4.src) {
			__be32 t = fl->addrs.u.v4.src;
			fl->addrs.u.v4.src = fl->addrs.u.v4.dst;
			fl->addrs.u.v4.dst = t;
		}
		if ((__u16)fl->ports.dst < (__u16)fl->ports.src) {
			__be16 t = fl->ports.src;
			fl->ports.src = fl->ports.dst;
			fl->ports.dst = t;
		}
		break;
	case FK_KEY_IPV6: {
		int diff = memcmp(&fl->addrs.u.v6.dst,
				  &fl->addrs.u.v6.src,
				  sizeof(fl->addrs.u.v6.dst));
		if (diff < 0) {
			__u32 *s = (__u32 *)fl->addrs.u.v6.src;
			__u32 *d = (__u32 *)fl->addrs.u.v6.dst;
			for (int i = 0; i < 4; i++) {
				__u32 t = s[i]; s[i] = d[i]; d[i] = t;
			}
		}
		if ((__u16)fl->ports.dst < (__u16)fl->ports.src) {
			__be16 t = fl->ports.src;
			fl->ports.src = fl->ports.dst;
			fl->ports.dst = t;
		}
		break;
	}
	}
}

/* full flow_hash_from_keys path */
static inline __u32 fk_hash(struct flow_keys *fl, const siphash_key_t *k)
{
	fk_consistentify(fl);
	__u32 h = __siphash_aligned(fk_hash_start(fl), fk_hash_length(fl), k);
	if (!h) h = 1;
	return h;
}

/* ---- timing harness ---- */
static inline uint64_t rdtsc_start(void)
{
	uint32_t hi, lo;
	asm volatile ("CPUID\n\t" "RDTSC\n\t"
		      "mov %%edx, %0\n\t" "mov %%eax, %1\n\t"
		      : "=r"(hi), "=r"(lo) :: "%rax", "%rbx", "%rcx", "%rdx");
	return ((uint64_t)hi << 32) | lo;
}
static inline uint64_t rdtsc_end(void)
{
	uint32_t hi, lo;
	asm volatile ("RDTSCP\n\t"
		      "mov %%edx, %0\n\t" "mov %%eax, %1\n\t" "CPUID\n\t"
		      : "=r"(hi), "=r"(lo) :: "%rax", "%rbx", "%rcx", "%rdx");
	return ((uint64_t)hi << 32) | lo;
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

#define ITERS 100000

static void
report(const char *name, uint64_t *samples, int n)
{
	qsort(samples, n, sizeof(uint64_t), cmp_u64);
	uint64_t p50 = samples[n / 2];
	uint64_t p10 = samples[n / 10];
	uint64_t p99 = samples[(n * 99) / 100];
	uint64_t min = samples[0];
	printf("  %-44s  min=%5lu  p10=%5lu  p50=%5lu  p99=%5lu\n",
	       name, (unsigned long)min, (unsigned long)p10,
	       (unsigned long)p50, (unsigned long)p99);
}

/* Build a populated flow_keys with a fixed v4 5-tuple */
static void populate_v4(struct flow_keys *fl)
{
	memset(fl, 0, sizeof(*fl));
	fl->control.addr_type = FK_KEY_IPV4;
	fl->basic.n_proto = __builtin_bswap16(0x0800);
	fl->basic.ip_proto = 6;
	fl->ports.src = __builtin_bswap16(54321);
	fl->ports.dst = __builtin_bswap16(443);
	fl->addrs.u.v4.src = __builtin_bswap32(0x0a000001);
	fl->addrs.u.v4.dst = __builtin_bswap32(0x0a000002);
}

static void populate_v6(struct flow_keys *fl)
{
	memset(fl, 0, sizeof(*fl));
	fl->control.addr_type = FK_KEY_IPV6;
	fl->basic.n_proto = __builtin_bswap16(0x86dd);
	fl->basic.ip_proto = 6;
	fl->ports.src = __builtin_bswap16(54321);
	fl->ports.dst = __builtin_bswap16(443);
	for (int i = 0; i < 16; i++) {
		fl->addrs.u.v6.src[i] = 0x10 + i;
		fl->addrs.u.v6.dst[i] = 0x20 + i;
	}
}

/* Buffer for "siphash over N bytes only" experiments. We need
 * the buffer to be at least 80 B because we sweep up to 72-B
 * region sizes plus alignment headroom. */
static __u64 sweep_buf[16] __attribute__((aligned(SIPHASH_ALIGNMENT)));

int main(void)
{
	siphash_key_t key = {{ 0xdeadbeefcafebabeULL, 0x0123456789abcdefULL }};
	struct flow_keys flv4, flv6, tmp;
	uint64_t *t;

	/* Pin to one core for stable rdtsc */
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(1, &set);
	if (sched_setaffinity(0, sizeof(set), &set) != 0)
		fprintf(stderr, "warning: sched_setaffinity failed\n");

	populate_v4(&flv4);
	populate_v6(&flv6);
	memset(sweep_buf, 0xa5, sizeof(sweep_buf));

	printf("flow_hash_from_keys() microbench — Phase 3\n");
	printf("CPU: see /proc/cpuinfo; %u iters per measurement; cycles\n\n",
	       ITERS);

	t = malloc(ITERS * sizeof(uint64_t));

	/* === group A: consistentify alone === */
	printf("[A] __flow_hash_consistentify only (no siphash):\n");

	for (int i = 0; i < ITERS; i++) {
		tmp = flv4;
		uint64_t s = rdtsc_start();
		fk_consistentify(&tmp);
		uint64_t e = rdtsc_end();
		t[i] = e - s;
	}
	report("consistentify v4 (already-sorted)", t, ITERS);

	for (int i = 0; i < ITERS; i++) {
		tmp = flv4;
		/* swap to force the consistentify swap path */
		tmp.addrs.u.v4.src = __builtin_bswap32(0xffffffff);
		uint64_t s = rdtsc_start();
		fk_consistentify(&tmp);
		uint64_t e = rdtsc_end();
		t[i] = e - s;
	}
	report("consistentify v4 (needs swap)", t, ITERS);

	for (int i = 0; i < ITERS; i++) {
		tmp = flv6;
		uint64_t s = rdtsc_start();
		fk_consistentify(&tmp);
		uint64_t e = rdtsc_end();
		t[i] = e - s;
	}
	report("consistentify v6 (already-sorted)", t, ITERS);

	for (int i = 0; i < ITERS; i++) {
		tmp = flv6;
		for (int j = 0; j < 16; j++)
			tmp.addrs.u.v6.src[j] = 0xff;
		uint64_t s = rdtsc_start();
		fk_consistentify(&tmp);
		uint64_t e = rdtsc_end();
		t[i] = e - s;
	}
	report("consistentify v6 (needs swap)", t, ITERS);

	/* === group B: siphash over N bytes === */
	printf("\n[B] __siphash_aligned over N bytes (no consistentify):\n");

	size_t sweep[] = { 16, 24, 32, 40, 48, 56, 64, 72 };
	for (size_t si = 0; si < sizeof(sweep) / sizeof(sweep[0]); si++) {
		size_t n = sweep[si];
		for (int i = 0; i < ITERS; i++) {
			uint64_t s = rdtsc_start();
			__u64 h = __siphash_aligned(sweep_buf, n, &key);
			uint64_t e = rdtsc_end();
			t[i] = e - s;
			__asm__ __volatile__ ("" :: "r"(h) : "memory");
		}
		char label[64];
		snprintf(label, sizeof(label), "siphash %2zu B", n);
		report(label, t, ITERS);
	}

	/* === group C: full fk_hash (consistentify + siphash) === */
	printf("\n[C] full flow_hash_from_keys() (consistentify + siphash):\n");

	for (int i = 0; i < ITERS; i++) {
		tmp = flv4;
		uint64_t s = rdtsc_start();
		__u32 h = fk_hash(&tmp, &key);
		uint64_t e = rdtsc_end();
		t[i] = e - s;
		__asm__ __volatile__ ("" :: "r"(h) : "memory");
	}
	report("flow_hash_from_keys v4 (40 B region)", t, ITERS);

	for (int i = 0; i < ITERS; i++) {
		tmp = flv6;
		uint64_t s = rdtsc_start();
		__u32 h = fk_hash(&tmp, &key);
		uint64_t e = rdtsc_end();
		t[i] = e - s;
		__asm__ __volatile__ ("" :: "r"(h) : "memory");
	}
	report("flow_hash_from_keys v6 (64 B region)", t, ITERS);

	/* === group D: hypothesis — what if the region were just the
	 *     5-tuple (24 B: basic + ports + v4 addrs)? === */
	printf("\n[D] hypothetical 5-tuple-only hash (24 B):\n");
	for (int i = 0; i < ITERS; i++) {
		tmp = flv4;
		uint64_t s = rdtsc_start();
		fk_consistentify(&tmp);
		__u64 h = __siphash_aligned(&tmp.basic, 24, &key);
		uint64_t e = rdtsc_end();
		t[i] = e - s;
		__asm__ __volatile__ ("" :: "r"(h) : "memory");
	}
	report("consistentify v4 + siphash 24 B", t, ITERS);

	free(t);
	return 0;
}
