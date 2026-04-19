// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
//
// D4 coverage-parity test for xdp2-flow-ebpf fast-path.
//
// See samples/flow_dissector/docs/super-flow-dissector-plan.md §5 and
// super-flow-dissector-implementation.md D4.
//
// Runs two BPF flow dissectors on every packet of a PCAP via
// BPF_PROG_TEST_RUN and asserts that whenever the fast-path returns
// BPF_OK its `bpf_flow_keys` match the oracle's. The oracle defaults
// to the vendored upstream `bpf_flow.kern.o`; once D6 (slow-path
// fallback via xdp2-compiler) lands, the same harness will point at
// the slow-path program.
//
// Usage:
//   ./parity_test -f <fast.o> -r <oracle.o> [-v] <pcap_file>
//
// Exit status: 0 if every fast-path hit matched the oracle, 1 if any
// mismatch was seen, 2 on load/run error. Suitable for Nix/CI gating.
//

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include "../pcap_loader.h"

struct bpf_ctx {
	struct bpf_object *obj;
	int prog_fd;
};

/* Mirror of load_bpf_flow_dissector() in benchmark_bpf.c: open, set all
 * programs to FLOW_DISSECTOR type, load, find "_dissect", and if the
 * object has a jmp_table prog_array fill it with non-entry programs in
 * declaration order. */
static int load_dissector(struct bpf_ctx *ctx, const char *path)
{
	struct bpf_program *prog, *main_prog;
	struct bpf_map *prog_array;
	int prog_array_fd, fd, err, i;

	ctx->obj = bpf_object__open(path);
	if (!ctx->obj) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return -1;
	}

	bpf_object__for_each_program(prog, ctx->obj)
		bpf_program__set_type(prog, BPF_PROG_TYPE_FLOW_DISSECTOR);

	err = bpf_object__load(ctx->obj);
	if (err) {
		fprintf(stderr, "load %s: err=%d\n", path, err);
		bpf_object__close(ctx->obj);
		return -1;
	}

	main_prog = bpf_object__find_program_by_name(ctx->obj, "_dissect");
	if (!main_prog) {
		fprintf(stderr, "no '_dissect' program in %s\n", path);
		bpf_object__close(ctx->obj);
		return -1;
	}
	ctx->prog_fd = bpf_program__fd(main_prog);

	prog_array = bpf_object__find_map_by_name(ctx->obj, "jmp_table");
	if (prog_array) {
		prog_array_fd = bpf_map__fd(prog_array);
		i = 0;
		bpf_object__for_each_program(prog, ctx->obj) {
			fd = bpf_program__fd(prog);
			if (fd < 0 || fd == ctx->prog_fd)
				continue;
			err = bpf_map_update_elem(prog_array_fd, &i, &fd,
						  BPF_ANY);
			if (err) {
				fprintf(stderr,
					"jmp_table[%d] update in %s: %s\n",
					i, path, strerror(errno));
				bpf_object__close(ctx->obj);
				return -1;
			}
			i++;
		}
	}

	return 0;
}

static int run_once(int prog_fd, void *pkt, size_t pkt_len,
		    struct bpf_flow_keys *out, __u32 *retval)
{
	struct bpf_flow_keys keys = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = pkt,
		.data_size_in = pkt_len,
		.data_out = &keys,
		.data_size_out = sizeof(keys),
		.repeat = 1,
	);

	if (bpf_prog_test_run_opts(prog_fd, &opts))
		return -1;

	memcpy(out, &keys, sizeof(keys));
	*retval = opts.retval;
	return 0;
}

/* Compare fields the fast-path ETH/IPv4/TCP extractor populates. We
 * deliberately do NOT compare fields the current fast-path skeleton
 * doesn't set yet (e.g. flow_label, vlan, mpls) — those are covered by
 * future fast-path slots (D5) or by the slow-path fallback (D6). */
struct mismatch {
	const char *field;
	unsigned long fast;
	unsigned long oracle;
};

static int diff_keys(const struct bpf_flow_keys *fast,
		     const struct bpf_flow_keys *oracle,
		     struct mismatch *m, int max)
{
	int n = 0;

#define CHECK(F) do {							\
		if ((unsigned long)fast->F !=				\
		    (unsigned long)oracle->F && n < max) {		\
			m[n].field = #F;				\
			m[n].fast = (unsigned long)fast->F;		\
			m[n].oracle = (unsigned long)oracle->F;		\
			n++;						\
		}							\
	} while (0)

	CHECK(addr_proto);
	CHECK(ip_proto);
	CHECK(thoff);
	CHECK(sport);
	CHECK(dport);
	CHECK(ipv4_src);
	CHECK(ipv4_dst);
	CHECK(is_frag);
	CHECK(is_first_frag);
#undef CHECK
	return n;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s -f <fast.o> -r <oracle.o> [-v] <pcap_file>\n"
		"\n"
		"  -f  Fast-path BPF .o (xdp2-flow-ebpf)\n"
		"  -r  Oracle BPF .o (upstream bpf_flow.kern.o by default)\n"
		"  -v  Verbose (print each mismatch)\n", prog);
	exit(2);
}

int main(int argc, char *argv[])
{
	const char *fast_path = NULL, *oracle_path = NULL;
	struct bpf_ctx fast = {}, oracle = {};
	struct stored_packet *packets;
	int verbose = 0;
	int npkts, fast_hit = 0, fast_miss = 0, mismatches = 0;
	int run_err = 0;
	int c;

	while ((c = getopt(argc, argv, "f:r:v")) != -1) {
		switch (c) {
		case 'f': fast_path = optarg; break;
		case 'r': oracle_path = optarg; break;
		case 'v': verbose = 1; break;
		default: usage(argv[0]);
		}
	}
	if (optind != argc - 1 || !fast_path || !oracle_path)
		usage(argv[0]);

	if (load_dissector(&fast, fast_path) < 0)
		return 2;
	if (load_dissector(&oracle, oracle_path) < 0) {
		bpf_object__close(fast.obj);
		return 2;
	}

	packets = calloc(MAX_PACKETS, sizeof(*packets));
	if (!packets) {
		fprintf(stderr, "oom\n");
		return 2;
	}

	npkts = load_pcap(argv[optind], packets, MAX_PACKETS);
	if (npkts < 0)
		return 2;

	printf("=== xdp2-flow-ebpf D4 coverage-parity test ===\n");
	printf("Fast:   %s\n", fast_path);
	printf("Oracle: %s\n", oracle_path);
	printf("PCAP:   %s  (%d packets)\n\n", argv[optind], npkts);

	for (int i = 0; i < npkts; i++) {
		struct bpf_flow_keys fk = {}, ok_keys = {};
		__u32 fret = 0, oret = 0;

		if (packets[i].len < ETH_HLEN)
			continue;

		if (run_once(fast.prog_fd, packets[i].data, packets[i].len,
			     &fk, &fret) < 0 ||
		    run_once(oracle.prog_fd, packets[i].data, packets[i].len,
			     &ok_keys, &oret) < 0) {
			run_err++;
			continue;
		}

		if (fret != BPF_OK) {
			fast_miss++;
			continue;
		}
		fast_hit++;

		struct mismatch m[16];
		int n = diff_keys(&fk, &ok_keys, m, 16);
		if (n == 0)
			continue;

		mismatches++;
		if (verbose) {
			fprintf(stderr, "pkt %d: %d field(s) differ\n",
				i + 1, n);
			for (int j = 0; j < n; j++)
				fprintf(stderr,
					"  %-15s fast=0x%lx oracle=0x%lx\n",
					m[j].field, m[j].fast, m[j].oracle);
		}
	}

	printf("Fast-path hits:   %d / %d\n", fast_hit, npkts);
	printf("Fast-path misses: %d  (expected for non-IPv4-TCP or frag/options)\n",
	       fast_miss);
	if (run_err)
		printf("Run errors:       %d\n", run_err);
	printf("Mismatches:       %d\n", mismatches);

	bpf_object__close(fast.obj);
	bpf_object__close(oracle.obj);
	free(packets);
	return mismatches == 0 ? 0 : 1;
}
