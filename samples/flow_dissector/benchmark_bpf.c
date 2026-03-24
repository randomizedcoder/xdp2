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

/* BPF flow dissector benchmark: loads a BPF flow dissector program
 * and benchmarks it using BPF_PROG_TEST_RUN on packets from a PCAP file.
 *
 * This measures the real in-kernel JIT-compiled BPF performance, as
 * opposed to the userspace benchmark which measures C code performance.
 *
 * Requires CAP_BPF or CAP_SYS_ADMIN (typically run as root).
 *
 * Usage:
 *   ./benchmark_bpf [-c] [-p] [-v] [-n <repeat>] [-l <label>] -b <bpf_obj> <pcap_file>
 *
 *   -b  Path to compiled BPF flow dissector .o file
 *   -c  Correctness only (show flow keys, no timing)
 *   -p  Performance only (timing via BPF_PROG_TEST_RUN)
 *   -v  Verbose (print every packet's results)
 *   -n  BPF_PROG_TEST_RUN repeat count (default: 1000)
 *   -l  Output label for performance line (default: BPF flowdis)
 */

#include <errno.h>
#include <getopt.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* Prevent libpcap from re-defining struct bpf_insn (already from linux/bpf.h) */
#define PCAP_DONT_INCLUDE_PCAP_BPF_H

#include "pcap_loader.h"

/* ─── BPF program loading ─── */

struct bpf_flow_ctx {
	struct bpf_object *obj;
	int prog_fd;
};

/* Load a BPF flow dissector program and set up tail call prog_array.
 *
 * Pattern follows kernel selftest flow_dissector_load.h:bpf_flow_load().
 * The BPF flow dissector uses a jmp_table prog_array map with sub-programs
 * (IP=0, IPV6=1, IPV6OP=2, IPV6FR=3, MPLS=4, VLAN=5).
 */
static int load_bpf_flow_dissector(struct bpf_flow_ctx *ctx, const char *path)
{
	struct bpf_program *prog, *main_prog;
	struct bpf_map *prog_array;
	int prog_array_fd;
	int i, fd, err;

	ctx->obj = bpf_object__open(path);
	if (!ctx->obj) {
		fprintf(stderr, "Failed to open BPF object: %s\n", path);
		return -1;
	}

	/* Set all programs to FLOW_DISSECTOR type before loading */
	bpf_object__for_each_program(prog, ctx->obj) {
		bpf_program__set_type(prog, BPF_PROG_TYPE_FLOW_DISSECTOR);
	}

	err = bpf_object__load(ctx->obj);
	if (err) {
		fprintf(stderr, "Failed to load BPF object: %s (err=%d)\n",
			path, err);
		bpf_object__close(ctx->obj);
		return -1;
	}

	/* Find main entry program (_dissect) */
	main_prog = bpf_object__find_program_by_name(ctx->obj, "_dissect");
	if (!main_prog) {
		fprintf(stderr, "BPF program '_dissect' not found in %s\n",
			path);
		bpf_object__close(ctx->obj);
		return -1;
	}

	ctx->prog_fd = bpf_program__fd(main_prog);
	if (ctx->prog_fd < 0) {
		fprintf(stderr, "Failed to get fd for _dissect\n");
		bpf_object__close(ctx->obj);
		return -1;
	}

	/* Set up tail call jmp_table prog_array (optional — xdp2 BPF
	 * programs use a single _dissect function without tail calls) */
	prog_array = bpf_object__find_map_by_name(ctx->obj, "jmp_table");
	if (prog_array) {
		prog_array_fd = bpf_map__fd(prog_array);
		if (prog_array_fd < 0) {
			fprintf(stderr, "Failed to get fd for jmp_table\n");
			bpf_object__close(ctx->obj);
			return -1;
		}

		/* Insert all non-main programs into jmp_table by index */
		i = 0;
		bpf_object__for_each_program(prog, ctx->obj) {
			fd = bpf_program__fd(prog);
			if (fd < 0)
				continue;
			if (fd == ctx->prog_fd)
				continue;

			err = bpf_map_update_elem(prog_array_fd, &i, &fd,
						  BPF_ANY);
			if (err) {
				fprintf(stderr,
					"Failed to insert prog %d into jmp_table: %s\n",
					i, strerror(errno));
				bpf_object__close(ctx->obj);
				return -1;
			}
			i++;
		}
	}

	return 0;
}

/* ─── BPF_PROG_TEST_RUN wrapper ─── */

struct bpf_run_result {
	struct bpf_flow_keys flow_keys;
	__u32 duration_ns;
	__u32 retval;
};

/* Run BPF flow dissector on a single packet using BPF_PROG_TEST_RUN.
 *
 * Input: full Ethernet frame (data_in).
 * The kernel extracts eth->h_proto, sets nhoff=ETH_HLEN, and runs
 * the BPF program starting at L3.
 *
 * repeat=N runs the program N times and returns avg duration in ns.
 */
static int run_bpf_dissect(int prog_fd, void *pkt, size_t pkt_len,
			   int repeat, struct bpf_run_result *result)
{
	struct bpf_flow_keys flow_keys = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = pkt,
		.data_size_in = pkt_len,
		.data_out = &flow_keys,
		.data_size_out = sizeof(flow_keys),
		.repeat = repeat,
	);
	int err;

	err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (err) {
		return -1;
	}

	memcpy(&result->flow_keys, &flow_keys, sizeof(flow_keys));
	result->duration_ns = opts.duration;
	result->retval = opts.retval;

	return 0;
}

/* ─── BPF flow_keys → parsed_result translation ─── */

static void bpf_keys_to_result(struct bpf_flow_keys *keys,
				struct parsed_result *result)
{
	memset(result, 0, sizeof(*result));

	switch (keys->addr_proto) {
	case ETH_P_IP:
		result->addr_type = ADDR_TYPE_IPV4;
		result->ipv4_src = keys->ipv4_src;
		result->ipv4_dst = keys->ipv4_dst;
		break;
	case ETH_P_IPV6:
		result->addr_type = ADDR_TYPE_IPV6;
		memcpy(&result->ipv6_src, &keys->ipv6_src,
		       sizeof(result->ipv6_src));
		memcpy(&result->ipv6_dst, &keys->ipv6_dst,
		       sizeof(result->ipv6_dst));
		break;
	default:
		result->addr_type = ADDR_TYPE_NONE;
		break;
	}

	result->ip_proto = keys->ip_proto;
	result->sport = keys->sport;
	result->dport = keys->dport;
	result->flow_label = keys->flow_label;
	result->thoff = keys->thoff;
	result->is_frag = keys->is_frag;
	result->is_first_frag = keys->is_first_frag;
}

/* ─── CLI and main ─── */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-c] [-p] [-v] [-n <repeat>] [-l <label>] -b <bpf_obj> <pcap_file>\n"
		"\n"
		"  -b  Path to compiled BPF flow dissector .o file\n"
		"  -c  Correctness only (show flow keys)\n"
		"  -p  Performance only (timing via BPF_PROG_TEST_RUN)\n"
		"  -v  Verbose (print every packet's results)\n"
		"  -n  BPF_PROG_TEST_RUN repeat count (default: 1000)\n"
		"  -l  Output label for performance line (default: BPF flowdis)\n",
		prog);
	exit(1);
}

int main(int argc, char *argv[])
{
	int do_correctness = 1, do_performance = 1;
	const char *bpf_path = NULL;
	const char *label = "BPF flowdis";
	struct stored_packet *packets;
	struct bpf_flow_ctx bpf_ctx;
	int verbose = 0;
	int repeat = 1000;
	int npkts = 0;
	int c;

	while ((c = getopt(argc, argv, "cpvn:b:l:")) != -1) {
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
		case 'n':
			repeat = atoi(optarg);
			if (repeat < 1)
				repeat = 1;
			break;
		case 'b':
			bpf_path = optarg;
			break;
		case 'l':
			label = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}

	if (optind != argc - 1 || !bpf_path)
		usage(argv[0]);

	/* Load BPF flow dissector */
	if (load_bpf_flow_dissector(&bpf_ctx, bpf_path) < 0) {
		fprintf(stderr, "Failed to load BPF flow dissector\n");
		exit(1);
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

	printf("=== BPF Flow Dissector Benchmark ===\n");
	printf("Packets: %d\n", npkts);
	printf("PCAP: %s\n", argv[optind]);
	printf("BPF program: %s\n", bpf_path);
	printf("\n");

	if (npkts == 0) {
		fprintf(stderr, "No packets read\n");
		free(packets);
		exit(1);
	}

	/* Correctness: run each packet once and display flow keys */
	if (do_correctness) {
		int parsed = 0, parse_fail = 0, bpf_err = 0;

		printf("--- Correctness ---\n");

		for (int i = 0; i < npkts; i++) {
			struct bpf_run_result bpf_result;
			struct parsed_result result;
			int rc;

			if (packets[i].len < ETH_HLEN) {
				parse_fail++;
				continue;
			}

			rc = run_bpf_dissect(bpf_ctx.prog_fd,
					     packets[i].data,
					     packets[i].len,
					     1, &bpf_result);
			if (rc < 0) {
				bpf_err++;
				if (verbose)
					fprintf(stderr,
						"  Pkt %d: BPF_PROG_TEST_RUN failed\n",
						i + 1);
				continue;
			}

			bpf_keys_to_result(&bpf_result.flow_keys, &result);

			if (bpf_result.retval == BPF_OK) {
				parsed++;
				if (verbose)
					print_parsed_result(i + 1, "bpf",
							    &result);
			} else {
				parse_fail++;
				if (verbose)
					fprintf(stderr,
						"  Pkt %d: BPF returned %u (DROP)\n",
						i + 1, bpf_result.retval);
			}
		}

		printf("Parsed:        %d / %d", parsed, npkts);
		if (npkts > 0)
			printf(" (%.1f%%)", 100.0 * parsed / npkts);
		printf("\n");
		printf("Parse fail:    %d\n", parse_fail);
		if (bpf_err)
			printf("BPF errors:    %d\n", bpf_err);
		printf("\n");
	}

	/* Performance: BPF_PROG_TEST_RUN with repeat=N per packet */
	if (do_performance) {
		long long total_duration_ns = 0;
		int measured = 0;
		long long avg;

		printf("--- Performance (%d packets x %d BPF_PROG_TEST_RUN repeats) ---\n",
		       npkts, repeat);

		for (int i = 0; i < npkts; i++) {
			struct bpf_run_result bpf_result;
			int rc;

			if (packets[i].len < ETH_HLEN)
				continue;

			rc = run_bpf_dissect(bpf_ctx.prog_fd,
					     packets[i].data,
					     packets[i].len,
					     repeat, &bpf_result);
			if (rc < 0)
				continue;

			total_duration_ns += bpf_result.duration_ns;
			measured++;

			if (verbose)
				printf("  Pkt %d: %u ns/pkt (retval=%u)\n",
				       i + 1, bpf_result.duration_ns,
				       bpf_result.retval);
		}

		if (measured > 0) {
			avg = total_duration_ns / measured;
			printf("%s: %lld ns/pkt", label, avg);
			if (avg > 0)
				printf(",  %lld Mpps", 1000 / avg);
			printf("\n");
			printf("Packets measured: %d / %d\n", measured, npkts);
		} else {
			printf("No packets measured successfully\n");
		}
		printf("\n");
	}

	bpf_object__close(bpf_ctx.obj);
	free(packets);
	return 0;
}
