// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/*
 * AF_XDP parser sample: classify packets with XDP2 parser, then redirect
 * to an AF_XDP socket via XSKMAP for zero-copy delivery to userspace.
 *
 * Packet flow:
 *   NIC -> XDP program (this) -> XDP_REDIRECT -> XSKMAP -> UMEM -> Rust parser
 *
 * The XDP program parses each packet to extract metadata (5-tuple, etc.)
 * and then redirects it to the AF_XDP socket bound to the packet's RX queue.
 * Packets that fail parsing or have no bound socket fall through to the
 * kernel stack via XDP_PASS.
 *
 * Usage:
 *   1. Compile: make
 *   2. Load: ip link set dev eth0 xdpgeneric obj af_xdp_parser.xdp.o
 *   3. Run Rust AF_XDP reader (xdp2-bench --mode af-xdp --interface eth0)
 *   4. Send traffic to eth0
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "xdp2/xdp_tmpl.h"

#include "common.h"

#include "parser.xdp.h"

/* AF_XDP socket map: userspace binds XSK file descriptors here.
 * Key = RX queue index, Value = XSK socket fd.
 * Populated by userspace via bpf_map_update_elem() after creating
 * the AF_XDP socket.
 *
 * Modern BTF-annotated map definition (libbpf 1.0+ compatible — the
 * legacy bpf_elf_map/SEC("maps") format was dropped in libbpf 1.0).
 * LIBBPF_PIN_BY_NAME pins at /sys/fs/bpf/xsks_map which is exactly
 * where xdp2-bench's DEFAULT_XSKMAP_PATH looks.
 */
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} xsks_map SEC(".maps");

/* Per-CPU statistics for monitoring redirect vs pass vs parse-fail. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} af_xdp_stats SEC(".maps");

enum {
	STAT_REDIRECT = 0,
	STAT_PASS = 1,
	STAT_PARSE_FAIL = 2,
};

static __always_inline void inc_stat(__u32 key)
{
	__u64 *val = bpf_map_lookup_elem(&af_xdp_stats, &key);
	if (val)
		__sync_fetch_and_add(val, 1);
}

/* Packet processing callback: redirect successfully parsed packets
 * to the AF_XDP socket bound to this RX queue.
 *
 * The parsed metadata (IP addresses, ports, protocol) is available in
 * parser_ctx->frame for optional inspection. Currently we redirect
 * all successfully parsed packets regardless of protocol.
 */
static __always_inline int af_xdp_redirect(struct xdp_md *ctx,
					   struct af_xdp_parser_ctx *parser_ctx)
{
	inc_stat(STAT_REDIRECT);

	/* Redirect to the AF_XDP socket bound to this RX queue.
	 * Fallback: XDP_PASS if no socket is bound to this queue
	 * (e.g., queue not used by userspace).
	 */
	return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

/* Parser failure callback: deliver unrecognized packets to kernel stack. */
static __always_inline int af_xdp_parse_fail(int rc, struct xdp_md *xdp_ctx,
					     struct af_xdp_parser_ctx *ctx)
{
	inc_stat(STAT_PARSE_FAIL);
	return XDP_PASS;
}

/* Generate the XDP entry point using the XDP2 template macro.
 * This creates:
 *   - xdp_prog (SEC "xdp"): main entry, parses packet, calls af_xdp_redirect
 *   - parser_prog: tail-call continuation for complex headers
 *   - ctx_map: per-CPU parser state
 *   - parsers: tail-call program array
 */
XDP2_XDP_MAKE_PARSER_PROGRAM(xdp2_parser_simple_tuple,
			     struct af_xdp_parser_ctx,
			     sizeof(struct xdp2_metadata_all),
			     af_xdp_redirect, af_xdp_parse_fail);

char __license[] SEC("license") = "GPL";
