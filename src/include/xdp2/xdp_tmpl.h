/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
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

#ifndef __XDP2_XDP_TMPL_H__
#define __XDP2_XDP_TMPL_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "xdp2/parser.h"

#define PROG_MAP_ID 0xcafe

/* Convenience macro to  make an xdp program that invokes and XDP2
 * parser
 *
 * Aruments are:
 *   - PARSER: The name of the XDP2 parser
 *   - STRUCT: Type for user's context structure
 *   - FRAME_SIZE: Size of a metadat frame
 *   - PROCESS: Function to process packet after parsing
 *	int pocess(struct xdp_md *xdp_ctx,
 *		       struct <use_ctx> *ctx)
 *   - PARSER_FAIL: Function called when parser fails
 *	int parser_fail(struct xdp_md *xdp_ctx,
 *			struct <use_ctx> *ctx)
 *
 */
#define XDP2_XDP_MAKE_PARSER_PROGRAM(PARSER, STRUCT, FRAME_SIZE,	\
				      PROCESS, PARSER_FAIL)		\
int parser_prog(struct xdp_md *ctx);	/* fwd decl for prog-array init */ \
									\
/* Modern BTF-annotated map definitions (libbpf 1.0+ compatible).	\
 * Legacy bpf_elf_map / SEC("maps") / PIN_GLOBAL_NS were dropped in	\
 * libbpf 1.0. These maps are private to the XDP program and do NOT	\
 * need to be pinned for correct operation -- ctx_map is per-CPU	\
 * state, parsers is only read by bpf_tail_call. Samples that want	\
 * userspace inspection pin them via their own .xdp.c file. */		\
struct {								\
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);			\
	__uint(max_entries, 2);						\
	__type(key, __u32);						\
	__type(value, STRUCT);						\
} ctx_map SEC(".maps");							\
									\
/* Prog-array for tail-call to parser_prog. Modern libbpf auto-		\
 * populates __array(values, …) entries at load time, replacing the	\
 * iproute2-specific `.id = 0xcafe` auto-population mechanism. */	\
struct {								\
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);				\
	__uint(max_entries, 1);						\
	__uint(key_size, sizeof(__u32));				\
	/* __array MUST be last: it's a flexible array member. */	\
	__array(values, int (struct xdp_md *));				\
} parsers SEC(".maps") = {						\
	.values = { [0] = (void *)&parser_prog },			\
};									\
									\
static __always_inline STRUCT *xdp2_get_ctx(void)			\
{									\
	/* clang-10 has a bug if key == 0,				\
	 * it generates bogus bytecodes.				\
	 */								\
	__u32 key = 1;							\
									\
	return bpf_map_lookup_elem(&ctx_map, &key);			\
}									\
									\
/* Entry point for the XDP program.					\
 * Modern libbpf expects SEC("xdp"); the legacy iproute2 SEC("prog")	\
 * convention is no longer recognized as an XDP program type. */	\
SEC("xdp")								\
int xdp_prog(struct xdp_md *ctx)					\
{									\
	STRUCT *parser_ctx = xdp2_get_ctx();				\
	void *data_end = (void *)(long)ctx->data_end;			\
	void *data = (void *)(long)ctx->data;				\
	void *original = data;						\
	int rc = XDP2_OKAY;						\
									\
	if (!parser_ctx)						\
		return PARSER_FAIL(rc, ctx, NULL);			\
									\
	parser_ctx->ctx.frame_num = 0;					\
	parser_ctx->ctx.next = CODE_IGNORE;				\
	parser_ctx->ctx.metadata = parser_ctx->frame;			\
	parser_ctx->ctx.parser = PARSER;				\
									\
	/* Invoke XDP2 parser */					\
	rc = XDP2_PARSE_XDP(PARSER, &parser_ctx->ctx,			\
			     (const void **)&data, data_end, false, 0);	\
	if (rc != XDP2_OKAY && rc != XDP2_STOP_OKAY)			\
		return PARSER_FAIL(rc, ctx, parser_ctx);		\
									\
	if (parser_ctx->ctx.next != CODE_IGNORE) {			\
		/* Parser is not complete, need to continue in a	\
		 * tailcall						\
		 */							\
		parser_ctx->ctx.offset = data - original;		\
		bpf_xdp_adjust_head(ctx, parser_ctx->ctx.offset);	\
		bpf_tail_call(ctx, &parsers, 0);			\
	}								\
									\
	return PROCESS(ctx, parser_ctx);				\
}									\
									\
/* Tail call program. Continue parsing in a tail call.			\
 * Modern libbpf only recognizes a handful of XDP sub-sections		\
 * (xdp, xdp.frags, xdp/devmap, xdp/cpumap); arbitrary "xdp/foo" is	\
 * rejected. Both progs share SEC("xdp") -- libbpf disambiguates by	\
 * the C function name when building the object. The old		\
 * SEC("0xcafe/0") was iproute2's auto-population convention		\
 * (hex = PROG_MAP_ID), replaced by the __array(values, ...)		\
 * initializer on the parsers map. */					\
SEC("xdp")								\
int parser_prog(struct xdp_md *ctx)					\
{									\
	STRUCT *parser_ctx = xdp2_get_ctx();				\
	void *data_end = (void *)(long)ctx->data_end;			\
	const void *data = (void *)(long)ctx->data;			\
	const void *original = data;					\
	int rc = XDP2_OKAY;						\
									\
	if (!parser_ctx)						\
		return XDP_ABORTED;					\
									\
	/* XXXTH we need to set ctx.metadata here to satisfy the	\
	 * verifier. Not sure why we need to do this. Needs to be	\
	 * debugged							\
         */								\
        parser_ctx->ctx.metadata = parser_ctx->frame;			\
									\
	/* Invoke XDP2 parser */					\
	rc = XDP2_PARSE_XDP(xdp2_parser_simple_tuple, &parser_ctx->ctx,	\
			    &data, data_end, false, 0);			\
									\
	if (rc != XDP2_OKAY && rc != XDP2_STOP_OKAY) {			\
		bpf_xdp_adjust_head(ctx, -parser_ctx->ctx.offset);	\
		return XDP_PASS;					\
	}								\
	if (parser_ctx->ctx.next != CODE_IGNORE) {			\
		/* Parser is not complete, need to continue in another	\
                 * tailcall						\
                 */							\
		parser_ctx->ctx.offset += data - original;		\
		bpf_xdp_adjust_head(ctx, data - original);		\
		bpf_tail_call(ctx, &parsers, 0);			\
	}								\
									\
	/* Call processing user function here */			\
	PROCESS(ctx, parser_ctx);					\
									\
	bpf_xdp_adjust_head(ctx, -parser_ctx->ctx.offset);		\
	return XDP_PASS;						\
}

#endif /* __XDP2_XDP_TMPL_H__ */
