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

#ifndef __XDP2_PROTO_IB_GRH_H__
#define __XDP2_PROTO_IB_GRH_H__

#include "xdp2/parser.h"

/* InfiniBand Global Route Header (GRH).
 * 40 bytes, same layout as IPv6 header.
 * Chainable — next_hdr field (always 0x1B for BTH in practice).
 * Also used by RoCE v1 (ETH_P_IBOE → GRH → BTH).
 * Kernel: include/rdma/ib_pack.h
 */

struct ib_grh {
	__be32 version_tclass_flow; /* version(4)+tclass(8)+flow(20) */
	__be16 paylen;
	__u8 next_hdr;		/* 0x1B for IB BTH */
	__u8 hop_limit;
	__u8 sgid[16];
	__u8 dgid[16];
};

#endif /* __XDP2_PROTO_IB_GRH_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_ib_grh protocol definition
 *
 * Parse InfiniBand GRH (40 bytes, leaf — always chains to BTH in graph)
 */
static const struct xdp2_proto_def xdp2_parse_ib_grh __unused() = {
	.name = "IB GRH",
	.min_len = sizeof(struct ib_grh),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
