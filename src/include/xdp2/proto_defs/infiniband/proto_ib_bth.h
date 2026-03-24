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

#ifndef __XDP2_PROTO_IB_BTH_H__
#define __XDP2_PROTO_IB_BTH_H__

#include "xdp2/parser.h"

/* InfiniBand Base Transport Header (BTH).
 * 12 bytes. Leaf for flow keys — opcode, pkey, dest QP.
 * Also used by RoCE v2 (UDP port 4791 → BTH).
 * Kernel: include/rdma/ib_pack.h
 */

struct ib_bth {
	__u8 opcode;		/* transport type + operation */
	__u8 flags;		/* SE, M, padcnt, TVer */
	__be16 pkey;		/* partition key */
	__be32 dest_qpn;	/* reserved(8) + dest QP(24) */
	__be32 apsn;		/* ack request(1) + PSN(24) + reserved(7) */
};

#endif /* __XDP2_PROTO_IB_BTH_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_ib_bth protocol definition
 *
 * Parse InfiniBand BTH (leaf — no further dispatch)
 */
static const struct xdp2_proto_def xdp2_parse_ib_bth __unused() = {
	.name = "IB BTH",
	.min_len = sizeof(struct ib_bth),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
