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

#ifndef __XDP2_PROTO_IB_LRH_H__
#define __XDP2_PROTO_IB_LRH_H__

#include "xdp2/parser.h"

/* InfiniBand Local Route Header (LRH).
 * 8-byte header at the start of IB link-layer frames.
 * Chainable — dispatches on LNH (Link Next Header) field.
 * Kernel: include/rdma/ib_pack.h
 *
 * LNH values (bits 1-0 of vl_lver_sl_lnh word):
 *   0 = Raw payload, 1 = IPv6, 2 = BTH, 3 = GRH+BTH
 */

#define IB_LNH_RAW		0
#define IB_LNH_IPV6		1
#define IB_LNH_BTH		2
#define IB_LNH_GRH		3

struct ib_lrh {
	__be16 vl_lver_sl_lnh;	/* VL(4)+LVer(4)+SL(4)+LNH(2)+reserved(2) */
	__be16 dlid;
	__be16 pktlen;		/* in 4-byte words */
	__be16 slid;
};

/* Next protocol: return LNH field for dispatch */
static inline int ib_lrh_proto(const void *vhdr)
{
	return ntohs(((struct ib_lrh *)vhdr)->vl_lver_sl_lnh) & 0x0003;
}

#endif /* __XDP2_PROTO_IB_LRH_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_ib_lrh protocol definition
 *
 * Parse InfiniBand LRH (8 bytes).
 * Next protocol returns LNH field for dispatch.
 */
static const struct xdp2_proto_def xdp2_parse_ib_lrh __unused() = {
	.name = "IB LRH",
	.min_len = sizeof(struct ib_lrh),
	.ops.next_proto = ib_lrh_proto,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
