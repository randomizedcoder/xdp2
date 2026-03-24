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

#ifndef __XDP2_PROTO_IPX_H__
#define __XDP2_PROTO_IPX_H__

#include "xdp2/parser.h"

/* Novell IPX (ETH_P_IPX 0x8137).
 * Leaf protocol — 30-byte header with network addresses and ports.
 */

struct ipx_hdr {
	__be16 checksum;
	__be16 length;
	__u8 tc;		/* transport control (hop count) */
	__u8 type;		/* packet type */
	__u8 dest_net[4];
	__u8 dest_node[6];
	__be16 dest_port;
	__u8 src_net[4];
	__u8 src_node[6];
	__be16 src_port;
};

#endif /* __XDP2_PROTO_IPX_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_ipx protocol definition
 *
 * Parse IPX header (leaf — no further dispatch)
 */
static const struct xdp2_proto_def xdp2_parse_ipx __unused() = {
	.name = "IPX",
	.min_len = sizeof(struct ipx_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
