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

#ifndef __XDP2_PROTO_OSPF_H__
#define __XDP2_PROTO_OSPF_H__

#include "xdp2/parser.h"

/* OSPF (Open Shortest Path First, RFC 2328).
 * Common header for all OSPF packet types.
 * Leaf protocol — no further dispatch (auth data follows but is variable).
 */

struct ospfhdr {
	__u8 version;
	__u8 type;
	__be16 length;
	__be32 router_id;
	__be32 area_id;
	__be16 checksum;
	__be16 au_type;
};

#endif /* __XDP2_PROTO_OSPF_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_ospf protocol definition
 *
 * Parse OSPF header (leaf — open shortest path first)
 */
static const struct xdp2_proto_def xdp2_parse_ospf __unused() = {
	.name = "OSPF",
	.min_len = sizeof(struct ospfhdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
