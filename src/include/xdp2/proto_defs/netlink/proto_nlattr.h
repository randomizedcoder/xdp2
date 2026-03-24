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

#ifndef __XDP2_PROTO_NLATTR_H__
#define __XDP2_PROTO_NLATTR_H__

#include "xdp2/parser.h"

/* Netlink attribute (TLV format).
 * 4-byte header: nla_len (including header) + nla_type.
 * Leaf — TLV iteration handled at parse graph level.
 * Kernel: include/uapi/linux/netlink.h
 */

struct nlattr {
	__u16 nla_len;		/* length including header */
	__u16 nla_type;		/* type (lower 14 bits), NLA_F_NESTED (bit 15) */
};

#endif /* __XDP2_PROTO_NLATTR_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_nlattr protocol definition
 *
 * Parse Netlink attribute (leaf — TLV node)
 */
static const struct xdp2_proto_def xdp2_parse_nlattr __unused() = {
	.name = "Netlink Attr",
	.min_len = sizeof(struct nlattr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
