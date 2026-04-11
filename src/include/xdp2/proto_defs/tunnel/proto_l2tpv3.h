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

#ifndef __XDP2_PROTO_L2TPV3_H__
#define __XDP2_PROTO_L2TPV3_H__

#include <linux/types.h>
#include "xdp2/parser.h"

/* L2TPv3 header (RFC 3931)
 * Can be carried over UDP or directly over IP (protocol 115).
 */
struct l2tpv3_header {
	__be32	session_id;
	__be64	cookie;
} __attribute__((packed));

#endif /* __XDP2_PROTO_L2TPV3_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_l2tpv3 protocol definition
 *
 * Parse L2TPv3 header (leaf)
 */
static const struct xdp2_proto_def xdp2_parse_l2tpv3 __unused() = {
	.name = "L2TPv3",
	.min_len = sizeof(struct l2tpv3_header),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
