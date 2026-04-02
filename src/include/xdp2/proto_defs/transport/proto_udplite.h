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

#ifndef __XDP2_PROTO_UDPLITE_H__
#define __XDP2_PROTO_UDPLITE_H__

#include "xdp2/parser.h"

/* UDP-Lite (Lightweight User Datagram Protocol, RFC 3828).
 * Same layout as UDP but 'length' field is checksum coverage.
 * Leaf protocol — no further dispatch.
 */

struct udplitehdr {
	__be16 source;
	__be16 dest;
	__be16 coverage;	/* Checksum coverage (unlike UDP length) */
	__be16 checksum;
};

#endif /* __XDP2_PROTO_UDPLITE_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_udplite protocol definition
 *
 * Parse UDP-Lite header (leaf — lightweight user datagram protocol)
 */
static const struct xdp2_proto_def xdp2_parse_udplite __unused() = {
	.name = "UDP-Lite",
	.min_len = sizeof(struct udplitehdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
