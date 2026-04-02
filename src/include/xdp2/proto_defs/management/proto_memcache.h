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

#ifndef __XDP2_PROTO_MEMCACHE_H__
#define __XDP2_PROTO_MEMCACHE_H__

#include "xdp2/parser.h"

/* Memcache binary protocol.
 * In-memory key-value store wire format.
 * Leaf protocol — no further dispatch.
 */

struct memcache_hdr {
	__u8 magic;		/* request(0x80), response(0x81) */
	__u8 opcode;
	__be16 key_length;
	__u8 extras_length;
	__u8 data_type;
	__be16 status;		/* vbucket_id (request) or status (response) */
	__be32 total_body;	/* total body length */
	__be32 opaque;		/* opaque token */
	__be64 cas;		/* compare-and-swap value */
};

#endif /* __XDP2_PROTO_MEMCACHE_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_memcache protocol definition
 *
 * Parse Memcache header (leaf)
 */
static const struct xdp2_proto_def xdp2_parse_memcache __unused() = {
	.name = "Memcache",
	.min_len = sizeof(struct memcache_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
