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

#ifndef __XDP2_PROTO_TACACS_H__
#define __XDP2_PROTO_TACACS_H__

#include "xdp2/parser.h"

/* TACACS+ (Terminal Access Controller Access-Control System Plus, RFC 8907).
 * 12 bytes header. AAA protocol for network device administration.
 * Leaf protocol — no further dispatch.
 */

struct tacacs_hdr {
	__u8 major_minor;	/* major version(4) + minor version(4) */
	__u8 type;		/* authentication, authorization, accounting */
	__u8 seq_no;
	__u8 flags;
	__be32 session_id;
	__be32 length;		/* body length */
};

#endif /* __XDP2_PROTO_TACACS_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_tacacs protocol definition
 *
 * Parse TACACS+ header (leaf — AAA for network devices)
 */
static const struct xdp2_proto_def xdp2_parse_tacacs __unused() = {
	.name = "TACACS+",
	.min_len = sizeof(struct tacacs_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
