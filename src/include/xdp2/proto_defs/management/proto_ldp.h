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

#ifndef __XDP2_PROTO_LDP_H__
#define __XDP2_PROTO_LDP_H__

#include "xdp2/parser.h"

/* LDP (Label Distribution Protocol, RFC 5036).
 * MPLS label distribution signaling.
 * Leaf protocol — no further dispatch.
 */

struct ldp_hdr {
	__be16 version;		/* protocol version (1) */
	__be16 pdu_length;	/* PDU length excluding version and length */
	__be32 lsr_id;		/* LSR identifier */
	__be16 label_space;	/* label space ID */
};

#endif /* __XDP2_PROTO_LDP_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_ldp protocol definition
 *
 * Parse LDP header (leaf)
 */
static const struct xdp2_proto_def xdp2_parse_ldp __unused() = {
	.name = "LDP",
	.min_len = sizeof(struct ldp_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
