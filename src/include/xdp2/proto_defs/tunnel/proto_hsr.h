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

#ifndef __XDP2_PROTO_HSR_H__
#define __XDP2_PROTO_HSR_H__

#include "xdp2/parser.h"

/* HSR (High-availability Seamless Redundancy, IEC 62439-3 v1).
 * 6-byte HSR tag with ethertype dispatch to inner protocol.
 * Chainable — dispatches via ethertype in tag.
 */

struct hsr_tag {
	__be16 path_and_LSDU_size;  /* Network/Lane (4 bits) + LSDU size (12 bits) */
	__be16 sequence_nr;
	__be16 encap_proto;	    /* Ethertype of encapsulated frame */
};

/* Next protocol: return the encapsulated protocol ethertype */
static inline int hsr_proto(const void *vhdr)
{
	return ((struct hsr_tag *)vhdr)->encap_proto;
}

#endif /* __XDP2_PROTO_HSR_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_hsr protocol definition
 *
 * Parse HSR tag header.
 * Next protocol returns encapsulated ethertype for dispatch.
 */
static const struct xdp2_proto_def xdp2_parse_hsr __unused() = {
	.name = "HSR",
	.min_len = sizeof(struct hsr_tag),
	.ops.next_proto = hsr_proto,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
