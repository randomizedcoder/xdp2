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

#ifndef __XDP2_PROTO_GUE_H__
#define __XDP2_PROTO_GUE_H__

#include "xdp2/bpf_compat.h"

#include <linux/if_ether.h>
#include "xdp2/parser.h"

/* GUE (Generic UDP Encapsulation, RFC draft).
 * Encap protocol — dispatches based on proto_ctype field.
 * The proto_ctype field contains the IP protocol number of the
 * inner payload when C-bit is 0.
 */

/* IP protocol numbers used for GUE dispatch */
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP	4
#endif

#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6	41
#endif

struct guehdr {
	__u8 hdrlen_version;	/* Version (2 bits) + Hdr len (5 bits) + C (1 bit) */
	__u8 proto_ctype;	/* IP protocol (C=0) or control type (C=1) */
	__be16 flags;
};

static inline int gue_proto(const void *vhdr)
{
	return ((struct guehdr *)vhdr)->proto_ctype;
}

#endif /* __XDP2_PROTO_GUE_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_gue protocol definition
 *
 * Parse GUE header.
 * Next protocol from proto_ctype field (IP protocol number).
 */
static const struct xdp2_proto_def xdp2_parse_gue __unused() = {
	.name = "GUE",
	.encap = 1,
	.min_len = sizeof(struct guehdr),
	.ops.next_proto = gue_proto,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
