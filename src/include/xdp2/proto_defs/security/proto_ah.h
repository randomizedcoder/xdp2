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

#ifndef __XDP2_PROTO_AH_H__
#define __XDP2_PROTO_AH_H__

#include <linux/ip.h>
#include "xdp2/parser.h"

/* AH header (struct ip_auth_hdr from <linux/ip.h>):
 * Chains to the next IP protocol.
 * Variable length: (hdrlen + 2) * 4 bytes.
 */

static inline int ah_next_proto(const void *vah)
{
	return ((struct ip_auth_hdr *)vah)->nexthdr;
}

static inline ssize_t ah_len(const void *vah, size_t hdr_len)
{
	return (((struct ip_auth_hdr *)vah)->hdrlen + 2) << 2;
}

#endif /* __XDP2_PROTO_AH_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_ah protocol definition
 *
 * Parse AH header — chains to next IP protocol via nexthdr field
 */
static const struct xdp2_proto_def xdp2_parse_ah __unused() = {
	.name = "AH",
	.min_len = sizeof(struct ip_auth_hdr),
	.ops.next_proto = ah_next_proto,
	.ops.len = ah_len,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
