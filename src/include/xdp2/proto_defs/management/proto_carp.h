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

#ifndef __XDP2_PROTO_CARP_H__
#define __XDP2_PROTO_CARP_H__

#include "xdp2/parser.h"

/* CARP (Common Address Redundancy Protocol).
 * 36 bytes. Similar to VRRP but with HMAC authentication.
 * Leaf protocol — no further dispatch.
 */

struct carp_hdr {
	__u8 carp_version_type;	/* version(4) + type(4) */
	__u8 vhid;
	__u8 advskew;
	__u8 authlen;
	__u8 demotion;
	__u8 advbase;
	__be16 checksum;
	__be32 counter[2];	/* 64-bit counter as two 32-bit words */
	__u8 hmac[20];		/* SHA-1 HMAC */
};

#endif /* __XDP2_PROTO_CARP_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_carp protocol definition
 *
 * Parse CARP header (leaf — address redundancy)
 */
static const struct xdp2_proto_def xdp2_parse_carp __unused() = {
	.name = "CARP",
	.min_len = sizeof(struct carp_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
