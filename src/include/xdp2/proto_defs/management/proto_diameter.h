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

#ifndef __XDP2_PROTO_DIAMETER_H__
#define __XDP2_PROTO_DIAMETER_H__

#include "xdp2/parser.h"

/* Diameter protocol (RFC 6733).
 * 20 bytes minimum. AAA protocol successor to RADIUS.
 * Leaf protocol — no further dispatch.
 */

struct diameter_hdr {
	__u8 version;
	__u8 length[3];		/* 24-bit message length */
	__u8 flags;		/* R,P,E,T flags */
	__u8 command_code[3];	/* 24-bit command code */
	__be32 app_id;		/* application ID */
	__be32 hop_by_hop_id;
	__be32 end_to_end_id;
} __packed;

#endif /* __XDP2_PROTO_DIAMETER_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_diameter protocol definition
 *
 * Parse Diameter header (leaf — AAA protocol)
 */
static const struct xdp2_proto_def xdp2_parse_diameter __unused() = {
	.name = "Diameter",
	.min_len = sizeof(struct diameter_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
