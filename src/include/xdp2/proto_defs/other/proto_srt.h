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

#ifndef __XDP2_PROTO_SRT_H__
#define __XDP2_PROTO_SRT_H__

#include "xdp2/parser.h"

/* SRT (Secure Reliable Transport).
 * UDT-based media transport protocol.
 * Leaf protocol — encrypted media payload.
 */

struct srt_hdr {
	__be16 is_control_type;	/* control flag(1) + type(15) / packet seq */
	__be16 additional;	/* subtype or additional info */
	__be32 timestamp;
	__be32 dest_socket_id;
};

#endif /* __XDP2_PROTO_SRT_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_srt protocol definition
 *
 * Parse SRT header (leaf)
 */
static const struct xdp2_proto_def xdp2_parse_srt __unused() = {
	.name = "SRT",
	.min_len = sizeof(struct srt_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
