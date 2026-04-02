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

#ifndef __XDP2_PROTO_BFD_H__
#define __XDP2_PROTO_BFD_H__

#include "xdp2/parser.h"

/* BFD (Bidirectional Forwarding Detection, RFC 5880).
 * Leaf protocol — no further dispatch.
 */

struct bfdhdr {
	__u8 vers_diag;		/* Version (3 bits) + Diagnostic (5 bits) */
	__u8 sta_flags;		/* State (2 bits) + Flags (6 bits) */
	__u8 detect_mult;
	__u8 length;
	__be32 my_discriminator;
	__be32 your_discriminator;
	__be32 desired_min_tx;
	__be32 required_min_rx;
	__be32 required_min_echo_rx;
};

#endif /* __XDP2_PROTO_BFD_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_bfd protocol definition
 *
 * Parse BFD header (leaf — bidirectional forwarding detection)
 */
static const struct xdp2_proto_def xdp2_parse_bfd __unused() = {
	.name = "BFD",
	.min_len = sizeof(struct bfdhdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
