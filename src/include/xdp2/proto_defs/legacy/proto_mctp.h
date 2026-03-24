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

#ifndef __XDP2_PROTO_MCTP_H__
#define __XDP2_PROTO_MCTP_H__

#include "xdp2/parser.h"

/* MCTP (Management Component Transport Protocol, DMTF DSP0236).
 * 4-byte header with endpoint IDs and tag.
 * Leaf for flow key extraction — message type is in first payload byte.
 * Kernel: include/net/mctp.h
 */

struct mctp_hdr {
	__u8 ver;		/* version (4 bits) + reserved */
	__u8 dest;		/* destination EID */
	__u8 src;		/* source EID */
	__u8 flags_seq_tag;	/* SOM(1)+EOM(1)+pkt_seq(2)+TO(1)+tag(3) */
};

#endif /* __XDP2_PROTO_MCTP_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_mctp protocol definition
 *
 * Parse MCTP header (leaf — no further dispatch)
 */
static const struct xdp2_proto_def xdp2_parse_mctp __unused() = {
	.name = "MCTP",
	.min_len = sizeof(struct mctp_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
