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

#ifndef __XDP2_PROTO_DCCP_H__
#define __XDP2_PROTO_DCCP_H__

/* DCCP protocol definitions (RFC 4340) */

#include <linux/dccp.h>

#include "xdp2/parser.h"

/* DCCP packet types */
#define DCCP_PKT_REQUEST	0
#define DCCP_PKT_RESPONSE	1
#define DCCP_PKT_DATA		2
#define DCCP_PKT_ACK		3
#define DCCP_PKT_DATAACK	4
#define DCCP_PKT_CLOSEREQ	5
#define DCCP_PKT_CLOSE		6
#define DCCP_PKT_RESET		7
#define DCCP_PKT_SYNC		8
#define DCCP_PKT_SYNCACK	9

static inline ssize_t dccp_len(const void *vdccp, size_t maxlen)
{
	return ((struct dccp_hdr *)vdccp)->dccph_doff * 4;
}

#endif /* __XDP2_PROTO_DCCP_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_dccp protocol definition
 *
 * Parse DCCP header. Header length is variable, determined by
 * dccph_doff (data offset) field in units of 32-bit words.
 */
static const struct xdp2_proto_def xdp2_parse_dccp __unused() = {
	.name = "DCCP",
	.min_len = sizeof(struct dccp_hdr),
	.ops.len = dccp_len,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
