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

#ifndef __XDP2_PROTO_TZSP_H__
#define __XDP2_PROTO_TZSP_H__

#include "xdp2/parser.h"

/* TZSP (TaZmen Sniffer Protocol).
 * 4 bytes minimum. Encapsulates captured packets for remote monitoring.
 * Encap protocol — encap_proto identifies the encapsulated link type.
 */

struct tzsp_hdr {
	__u8 version;		/* protocol version (typically 1) */
	__u8 type;		/* 0=normal, 1=tagged, 2-4 reserved */
	__be16 encap_proto;	/* encapsulated protocol */
};

static inline int tzsp_proto(const void *vtzsp)
{
	return ((struct tzsp_hdr *)vtzsp)->encap_proto;
}

#endif /* __XDP2_PROTO_TZSP_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_tzsp protocol definition
 *
 * Parse TZSP header.
 * Encap tunnel — encap_proto identifies encapsulated link type.
 */
static const struct xdp2_proto_def xdp2_parse_tzsp __unused() = {
	.name = "TZSP",
	.min_len = sizeof(struct tzsp_hdr),
	.encap = 1,
	.ops.next_proto = tzsp_proto,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
