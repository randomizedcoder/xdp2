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

#ifndef __XDP2_PROTO_GTP_H__
#define __XDP2_PROTO_GTP_H__

#include <linux/if_ether.h>
#include "xdp2/parser.h"

/* GTP-U (GPRS Tunnelling Protocol User Plane, 3GPP TS 29.281).
 * Encap protocol — inner packet is typically IP.
 * Dispatches based on first nibble of inner payload (IPv4 vs IPv6).
 */

struct gtpuhdr {
	__u8 flags;
	__u8 message_type;
	__be16 length;
	__be32 teid;
};

/* Determine inner protocol by inspecting first nibble of payload
 * after the GTP-U header.
 */
static inline int gtpu_proto(const void *vgtp)
{
	const __u8 *inner = (const __u8 *)vgtp + sizeof(struct gtpuhdr);
	__u8 version = (*inner) >> 4;

	switch (version) {
	case 4:
		return __cpu_to_be16(ETH_P_IP);
	case 6:
		return __cpu_to_be16(ETH_P_IPV6);
	default:
		return 0;
	}
}

#endif /* __XDP2_PROTO_GTP_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_gtpu protocol definition
 *
 * Parse GTP-U header.
 * Next protocol determined by first nibble of inner payload.
 */
static const struct xdp2_proto_def xdp2_parse_gtpu __unused() = {
	.name = "GTP-U",
	.encap = 1,
	.min_len = sizeof(struct gtpuhdr),
	.ops.next_proto = gtpu_proto,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
