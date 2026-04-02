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

#ifndef __XDP2_PROTO_SLL2_H__
#define __XDP2_PROTO_SLL2_H__

#include "xdp2/parser.h"

/* Linux SLL2 (cooked capture v2) header.
 * 20 bytes. Used by libpcap for cooked captures (DLT_LINUX_SLL2).
 * Next protocol is the Ethertype in the protocol field.
 */

struct sll2_hdr {
	__be16 protocol;	/* Ethertype */
	__be16 reserved;
	__be32 interface_index;
	__be16 arphrd;		/* ARPHRD_ link-layer address type */
	__u8 pkttype;		/* packet type */
	__u8 ll_addr_len;	/* link-layer address length */
	__u8 ll_addr[8];	/* link-layer address */
};

static inline int sll2_proto(const void *vsll2)
{
	return ((struct sll2_hdr *)vsll2)->protocol;
}

#endif /* __XDP2_PROTO_SLL2_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_sll2 protocol definition
 *
 * Parse Linux SLL2 header.
 * Next protocol returns Ethertype (e.g. ETH_P_IPV4).
 */
static const struct xdp2_proto_def xdp2_parse_sll2 __unused() = {
	.name = "SLL2",
	.min_len = sizeof(struct sll2_hdr),
	.ops.next_proto = sll2_proto,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
