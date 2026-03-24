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

#ifndef __XDP2_PROTO_NSH_H__
#define __XDP2_PROTO_NSH_H__

#include <linux/if_ether.h>
#include "xdp2/parser.h"

/* NSH (Network Service Header, RFC 8300).
 * 8-byte base header (MD Type 1) for service function chaining.
 * Chainable — dispatches based on Next Protocol field.
 *
 * NSH Next Protocol values:
 *   1 = IPv4, 2 = IPv6, 3 = Ethernet, 4 = NSH, 5 = MPLS
 */

#define NSH_NEXT_PROTO_IPV4	1
#define NSH_NEXT_PROTO_IPV6	2
#define NSH_NEXT_PROTO_ETH	3
#define NSH_NEXT_PROTO_NSH	4
#define NSH_NEXT_PROTO_MPLS	5

struct nsh_base_hdr {
	__be16 ver_flags_ttl_len;  /* Ver(2)+OAM(1)+UN(1)+TTL(6)+Len(6) */
	__u8 md_type;
	__u8 next_proto;
	__be32 spi_si;		   /* SPI (24 bits) + SI (8 bits) */
};

/* Map NSH next_proto to ethertypes for dispatch table compatibility.
 * Returns big-endian ethertype values for the dispatch table.
 */
static inline int nsh_proto(const void *vhdr)
{
	__u8 np = ((struct nsh_base_hdr *)vhdr)->next_proto;

	switch (np) {
	case NSH_NEXT_PROTO_IPV4:
		return __cpu_to_be16(ETH_P_IP);
	case NSH_NEXT_PROTO_IPV6:
		return __cpu_to_be16(ETH_P_IPV6);
	case NSH_NEXT_PROTO_ETH:
		return __cpu_to_be16(ETH_P_TEB);
	case NSH_NEXT_PROTO_MPLS:
		return __cpu_to_be16(ETH_P_MPLS_UC);
	default:
		return 0;
	}
}

#endif /* __XDP2_PROTO_NSH_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_nsh protocol definition
 *
 * Parse NSH base header.
 * Next protocol maps NSH next_proto to ethertypes for dispatch.
 */
static const struct xdp2_proto_def xdp2_parse_nsh __unused() = {
	.name = "NSH",
	.encap = 1,
	.min_len = sizeof(struct nsh_base_hdr),
	.ops.next_proto = nsh_proto,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
