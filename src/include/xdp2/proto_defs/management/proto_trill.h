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

#ifndef __XDP2_PROTO_TRILL_H__
#define __XDP2_PROTO_TRILL_H__

#include <linux/if_ether.h>
#include "xdp2/parser.h"

/* TRILL (Transparent Interconnection of Lots of Links, RFC 6325).
 * 6-byte base header followed by inner Ethernet frame.
 * Chainable — dispatches to inner Ethernet.
 */

#define ETH_P_TRILL	0x22F3

struct trill_hdr {
	__be16 flags_hopcount;	/* V(2) + R(2) + M(1) + OpLen(5) + HopCount(6) */
	__be16 egress_nick;
	__be16 ingress_nick;
} __attribute__((packed));

/* TRILL: 6-byte header + inner Ethernet (14 bytes min) */
struct trill_full_hdr {
	struct trill_hdr trill;
	struct ethhdr inner_eth;
};

/* Next protocol: return inner Ethernet's ethertype */
static inline int trill_proto(const void *vhdr)
{
	return ((struct trill_full_hdr *)vhdr)->inner_eth.h_proto;
}

/* Length: TRILL header + inner Ethernet header */
static inline ssize_t trill_len(const void *vhdr, size_t maxlen)
{
	return sizeof(struct trill_full_hdr);
}

#endif /* __XDP2_PROTO_TRILL_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_trill protocol definition
 *
 * Parse TRILL header + inner Ethernet.
 * Next protocol returns inner ethertype for dispatch.
 */
static const struct xdp2_proto_def xdp2_parse_trill __unused() = {
	.name = "TRILL",
	.encap = 1,
	.min_len = sizeof(struct trill_full_hdr),
	.ops.next_proto = trill_proto,
	.ops.len = trill_len,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
