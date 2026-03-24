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

#ifndef __XDP2_PROTO_PBB_H__
#define __XDP2_PROTO_PBB_H__

#include <linux/if_ether.h>
#include "xdp2/parser.h"

/* PBB / MAC-in-MAC (IEEE 802.1ah) I-TAG header.
 * 4-byte I-TAG followed by inner Ethernet frame.
 * Chainable — dispatches to inner Ethernet.
 */

struct pbb_itag {
	__be32 isid_flags;	/* I-PCP (3) + I-DEI (1) + UCA (1) + Res (3) + I-SID (24) */
};

/* PBB: I-TAG is 4 bytes, followed by inner Ethernet (14 bytes min).
 * Total min_len includes I-TAG + inner ethhdr.
 */
struct pbb_hdr {
	struct pbb_itag itag;
	struct ethhdr inner_eth;
};

/* Next protocol: return inner Ethernet's ethertype */
static inline int pbb_proto(const void *vhdr)
{
	return ((struct pbb_hdr *)vhdr)->inner_eth.h_proto;
}

/* Length: I-TAG + inner Ethernet header */
static inline ssize_t pbb_len(const void *vhdr, size_t maxlen)
{
	return sizeof(struct pbb_hdr);
}

#endif /* __XDP2_PROTO_PBB_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_pbb protocol definition
 *
 * Parse PBB I-TAG + inner Ethernet header.
 * Next protocol returns inner ethertype for dispatch.
 */
static const struct xdp2_proto_def xdp2_parse_pbb __unused() = {
	.name = "PBB",
	.encap = 1,
	.min_len = sizeof(struct pbb_hdr),
	.ops.next_proto = pbb_proto,
	.ops.len = pbb_len,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
