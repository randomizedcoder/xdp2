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

#ifndef __XDP2_PROTO_CAPWAP_H__
#define __XDP2_PROTO_CAPWAP_H__

#include <linux/if_ether.h>
#include "xdp2/parser.h"

/* CAPWAP (Control And Provisioning of Wireless Access Points, RFC 5415).
 * Variable-length header, minimum 4 bytes (preamble).
 * Encapsulates 802.11 or Ethernet frames.
 */

struct capwap_hdr {
	__u8 preamble;		/* version(4) + type(4) */
	__u8 hlen_rid;		/* HLEN(5) + RID(3) */
	__u8 wbid_flags;	/* WBID(5) + T,F,L flags(3) */
	__u8 frag_id;		/* fragment ID */
};

/* CAPWAP type 0 = IEEE 802.3, type 1 = IEEE 802.11 */
static inline int capwap_proto(const void *vcapwap)
{
	return ETH_P_TEB;
}

#endif /* __XDP2_PROTO_CAPWAP_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_capwap protocol definition
 *
 * Parse CAPWAP header.
 * Encap tunnel — carries wireless AP traffic.
 */
static const struct xdp2_proto_def xdp2_parse_capwap __unused() = {
	.name = "CAPWAP",
	.min_len = sizeof(struct capwap_hdr),
	.encap = 1,
	.ops.next_proto = capwap_proto,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
