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

#ifndef __XDP2_PROTO_LLC_H__
#define __XDP2_PROTO_LLC_H__

/* LLC/SNAP protocol definitions (IEEE 802.2) */

#include "xdp2/parser.h"

/* LLC header (3 bytes) */
struct llc_hdr {
	__u8 dsap;
	__u8 ssap;
	__u8 ctrl;
} __packed;

/* LLC/SNAP header (8 bytes) — LLC with DSAP/SSAP = 0xAA (SNAP) */
struct llc_snap_hdr {
	__u8 dsap;		/* 0xAA for SNAP */
	__u8 ssap;		/* 0xAA for SNAP */
	__u8 ctrl;		/* 0x03 for UI frame */
	__u8 oui[3];		/* Organizationally Unique Identifier */
	__be16 ethertype;	/* EtherType of encapsulated payload */
} __packed;

#define LLC_SAP_SNAP	0xAA
#define LLC_SAP_IP	0x06
#define LLC_SAP_STP	0x42
#define LLC_SAP_IPX	0xE0

static inline int llc_snap_next_proto(const void *vllc)
{
	return ((struct llc_snap_hdr *)vllc)->ethertype;
}

#endif /* __XDP2_PROTO_LLC_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_llc protocol definition
 *
 * Parse basic LLC header (3 bytes, leaf).
 */
static const struct xdp2_proto_def xdp2_parse_llc __unused() = {
	.name = "LLC",
	.min_len = sizeof(struct llc_hdr),
};

/* xdp2_parse_llc_snap protocol definition
 *
 * Parse LLC/SNAP header (8 bytes). Next protocol is the
 * encapsulated EtherType, enabling dispatch to L3 protocols.
 */
static const struct xdp2_proto_def xdp2_parse_llc_snap __unused() = {
	.name = "LLC/SNAP",
	.encap = 1,
	.min_len = sizeof(struct llc_snap_hdr),
	.ops.next_proto = llc_snap_next_proto,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
