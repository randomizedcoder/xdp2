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

#ifndef __XDP2_PROTO_MPLS_OAM_H__
#define __XDP2_PROTO_MPLS_OAM_H__

#include "xdp2/parser.h"

/* MPLS OAM (G-ACh — Generic Associated Channel, RFC 5586).
 * MPLS operations, administration, and maintenance.
 * Leaf protocol — no further dispatch.
 */

struct mpls_oam_hdr {
	__u8 first_nibble_ver;	/* first nibble(4) + version(4) */
	__u8 reserved;
	__be16 channel_type;	/* associated channel type */
};

#endif /* __XDP2_PROTO_MPLS_OAM_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_mpls_oam protocol definition
 *
 * Parse MPLS-OAM header (leaf)
 */
static const struct xdp2_proto_def xdp2_parse_mpls_oam __unused() = {
	.name = "MPLS-OAM",
	.min_len = sizeof(struct mpls_oam_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
