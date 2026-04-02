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

#ifndef __XDP2_PROTO_GRE_PPTP_H__
#define __XDP2_PROTO_GRE_PPTP_H__

#include "xdp2/parser.h"

/* GRE PPTP (PPP over GRE version 1, RFC 2637).
 * Enhanced GRE for PPTP VPN tunneling.
 * Leaf protocol — carries encrypted PPP payload.
 */

struct gre_pptp_hdr {
	__be16 flags_version;	/* C,R,K,S flags + version (must be 1) */
	__be16 protocol;	/* 0x880B for PPTP */
	__be16 payload_len;
	__be16 call_id;
};

#endif /* __XDP2_PROTO_GRE_PPTP_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_gre_pptp protocol definition
 *
 * Parse GRE-PPTP header (leaf)
 */
static const struct xdp2_proto_def xdp2_parse_gre_pptp __unused() = {
	.name = "GRE-PPTP",
	.min_len = sizeof(struct gre_pptp_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
