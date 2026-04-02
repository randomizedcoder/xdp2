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

#ifndef __XDP2_PROTO_NTP_H__
#define __XDP2_PROTO_NTP_H__

#include "xdp2/parser.h"

/* NTP (Network Time Protocol, RFC 5905).
 * Leaf protocol — no further dispatch.
 */

struct ntphdr {
	__u8 li_vn_mode;	/* LI (2) + VN (3) + Mode (3) */
	__u8 stratum;
	__s8 poll;
	__s8 precision;
	__be32 root_delay;
	__be32 root_dispersion;
	__be32 reference_id;
	__be64 reference_ts;
	__be64 origin_ts;
	__be64 receive_ts;
	__be64 transmit_ts;
};

#endif /* __XDP2_PROTO_NTP_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_ntp protocol definition
 *
 * Parse NTP header (leaf — network time protocol)
 */
static const struct xdp2_proto_def xdp2_parse_ntp __unused() = {
	.name = "NTP",
	.min_len = sizeof(struct ntphdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
