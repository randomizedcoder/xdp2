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

#ifndef __XDP2_PROTO_WOL_H__
#define __XDP2_PROTO_WOL_H__

#include "xdp2/parser.h"

/* WoL (Wake-on-LAN) magic packet.
 * 102 bytes minimum (6-byte sync + 16 repetitions of 6-byte target MAC).
 * Leaf protocol — no further dispatch.
 */

struct wol_hdr {
	__u8 sync[6];		/* 6 bytes of 0xFF */
	__u8 target_mac[6];	/* first repetition of target MAC */
	/* followed by 15 more repetitions of target MAC (90 bytes) */
};

#endif /* __XDP2_PROTO_WOL_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_wol protocol definition
 *
 * Parse WoL magic packet (leaf — wake-on-LAN)
 */
static const struct xdp2_proto_def xdp2_parse_wol __unused() = {
	.name = "WoL",
	.min_len = 102,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
