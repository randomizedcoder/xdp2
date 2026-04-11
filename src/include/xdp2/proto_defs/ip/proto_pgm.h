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

#ifndef __XDP2_PROTO_PGM_H__
#define __XDP2_PROTO_PGM_H__

#include <linux/types.h>
#include "xdp2/parser.h"

/* PGM header (RFC 3208):
 *   sport     (16 bits) — source port
 *   dport     (16 bits) — destination port
 *   type      (8 bits) — PGM type
 *   options   (8 bits) — options
 *   checksum  (16 bits) — header checksum
 *   gsi       (48 bits) — global source identifier
 *   tsdu_len  (16 bits) — TSDU length
 * Total: 16 bytes minimum fixed header.
 */
struct pgm_header {
	__be16 sport;
	__be16 dport;
	__u8 type;
	__u8 options;
	__be16 checksum;
	__u8 gsi[6];
	__be16 tsdu_len;
};

#endif /* __XDP2_PROTO_PGM_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_pgm protocol definition
 *
 * Parse PGM (Pragmatic General Multicast) header.
 * PGM is a reliable multicast protocol that runs directly over IP.
 */
static const struct xdp2_proto_def xdp2_parse_pgm __unused() = {
	.name = "PGM",
	.min_len = sizeof(struct pgm_header),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
