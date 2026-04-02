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

#ifndef __XDP2_PROTO_MPEG_TS_H__
#define __XDP2_PROTO_MPEG_TS_H__

#include "xdp2/parser.h"

/* MPEG Transport Stream (ISO/IEC 13818-1).
 * 188-byte fixed packets, 4-byte header.
 * Leaf protocol — payload is PES or PSI data.
 */

struct mpeg_ts_hdr {
	__u8 sync_byte;		/* 0x47 sync byte */
	__be16 pid_flags;	/* TEI(1) + PUSI(1) + priority(1) + PID(13) */
	__u8 adaptation_cc;	/* scrambling(2) + adaptation(2) + continuity(4) */
};

#endif /* __XDP2_PROTO_MPEG_TS_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_mpeg_ts protocol definition
 *
 * Parse MPEG-TS header (leaf)
 */
static const struct xdp2_proto_def xdp2_parse_mpeg_ts __unused() = {
	.name = "MPEG-TS",
	.min_len = sizeof(struct mpeg_ts_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
