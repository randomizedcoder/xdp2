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

#ifndef __XDP2_PROTO_STP_H__
#define __XDP2_PROTO_STP_H__

#include "xdp2/parser.h"

/* STP (Spanning Tree Protocol, IEEE 802.1D) BPDU header.
 * Leaf protocol — no further dispatch.
 */

struct stp_bpdu {
	__be16 protocol_id;
	__u8 version_id;
	__u8 bpdu_type;
	__u8 flags;
	__be64 root_id;
	__be32 root_path_cost;
	__be64 bridge_id;
	__be16 port_id;
	__be16 message_age;
	__be16 max_age;
	__be16 hello_time;
	__be16 forward_delay;
} __attribute__((packed));

#endif /* __XDP2_PROTO_STP_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_stp protocol definition
 *
 * Parse STP BPDU header (leaf — IEEE 802.1D spanning tree)
 */
static const struct xdp2_proto_def xdp2_parse_stp __unused() = {
	.name = "STP",
	.min_len = 35,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
