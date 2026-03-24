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

#ifndef __XDP2_PROTO_PTP_H__
#define __XDP2_PROTO_PTP_H__

#include "xdp2/parser.h"

/* PTP (IEEE 1588 Precision Time Protocol) common header.
 * 34-byte common header for all PTP message types.
 * Leaf protocol — timing protocol, no further dispatch.
 */

struct ptp_common_hdr {
	__u8 tsmt;		/* transport_specific (4) + messageType (4) */
	__u8 ver;		/* reserved (4) + versionPTP (4) */
	__be16 msg_length;
	__u8 domain_number;
	__u8 reserved1;
	__be16 flags;
	__u8 correction[8];
	__u8 reserved2[4];
	__u8 source_port_id[10];
	__be16 sequence_id;
	__u8 control;
	__u8 log_msg_interval;
};

#endif /* __XDP2_PROTO_PTP_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_ptp protocol definition
 *
 * Parse PTP common header (leaf — 34-byte IEEE 1588 header)
 */
static const struct xdp2_proto_def xdp2_parse_ptp __unused() = {
	.name = "PTP",
	.min_len = sizeof(struct ptp_common_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
