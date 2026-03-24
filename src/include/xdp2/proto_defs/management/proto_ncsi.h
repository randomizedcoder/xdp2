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

#ifndef __XDP2_PROTO_NCSI_H__
#define __XDP2_PROTO_NCSI_H__

#include "xdp2/parser.h"

/* NC-SI (Network Controller Sideband Interface, ETH_P_NCSI 0x88F8).
 * BMC-to-NIC management protocol. Leaf — no further dispatch.
 */

struct ncsi_hdr {
	__u8 mc_id;
	__u8 revision;
	__u8 reserved;
	__u8 id;
	__u8 type;		/* command/response type */
	__u8 channel;
	__be16 length;
};

#endif /* __XDP2_PROTO_NCSI_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_ncsi protocol definition
 *
 * Parse NC-SI header (leaf — no further dispatch)
 */
static const struct xdp2_proto_def xdp2_parse_ncsi __unused() = {
	.name = "NC-SI",
	.min_len = sizeof(struct ncsi_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
