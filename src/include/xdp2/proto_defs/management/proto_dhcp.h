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

#ifndef __XDP2_PROTO_DHCP_H__
#define __XDP2_PROTO_DHCP_H__

#include "xdp2/parser.h"

/* DHCP (Dynamic Host Configuration Protocol, RFC 2131).
 * Fixed-length header (236 bytes) followed by variable options.
 * Leaf protocol — no further dispatch.
 */

struct dhcphdr {
	__u8 op;
	__u8 htype;
	__u8 hlen;
	__u8 hops;
	__be32 xid;
	__be16 secs;
	__be16 flags;
	__be32 ciaddr;
	__be32 yiaddr;
	__be32 siaddr;
	__be32 giaddr;
	__u8 chaddr[16];
	__u8 sname[64];
	__u8 file[128];
};

#endif /* __XDP2_PROTO_DHCP_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_dhcp protocol definition
 *
 * Parse DHCP header (leaf — dynamic host configuration protocol)
 */
static const struct xdp2_proto_def xdp2_parse_dhcp __unused() = {
	.name = "DHCP",
	.min_len = sizeof(struct dhcphdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
