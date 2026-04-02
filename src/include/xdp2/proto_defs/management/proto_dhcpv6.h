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

#ifndef __XDP2_PROTO_DHCPV6_H__
#define __XDP2_PROTO_DHCPV6_H__

#include "xdp2/parser.h"

/* DHCPv6 (Dynamic Host Configuration Protocol for IPv6, RFC 8415).
 * 4 bytes minimum. Message type + 24-bit transaction ID.
 * Leaf protocol — no further dispatch.
 */

struct dhcpv6_hdr {
	__u8 msg_type;
	__u8 transaction_id[3];
} __packed;

#endif /* __XDP2_PROTO_DHCPV6_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_dhcpv6 protocol definition
 *
 * Parse DHCPv6 header (leaf — IPv6 address configuration)
 */
static const struct xdp2_proto_def xdp2_parse_dhcpv6 __unused() = {
	.name = "DHCPv6",
	.min_len = sizeof(struct dhcpv6_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
