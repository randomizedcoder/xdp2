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

#ifndef __XDP2_PROTO_IP_IN_IP_H__
#define __XDP2_PROTO_IP_IN_IP_H__

/* IP-in-IP encapsulation (RFC 2003, IP protocol 4)
 *
 * The inner header is a standard IPv4 header. This proto_def simply
 * identifies the encapsulation boundary — the inner IPv4 header is
 * parsed by the normal IPv4 proto_def via the IP overlay mechanism.
 *
 * In XDP2's parser graph, IP-in-IP is dispatched from IPv4's protocol
 * field (IPPROTO_IPIP = 4) and the overlay routes to ipv4_check which
 * verifies the inner version field.
 */

#include <linux/ip.h>

#include "xdp2/parser.h"

/* Inner header is a full IPv4 header — reuse ipv4 helpers */

static inline int ip_in_ip_proto(const void *viph)
{
	return ((struct iphdr *)viph)->protocol;
}

static inline ssize_t ip_in_ip_length(const void *viph, size_t maxlen)
{
	return ((struct iphdr *)viph)->ihl * 4;
}

#endif /* __XDP2_PROTO_IP_IN_IP_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_ip_in_ip protocol definition
 *
 * Parse inner IPv4 header in IP-in-IP encapsulation (protocol 4)
 *
 * This is functionally identical to ipv4 parsing — the inner header
 * is a standard IPv4 header with its own protocol dispatch.
 */
static const struct xdp2_proto_def xdp2_parse_ip_in_ip __unused() = {
	.name = "IP-in-IP",
	.min_len = sizeof(struct iphdr),
	.ops.len = ip_in_ip_length,
	.ops.next_proto = ip_in_ip_proto,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
