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

#ifndef __XDP2_PROTO_NETLINK_H__
#define __XDP2_PROTO_NETLINK_H__

#include "xdp2/parser.h"

/* Netlink message header (AF_NETLINK).
 * 16-byte header. Chainable — dispatches on nlmsg_type.
 * Kernel: include/uapi/linux/netlink.h
 *
 * nlmsg_type < 0x10 = control messages (NOOP/ERROR/DONE/OVERRUN)
 * nlmsg_type >= 0x10 = family-specific messages
 */

#define NLMSG_NOOP		0x1
#define NLMSG_ERROR		0x2
#define NLMSG_DONE		0x3
#define NLMSG_OVERRUN		0x4

struct nlmsghdr {
	__u32 nlmsg_len;	/* message length including header */
	__u16 nlmsg_type;	/* message type — dispatch field */
	__u16 nlmsg_flags;
	__u32 nlmsg_seq;
	__u32 nlmsg_pid;
};

/* Next protocol: return nlmsg_type for dispatch */
static inline int netlink_proto(const void *vhdr)
{
	return ((struct nlmsghdr *)vhdr)->nlmsg_type;
}

#endif /* __XDP2_PROTO_NETLINK_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_netlink protocol definition
 *
 * Parse Netlink message header (16 bytes).
 * Next protocol returns nlmsg_type for dispatch.
 */
static const struct xdp2_proto_def xdp2_parse_netlink __unused() = {
	.name = "Netlink",
	.min_len = sizeof(struct nlmsghdr),
	.ops.next_proto = netlink_proto,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
