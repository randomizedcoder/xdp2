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

#ifndef __XDP2_PROTO_VXLAN_GPE_H__
#define __XDP2_PROTO_VXLAN_GPE_H__

#include <linux/if_ether.h>
#include "xdp2/parser.h"

/* VXLAN-GPE (Generic Protocol Extension, RFC 8926).
 * Encap protocol — dispatches based on next_protocol field.
 *
 * Next Protocol values:
 *   1 = IPv4, 2 = IPv6, 3 = Ethernet, 4 = NSH
 */

#define VXLAN_GPE_NP_IPV4	1
#define VXLAN_GPE_NP_IPV6	2
#define VXLAN_GPE_NP_ETH	3
#define VXLAN_GPE_NP_NSH	4

struct vxlan_gpe_hdr {
	__u8 flags;
	__be16 reserved1;
	__u8 next_protocol;
	__be32 vni_reserved;
};

static inline int vxlan_gpe_proto(const void *vhdr)
{
	__u8 np = ((struct vxlan_gpe_hdr *)vhdr)->next_protocol;

	switch (np) {
	case VXLAN_GPE_NP_IPV4:
		return __cpu_to_be16(ETH_P_IP);
	case VXLAN_GPE_NP_IPV6:
		return __cpu_to_be16(ETH_P_IPV6);
	case VXLAN_GPE_NP_ETH:
		return __cpu_to_be16(ETH_P_TEB);
	default:
		return 0;
	}
}

#endif /* __XDP2_PROTO_VXLAN_GPE_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_vxlan_gpe protocol definition
 *
 * Parse VXLAN-GPE header.
 * Next protocol maps next_protocol field to ethertypes for dispatch.
 */
static const struct xdp2_proto_def xdp2_parse_vxlan_gpe __unused() = {
	.name = "VXLAN-GPE",
	.encap = 1,
	.min_len = sizeof(struct vxlan_gpe_hdr),
	.ops.next_proto = vxlan_gpe_proto,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
