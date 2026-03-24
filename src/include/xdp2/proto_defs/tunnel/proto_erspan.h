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

#ifndef __XDP2_PROTO_ERSPAN_H__
#define __XDP2_PROTO_ERSPAN_H__

#include "xdp2/parser.h"

/* ERSPAN Type II (ETH_P_ERSPAN 0x88BE) and Type III (ETH_P_ERSPAN2 0x22EB).
 * Carried inside GRE tunnels. Inner payload is Ethernet.
 * Kernel: include/uapi/linux/erspan.h, net/ipv4/ip_gre.c
 * Leaf — inner Ethernet follows after ERSPAN+GRE but is not dispatched here.
 */

struct erspan_base_hdr {
	__be16 ver_vlan;	/* version(4) + vlan(12) */
	__be16 cos_en_t_session; /* cos(3) + en(2) + t(1) + session(10) */
};

#endif /* __XDP2_PROTO_ERSPAN_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_erspan protocol definition
 *
 * Parse ERSPAN header (leaf — no further dispatch)
 */
static const struct xdp2_proto_def xdp2_parse_erspan __unused() = {
	.name = "ERSPAN",
	.min_len = sizeof(struct erspan_base_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
