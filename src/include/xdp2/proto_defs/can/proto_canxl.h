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

#ifndef __XDP2_PROTO_CANXL_H__
#define __XDP2_PROTO_CANXL_H__

#include "xdp2/parser.h"

/* CAN XL frame header (ETH_P 0x000E, not yet in mainline if_ether.h).
 * Chainable — SDT (SDU type) field dispatches to inner protocol.
 * Kernel: include/uapi/linux/can.h (proposed)
 */

#ifndef ETH_P_CANXL
#define ETH_P_CANXL	0x000E
#endif

struct canxl_frame_hdr {
	__u32 prio;		/* priority(11) + VCID(8) + flags */
	__u8 flags;		/* CANXL_XLF | CANXL_SEC */
	__u8 sdt;		/* SDU type — dispatch field */
	__be16 len;		/* 1..2048 */
	__u32 af;		/* acceptance field */
};

/* Next protocol: return SDT field for dispatch */
static inline int canxl_proto(const void *vhdr)
{
	return ((struct canxl_frame_hdr *)vhdr)->sdt;
}

#endif /* __XDP2_PROTO_CANXL_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_canxl protocol definition
 *
 * Parse CAN XL frame header.
 * Next protocol returns SDT field for dispatch.
 */
static const struct xdp2_proto_def xdp2_parse_canxl __unused() = {
	.name = "CAN XL",
	.min_len = sizeof(struct canxl_frame_hdr),
	.ops.next_proto = canxl_proto,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
