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

#ifndef __XDP2_PROTO_CAN_H__
#define __XDP2_PROTO_CAN_H__

#include "xdp2/parser.h"

/* Classical CAN frame (ETH_P_CAN 0x000C).
 * 16-byte fixed frame. Leaf — no inner dispatch.
 * Kernel: include/uapi/linux/can.h
 */

struct can_frame {
	__u32 can_id;		/* bits 0-28: ID, bit 29: ERR, bit 30: RTR, bit 31: EFF */
	__u8 len;
	__u8 __pad;
	__u8 __res0;
	__u8 len8_dlc;
	__u8 data[8];
};

#endif /* __XDP2_PROTO_CAN_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_can protocol definition
 *
 * Parse classical CAN frame (leaf — no further dispatch)
 */
static const struct xdp2_proto_def xdp2_parse_can __unused() = {
	.name = "CAN",
	.min_len = sizeof(struct can_frame),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
