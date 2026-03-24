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

#ifndef __XDP2_PROTO_PHONET_H__
#define __XDP2_PROTO_PHONET_H__

#include "xdp2/parser.h"

/* Nokia Phonet/ISI protocol (ETH_P_PHONET 0x00F5).
 * 7-byte header (packed) with device/object addressing.
 * Leaf for flow key extraction.
 * Kernel: include/uapi/linux/phonet.h
 */

struct phonethdr {
	__u8 pn_rdev;		/* receiver device */
	__u8 pn_sdev;		/* sender device */
	__u8 pn_res;
	__be16 pn_length;
	__u8 pn_robj;		/* receiver object */
	__u8 pn_sobj;		/* sender object */
} __packed;

#endif /* __XDP2_PROTO_PHONET_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_phonet protocol definition
 *
 * Parse Phonet header (leaf — no further dispatch)
 */
static const struct xdp2_proto_def xdp2_parse_phonet __unused() = {
	.name = "Phonet",
	.min_len = sizeof(struct phonethdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
