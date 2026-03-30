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

#ifndef __XDP2_PROTO_ISER_H__
#define __XDP2_PROTO_ISER_H__

/* iSER (iSCSI Extensions for RDMA) protocol definitions (RFC 7145)
 *
 * iSER carries iSCSI PDUs over RDMA. The control message header
 * precedes the iSCSI BHS in RDMA Send messages.
 * The kernel struct is in scsi/iser.h (internal).
 */

#include "xdp2/parser.h"

/* iSER control header (28 bytes) */
struct iser_ctrl {
	__u8  flags;		/* opcode + flags */
	__u8  rsvd[3];
	__be32 write_stag;	/* write RDMA STag */
	__be64 write_va;	/* write RDMA virtual address */
	__be32 read_stag;	/* read RDMA STag */
	__be64 read_va;		/* read RDMA virtual address */
} __packed;

/* iSER opcodes (in flags field) */
#define ISER_HELLO		0x20
#define ISER_HELLORPLY		0x30

#endif /* __XDP2_PROTO_ISER_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_iser protocol definition
 *
 * Parse iSER control header (28 bytes fixed).
 * Followed by an iSCSI BHS.
 */
static const struct xdp2_proto_def xdp2_parse_iser __unused() = {
	.name = "iSER",
	.min_len = sizeof(struct iser_ctrl),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
