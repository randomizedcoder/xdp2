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

#ifndef __XDP2_PROTO_ISCSI_H__
#define __XDP2_PROTO_ISCSI_H__

/* iSCSI protocol definitions (RFC 7143)
 *
 * iSCSI Basic Header Segment (BHS) is always 48 bytes.
 * The kernel struct is in scsi/iscsi_proto.h but that is an internal
 * kernel header, so we define the BHS here.
 */

#include "xdp2/parser.h"

/* iSCSI BHS — Basic Header Segment (48 bytes) */
struct iscsi_hdr {
	__u8  opcode;		/* opcode + immediate bit */
	__u8  flags;		/* opcode-specific flags */
	__u8  rsvd2[2];
	__u8  hlength;		/* AHS total length (units of 4 bytes) */
	__u8  dlength[3];	/* data segment length (24 bits) */
	__u8  lun[8];		/* LUN or opcode-specific */
	__be32 itt;		/* initiator task tag */
	__u8  other[28];	/* remaining fields vary by opcode */
} __packed;

/* iSCSI opcodes */
#define ISCSI_OP_NOP_OUT	0x00
#define ISCSI_OP_SCSI_CMD	0x01
#define ISCSI_OP_LOGIN		0x03
#define ISCSI_OP_TEXT		0x04
#define ISCSI_OP_SCSI_DATA_OUT	0x05
#define ISCSI_OP_LOGOUT		0x06

#define ISCSI_OP_NOP_IN		0x20
#define ISCSI_OP_SCSI_CMD_RSP	0x21
#define ISCSI_OP_LOGIN_RSP	0x23
#define ISCSI_OP_TEXT_RSP	0x24
#define ISCSI_OP_SCSI_DATA_IN	0x25
#define ISCSI_OP_LOGOUT_RSP	0x26
#define ISCSI_OP_REJECT		0x3F

#endif /* __XDP2_PROTO_ISCSI_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_iscsi protocol definition
 *
 * Parse iSCSI BHS (48 bytes fixed). Additional Header Segments
 * and Data Segments follow, making the total PDU variable.
 */
static const struct xdp2_proto_def xdp2_parse_iscsi __unused() = {
	.name = "iSCSI",
	.min_len = sizeof(struct iscsi_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
