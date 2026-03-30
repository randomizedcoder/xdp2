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

#ifndef __XDP2_PROTO_NVME_H__
#define __XDP2_PROTO_NVME_H__

/* NVMe over Fabrics protocol definitions (NVM Express 2.0)
 *
 * NVMe commands are 64 bytes. The kernel struct is in linux/nvme.h
 * but we define a minimal version here for BPF compatibility.
 */

#include "xdp2/parser.h"

/* NVMe common command format (64 bytes) */
struct nvme_common_command {
	__u8  opcode;
	__u8  flags;
	__u16 command_id;
	__le32 nsid;		/* namespace identifier */
	__le32 cdw2[2];
	__le64 metadata;
	__le64 prp1;		/* PRP entry 1 */
	__le64 prp2;		/* PRP entry 2 */
	__le32 cdw10[6];	/* command dwords 10-15 */
} __packed;

#define NVME_CMD_SIZE	64

/* NVMe admin opcodes */
#define NVME_ADMIN_OP_DELETE_SQ		0x00
#define NVME_ADMIN_OP_CREATE_SQ		0x01
#define NVME_ADMIN_OP_IDENTIFY		0x06
#define NVME_ADMIN_OP_SET_FEATURES	0x09
#define NVME_ADMIN_OP_GET_FEATURES	0x0A

/* NVMe I/O opcodes */
#define NVME_IO_OP_READ			0x02
#define NVME_IO_OP_WRITE		0x01

#endif /* __XDP2_PROTO_NVME_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_nvme protocol definition
 *
 * Parse NVMe command capsule (64 bytes fixed).
 * Carried over RDMA (NVMe-oF/RDMA) or TCP (NVMe-oF/TCP).
 */
static const struct xdp2_proto_def xdp2_parse_nvme __unused() = {
	.name = "NVMe",
	.min_len = NVME_CMD_SIZE,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
