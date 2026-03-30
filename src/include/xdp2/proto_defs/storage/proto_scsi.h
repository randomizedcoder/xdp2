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

#ifndef __XDP2_PROTO_SCSI_H__
#define __XDP2_PROTO_SCSI_H__

/* SCSI LUN and CDB definitions (SAM-5, SPC-5)
 *
 * SCSI is typically carried over iSCSI or FCP (Fibre Channel Protocol).
 * The kernel struct is in scsi/scsi_proto.h (internal), so we define
 * a minimal version here.
 */

#include "xdp2/parser.h"

/* SCSI LUN representation (8 bytes) */
struct scsi_lun {
	__u8 scsi_lun[8];
} __packed;

/* FCP_CMND IU — SCSI command carried over Fibre Channel (variable) */
struct fcp_cmnd {
	struct scsi_lun	fc_lun;		/* 8 bytes */
	__u8		fc_cmdref;
	__u8		fc_pri_ta;	/* priority + task attribute */
	__u8		fc_tm_flags;	/* task management flags */
	__u8		fc_flags;	/* additional CDB length + flags */
	__u8		fc_cdb[16];	/* SCSI CDB */
	__be32		fc_dl;		/* data length */
} __packed;

#endif /* __XDP2_PROTO_SCSI_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_scsi protocol definition
 *
 * Parse SCSI FCP_CMND IU (32 bytes minimum, variable with
 * additional CDB bytes).
 */
static const struct xdp2_proto_def xdp2_parse_scsi __unused() = {
	.name = "SCSI",
	.min_len = sizeof(struct fcp_cmnd),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
