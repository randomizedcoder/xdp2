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

#ifndef __XDP2_PROTO_FC_H__
#define __XDP2_PROTO_FC_H__

/* Fibre Channel frame header definitions (FC-FS-5)
 *
 * The kernel struct is in uapi/scsi/fc/fc_fs.h. We define it here
 * for BPF compatibility.
 */

#include "xdp2/parser.h"

/* Fibre Channel frame header (24 bytes) */
struct fc_frame_header {
	__u8  fh_r_ctl;		/* routing control */
	__u8  fh_d_id[3];	/* destination ID */
	__u8  fh_cs_ctl;	/* class/priority of service */
	__u8  fh_s_id[3];	/* source ID */
	__u8  fh_type;		/* data structure type */
	__u8  fh_f_ctl[3];	/* frame control */
	__u8  fh_seq_id;	/* sequence ID */
	__u8  fh_df_ctl;	/* data field control */
	__be16 fh_seq_cnt;	/* sequence count */
	__be16 fh_ox_id;	/* originator exchange ID */
	__be16 fh_rx_id;	/* responder exchange ID */
	__be32 fh_parm_offset;	/* parameter or relative offset */
} __packed;

/* FC types */
#define FC_TYPE_BLS	0x00	/* basic link service */
#define FC_TYPE_ELS	0x01	/* extended link service */
#define FC_TYPE_FCP	0x08	/* Fibre Channel Protocol (SCSI) */
#define FC_TYPE_CT	0x20	/* common transport */

static inline int fc_frame_type(const void *vfc)
{
	return ((struct fc_frame_header *)vfc)->fh_type;
}

#endif /* __XDP2_PROTO_FC_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_fc protocol definition
 *
 * Parse Fibre Channel frame header (24 bytes fixed).
 * Dispatches to FCP, ELS, etc. based on type field.
 */
static const struct xdp2_proto_def xdp2_parse_fc __unused() = {
	.name = "FC",
	.min_len = sizeof(struct fc_frame_header),
	.ops.next_proto = fc_frame_type,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
