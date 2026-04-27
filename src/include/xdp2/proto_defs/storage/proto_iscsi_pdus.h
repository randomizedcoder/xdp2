/* SPDX-License-Identifier: GPL-2.0 */
/*
 * iSCSI PDU type-specific headers for XDP2 (RFC 7143).
 *
 * The generic BHS is in proto_iscsi.h. This file adds the
 * opcode-specific PDU structs from the kernel's scsi/iscsi_proto.h.
 * All PDUs are 48 bytes (ISCSI_HDR_LEN).
 */

#ifndef __XDP2_PROTO_ISCSI_PDUS_H__
#define __XDP2_PROTO_ISCSI_PDUS_H__

#include "xdp2/utility.h"

/**
 * struct xdp2_iscsi_scsi_req - SCSI Command PDU (48 bytes)
 */
struct xdp2_iscsi_scsi_req {
	__u8	opcode;
	__u8	flags;
	__be16	rsvd2;
	__u8	hlength;
	__u8	dlength[3];
	__u8	lun[8];
	__be32	itt;
	__be32	data_length;
	__be32	cmdsn;
	__be32	exp_statsn;
	__u8	cdb[16];
} __packed;

/**
 * struct xdp2_iscsi_scsi_rsp - SCSI Response PDU (48 bytes)
 */
struct xdp2_iscsi_scsi_rsp {
	__u8	opcode;
	__u8	flags;
	__u8	response;
	__u8	cmd_status;
	__u8	hlength;
	__u8	dlength[3];
	__u8	rsvd[8];
	__be32	itt;
	__be32	rsvd1;
	__be32	statsn;
	__be32	exp_cmdsn;
	__be32	max_cmdsn;
	__be32	exp_datasn;
	__be32	bi_residual_count;
	__be32	residual_count;
} __packed;

/**
 * struct xdp2_iscsi_tm - Task Management PDU (48 bytes)
 */
struct xdp2_iscsi_tm {
	__u8	opcode;
	__u8	flags;
	__u8	rsvd1[2];
	__u8	hlength;
	__u8	dlength[3];
	__u8	lun[8];
	__be32	itt;
	__be32	rtt;
	__be32	cmdsn;
	__be32	exp_statsn;
	__be32	refcmdsn;
	__be32	exp_datasn;
	__u8	rsvd2[8];
} __packed;

/**
 * struct xdp2_iscsi_tm_rsp - Task Management Response PDU (48 bytes)
 */
struct xdp2_iscsi_tm_rsp {
	__u8	opcode;
	__u8	flags;
	__u8	response;
	__u8	qualifier;
	__u8	hlength;
	__u8	dlength[3];
	__u8	rsvd2[8];
	__be32	itt;
	__be32	rtt;
	__be32	statsn;
	__be32	exp_cmdsn;
	__be32	max_cmdsn;
	__u8	rsvd3[12];
} __packed;

/**
 * struct xdp2_iscsi_data - SCSI Data-Out PDU (48 bytes)
 */
struct xdp2_iscsi_data {
	__u8	opcode;
	__u8	flags;
	__u8	rsvd2[2];
	__u8	rsvd3;
	__u8	dlength[3];
	__u8	lun[8];
	__be32	itt;
	__be32	ttt;
	__be32	rsvd4;
	__be32	exp_statsn;
	__be32	rsvd5;
	__be32	datasn;
	__be32	offset;
	__be32	rsvd6;
} __packed;

/**
 * struct xdp2_iscsi_data_rsp - SCSI Data-In PDU (48 bytes)
 */
struct xdp2_iscsi_data_rsp {
	__u8	opcode;
	__u8	flags;
	__u8	rsvd2;
	__u8	cmd_status;
	__u8	hlength;
	__u8	dlength[3];
	__u8	lun[8];
	__be32	itt;
	__be32	ttt;
	__be32	statsn;
	__be32	exp_cmdsn;
	__be32	max_cmdsn;
	__be32	datasn;
	__be32	offset;
	__be32	residual_count;
} __packed;

/**
 * struct xdp2_iscsi_r2t_rsp - Ready To Transfer PDU (48 bytes)
 */
struct xdp2_iscsi_r2t_rsp {
	__u8	opcode;
	__u8	flags;
	__u8	rsvd2[2];
	__u8	hlength;
	__u8	dlength[3];
	__u8	lun[8];
	__be32	itt;
	__be32	ttt;
	__be32	statsn;
	__be32	exp_cmdsn;
	__be32	max_cmdsn;
	__be32	r2tsn;
	__be32	data_offset;
	__be32	data_length;
} __packed;

/**
 * struct xdp2_iscsi_nopout - NOP-Out PDU (48 bytes)
 */
struct xdp2_iscsi_nopout {
	__u8	opcode;
	__u8	flags;
	__be16	rsvd2;
	__u8	rsvd3;
	__u8	dlength[3];
	__u8	lun[8];
	__be32	itt;
	__be32	ttt;
	__be32	cmdsn;
	__be32	exp_statsn;
	__u8	rsvd4[16];
} __packed;

/**
 * struct xdp2_iscsi_nopin - NOP-In PDU (48 bytes)
 */
struct xdp2_iscsi_nopin {
	__u8	opcode;
	__u8	flags;
	__be16	rsvd2;
	__u8	rsvd3;
	__u8	dlength[3];
	__u8	lun[8];
	__be32	itt;
	__be32	ttt;
	__be32	statsn;
	__be32	exp_cmdsn;
	__be32	max_cmdsn;
	__u8	rsvd4[12];
} __packed;

/**
 * struct xdp2_iscsi_login_req - Login Request PDU (48 bytes)
 */
struct xdp2_iscsi_login_req {
	__u8	opcode;
	__u8	flags;
	__u8	max_version;
	__u8	min_version;
	__u8	hlength;
	__u8	dlength[3];
	__u8	isid[6];
	__be16	tsih;
	__be32	itt;
	__be16	cid;
	__be16	rsvd3;
	__be32	cmdsn;
	__be32	exp_statsn;
	__u8	rsvd5[16];
} __packed;

/**
 * struct xdp2_iscsi_login_rsp - Login Response PDU (48 bytes)
 */
struct xdp2_iscsi_login_rsp {
	__u8	opcode;
	__u8	flags;
	__u8	max_version;
	__u8	active_version;
	__u8	hlength;
	__u8	dlength[3];
	__u8	isid[6];
	__be16	tsih;
	__be32	itt;
	__be32	rsvd3;
	__be32	statsn;
	__be32	exp_cmdsn;
	__be32	max_cmdsn;
	__u8	status_class;
	__u8	status_detail;
	__u8	rsvd4[10];
} __packed;

/**
 * struct xdp2_iscsi_text - Text Request PDU (48 bytes)
 */
struct xdp2_iscsi_text {
	__u8	opcode;
	__u8	flags;
	__u8	rsvd2[2];
	__u8	hlength;
	__u8	dlength[3];
	__u8	rsvd4[8];
	__be32	itt;
	__be32	ttt;
	__be32	cmdsn;
	__be32	exp_statsn;
	__u8	rsvd5[16];
} __packed;

/**
 * struct xdp2_iscsi_text_rsp - Text Response PDU (48 bytes)
 */
struct xdp2_iscsi_text_rsp {
	__u8	opcode;
	__u8	flags;
	__u8	rsvd2[2];
	__u8	hlength;
	__u8	dlength[3];
	__u8	rsvd4[8];
	__be32	itt;
	__be32	ttt;
	__be32	statsn;
	__be32	exp_cmdsn;
	__be32	max_cmdsn;
	__u8	rsvd5[12];
} __packed;

/**
 * struct xdp2_iscsi_logout - Logout Request PDU (48 bytes)
 */
struct xdp2_iscsi_logout {
	__u8	opcode;
	__u8	flags;
	__u8	rsvd1[2];
	__u8	hlength;
	__u8	dlength[3];
	__u8	rsvd2[8];
	__be32	itt;
	__be16	cid;
	__u8	rsvd3[2];
	__be32	cmdsn;
	__be32	exp_statsn;
	__u8	rsvd4[16];
} __packed;

/**
 * struct xdp2_iscsi_logout_rsp - Logout Response PDU (48 bytes)
 */
struct xdp2_iscsi_logout_rsp {
	__u8	opcode;
	__u8	flags;
	__u8	response;
	__u8	rsvd2;
	__u8	hlength;
	__u8	dlength[3];
	__u8	rsvd3[8];
	__be32	itt;
	__be32	rsvd4;
	__be32	statsn;
	__be32	exp_cmdsn;
	__be32	max_cmdsn;
	__be32	rsvd5;
	__be16	t2wait;
	__be16	t2retain;
	__be32	rsvd6;
} __packed;

/**
 * struct xdp2_iscsi_async - Async Event PDU (48 bytes)
 */
struct xdp2_iscsi_async {
	__u8	opcode;
	__u8	flags;
	__u8	rsvd2[2];
	__u8	rsvd3;
	__u8	dlength[3];
	__u8	lun[8];
	__u8	rsvd4[8];
	__be32	statsn;
	__be32	exp_cmdsn;
	__be32	max_cmdsn;
	__u8	async_event;
	__u8	async_vcode;
	__be16	param1;
	__be16	param2;
	__be16	param3;
	__u8	rsvd5[4];
} __packed;

/**
 * struct xdp2_iscsi_reject - Reject PDU (48 bytes)
 */
struct xdp2_iscsi_reject {
	__u8	opcode;
	__u8	flags;
	__u8	reason;
	__u8	rsvd2;
	__u8	hlength;
	__u8	dlength[3];
	__u8	rsvd3[8];
	__be32	ffffffff;
	__u8	rsvd4[4];
	__be32	statsn;
	__be32	exp_cmdsn;
	__be32	max_cmdsn;
	__be32	datasn;
	__u8	rsvd5[8];
} __packed;

#endif /* __XDP2_PROTO_ISCSI_PDUS_H__ */
