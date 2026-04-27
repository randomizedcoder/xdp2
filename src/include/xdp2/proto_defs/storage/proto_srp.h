/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SCSI RDMA Protocol (SRP) Information Units for XDP2.
 *
 * Based on Linux kernel include/scsi/srp.h
 * SRP carries SCSI commands and responses over InfiniBand/RDMA.
 * T10 SRP Revision 16a.
 */

#ifndef __XDP2_PROTO_SRP_H__
#define __XDP2_PROTO_SRP_H__

#include "xdp2/utility.h"

/**
 * struct xdp2_srp_login_req - SRP Login Request IU (64 bytes)
 */
struct xdp2_srp_login_req {
	__u8	opcode;
	__u8	reserved1[7];
	__be64	tag;
	__be32	req_it_iu_len;
	__u8	reserved2[4];
	__be16	req_buf_fmt;
	__u8	req_flags;
	__u8	reserved3[1];
	__be16	imm_data_offset;
	__u8	reserved4[2];
	__u8	initiator_port_id[16];
	__u8	target_port_id[16];
} __packed;

/**
 * struct xdp2_srp_login_rsp - SRP Login Response IU (52 bytes)
 */
struct xdp2_srp_login_rsp {
	__u8	opcode;
	__u8	reserved1[3];
	__be32	req_lim_delta;
	__be64	tag;
	__be32	max_it_iu_len;
	__be32	max_ti_iu_len;
	__be16	buf_fmt;
	__u8	rsp_flags;
	__u8	reserved2[25];
} __packed;

/**
 * struct xdp2_srp_login_rej - SRP Login Reject IU (32 bytes)
 */
struct xdp2_srp_login_rej {
	__u8	opcode;
	__u8	reserved1[3];
	__be32	reason;
	__be64	tag;
	__u8	reserved2[8];
	__be16	buf_fmt;
	__u8	reserved3[6];
} __packed;

/**
 * struct xdp2_srp_cmd - SRP Command IU (48 bytes fixed portion)
 */
struct xdp2_srp_cmd {
	__u8	opcode;
	__u8	sol_not;
	__u8	reserved1[3];
	__u8	buf_fmt;
	__u8	data_out_desc_cnt;
	__u8	data_in_desc_cnt;
	__be64	tag;
	__u8	reserved2[4];
	__u8	lun[8];
	__u8	reserved3;
	__u8	task_attr;
	__u8	reserved4;
	__u8	add_cdb_len;
	__u8	cdb[16];
} __packed;

/**
 * struct xdp2_srp_rsp - SRP Response IU (36 bytes fixed portion)
 */
struct xdp2_srp_rsp {
	__u8	opcode;
	__u8	sol_not;
	__u8	reserved1[2];
	__be32	req_lim_delta;
	__be64	tag;
	__u8	reserved2[2];
	__u8	flags;
	__u8	status;
	__be32	data_out_res_cnt;
	__be32	data_in_res_cnt;
	__be32	sense_data_len;
	__be32	resp_data_len;
} __packed;

/**
 * struct xdp2_srp_tsk_mgmt - SRP Task Management IU (48 bytes)
 */
struct xdp2_srp_tsk_mgmt {
	__u8	opcode;
	__u8	sol_not;
	__u8	reserved1[6];
	__be64	tag;
	__u8	reserved2[4];
	__u8	lun[8];
	__u8	reserved3[2];
	__u8	tsk_mgmt_func;
	__u8	reserved4;
	__be64	task_tag;
	__u8	reserved5[8];
} __packed;

/**
 * struct xdp2_srp_i_logout - SRP Initiator Logout IU (16 bytes)
 */
struct xdp2_srp_i_logout {
	__u8	opcode;
	__u8	reserved[7];
	__be64	tag;
} __packed;

/**
 * struct xdp2_srp_t_logout - SRP Target Logout IU (16 bytes)
 */
struct xdp2_srp_t_logout {
	__u8	opcode;
	__u8	sol_not;
	__u8	reserved[2];
	__be32	reason;
	__be64	tag;
} __packed;

/**
 * struct xdp2_srp_cred_req - SRP Credit Request IU (16 bytes)
 */
struct xdp2_srp_cred_req {
	__u8	opcode;
	__u8	sol_not;
	__u8	reserved[2];
	__be32	req_lim_delta;
	__be64	tag;
} __packed;

/**
 * struct xdp2_srp_cred_rsp - SRP Credit Response IU (16 bytes)
 */
struct xdp2_srp_cred_rsp {
	__u8	opcode;
	__u8	reserved[7];
	__be64	tag;
} __packed;

#endif /* __XDP2_PROTO_SRP_H__ */
