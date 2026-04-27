/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Fibre Channel Protocol for SCSI (FCP) IU headers for XDP2.
 *
 * Based on Linux kernel include/scsi/fc/fc_fcp.h
 * FCP carries SCSI commands and data over Fibre Channel.
 * T10 FCP-3 Rev 4.
 */

#ifndef __XDP2_PROTO_FCP_H__
#define __XDP2_PROTO_FCP_H__

#include "xdp2/utility.h"

/**
 * struct xdp2_fcp_cmnd - FCP Command IU (32 bytes)
 */
struct xdp2_fcp_cmnd {
	__u8	fc_lun[8];
	__u8	fc_cmdref;
	__u8	fc_pri_ta;
	__u8	fc_tm_flags;
	__u8	fc_flags;
	__u8	fc_cdb[16];
	__be32	fc_dl;
} __packed;

/**
 * struct xdp2_fcp_txrdy - FCP Transfer Ready IU (12 bytes)
 */
struct xdp2_fcp_txrdy {
	__be32	ft_data_ro;
	__be32	ft_burst_len;
	__u8	_ft_resvd[4];
} __packed;

/**
 * struct xdp2_fcp_resp - FCP Response IU (12 bytes)
 */
struct xdp2_fcp_resp {
	__u8	_fr_resvd[8];
	__be16	fr_retry_delay;
	__u8	fr_flags;
	__u8	fr_status;
} __packed;

/**
 * struct xdp2_fcp_resp_ext - FCP Response Extension (12 bytes)
 */
struct xdp2_fcp_resp_ext {
	__be32	fr_resid;
	__be32	fr_sns_len;
	__be32	fr_rsp_len;
} __packed;

/**
 * struct xdp2_fcp_srr - FCP Sequence Retransmission Request (16 bytes)
 */
struct xdp2_fcp_srr {
	__u8	srr_op;
	__u8	srr_resvd[3];
	__be16	srr_ox_id;
	__be16	srr_rx_id;
	__be32	srr_rel_off;
	__u8	srr_r_ctl;
	__u8	srr_resvd2[3];
} __packed;

#endif /* __XDP2_PROTO_FCP_H__ */
