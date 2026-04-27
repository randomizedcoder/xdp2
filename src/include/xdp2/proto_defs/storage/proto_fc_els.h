/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Fibre Channel Extended Link Services (FC ELS) headers for XDP2.
 *
 * Based on Linux kernel include/uapi/scsi/fc/fc_els.h
 * FC-LS Rev 1.2.
 */

#ifndef __XDP2_PROTO_FC_ELS_H__
#define __XDP2_PROTO_FC_ELS_H__

#include "xdp2/utility.h"

/**
 * struct xdp2_fc_els_ls_acc - ELS Accept (4 bytes)
 */
struct xdp2_fc_els_ls_acc {
	__u8	la_cmd;
	__u8	la_resv[3];
} __packed;

/**
 * struct xdp2_fc_els_ls_rjt - ELS Reject (8 bytes)
 */
struct xdp2_fc_els_ls_rjt {
	__u8	er_cmd;
	__u8	er_resv[4];
	__u8	er_reason;
	__u8	er_explan;
	__u8	er_vendor;
} __packed;

/**
 * struct xdp2_fc_els_flogi - FLOGI/PLOGI (116 bytes)
 *
 * Contains common service parameters (16 bytes), port name (8),
 * node name (8), 4x class service params (4x16=64), vendor (16).
 */
struct xdp2_fc_els_flogi {
	__u8	fl_cmd;
	__u8	_fl_resvd[3];
	/* Common service parameters (16 bytes) */
	__u8	sp_hi_ver;
	__u8	sp_lo_ver;
	__be16	sp_bb_cred;
	__be16	sp_features;
	__be16	sp_bb_data;
	__be32	sp_u;
	__be32	sp_e_d_tov;
	/* Port and node names */
	__be64	fl_wwpn;
	__be64	fl_wwnn;
	/* Class 1-4 service parameters (4 x 16 bytes = 64) */
	__u8	fl_cssp[64];
	/* Vendor version level */
	__u8	fl_vend[16];
} __packed;

/**
 * struct xdp2_fc_els_logo - Logout (12 bytes)
 */
struct xdp2_fc_els_logo {
	__u8	fl_cmd;
	__u8	fl_zero[3];
	__u8	fl_resvd;
	__u8	fl_n_port_id[3];
	__be64	fl_n_port_wwn;
} __packed;

/**
 * struct xdp2_fc_els_prli - Process Login (4 bytes header)
 */
struct xdp2_fc_els_prli {
	__u8	prli_cmd;
	__u8	prli_spp_len;
	__be16	prli_len;
} __packed;

/**
 * struct xdp2_fc_els_adisc - Address Discovery (28 bytes)
 */
struct xdp2_fc_els_adisc {
	__u8	adisc_cmd;
	__u8	adisc_resv[3];
	__u8	adisc_resv1;
	__u8	adisc_hard_addr[3];
	__be64	adisc_wwpn;
	__be64	adisc_wwnn;
	__u8	adisc_resv2;
	__u8	adisc_port_id[3];
} __packed;

/**
 * struct xdp2_fc_els_rscn - Registered State Change Notification (4 bytes header)
 */
struct xdp2_fc_els_rscn {
	__u8	rscn_cmd;
	__u8	rscn_page_len;
	__be16	rscn_plen;
} __packed;

/**
 * struct xdp2_fc_els_scr - State Change Registration (8 bytes)
 */
struct xdp2_fc_els_scr {
	__u8	scr_cmd;
	__u8	scr_resv[6];
	__u8	scr_reg_func;
} __packed;

#endif /* __XDP2_PROTO_FC_ELS_H__ */
