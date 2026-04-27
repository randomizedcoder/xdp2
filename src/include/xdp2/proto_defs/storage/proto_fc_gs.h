/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Fibre Channel Generic Services / Name Server headers for XDP2.
 *
 * Based on Linux kernel include/uapi/scsi/fc/fc_gs.h and fc_ns.h
 * FC-GS-2 Rev 5.3.
 */

#ifndef __XDP2_PROTO_FC_GS_H__
#define __XDP2_PROTO_FC_GS_H__

#include "xdp2/utility.h"

/**
 * struct xdp2_fc_ct_hdr - FC Common Transport Header (16 bytes)
 */
struct xdp2_fc_ct_hdr {
	__u8	ct_rev;
	__u8	ct_in_id[3];
	__u8	ct_fs_type;
	__u8	ct_fs_subtype;
	__u8	ct_options;
	__u8	_ct_resvd1;
	__be16	ct_cmd;
	__be16	ct_mr_size;
	__u8	_ct_resvd2;
	__u8	ct_reason;
	__u8	ct_explan;
	__u8	ct_vendor;
} __packed;

/**
 * struct xdp2_fc_ns_gid_ft - GID_FT Request (4 bytes)
 */
struct xdp2_fc_ns_gid_ft {
	__u8	fn_resvd;
	__u8	fn_domain_id_scope;
	__u8	fn_area_id_scope;
	__u8	fn_fc4_type;
} __packed;

/**
 * struct xdp2_fc_gpn_ft_resp - GPN_FT Response entry (16 bytes)
 */
struct xdp2_fc_gpn_ft_resp {
	__u8	fp_flags;
	__u8	fp_fid[3];
	__be32	fp_resvd;
	__be64	fp_wwpn;
} __packed;

#endif /* __XDP2_PROTO_FC_GS_H__ */
