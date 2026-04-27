/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Serial Attached SCSI (SAS) protocol headers for XDP2.
 *
 * Based on Linux kernel include/scsi/sas.h
 * Includes SSP (Serial SCSI Protocol) and SMP (Serial Management Protocol)
 * frame structures, plus ATA FIS (Frame Information Structure).
 */

#ifndef __XDP2_PROTO_SAS_H__
#define __XDP2_PROTO_SAS_H__

#include "xdp2/utility.h"

/**
 * struct xdp2_ssp_frame_hdr - SSP Frame Header (24 bytes)
 */
struct xdp2_ssp_frame_hdr {
	__u8	frame_type;
	__u8	hashed_dest_addr[3];
	__u8	_r_a;
	__u8	hashed_src_addr[3];
	__be16	_r_b;
	__u8	flags1;
	__u8	flags2;
	__be32	_r_e;
	__be16	tag;
	__be16	tptt;
	__be32	data_offs;
} __packed;

/**
 * struct xdp2_ssp_command_iu - SSP Command IU (28 bytes fixed)
 */
struct xdp2_ssp_command_iu {
	__u8	lun[8];
	__u8	_r_a;
	__u8	efb_prio_attr;
	__u8	_r_b;
	__u8	add_cdb_len_flags;
	__u8	cdb[16];
} __packed;

/**
 * struct xdp2_ssp_response_iu - SSP Response IU (24 bytes fixed)
 */
struct xdp2_ssp_response_iu {
	__u8	_r_a[10];
	__u8	datapres_flags;
	__u8	status;
	__be32	_r_c;
	__be32	sense_data_len;
	__be32	response_data_len;
} __packed;

/**
 * struct xdp2_xfer_rdy_iu - Transfer Ready IU (12 bytes)
 */
struct xdp2_xfer_rdy_iu {
	__be32	requested_offset;
	__be32	write_data_len;
	__be32	_r_a;
} __packed;

/**
 * struct xdp2_ssp_tmf_iu - SSP Task Management Function IU (24 bytes)
 */
struct xdp2_ssp_tmf_iu {
	__u8	lun[8];
	__be16	_r_a;
	__u8	tmf;
	__u8	_r_b;
	__be16	tag;
	__u8	_r_c[14];
} __packed;

/**
 * struct xdp2_host_to_dev_fis - ATA Host-to-Device FIS (20 bytes)
 */
struct xdp2_host_to_dev_fis {
	__u8	fis_type;	/* 0x27 */
	__u8	flags;
	__u8	command;
	__u8	features;
	__u8	lbal;
	__u8	lbam;
	__u8	lbah;
	__u8	device;
	__u8	lbal_exp;
	__u8	lbam_exp;
	__u8	lbah_exp;
	__u8	features_exp;
	__u8	sector_count;
	__u8	sector_count_exp;
	__u8	_r_a;
	__u8	control;
	__be32	_r_b;
} __packed;

/**
 * struct xdp2_dev_to_host_fis - ATA Device-to-Host FIS (20 bytes)
 */
struct xdp2_dev_to_host_fis {
	__u8	fis_type;	/* 0x34 */
	__u8	flags;
	__u8	status;
	__u8	error;
	__u8	lbal;
	__u8	lbam;
	__u8	lbah;
	__u8	device;
	__u8	lbal_exp;
	__u8	lbam_exp;
	__u8	lbah_exp;
	__u8	_r_a;
	__u8	sector_count;
	__u8	sector_count_exp;
	__u8	_r_b;
	__u8	_r_c;
	__be32	_r_d;
} __packed;

/**
 * struct xdp2_sas_identify_frame - SAS Identification Frame (32 bytes)
 */
struct xdp2_sas_identify_frame {
	__u8	frame_type_dev_type;
	__u8	_un1;
	__u8	initiator_bits;
	__u8	target_bits;
	__u8	_un4_11[8];
	__u8	sas_addr[8];
	__u8	phy_id;
	__u8	_un21_27[7];
} __packed;

#endif /* __XDP2_PROTO_SAS_H__ */
