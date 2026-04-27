/* SPDX-License-Identifier: GPL-2.0 */
/*
 * NVMe over Fabrics TCP protocol header definitions for XDP2.
 *
 * Based on Linux kernel include/linux/nvme-tcp.h
 * Copyright (c) 2018 Lightbits Labs. All rights reserved.
 */

#ifndef __XDP2_PROTO_NVME_TCP_H__
#define __XDP2_PROTO_NVME_TCP_H__

#include "xdp2/utility.h"

/* NVMe/TCP well-known ports */
#define NVME_TCP_PORT		4420
#define NVME_TCP_DISC_PORT	8009

/* NVMe/TCP PDU types */
enum nvme_tcp_pdu_type {
	NVME_TCP_ICREQ		= 0x0,
	NVME_TCP_ICRESP		= 0x1,
	NVME_TCP_H2C_TERM	= 0x2,
	NVME_TCP_C2H_TERM	= 0x3,
	NVME_TCP_CMD		= 0x4,
	NVME_TCP_RSP		= 0x5,
	NVME_TCP_H2C_DATA	= 0x6,
	NVME_TCP_C2H_DATA	= 0x7,
	NVME_TCP_R2T		= 0x9,
};

/**
 * struct nvme_tcp_hdr - NVMe/TCP common PDU header (8 bytes)
 * @type:   PDU type
 * @flags:  PDU-specific flags (HDGST, DDGST, DATA_LAST, DATA_SUCCESS)
 * @hlen:   PDU header length in bytes
 * @pdo:    PDU data offset in bytes
 * @plen:   PDU wire byte length (little-endian)
 */
struct xdp2_nvme_tcp_hdr {
	__u8	type;
	__u8	flags;
	__u8	hlen;
	__u8	pdo;
	__le32	plen;
} __packed;

/**
 * struct xdp2_nvme_tcp_icreq_pdu - Initialize Connection Request (128 bytes)
 */
struct xdp2_nvme_tcp_icreq_pdu {
	struct xdp2_nvme_tcp_hdr	hdr;
	__le16				pfv;
	__u8				hpda;
	__u8				digest;
	__le32				maxr2t;
	__u8				rsvd2[112];
} __packed;

/**
 * struct xdp2_nvme_tcp_icresp_pdu - Initialize Connection Response (128 bytes)
 */
struct xdp2_nvme_tcp_icresp_pdu {
	struct xdp2_nvme_tcp_hdr	hdr;
	__le16				pfv;
	__u8				cpda;
	__u8				digest;
	__le32				maxdata;
	__u8				rsvd[112];
} __packed;

/**
 * struct xdp2_nvme_tcp_r2t_pdu - Ready to Transfer (24 bytes)
 */
struct xdp2_nvme_tcp_r2t_pdu {
	struct xdp2_nvme_tcp_hdr	hdr;
	__u16				command_id;
	__u16				ttag;
	__le32				r2t_offset;
	__le32				r2t_length;
	__u8				rsvd[4];
} __packed;

/**
 * struct xdp2_nvme_tcp_data_pdu - Data Transfer PDU header (24 bytes)
 */
struct xdp2_nvme_tcp_data_pdu {
	struct xdp2_nvme_tcp_hdr	hdr;
	__u16				command_id;
	__u16				ttag;
	__le32				data_offset;
	__le32				data_length;
	__u8				rsvd[4];
} __packed;

/**
 * struct xdp2_nvme_tcp_rsp_pdu - Response Capsule (24 bytes)
 * Note: The full kernel struct embeds nvme_completion (16 bytes) after
 * the 8-byte hdr, but we treat it as flat fields for XDP parsing.
 */
struct xdp2_nvme_tcp_rsp_pdu {
	struct xdp2_nvme_tcp_hdr	hdr;
	/* nvme_completion fields inlined */
	__le32				result_lo;
	__le32				result_hi;
	__le16				sq_head;
	__le16				sq_id;
	__le16				command_id;
	__le16				status;
} __packed;

static inline ssize_t nvme_tcp_hdr_len(const void *vhdr, size_t maxlen)
{
	return ((struct xdp2_nvme_tcp_hdr *)vhdr)->hlen;
}

static inline int nvme_tcp_pdu_proto(const void *vhdr)
{
	return ((struct xdp2_nvme_tcp_hdr *)vhdr)->type;
}

#endif /* __XDP2_PROTO_NVME_TCP_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_nvme_tcp protocol definition
 *
 * Parse NVMe/TCP common PDU header (8 bytes).
 * Dispatches on PDU type to specific PDU formats.
 */
static const struct xdp2_proto_def xdp2_parse_nvme_tcp __unused() = {
	.name = "NVMe/TCP",
	.min_len = sizeof(struct xdp2_nvme_tcp_hdr),
	.ops.next_proto = nvme_tcp_pdu_proto,
	.ops.len = nvme_tcp_hdr_len,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
