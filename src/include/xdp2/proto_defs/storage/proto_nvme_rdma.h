/* SPDX-License-Identifier: GPL-2.0 */
/*
 * NVMe over RDMA (NVMe/RoCEv2) Connection Manager private data for XDP2.
 *
 * Based on Linux kernel include/linux/nvme-rdma.h
 * Copyright (c) 2015 Mellanox Technologies. All rights reserved.
 *
 * NVMe/RDMA data-path uses standard RoCEv2 + IB transport headers
 * (BTH, RETH, AETH) to carry NVMe command/completion capsules.
 * These structures are RDMA CM private data exchanged during
 * connection setup, not on the data path.
 */

#ifndef __XDP2_PROTO_NVME_RDMA_H__
#define __XDP2_PROTO_NVME_RDMA_H__

#include "xdp2/utility.h"

/**
 * struct xdp2_nvme_rdma_cm_req - NVMe/RDMA connect request (32 bytes)
 * @recfmt:   record format version (0 = v1.0)
 * @qid:      queue identifier (0 = admin queue)
 * @hrqsize:  host receive queue size
 * @hsqsize:  host send queue size
 * @cntlid:   controller ID
 */
struct xdp2_nvme_rdma_cm_req {
	__le16	recfmt;
	__le16	qid;
	__le16	hrqsize;
	__le16	hsqsize;
	__le16	cntlid;
	__u8	rsvd[22];
} __packed;

/**
 * struct xdp2_nvme_rdma_cm_rep - NVMe/RDMA connect reply (32 bytes)
 * @recfmt:   record format version
 * @crqsize:  controller receive queue size
 */
struct xdp2_nvme_rdma_cm_rep {
	__le16	recfmt;
	__le16	crqsize;
	__u8	rsvd[28];
} __packed;

/**
 * struct xdp2_nvme_rdma_cm_rej - NVMe/RDMA connect reject (4 bytes)
 * @recfmt:   record format version
 * @sts:      error status (nvme_rdma_cm_status enum)
 */
struct xdp2_nvme_rdma_cm_rej {
	__le16	recfmt;
	__le16	sts;
} __packed;

#endif /* __XDP2_PROTO_NVME_RDMA_H__ */
