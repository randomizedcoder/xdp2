/* SPDX-License-Identifier: GPL-2.0 */
/*
 * eCPRI (enhanced Common Public Radio Interface) header for XDP2.
 *
 * eCPRI is carried on Ethernet (EtherType 0xAEFE) or UDP.
 * This defines the 4-byte common header per ORAN/eCPRI spec v2.0.
 *
 * Based on DPDK rte_ecpri.h layout.
 */

#ifndef __XDP2_PROTO_ECPRI_H__
#define __XDP2_PROTO_ECPRI_H__

#include "xdp2/utility.h"

/* eCPRI EtherType */
#define ECPRI_ETHER_TYPE 0xAEFE

/* eCPRI message types */
enum ecpri_msg_type {
	ECPRI_MSG_IQ_DATA         = 0,
	ECPRI_MSG_BIT_SEQUENCE    = 1,
	ECPRI_MSG_REAL_TIME_CTRL  = 2,
	ECPRI_MSG_GENERIC_DATA    = 3,
	ECPRI_MSG_REMOTE_MEM_ACC  = 4,
	ECPRI_MSG_ONE_WAY_DELAY   = 5,
	ECPRI_MSG_REMOTE_RESET    = 6,
	ECPRI_MSG_EVENT_IND       = 7,
};

/**
 * struct xdp2_ecpri_common_hdr - eCPRI common header (4 bytes)
 * @revision:     protocol revision (4 bits, currently 1)
 * @reserved:     reserved (3 bits)
 * @c:            concatenation indicator (1 bit)
 * @msg_type:     message type (8 bits)
 * @payload_size: payload size in bytes (16 bits, big-endian)
 */
struct xdp2_ecpri_common_hdr {
#if defined(__BIG_ENDIAN_BITFIELD)
	__u8 revision: 4;
	__u8 reserved: 3;
	__u8 c: 1;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 c: 1;
	__u8 reserved: 3;
	__u8 revision: 4;
#else
#error "Please fix bitfield endianness"
#endif
	__u8 msg_type;
	__be16 payload_size;
} __packed;

#endif /* __XDP2_PROTO_ECPRI_H__ */
