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

#ifndef __XDP2_PROTO_ATM_H__
#define __XDP2_PROTO_ATM_H__

#include "xdp2/parser.h"

/* ATM cell header (ETH_P_ATMMPOA 0x884c for MPOA over Ethernet).
 * 5-byte header (53-byte cells: 5 header + 48 payload).
 * Leaf for flow keys — extracts VPI/VCI.
 * Kernel: include/uapi/linux/atm.h
 */

struct atm_cell_hdr {
	__u8 gfc_vpi;		/* GFC(4) + VPI high(4) */
	__u8 vpi_vci;		/* VPI low(4) + VCI high(4) */
	__u8 vci_mid;		/* VCI mid(8) */
	__u8 vci_pti_clp;	/* VCI low(4) + PTI(3) + CLP(1) */
	__u8 hec;		/* header error control */
};

#endif /* __XDP2_PROTO_ATM_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_atm protocol definition
 *
 * Parse ATM cell header (leaf — no further dispatch)
 */
static const struct xdp2_proto_def xdp2_parse_atm __unused() = {
	.name = "ATM",
	.min_len = sizeof(struct atm_cell_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
