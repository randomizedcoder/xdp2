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

#ifndef __XDP2_PROTO_QINQ_H__
#define __XDP2_PROTO_QINQ_H__

/* Q-in-Q (802.1ad) double VLAN tagging
 *
 * Structurally identical to VLAN — same 4-byte TCI + encapsulated proto.
 * The outer tag uses EtherType 0x88a8 (ETH_P_8021AD), the inner uses
 * 0x8100 (ETH_P_8021Q). Both dispatch on h_vlan_encapsulated_proto.
 */

#include "xdp2/proto_defs/ethernet/proto_vlan.h"

#endif /* __XDP2_PROTO_QINQ_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_qinq protocol definition
 *
 * Parse Q-in-Q (802.1ad) outer VLAN tag
 *
 * Same struct as VLAN, dispatches on encapsulated proto (typically 0x8100)
 */
static const struct xdp2_proto_def xdp2_parse_qinq __unused() = {
	.name = "QinQ",
	.min_len = sizeof(struct vlan_hdr),
	.ops.next_proto = vlan_proto,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
