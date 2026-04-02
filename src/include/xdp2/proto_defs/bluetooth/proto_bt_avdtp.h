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

#ifndef __XDP2_PROTO_BT_AVDTP_H__
#define __XDP2_PROTO_BT_AVDTP_H__

#include "xdp2/parser.h"

/* Bluetooth AVDTP (Audio/Video Distribution Transport Protocol).
 * Carried over L2CAP for A2DP audio streaming.
 * Leaf protocol — header identifies signaling or media transport.
 */

struct bt_avdtp_hdr {
	__u8 msg_type_pkt_type;	/* transaction label, pkt type, msg type */
	__u8 signal_id;		/* signal identifier (signaling only) */
};

#endif /* __XDP2_PROTO_BT_AVDTP_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_bt_avdtp protocol definition
 *
 * Parse BT AVDTP header (leaf — audio/video distribution)
 */
static const struct xdp2_proto_def xdp2_parse_bt_avdtp __unused() = {
	.name = "BT AVDTP",
	.min_len = sizeof(struct bt_avdtp_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
