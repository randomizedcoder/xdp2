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

#ifndef __XDP2_PROTO_IEEE80211_H__
#define __XDP2_PROTO_IEEE80211_H__

#include "xdp2/parser.h"

/* IEEE 802.11 MAC header (WiFi).
 * Root header for 802.11 frames, chainable on frame type.
 * Kernel: include/linux/ieee80211.h
 *
 * Frame control: type(2)+subtype(4)+to_ds(1)+from_ds(1)+...
 * Dispatch on type field (bits 2-3 of frame_control):
 *   0x0000 = Management, 0x0004 = Control, 0x0008 = Data, 0x000c = Extension
 */

#define IEEE80211_FTYPE_MGMT	0x0000
#define IEEE80211_FTYPE_CTL	0x0004
#define IEEE80211_FTYPE_DATA	0x0008
#define IEEE80211_FTYPE_EXT	0x000c
#define IEEE80211_FCTL_FTYPE	0x000c

struct ieee80211_hdr {
	__le16 frame_control;
	__le16 duration_id;
	__u8 addr1[6];
	__u8 addr2[6];
	__u8 addr3[6];
	__le16 seq_ctrl;
	/* addr4[6] conditionally present when To DS=1 AND From DS=1 */
};

/* Next protocol: return frame type field for dispatch */
static inline int ieee80211_proto(const void *vhdr)
{
	return ((struct ieee80211_hdr *)vhdr)->frame_control & IEEE80211_FCTL_FTYPE;
}

#endif /* __XDP2_PROTO_IEEE80211_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_ieee80211 protocol definition
 *
 * Parse 802.11 MAC header (min 24 bytes, 3-address form).
 * Next protocol returns frame type for dispatch.
 */
static const struct xdp2_proto_def xdp2_parse_ieee80211 __unused() = {
	.name = "IEEE 802.11",
	.min_len = sizeof(struct ieee80211_hdr),
	.ops.next_proto = ieee80211_proto,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
