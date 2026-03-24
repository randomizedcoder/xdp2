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

#ifndef __XDP2_PROTO_HCI_H__
#define __XDP2_PROTO_HCI_H__

#include "xdp2/parser.h"

/* Bluetooth HCI packet indicator.
 * 1-byte prefix identifying the HCI packet type.
 * Chainable — dispatches on type field.
 * Kernel: include/net/bluetooth/bluetooth.h
 *
 * Type values: 0x01=cmd, 0x02=ACL, 0x03=SCO, 0x04=event, 0x05=ISO
 */

#define HCI_COMMAND_PKT		0x01
#define HCI_ACLDATA_PKT		0x02
#define HCI_SCODATA_PKT		0x03
#define HCI_EVENT_PKT		0x04
#define HCI_ISODATA_PKT		0x05

struct hci_pkt_indicator {
	__u8 type;
};

/* Next protocol: return packet type for dispatch */
static inline int hci_proto(const void *vhdr)
{
	return ((struct hci_pkt_indicator *)vhdr)->type;
}

#endif /* __XDP2_PROTO_HCI_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_hci protocol definition
 *
 * Parse HCI packet indicator (1 byte).
 * Next protocol returns packet type for dispatch.
 */
static const struct xdp2_proto_def xdp2_parse_hci __unused() = {
	.name = "HCI",
	.min_len = sizeof(struct hci_pkt_indicator),
	.ops.next_proto = hci_proto,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
