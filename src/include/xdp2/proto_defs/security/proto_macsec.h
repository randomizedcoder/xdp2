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

#ifndef __XDP2_PROTO_MACSEC_H__
#define __XDP2_PROTO_MACSEC_H__

#include "xdp2/parser.h"

/* MACsec (IEEE 802.1AE) SecTAG header.
 * Encrypted payload follows — this is a leaf protocol.
 * TCI (1 byte) + SL (1 byte) + PN (4 bytes) = 6 bytes minimum.
 */

struct macsec_sectag {
	__u8 tci_an;		/* TCI (6 bits) + AN (2 bits) */
	__u8 sl;		/* Short Length */
	__be32 pn;		/* Packet Number */
};

#endif /* __XDP2_PROTO_MACSEC_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_macsec protocol definition
 *
 * Parse MACsec SecTAG (leaf — encrypted payload)
 */
static const struct xdp2_proto_def xdp2_parse_macsec __unused() = {
	.name = "MACsec",
	.min_len = sizeof(struct macsec_sectag),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
