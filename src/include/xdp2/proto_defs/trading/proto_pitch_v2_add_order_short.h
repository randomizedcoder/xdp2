/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2026 XDP2 contributors
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

#ifndef __XDP2_PROTO_PITCH_V2_ADD_ORDER_SHORT_H__
#define __XDP2_PROTO_PITCH_V2_ADD_ORDER_SHORT_H__

#include "xdp2/parser.h"

/* PITCH v2 AddOrderShort message.
 *
 * Leaf protocol: min_len sourced from OMI c-struct AddOrderShortMessageT
 * (Cboe.Byx.Equities.DepthOfBook.Pitch.v2.41.29.h). Field layout intentionally not declared here — proto-audit
 * draws layout from the OMI source for cross-source comparison; XDP2 field
 * parsing and MessageType-char dispatch for these messages is a follow-up
 * phase.
 */

#endif /* __XDP2_PROTO_PITCH_V2_ADD_ORDER_SHORT_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_pitch_v2_add_order_short protocol definition */
static const struct xdp2_proto_def xdp2_parse_pitch_v2_add_order_short __unused() = {
	.name = "PITCH v2 AddOrderShort",
	.min_len = 26,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
