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

#ifndef __XDP2_PROTO_ITCH_V5_STOCK_TRADING_ACTION_H__
#define __XDP2_PROTO_ITCH_V5_STOCK_TRADING_ACTION_H__

#include "xdp2/parser.h"

/* ITCH v5 StockTradingAction message.
 *
 * Leaf protocol: min_len sourced from OMI c-struct StockTradingActionMessageT
 * (Nasdaq.Equities.TotalView.Itch.v5.0.h). Field layout intentionally not declared here — proto-audit
 * draws layout from the OMI source for cross-source comparison; XDP2 field
 * parsing and MessageType-char dispatch for these messages is a follow-up
 * phase.
 */

#endif /* __XDP2_PROTO_ITCH_V5_STOCK_TRADING_ACTION_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_itch_v5_stock_trading_action protocol definition */
static const struct xdp2_proto_def xdp2_parse_itch_v5_stock_trading_action __unused() = {
	.name = "ITCH v5 StockTradingAction",
	.min_len = 19,
};

#endif /* XDP2_DEFINE_PARSE_NODE */
