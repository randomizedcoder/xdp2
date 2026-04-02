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

#ifndef __XDP2_PROTO_COAP_H__
#define __XDP2_PROTO_COAP_H__

#include "xdp2/parser.h"

/* CoAP (Constrained Application Protocol, RFC 7252).
 * 4 bytes minimum. RESTful protocol for constrained devices.
 * Leaf protocol — no further dispatch.
 */

struct coap_hdr {
	__u8 ver_type_tkl;	/* version(2) + type(2) + token length(4) */
	__u8 code;		/* class(3) + detail(5) */
	__be16 message_id;
};

#endif /* __XDP2_PROTO_COAP_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_coap protocol definition
 *
 * Parse CoAP header (leaf — constrained application protocol)
 */
static const struct xdp2_proto_def xdp2_parse_coap __unused() = {
	.name = "CoAP",
	.min_len = sizeof(struct coap_hdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
