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

#ifndef __XDP2_PROTO_SCTP_H__
#define __XDP2_PROTO_SCTP_H__

/* SCTP protocol definitions (RFC 9260) */

/* We deliberately don't include <linux/sctp.h> here: it pulls in SCTP
 * socket-API UAPI definitions that (linux-headers ≥6.18) use
 * `struct sockaddr_storage` by value, which requires <sys/socket.h>.
 * BPF translation units can't use libc, so the include breaks the BPF
 * build. XDP2 only needs struct sctphdr, which it defines below.
 */

#include "xdp2/parser.h"

/* struct sctphdr is not in linux/sctp.h UAPI — define if not already available */
#ifndef __XDP2_STRUCT_SCTPHDR_DEFINED__
#define __XDP2_STRUCT_SCTPHDR_DEFINED__
struct sctphdr {
	__be16 source;
	__be16 dest;
	__be32 vtag;
	__le32 checksum;
};
#endif

#endif /* __XDP2_PROTO_SCTP_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_sctp protocol definition
 *
 * Parse SCTP common header (12 bytes fixed).
 * SCTP payload consists of chunks, each with its own type/length.
 */
static const struct xdp2_proto_def xdp2_parse_sctp __unused() = {
	.name = "SCTP",
	.min_len = sizeof(struct sctphdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
