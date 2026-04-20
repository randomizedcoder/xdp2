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

#ifndef __XDP2_PROTO_SCTP_CHUNK_H__
#define __XDP2_PROTO_SCTP_CHUNK_H__

/* SCTP chunk definitions (RFC 9260, Section 3.2) */

/* See proto_sctp.h for why <linux/sctp.h> is not included: its UAPI
 * struct definitions use `struct sockaddr_storage` by value, which
 * needs <sys/socket.h> — unavailable in BPF TUs. Everything this file
 * requires (sctphdr, sctp_chunkhdr, SCTP_CID_*) is defined below.
 */

#include "xdp2/parser.h"

/* struct sctphdr and struct sctp_chunkhdr are not in linux/sctp.h UAPI.
 * Define them here if not already available (they live in kernel-internal
 * headers or in lksctp-tools' netinet/sctp.h which may not be present).
 */
#ifndef __XDP2_STRUCT_SCTPHDR_DEFINED__
#define __XDP2_STRUCT_SCTPHDR_DEFINED__
struct sctphdr {
	__be16 source;
	__be16 dest;
	__be32 vtag;
	__le32 checksum;
};
#endif

#ifndef __XDP2_STRUCT_SCTP_CHUNKHDR_DEFINED__
#define __XDP2_STRUCT_SCTP_CHUNKHDR_DEFINED__
struct sctp_chunkhdr {
	__u8 type;
	__u8 flags;
	__be16 length;
};
#endif

/* SCTP chunk types */
#define SCTP_CID_DATA			0
#define SCTP_CID_INIT			1
#define SCTP_CID_INIT_ACK		2
#define SCTP_CID_SACK			3
#define SCTP_CID_HEARTBEAT		4
#define SCTP_CID_HEARTBEAT_ACK		5
#define SCTP_CID_ABORT			6
#define SCTP_CID_SHUTDOWN		7
#define SCTP_CID_SHUTDOWN_ACK		8
#define SCTP_CID_ERROR			9
#define SCTP_CID_COOKIE_ECHO		10
#define SCTP_CID_COOKIE_ACK		11
#define SCTP_CID_FWD_TSN		0xC0

static inline ssize_t sctp_chunk_len(const void *hdr, size_t maxlen)
{
	__be16 len = ((struct sctp_chunkhdr *)hdr)->length;

	/* Chunk length includes the header, round up to 4-byte boundary */
	return (ntohs(len) + 3) & ~3;
}

static inline int sctp_chunk_type(const void *hdr)
{
	return ((struct sctp_chunkhdr *)hdr)->type;
}

static inline size_t sctp_chunks_start_offset(const void *hdr)
{
	return sizeof(struct sctphdr);
}

#endif /* __XDP2_PROTO_SCTP_CHUNK_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_sctp_chunks protocol definition
 *
 * Parse SCTP chunks as TLVs within an SCTP packet.
 */
static const struct xdp2_proto_tlvs_def xdp2_parse_sctp_chunks __unused() = {
	.proto_def.node_type = XDP2_NODE_TYPE_TLVS,
	.proto_def.name = "SCTP with chunks",
	.proto_def.min_len = sizeof(struct sctphdr),
	.ops.len = sctp_chunk_len,
	.ops.type = sctp_chunk_type,
	.ops.start_offset = sctp_chunks_start_offset,
	.min_len = sizeof(struct sctp_chunkhdr),
};

/* xdp2_parse_sctp_chunk protocol definition
 *
 * Individual SCTP chunk TLV.
 */
static const struct xdp2_proto_tlv_def xdp2_parse_sctp_chunk __unused() = {
	.min_len = sizeof(struct sctp_chunkhdr),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
