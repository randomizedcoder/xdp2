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

#ifndef __XDP2_PROTO_MLD_H__
#define __XDP2_PROTO_MLD_H__

/* MLD protocol definitions (RFC 2710, RFC 3810) */

#ifdef __bpf__
/* BPF: icmp6hdr comes from xdp2/proto_defs/ip/proto_icmp.h (minimal
 * definition). <linux/icmpv6.h> would redefine it. <linux/in6.h> is
 * safe — <linux/ipv6.h> already pulls it and its struct in6_addr
 * definition matches what we need.
 */
#include "xdp2/proto_defs/ip/proto_icmp.h"
#include <linux/in6.h>
#else
#include <linux/icmpv6.h>
#include <linux/in6.h>
#endif

#include "xdp2/parser.h"

/* MLDv1 message (RFC 2710) — carried inside ICMPv6 */
struct mld_msg {
	struct icmp6hdr		mld_hdr;
	struct in6_addr		mld_mca;	/* multicast address */
};

#define mld_type	mld_hdr.icmp6_type
#define mld_code	mld_hdr.icmp6_code
#define mld_cksum	mld_hdr.icmp6_cksum
#define mld_maxdelay	mld_hdr.icmp6_maxdelay

/* MLDv2 Query (RFC 3810) */
struct mld2_query {
	struct icmp6hdr		mld2q_hdr;
	struct in6_addr		mld2q_mca;
	__u8			mld2q_qrv:3,	/* querier's robustness var */
				mld2q_suppress:1,
				mld2q_resv2:4;
	__u8			mld2q_qqic;	/* querier's query interval */
	__be16			mld2q_nsrcs;	/* number of sources */
	struct in6_addr		mld2q_srcs[0];
};

/* MLDv2 Report (RFC 3810) */
struct mld2_report {
	struct icmp6hdr		mld2r_hdr;
	__be16			mld2r_resv;
	__be16			mld2r_ngrec;	/* number of group records */
	/* group records follow */
};

#endif /* __XDP2_PROTO_MLD_H__ */

#ifdef XDP2_DEFINE_PARSE_NODE

/* xdp2_parse_mld protocol definition
 *
 * Parse MLDv1 message (24 bytes, carried inside ICMPv6).
 */
static const struct xdp2_proto_def xdp2_parse_mld __unused() = {
	.name = "MLD",
	.min_len = sizeof(struct mld_msg),
};

/* xdp2_parse_mldv2_query protocol definition
 *
 * Parse MLDv2 Query (28 bytes minimum, variable with source addresses).
 */
static const struct xdp2_proto_def xdp2_parse_mldv2_query __unused() = {
	.name = "MLDv2 Query",
	.min_len = sizeof(struct mld2_query),
};

/* xdp2_parse_mldv2_report protocol definition
 *
 * Parse MLDv2 Report (8 bytes minimum, variable with group records).
 */
static const struct xdp2_proto_def xdp2_parse_mldv2_report __unused() = {
	.name = "MLDv2 Report",
	.min_len = sizeof(struct mld2_report),
};

#endif /* XDP2_DEFINE_PARSE_NODE */
