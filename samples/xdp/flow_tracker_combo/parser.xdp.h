

#include "xdp2/compiler_helpers.h"

/* Common parser template. This combined with another use case specific
 * template to make a complete template
 */








/* Template for XDP parser */

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

#include "xdp2/bpf.h"
#include "xdp2/compiler_helpers.h"
#include "xdp2/parser.h"
#include "xdp2/parser_metadata.h"
#include "xdp2/proto_defs_define.h"

#include "parser.c"
#ifndef XDP2_LOOP_COUNT
#define XDP2_LOOP_COUNT 8
#endif

#define XDP2_MAX_ENCAPS (XDP2_LOOP_COUNT + 32)
enum {
CODE_ether_node,
CODE_ip_check_node,
CODE_ipv4_node,
CODE_ipv6_node,
CODE_ports_node,
CODE_IGNORE
};

static __attribute__((unused)) __always_inline int
	check_pkt_len(const void *hdr, const void *hdr_end,
					 const struct xdp2_proto_def *pnode,
					 ssize_t *hlen)
{
	size_t len = (uintptr_t)(hdr_end - hdr);
	*hlen = pnode->min_len;

	/* Protocol node length checks */
	if (xdp2_bpf_check_pkt(hdr, *hlen, hdr_end))
		return XDP2_STOP_LENGTH;

	if (pnode->ops.len) {
		*hlen = pnode->ops.len(hdr, len);
		if (*hlen < 0)
			return XDP2_STOP_LENGTH;
		if (*hlen < pnode->min_len)
			return XDP2_STOP_LENGTH;
		if (xdp2_bpf_check_pkt(hdr, *hlen, hdr_end))
			return XDP2_STOP_LENGTH;
	}

	return XDP2_OKAY;
}


/* Parse one TLV */
static inline __attribute__((unused)) __attribute__((always_inline)) int
	xdp2_parse_tlv(
		const struct xdp2_parse_tlvs_node *parse_node,
		const struct xdp2_parse_tlv_node *parse_tlv_node,
		const __u8 *cp, const void *hdr_end, size_t tlvs_len,
		void *_metadata, void *frame, struct xdp2_ctrl_data *ctrl,
		unsigned int flags) {
	const struct xdp2_parse_tlv_node_ops *ops = &parse_tlv_node->tlv_ops;
	const struct xdp2_proto_tlv_def *proto_tlv_node =
					parse_tlv_node->proto_tlv_def;

	if (proto_tlv_node &&
	    (cp + proto_tlv_node->min_len > (const __u8 *)hdr_end)) {
		/* Treat check length error as an unrecognized TLV */
		if (parse_node->tlv_wildcard_node)
			return xdp2_parse_tlv(parse_node,
					      parse_node->tlv_wildcard_node,
					      cp, hdr_end, tlvs_len, _metadata,
					      frame, ctrl, flags);
		else
			return parse_node->unknown_tlv_type_ret;
	}

	ssize_t hlen;
	int ret = check_pkt_len(cp, hdr_end,
		(const struct xdp2_proto_def *)
			parse_tlv_node->proto_tlv_def, &hlen);
	if (ret != XDP2_OKAY)
		return ret;

	if (ops->extract_metadata)
		ops->extract_metadata(cp, hlen, _metadata, frame, ctrl);

	if (ops->handler)
		ops->handler(cp, hlen, _metadata, frame, ctrl);

	return XDP2_OKAY;
}





static inline __attribute__((unused)) __attribute__((always_inline)) int
	xdp2_parser_simple_tuple_xdp2_encap_layer(struct xdp2_metadata_all *metadata,
					 void **frame, unsigned int *frame_num,
					 unsigned int flags)
{
	/* New encapsulation layer. Check against number of encap layers
	 * allowed and also if we need a new metadata frame.
	 */
	/* if (++metadata->num_encaps > 4) */
	/*	return XDP2_STOP_ENCAP_DEPTH; */

	/* if (metadata->num_encaps > *frame_num) { */
	/*	*frame += 200; */
	/*	*frame_num = (*frame_num) + 1; */
	/* } */

	return XDP2_OKAY;
}
static __attribute__((unused)) __always_inline int
	__ether_node_xdp2_parse(struct xdp2_xdp_ctx *ctx,
		const void **hdr, const void *hdr_end, void *_metadata,
		void *frame, unsigned int flags) __attribute__((unused));
static __attribute__((unused)) __always_inline int
	__ip_check_node_xdp2_parse(struct xdp2_xdp_ctx *ctx,
		const void **hdr, const void *hdr_end, void *_metadata,
		void *frame, unsigned int flags) __attribute__((unused));
static __attribute__((unused)) __always_inline int
	__ipv4_node_xdp2_parse(struct xdp2_xdp_ctx *ctx,
		const void **hdr, const void *hdr_end, void *_metadata,
		void *frame, unsigned int flags) __attribute__((unused));
static __attribute__((unused)) __always_inline int
	__ipv6_node_xdp2_parse(struct xdp2_xdp_ctx *ctx,
		const void **hdr, const void *hdr_end, void *_metadata,
		void *frame, unsigned int flags) __attribute__((unused));
static __attribute__((unused)) __always_inline int
	__ports_node_xdp2_parse(struct xdp2_xdp_ctx *ctx,
		const void **hdr, const void *hdr_end, void *_metadata,
		void *frame, unsigned int flags) __attribute__((unused));

/*  Main parse function. Header passed as a ** since parse functions may
 * advance it
 */
static __attribute__((unused)) __always_inline int __ether_node_xdp2_parse(
		struct xdp2_xdp_ctx *ctx, const void **hdr,
		const void *hdr_end, void *_metadata, void *frame,
		unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
				(const struct xdp2_parse_node*)&ether_node;
	const struct xdp2_proto_def *proto_def = parse_node->proto_def;
	struct xdp2_ctrl_data ctrl;
	int ret, type;
	ssize_t hlen;

	ret = check_pkt_len(*hdr, hdr_end, parse_node->proto_def, &hlen);
	if (ret != XDP2_OKAY)
		return ret;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, hlen, _metadata,
						 frame, &ctrl);


	if (proto_def->encap) {
		ret = xdp2_parser_simple_tuple_xdp2_encap_layer(_metadata, &frame,
					&ctx->frame_num, flags);
		if (ret != XDP2_OKAY)
			return ret;
	}

	type = proto_def->ops.next_proto(*hdr);
	if (type < 0)
		return type;
	if (!proto_def->overlay)
		*hdr += hlen;

	switch (type) {
	case 0x8:
		ctx->next = CODE_ip_check_node;
		return XDP2_OKAY;
	case 0xdd86:
		ctx->next = CODE_ip_check_node;
		return XDP2_OKAY;
	}
	/* Unknown protocol */
	return XDP2_STOP_UNKNOWN_PROTO;
}
/*  Main parse function. Header passed as a ** since parse functions may
 * advance it
 */
static __attribute__((unused)) __always_inline int __ip_check_node_xdp2_parse(
		struct xdp2_xdp_ctx *ctx, const void **hdr,
		const void *hdr_end, void *_metadata, void *frame,
		unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
				(const struct xdp2_parse_node*)&ip_check_node;
	const struct xdp2_proto_def *proto_def = parse_node->proto_def;
	struct xdp2_ctrl_data ctrl;
	int ret, type;
	ssize_t hlen;

	ret = check_pkt_len(*hdr, hdr_end, parse_node->proto_def, &hlen);
	if (ret != XDP2_OKAY)
		return ret;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, hlen, _metadata,
						 frame, &ctrl);


	if (proto_def->encap) {
		ret = xdp2_parser_simple_tuple_xdp2_encap_layer(_metadata, &frame,
					&ctx->frame_num, flags);
		if (ret != XDP2_OKAY)
			return ret;
	}

	type = proto_def->ops.next_proto(*hdr);
	if (type < 0)
		return type;
	if (!proto_def->overlay)
		*hdr += hlen;

	switch (type) {
	case 0x4:
		ctx->next = CODE_ipv4_node;
		return XDP2_OKAY;
	case 0x6:
		ctx->next = CODE_ipv6_node;
		return XDP2_OKAY;
	}
	/* Unknown protocol */
	return XDP2_STOP_UNKNOWN_PROTO;
}
/*  Main parse function. Header passed as a ** since parse functions may
 * advance it
 */
static __attribute__((unused)) __always_inline int __ipv4_node_xdp2_parse(
		struct xdp2_xdp_ctx *ctx, const void **hdr,
		const void *hdr_end, void *_metadata, void *frame,
		unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
				(const struct xdp2_parse_node*)&ipv4_node;
	const struct xdp2_proto_def *proto_def = parse_node->proto_def;
	struct xdp2_ctrl_data ctrl;
	int ret, type;
	ssize_t hlen;

	ret = check_pkt_len(*hdr, hdr_end, parse_node->proto_def, &hlen);
	if (ret != XDP2_OKAY)
		return ret;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, hlen, _metadata,
						 frame, &ctrl);


	if (proto_def->encap) {
		ret = xdp2_parser_simple_tuple_xdp2_encap_layer(_metadata, &frame,
					&ctx->frame_num, flags);
		if (ret != XDP2_OKAY)
			return ret;
	}

	type = proto_def->ops.next_proto(*hdr);
	if (type < 0)
		return type;
	if (!proto_def->overlay)
		*hdr += hlen;

	switch (type) {
	case 0x6:
		ctx->next = CODE_ports_node;
		return XDP2_OKAY;
	case 0x11:
		ctx->next = CODE_ports_node;
		return XDP2_OKAY;
	}
	/* Unknown protocol */
	return XDP2_STOP_UNKNOWN_PROTO;
}
/*  Main parse function. Header passed as a ** since parse functions may
 * advance it
 */
static __attribute__((unused)) __always_inline int __ipv6_node_xdp2_parse(
		struct xdp2_xdp_ctx *ctx, const void **hdr,
		const void *hdr_end, void *_metadata, void *frame,
		unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
				(const struct xdp2_parse_node*)&ipv6_node;
	const struct xdp2_proto_def *proto_def = parse_node->proto_def;
	struct xdp2_ctrl_data ctrl;
	int ret, type;
	ssize_t hlen;

	ret = check_pkt_len(*hdr, hdr_end, parse_node->proto_def, &hlen);
	if (ret != XDP2_OKAY)
		return ret;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, hlen, _metadata,
						 frame, &ctrl);


	if (proto_def->encap) {
		ret = xdp2_parser_simple_tuple_xdp2_encap_layer(_metadata, &frame,
					&ctx->frame_num, flags);
		if (ret != XDP2_OKAY)
			return ret;
	}

	type = proto_def->ops.next_proto(*hdr);
	if (type < 0)
		return type;
	if (!proto_def->overlay)
		*hdr += hlen;

	switch (type) {
	case 0x6:
		ctx->next = CODE_ports_node;
		return XDP2_OKAY;
	case 0x11:
		ctx->next = CODE_ports_node;
		return XDP2_OKAY;
	}
	/* Unknown protocol */
	return XDP2_STOP_UNKNOWN_PROTO;
}
/*  Main parse function. Header passed as a ** since parse functions may
 * advance it
 */
static __attribute__((unused)) __always_inline int __ports_node_xdp2_parse(
		struct xdp2_xdp_ctx *ctx, const void **hdr,
		const void *hdr_end, void *_metadata, void *frame,
		unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
				(const struct xdp2_parse_node*)&ports_node;
	const struct xdp2_proto_def *proto_def = parse_node->proto_def;
	struct xdp2_ctrl_data ctrl;
	int ret, type;
	ssize_t hlen;

	ret = check_pkt_len(*hdr, hdr_end, parse_node->proto_def, &hlen);
	if (ret != XDP2_OKAY)
		return ret;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, hlen, _metadata,
						 frame, &ctrl);


	if (proto_def->encap) {
		ret = xdp2_parser_simple_tuple_xdp2_encap_layer(_metadata, &frame,
					&ctx->frame_num, flags);
		if (ret != XDP2_OKAY)
			return ret;
	}

	ctx->next = CODE_IGNORE;
	return XDP2_STOP_OKAY;
}

/* Parse root function. Header passed as a ** since parse functions may
 * advance it
 */
static __attribute__((unused)) __always_inline int
	xdp2_parser_simple_tuple_xdp2_parse_ether_node(
		struct xdp2_xdp_ctx *ctx, const void **hdr,
		const void *hdr_end, void *_metadata, bool tailcall,
		unsigned int flags)
{
	void *frame = (void *)_metadata;
	const void *start_hdr = *hdr;
	int ret = XDP2_OKAY;

	if (!tailcall)
		ret = __ether_node_xdp2_parse(ctx, hdr, hdr_end, _metadata,
						 frame, flags);

	#pragma unroll
	for (int i = 0; i < (tailcall ? 1 : XDP2_LOOP_COUNT); i++) {
		if (ctx->next == CODE_IGNORE || ret != XDP2_OKAY)
			break;
		else if (ctx->next == CODE_ether_node)
			ret = __ether_node_xdp2_parse(ctx, hdr, hdr_end,
					_metadata, frame, flags);
		else if (ctx->next == CODE_ip_check_node)
			ret = __ip_check_node_xdp2_parse(ctx, hdr, hdr_end,
					_metadata, frame, flags);
		else if (ctx->next == CODE_ipv4_node)
			ret = __ipv4_node_xdp2_parse(ctx, hdr, hdr_end,
					_metadata, frame, flags);
		else if (ctx->next == CODE_ipv6_node)
			ret = __ipv6_node_xdp2_parse(ctx, hdr, hdr_end,
					_metadata, frame, flags);
		else if (ctx->next == CODE_ports_node)
			ret = __ports_node_xdp2_parse(ctx, hdr, hdr_end,
					_metadata, frame, flags);
		else
			return XDP2_STOP_UNKNOWN_PROTO;
	}
	return ret;
}

/* Parse node function. Header passed as a ** since parse functions may
 * advance it
 */
static __attribute__((unused)) __always_inline int
	xdp2_xdp_parser_xdp2_parser_simple_tuple(
		struct xdp2_xdp_ctx *ictx, const void **hdr,
		const void *hdr_end, bool tailcall, unsigned int flags)
{
	return xdp2_parser_simple_tuple_xdp2_parse_ether_node(
			ictx, hdr, hdr_end, ictx->metadata,
			tailcall, flags);
}
