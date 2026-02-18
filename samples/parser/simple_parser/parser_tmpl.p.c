

#include "xdp2/compiler_helpers.h"

/* Common parser template. This combined with another use case specific
 * template to make a complete template
 */








#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "xdp2/parser.h"
#include "xdp2/proto_defs_define.h"
#include "xdp2/compiler_helpers.h"
#include "parser_tmpl.c"

/* Template for making a plain C parser */

static inline __unused() __attribute__((always_inline)) int
	check_pkt_len(const void *hdr,
		const struct xdp2_proto_def *pnode, size_t len, ssize_t *hlen)
{
	*hlen = pnode->min_len;

	/* Protocol node length checks */
	if (len < *hlen)
		return XDP2_STOP_LENGTH;

	if (pnode->ops.len) {
		*hlen = pnode->ops.len(hdr, len);
		if (len < *hlen)
			return XDP2_STOP_LENGTH;
		if (*hlen < pnode->min_len)
			return *hlen < 0 ? *hlen : XDP2_STOP_LENGTH;
	}

	return XDP2_OKAY;
}



/* Parse wildcard TLV */
static inline __unused() __attribute__((always_inline)) int
	xdp2_parse_wildcard_tlv(
		const struct xdp2_parse_tlvs_node *parse_node,
		const struct xdp2_parse_tlv_node *wildcard_parse_tlv_node,
		void *hdr, size_t hdr_len, void *_metadata, void *frame,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_tlv_node_ops *ops =
					&wildcard_parse_tlv_node->tlv_ops;
	const struct xdp2_proto_tlv_def *proto_tlv_node =
					wildcard_parse_tlv_node->proto_tlv_def;

	if (proto_tlv_node && (hdr_len < proto_tlv_node->min_len))
		return parse_node->unknown_tlv_type_ret;

	if (ops->extract_metadata)
		ops->extract_metadata(hdr, hdr_len, _metadata, frame, ctrl);

	if (ops->handler)
		ops->handler(hdr, hdr_len, _metadata, frame, ctrl);

	return XDP2_OKAY;
}

/* Parse one TLV */
static inline __unused() __attribute__((always_inline))
	int xdp2_parse_tlv(
		const struct xdp2_parse_tlvs_node *parse_node,
		const struct xdp2_parse_tlv_node *parse_tlv_node, void *hdr,
		ssize_t hdr_len, void *_metadata, void *frame,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_tlv_node_ops *ops = &parse_tlv_node->tlv_ops;
	const struct xdp2_proto_tlv_def *proto_tlv_node =
					parse_tlv_node->proto_tlv_def;

	if (proto_tlv_node && (hdr_len < proto_tlv_node->min_len)) {
		/* Treat check length error as an unrecognized TLV */
		if (parse_node->tlv_wildcard_node)
			return xdp2_parse_wildcard_tlv(parse_node,
					parse_node->tlv_wildcard_node,
					hdr, hdr_len, _metadata, frame,
					ctrl, flags);
		else
			return parse_node->unknown_tlv_type_ret;
	}

	if (ops->extract_metadata)
		ops->extract_metadata(hdr, hdr_len, _metadata, frame, ctrl);

	if (ops->handler)
		ops->handler(hdr, hdr_len, _metadata, frame, ctrl);

	return XDP2_OKAY;
}

static inline __unused() __attribute__((always_inline)) int
	my_parser_xdp2_encap_layer(
		struct xdp2_metadata_all *metadata,
		void **frame, unsigned *frame_num)
{
	/* New encapsulation layer. Check against number of encap layers
	 * allowed and also if we need a new metadata frame.
	 */
	/* if (++metadata->num_encaps > 4) */
	/*	return XDP2_STOP_ENCAP_DEPTH; */

	/* if (metadata->num_encaps > *frame_num) { */
	/*	*frame += 88; */
	/*	*frame_num = (*frame_num) + 1; */
	/* } */

	return XDP2_OKAY;
}

/* Prototype for parse functions */
static inline __unused() int
	__my_parser_ether_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__my_parser_ipv4_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__my_parser_ipv6_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__my_parser_ports_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__my_parser_tcp_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Parse function */
static inline __unused() int
	__my_parser_ether_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ether_node;
	const struct xdp2_proto_def *proto_def = parse_node->proto_def;
	ssize_t hlen;
	int ret;

	ctrl->var.last_node = parse_node;

	ret = check_pkt_len(hdr, parse_node->proto_def, len, &hlen);
	if (ret != XDP2_OKAY)
		return ret;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(hdr, hlen, metadata,
						 *frame, ctrl);

	if (parse_node->ops.handler)
		parse_node->ops.handler(hdr, hlen, metadata, *frame, ctrl);



	if (proto_def->encap) {
		if (parser->config.atencap_node) {
			ret = __xdp2_parse_run_exit_node(parser,
				parser->config.atencap_node, metadata,
				*frame, ctrl, flags);
			if (ret != XDP2_OKAY)
				return ret;
		}

		/* New encapsulation leyer. Check against
		 * number of encap layers allowed and also
		 * if we need a new metadata frame.
		 */
		if (++ctrl->var.encaps > parser->config.max_encaps)
			return XDP2_STOP_ENCAP_DEPTH;

		if (parser->config.max_frames > frame_num) {
			(*frame) += parser->config.frame_size;
			frame_num++;
		}
	}

	{
	int type = proto_def->ops.next_proto_keyin ?
		proto_def->ops.next_proto_keyin(hdr,
					ctrl->key.keys[parse_node->key_sel]) :
		proto_def->ops.next_proto(hdr);

	if (type < 0)
		return type;

	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	switch (type) {
	case 0x8:
		return __my_parser_ipv4_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xdd86:
		return __my_parser_ipv6_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__my_parser_ipv4_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ipv4_node;
	const struct xdp2_proto_def *proto_def = parse_node->proto_def;
	ssize_t hlen;
	int ret;

	ctrl->var.last_node = parse_node;

	ret = check_pkt_len(hdr, parse_node->proto_def, len, &hlen);
	if (ret != XDP2_OKAY)
		return ret;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(hdr, hlen, metadata,
						 *frame, ctrl);

	if (parse_node->ops.handler)
		parse_node->ops.handler(hdr, hlen, metadata, *frame, ctrl);



	if (proto_def->encap) {
		if (parser->config.atencap_node) {
			ret = __xdp2_parse_run_exit_node(parser,
				parser->config.atencap_node, metadata,
				*frame, ctrl, flags);
			if (ret != XDP2_OKAY)
				return ret;
		}

		/* New encapsulation leyer. Check against
		 * number of encap layers allowed and also
		 * if we need a new metadata frame.
		 */
		if (++ctrl->var.encaps > parser->config.max_encaps)
			return XDP2_STOP_ENCAP_DEPTH;

		if (parser->config.max_frames > frame_num) {
			(*frame) += parser->config.frame_size;
			frame_num++;
		}
	}

	{
	int type = proto_def->ops.next_proto_keyin ?
		proto_def->ops.next_proto_keyin(hdr,
					ctrl->key.keys[parse_node->key_sel]) :
		proto_def->ops.next_proto(hdr);

	if (type < 0)
		return type;

	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	switch (type) {
	case 0x6:
		return __my_parser_tcp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x11:
		return __my_parser_ports_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__my_parser_ipv6_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ipv6_node;
	const struct xdp2_proto_def *proto_def = parse_node->proto_def;
	ssize_t hlen;
	int ret;

	ctrl->var.last_node = parse_node;

	ret = check_pkt_len(hdr, parse_node->proto_def, len, &hlen);
	if (ret != XDP2_OKAY)
		return ret;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(hdr, hlen, metadata,
						 *frame, ctrl);

	if (parse_node->ops.handler)
		parse_node->ops.handler(hdr, hlen, metadata, *frame, ctrl);



	if (proto_def->encap) {
		if (parser->config.atencap_node) {
			ret = __xdp2_parse_run_exit_node(parser,
				parser->config.atencap_node, metadata,
				*frame, ctrl, flags);
			if (ret != XDP2_OKAY)
				return ret;
		}

		/* New encapsulation leyer. Check against
		 * number of encap layers allowed and also
		 * if we need a new metadata frame.
		 */
		if (++ctrl->var.encaps > parser->config.max_encaps)
			return XDP2_STOP_ENCAP_DEPTH;

		if (parser->config.max_frames > frame_num) {
			(*frame) += parser->config.frame_size;
			frame_num++;
		}
	}

	{
	int type = proto_def->ops.next_proto_keyin ?
		proto_def->ops.next_proto_keyin(hdr,
					ctrl->key.keys[parse_node->key_sel]) :
		proto_def->ops.next_proto(hdr);

	if (type < 0)
		return type;

	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	switch (type) {
	case 0x6:
		return __my_parser_tcp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x11:
		return __my_parser_ports_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__my_parser_ports_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ports_node;
	const struct xdp2_proto_def *proto_def = parse_node->proto_def;
	ssize_t hlen;
	int ret;

	ctrl->var.last_node = parse_node;

	ret = check_pkt_len(hdr, parse_node->proto_def, len, &hlen);
	if (ret != XDP2_OKAY)
		return ret;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(hdr, hlen, metadata,
						 *frame, ctrl);

	if (parse_node->ops.handler)
		parse_node->ops.handler(hdr, hlen, metadata, *frame, ctrl);



	if (proto_def->encap) {
		if (parser->config.atencap_node) {
			ret = __xdp2_parse_run_exit_node(parser,
				parser->config.atencap_node, metadata,
				*frame, ctrl, flags);
			if (ret != XDP2_OKAY)
				return ret;
		}

		/* New encapsulation leyer. Check against
		 * number of encap layers allowed and also
		 * if we need a new metadata frame.
		 */
		if (++ctrl->var.encaps > parser->config.max_encaps)
			return XDP2_STOP_ENCAP_DEPTH;

		if (parser->config.max_frames > frame_num) {
			(*frame) += parser->config.frame_size;
			frame_num++;
		}
	}


	return XDP2_STOP_OKAY;
}

/* Template for parsing TLVs */
static inline __unused() __attribute__((unused)) int
	__my_parser_tcp_node_xdp2_parse_tlvs(
		const struct xdp2_parse_node *parse_node,
		void *hdr, size_t len, void *_metadata,
		void *frame, struct xdp2_ctrl_data *ctrl,
		unsigned int flags)
{
	const struct xdp2_proto_tlvs_def *proto_tlvs_def =
		(const struct xdp2_proto_tlvs_def *)parse_node->proto_def;
	const struct xdp2_parse_tlvs_node *parse_tlvs_node =
		(const struct xdp2_parse_tlvs_node*)&tcp_node;
	const struct xdp2_parse_tlv_node *parse_tlv_node;
	const struct xdp2_parse_tlv_node_ops *ops;
	size_t hdr_offset = 0;
	ssize_t tlv_len;
	__u8 *cp = hdr;
	int type;

	(void)ops;

	hdr_offset = proto_tlvs_def->ops.start_offset(hdr);
	/* Assume len marks end of TLVs */
	len -= hdr_offset;
	cp += hdr_offset;

	while (len > 0) {
		if (proto_tlvs_def->pad1_enable &&
		    *cp == proto_tlvs_def->pad1_val) {
			/* One byte padding, just advance */
			cp++;
			len--;
			continue;
		}

		if (proto_tlvs_def->eol_enable &&
		    *cp == proto_tlvs_def->eol_val) {
			cp++;
			len--;
			break;
		}

		if (len < proto_tlvs_def->min_len)
			return XDP2_STOP_TLV_LENGTH;

		if (proto_tlvs_def->ops.len) {
			tlv_len = proto_tlvs_def->ops.len(cp, len);
			if (!tlv_len || len < tlv_len)
				return XDP2_STOP_TLV_LENGTH;
			if (tlv_len < proto_tlvs_def->min_len)
				return tlv_len < 0 ? tlv_len :
							XDP2_STOP_TLV_LENGTH;
		}

		type = proto_tlvs_def->ops.type(cp);

		switch (type) {
		case 0x8:
		{
			int ret;

			parse_tlv_node = &tcp_opt_timestamp_node;
			ret = xdp2_parse_tlv(parse_tlvs_node, parse_tlv_node,
					     cp, tlv_len, _metadata, frame,
					     ctrl, flags);
			if (ret != XDP2_OKAY)
				return ret;

			if (!parse_tlv_node->overlay_table)
				break;

		}
		default:
		{
			/* struct xdp2_ctrl_data tlv_ctrl = */
			/*			{ tlv_len, offset }; */

			if (parse_tlvs_node->tlv_wildcard_node)
				return  xdp2_parse_tlv(parse_tlvs_node,
					parse_tlvs_node->tlv_wildcard_node,
					cp, tlv_len, _metadata, frame, ctrl,
					flags);
			else if (parse_tlvs_node->unknown_tlv_type_ret !=
							XDP2_OKAY)
				return parse_tlvs_node->unknown_tlv_type_ret;
		}
		}

		/* Move over current header */
		cp += tlv_len;
		len -= tlv_len;
	}
	return XDP2_OKAY;
}

/* Parse function */
static inline __unused() int
	__my_parser_tcp_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&tcp_node;
	const struct xdp2_proto_def *proto_def = parse_node->proto_def;
	ssize_t hlen;
	int ret;

	ctrl->var.last_node = parse_node;

	ret = check_pkt_len(hdr, parse_node->proto_def, len, &hlen);
	if (ret != XDP2_OKAY)
		return ret;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(hdr, hlen, metadata,
						 *frame, ctrl);

	if (parse_node->ops.handler)
		parse_node->ops.handler(hdr, hlen, metadata, *frame, ctrl);

	ret = __my_parser_tcp_node_xdp2_parse_tlvs(
			parse_node, hdr, hlen, metadata, *frame, ctrl, flags);
	if (ret != XDP2_OKAY)
		return ret;


	if (proto_def->encap) {
		if (parser->config.atencap_node) {
			ret = __xdp2_parse_run_exit_node(parser,
				parser->config.atencap_node, metadata,
				*frame, ctrl, flags);
			if (ret != XDP2_OKAY)
				return ret;
		}

		/* New encapsulation leyer. Check against
		 * number of encap layers allowed and also
		 * if we need a new metadata frame.
		 */
		if (++ctrl->var.encaps > parser->config.max_encaps)
			return XDP2_STOP_ENCAP_DEPTH;

		if (parser->config.max_frames > frame_num) {
			(*frame) += parser->config.frame_size;
			frame_num++;
		}
	}


	return XDP2_STOP_OKAY;
}

/* Parser entry function to commence parsing at the root */
static inline __unused() int
	my_parser_xdp2_parse_ether_node(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, struct xdp2_ctrl_data *ctrl,
		unsigned int flags)
{
	void *frame = metadata + parser->config.metameta_size;
	const struct xdp2_parse_node *parse_node;
	int ret;

	(void)&__my_parser_ether_node_xdp2_parse;
	(void)&__my_parser_ipv4_node_xdp2_parse;
	(void)&__my_parser_ipv6_node_xdp2_parse;
	(void)&__my_parser_ports_node_xdp2_parse;
	(void)&__my_parser_tcp_node_xdp2_parse;

	ret = __my_parser_ether_node_xdp2_parse(
			parser, hdr, len, metadata, &frame, 0, ctrl, flags);

	ctrl->var.ret_code = ret;

	parse_node = XDP2_CODE_IS_OKAY(ret) ?
			parser->config.okay_node : parser->config.fail_node;
	if (parse_node)
		__xdp2_parse_run_exit_node(parser, parse_node, metadata, frame,
					   ctrl, flags);
	return ret;
}

/* Define optimized parser */
XDP2_PARSER_OPT(
	my_parser_opt,
	"",
	ether_node,
	my_parser_xdp2_parse_ether_node,
	(
		.max_nodes = 255,
		.max_encaps = 4,
		.max_frames = 1,
		.metameta_size = 0,
		.frame_size = 88,
		.num_counters = 255,
		.num_keys = 255,
	)
    );
