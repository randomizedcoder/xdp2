

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
#include "parser.c"

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
	parse_dump_xdp2_encap_layer(
		struct xdp2_metadata_all *metadata,
		void **frame, unsigned *frame_num)
{
	/* New encapsulation layer. Check against number of encap layers
	 * allowed and also if we need a new metadata frame.
	 */
	/* if (++metadata->num_encaps > 4) */
	/*	return XDP2_STOP_ENCAP_DEPTH; */

	/* if (metadata->num_encaps > *frame_num) { */
	/*	*frame += 96; */
	/*	*frame_num = (*frame_num) + 1; */
	/* } */

	return XDP2_OKAY;
}

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_falcon_base_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_falcon_v1_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_falcon_pull_request_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_falcon_pull_data_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_falcon_push_data_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_falcon_resync_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_falcon_back_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_falcon_nack_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_falcon_eack_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_sue_base_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_sue_v0_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_sue_rh_ack_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_sue_rh_nack_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_sue_rh_invalid1_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_sue_rh_invalid2_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_sunh_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_superp_no_op_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_superp_tal_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_superp_pdl_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_base_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_ack_cc_base_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_ack_cc_nscc_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_ack_cc_credit_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_rud_request_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_rod_request_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_rud_request_cc_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_rod_request_cc_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_rud_request_syn_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_rod_request_syn_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_rud_request_cc_syn_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_rod_request_cc_syn_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_ack_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_ack_ccx_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_nack_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_nack_ccx_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_control_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_control_syn_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_uud_req_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_rudi_req_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pds_rudi_resp_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_read_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_read_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_som_read_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_write_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_write_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_som_write_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_som_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_datagram_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_datagram_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_som_datagram_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_tagged_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_tagged_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_som_tagged_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_tsend_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_tsend_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_som_tsend_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_tsend_fetch_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_tsend_fetch_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_som_tsend_fetch_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_error_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_error_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_som_error_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_atomic_switch_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_som_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_fetching_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_fetching_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_som_fetching_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_deferrable_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_deferrable_tsend_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_ready_restart_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_rendezvous_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_rendezvous_tsend_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_atomic_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_atomic_cmp_swp_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_no_op_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_write_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_read_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_send_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_tsend_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_datagram_send_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_tsend_atomic_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_tsend_fetch_atomic_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_atomic_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_fetching_atomic_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_msg_no_op_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_write_small_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_read_small_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_atomic_small_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_fetching_atomic_small_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_msg_no_op_small_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_no_next_hdr_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_small_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_request_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_normal_nodata_response_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_default_nodata_response_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_none_nodata_response_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_response_with_data_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_response_with_small_data_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_response_tnode_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_response_with_data_tnode_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_uet_ses_response_with_data_small_tnode_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ether_node_root_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ether_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ip_overlay_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ip_overlay_by_key_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ipv4_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ipv4_check_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ipv4ip_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ipv6_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ipv6_check_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ipv6ip_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_l2tp_base_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_geneve_base_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_geneve_v0_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ppp_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_pppoe_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_icmpv4_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_icmpv6_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_icmpv6_neigh_solicit_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_icmpv6_neigh_advert_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_vxlan_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_protobufs1_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_protobufs2_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ospf_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_udp_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_arp_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_protobufs1_phone_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_tcp_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_okay_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_fail_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_atencap_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_gre_base_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_gre_v0_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_gre_v1_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_e8021AD_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_e8021Q_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_sunh_node_alt_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ipv6_hbh_options_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ipv6_dest_options_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ipv6_routing_header_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ipv6_routing_header_node_check_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ipv6_fragment_header_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ipv6_ah_header_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_l2tp_v0_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_l2tp_v0_offsz_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_l2tp_v1_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_l2tp_v2_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_l2tp_v3_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ppp_lcp_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ppp_pap_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ppp_chap_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Prototype for parse functions */
static inline __unused() int
	__parse_dump_ppp_icpc_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags);

/* Parse function */
static inline __unused() int
	__parse_dump_falcon_base_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&falcon_base_node;
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
	case 0x1:
		return __parse_dump_falcon_v1_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_falcon_v1_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&falcon_v1_node;
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
	case 0x0:
		return __parse_dump_falcon_pull_request_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_falcon_pull_data_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5:
		return __parse_dump_falcon_push_data_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6:
		return __parse_dump_falcon_resync_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x9:
		return __parse_dump_falcon_back_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xa:
		return __parse_dump_falcon_eack_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x8:
		return __parse_dump_falcon_nack_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_falcon_pull_request_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&falcon_pull_request;
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

/* Parse function */
static inline __unused() int
	__parse_dump_falcon_pull_data_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&falcon_pull_data;
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

/* Parse function */
static inline __unused() int
	__parse_dump_falcon_push_data_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&falcon_push_data;
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

/* Parse function */
static inline __unused() int
	__parse_dump_falcon_resync_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&falcon_resync;
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

/* Parse function */
static inline __unused() int
	__parse_dump_falcon_back_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&falcon_back;
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

/* Parse function */
static inline __unused() int
	__parse_dump_falcon_nack_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&falcon_nack;
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

/* Parse function */
static inline __unused() int
	__parse_dump_falcon_eack_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&falcon_eack;
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

/* Parse function */
static inline __unused() int
	__parse_dump_sue_base_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&sue_base_node;
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
	case 0x0:
		return __parse_dump_sue_v0_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_sue_v0_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&sue_v0_node;
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
	case 0x0:
		return __parse_dump_sue_rh_ack_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_sue_rh_nack_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2:
		return __parse_dump_sue_rh_invalid1_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_sue_rh_invalid2_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_sue_rh_ack_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&sue_rh_ack;
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

/* Parse function */
static inline __unused() int
	__parse_dump_sue_rh_nack_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&sue_rh_nack;
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

/* Parse function */
static inline __unused() int
	__parse_dump_sue_rh_invalid1_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&sue_rh_invalid1;
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

/* Parse function */
static inline __unused() int
	__parse_dump_sue_rh_invalid2_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&sue_rh_invalid2;
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

/* Parse function */
static inline __unused() int
	__parse_dump_sunh_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&sunh_node;
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
		return __parse_dump_tcp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x11:
		return __parse_dump_udp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2f:
		return __parse_dump_gre_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x73:
		return __parse_dump_l2tp_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_ipv4ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x29:
		return __parse_dump_ipv6ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3a:
		return __parse_dump_icmpv6_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x0:
		return __parse_dump_ipv6_hbh_options_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3c:
		return __parse_dump_ipv6_dest_options_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2b:
		return __parse_dump_ipv6_routing_header_node_check_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2c:
		return __parse_dump_ipv6_fragment_header_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x33:
		return __parse_dump_ipv6_ah_header_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xfd:
		return __parse_dump_superp_pdl_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_superp_no_op_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&superp_no_op_node;
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

/* Parse function */
static inline __unused() int
	__parse_dump_superp_tal_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&superp_tal_node;
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
	case 0x0:
		return __parse_dump_superp_no_op_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_superp_no_op_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_superp_pdl_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&superp_pdl_node;
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



	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	return __parse_dump_superp_tal_node_xdp2_parse(
		parser, hdr, len, metadata, frame, frame_num, ctrl, flags);
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_base_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_base_node;
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
	case 0x10:
		return __parse_dump_pds_rud_request_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x410:
		return __parse_dump_pds_rud_request_syn_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x18:
		return __parse_dump_pds_rod_request_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x418:
		return __parse_dump_pds_rod_request_syn_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x68:
		return __parse_dump_pds_rud_request_cc_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x468:
		return __parse_dump_pds_rud_request_cc_syn_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x70:
		return __parse_dump_pds_rod_request_cc_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x470:
		return __parse_dump_pds_rod_request_cc_syn_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x58:
		return __parse_dump_pds_control_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x458:
		return __parse_dump_pds_control_syn_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x20:
		return __parse_dump_pds_rudi_req_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x420:
		return __parse_dump_pds_rudi_req_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x38:
		return __parse_dump_pds_ack_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x438:
		return __parse_dump_pds_ack_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x40:
		return __parse_dump_pds_ack_cc_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x440:
		return __parse_dump_pds_ack_cc_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x48:
		return __parse_dump_pds_ack_ccx_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x448:
		return __parse_dump_pds_ack_ccx_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x50:
		return __parse_dump_pds_nack_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x450:
		return __parse_dump_pds_nack_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x60:
		return __parse_dump_pds_nack_ccx_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x460:
		return __parse_dump_pds_nack_ccx_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x28:
		return __parse_dump_pds_rudi_resp_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x428:
		return __parse_dump_pds_rudi_resp_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x30:
		return __parse_dump_pds_uud_req_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x430:
		return __parse_dump_pds_uud_req_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_ack_cc_base_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_ack_cc_base_node;
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
	case 0x0:
		return __parse_dump_pds_ack_cc_nscc_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_pds_ack_cc_credit_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_ack_cc_nscc_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_ack_cc_nscc;
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
	case 0x0:
		return __parse_dump_uet_ses_no_next_hdr_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_uet_ses_response_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5:
		return __parse_dump_uet_ses_response_with_data_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6:
		return __parse_dump_uet_ses_response_with_data_small_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_ack_cc_credit_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_ack_cc_credit;
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
	case 0x0:
		return __parse_dump_uet_ses_no_next_hdr_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_uet_ses_response_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5:
		return __parse_dump_uet_ses_response_with_data_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6:
		return __parse_dump_uet_ses_response_with_data_small_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_rud_request_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_rud_request;
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
	case 0x0:
		return __parse_dump_uet_ses_no_next_hdr_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_small_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2:
		return __parse_dump_uet_ses_request_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_uet_ses_request_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_rod_request_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_rod_request;
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
	case 0x0:
		return __parse_dump_uet_ses_no_next_hdr_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_small_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2:
		return __parse_dump_uet_ses_request_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_uet_ses_request_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_rud_request_cc_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_rud_request_cc;
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
	case 0x0:
		return __parse_dump_uet_ses_no_next_hdr_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_small_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2:
		return __parse_dump_uet_ses_request_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_uet_ses_request_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_rod_request_cc_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_rod_request_cc;
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
	case 0x0:
		return __parse_dump_uet_ses_no_next_hdr_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_small_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2:
		return __parse_dump_uet_ses_request_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_uet_ses_request_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_rud_request_syn_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_rud_request_syn;
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
	case 0x0:
		return __parse_dump_uet_ses_no_next_hdr_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_small_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2:
		return __parse_dump_uet_ses_request_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_uet_ses_request_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_rod_request_syn_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_rod_request_syn;
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
	case 0x0:
		return __parse_dump_uet_ses_no_next_hdr_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_small_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2:
		return __parse_dump_uet_ses_request_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_uet_ses_request_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_rud_request_cc_syn_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_rud_request_cc_syn;
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
	case 0x0:
		return __parse_dump_uet_ses_no_next_hdr_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_small_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2:
		return __parse_dump_uet_ses_request_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_uet_ses_request_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_rod_request_cc_syn_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_rod_request_cc_syn;
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
	case 0x0:
		return __parse_dump_uet_ses_no_next_hdr_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_small_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2:
		return __parse_dump_uet_ses_request_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_uet_ses_request_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_ack_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_ack;
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
	case 0x0:
		return __parse_dump_uet_ses_no_next_hdr_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_uet_ses_response_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5:
		return __parse_dump_uet_ses_response_with_data_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6:
		return __parse_dump_uet_ses_response_with_data_small_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_ack_ccx_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_ack_ccx;
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
	case 0x0:
		return __parse_dump_uet_ses_no_next_hdr_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_uet_ses_response_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5:
		return __parse_dump_uet_ses_response_with_data_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6:
		return __parse_dump_uet_ses_response_with_data_small_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_nack_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_nack;
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
	case 0x0:
		return __parse_dump_uet_ses_no_next_hdr_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_uet_ses_response_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5:
		return __parse_dump_uet_ses_response_with_data_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6:
		return __parse_dump_uet_ses_response_with_data_small_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_nack_ccx_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_nack_ccx;
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
	case 0x0:
		return __parse_dump_uet_ses_no_next_hdr_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_uet_ses_response_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5:
		return __parse_dump_uet_ses_response_with_data_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6:
		return __parse_dump_uet_ses_response_with_data_small_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_control_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_control;
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

/* Parse function */
static inline __unused() int
	__parse_dump_pds_control_syn_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_control_syn;
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

/* Parse function */
static inline __unused() int
	__parse_dump_pds_uud_req_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_uud_req;
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
	case 0x0:
		return __parse_dump_uet_ses_no_next_hdr_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_small_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2:
		return __parse_dump_uet_ses_request_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_uet_ses_request_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_rudi_req_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_rudi_req;
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
	case 0x0:
		return __parse_dump_uet_ses_no_next_hdr_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_small_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2:
		return __parse_dump_uet_ses_request_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_uet_ses_request_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pds_rudi_resp_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pds_rudi_resp;
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
	case 0x0:
		return __parse_dump_uet_ses_no_next_hdr_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_uet_ses_response_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5:
		return __parse_dump_uet_ses_response_with_data_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6:
		return __parse_dump_uet_ses_response_with_data_small_tnode_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_read_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_read_std;
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
	case 0x0:
		return __parse_dump_uet_ses_request_nosom_read_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_som_read_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_read_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_nosom_read_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_som_read_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_som_read_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_write_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_write_std;
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
	case 0x0:
		return __parse_dump_uet_ses_request_nosom_write_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_som_write_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_write_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_nosom_write_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_som_write_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_som_write_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_send_std;
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
	case 0x0:
		return __parse_dump_uet_ses_request_nosom_send_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_som_send_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_nosom_send_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_som_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_som_send_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_datagram_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_datagram_send_std;
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
	case 0x0:
		return __parse_dump_uet_ses_request_nosom_datagram_send_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_som_datagram_send_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_datagram_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_nosom_datagram_send_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_som_datagram_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_som_datagram_send_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_tagged_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_tagged_send_std;
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
	case 0x0:
		return __parse_dump_uet_ses_request_nosom_tagged_send_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_som_tagged_send_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_tagged_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_nosom_tagged_send_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_som_tagged_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_som_tagged_send_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_tsend_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_tsend_atomic_std;
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
	case 0x0:
		return __parse_dump_uet_ses_request_nosom_tsend_atomic_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_som_tsend_atomic_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_tsend_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_nosom_tsend_atomic_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_som_tsend_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_som_tsend_atomic_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_tsend_fetch_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_tsend_fetch_atomic_std;
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
	case 0x0:
		return __parse_dump_uet_ses_request_nosom_tsend_fetch_atomic_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_som_tsend_fetch_atomic_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_tsend_fetch_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_nosom_tsend_fetch_atomic_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_som_tsend_fetch_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_som_tsend_fetch_atomic_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_error_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_error_std;
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
	case 0x0:
		return __parse_dump_uet_ses_request_nosom_error_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_som_error_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_error_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_nosom_error_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_som_error_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_som_error_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_atomic_switch_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&atomic_switch_node;
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
	case 0x0:
		return __parse_dump_uet_ses_atomic_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_atomic_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2:
		return __parse_dump_uet_ses_atomic_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_uet_ses_atomic_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_uet_ses_atomic_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5:
		return __parse_dump_uet_ses_atomic_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6:
		return __parse_dump_uet_ses_atomic_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x7:
		return __parse_dump_uet_ses_atomic_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x8:
		return __parse_dump_uet_ses_atomic_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x9:
		return __parse_dump_uet_ses_atomic_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xa:
		return __parse_dump_uet_ses_atomic_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xb:
		return __parse_dump_uet_ses_atomic_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xc:
		return __parse_dump_uet_ses_atomic_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xd:
		return __parse_dump_uet_ses_atomic_cmp_swp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xe:
		return __parse_dump_uet_ses_atomic_cmp_swp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xf:
		return __parse_dump_uet_ses_atomic_cmp_swp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x10:
		return __parse_dump_uet_ses_atomic_cmp_swp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x11:
		return __parse_dump_uet_ses_atomic_cmp_swp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x12:
		return __parse_dump_uet_ses_atomic_cmp_swp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x13:
		return __parse_dump_uet_ses_atomic_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x14:
		return __parse_dump_uet_ses_atomic_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_atomic_std;
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
	case 0x0:
		return __parse_dump_uet_ses_request_nosom_atomic_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_som_atomic_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_nosom_atomic_std;
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



	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	return __parse_dump_atomic_switch_node_xdp2_parse(
		parser, hdr, len, metadata, frame, frame_num, ctrl, flags);
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_som_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_som_atomic_std;
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



	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	return __parse_dump_atomic_switch_node_xdp2_parse(
		parser, hdr, len, metadata, frame, frame_num, ctrl, flags);
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_fetching_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_fetching_atomic_std;
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
	case 0x0:
		return __parse_dump_uet_ses_request_nosom_fetching_atomic_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_som_fetching_atomic_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_nosom_fetching_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_nosom_fetching_atomic_std;
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



	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	return __parse_dump_atomic_switch_node_xdp2_parse(
		parser, hdr, len, metadata, frame, frame_num, ctrl, flags);
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_som_fetching_atomic_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_som_fetching_atomic_std;
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



	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	return __parse_dump_atomic_switch_node_xdp2_parse(
		parser, hdr, len, metadata, frame, frame_num, ctrl, flags);
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_deferrable_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_deferrable_send_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_deferrable_tsend_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_deferrable_tsend_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_ready_restart_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_ready_restart_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_rendezvous_send_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_rendezvous_send_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_rendezvous_tsend_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_rendezvous_tsend_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_atomic_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_atomic_node;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_atomic_cmp_swp_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_atomic_cmp_swp_node;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_no_op_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_no_op_std;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_write_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_write_medium;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_read_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_read_medium;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_send_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_send_medium;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_tsend_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_tsend_medium;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_datagram_send_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_datagram_send_medium;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_tsend_atomic_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_tsend_atomic_medium;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_tsend_fetch_atomic_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_tsend_fetch_atomic_medium;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_atomic_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_atomic_medium;
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



	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	return __parse_dump_atomic_switch_node_xdp2_parse(
		parser, hdr, len, metadata, frame, frame_num, ctrl, flags);
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_fetching_atomic_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_fetching_atomic_medium;
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



	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	return __parse_dump_atomic_switch_node_xdp2_parse(
		parser, hdr, len, metadata, frame, frame_num, ctrl, flags);
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_msg_no_op_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_msg_no_op_medium;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_write_small_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_write_small;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_read_small_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_read_small;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_atomic_small_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_atomic_small;
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



	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	return __parse_dump_atomic_switch_node_xdp2_parse(
		parser, hdr, len, metadata, frame, frame_num, ctrl, flags);
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_fetching_atomic_small_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_fetching_atomic_small;
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



	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	return __parse_dump_atomic_switch_node_xdp2_parse(
		parser, hdr, len, metadata, frame, frame_num, ctrl, flags);
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_msg_no_op_small_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_msg_no_op_small;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_no_next_hdr_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_no_next_hdr;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_small_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_small;
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
	case 0x0:
		return __parse_dump_uet_ses_msg_no_op_small_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_write_small_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2:
		return __parse_dump_uet_ses_request_read_small_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_uet_ses_request_atomic_small_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_uet_ses_request_fetching_atomic_small_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_medium_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_medium;
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
	case 0x0:
		return __parse_dump_uet_ses_msg_no_op_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_write_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2:
		return __parse_dump_uet_ses_request_read_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5:
		return __parse_dump_uet_ses_request_send_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x9:
		return __parse_dump_uet_ses_request_tsend_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x7:
		return __parse_dump_uet_ses_request_datagram_send_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xd:
		return __parse_dump_uet_ses_request_tsend_atomic_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xe:
		return __parse_dump_uet_ses_request_tsend_fetch_atomic_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_uet_ses_request_atomic_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_uet_ses_request_fetching_atomic_medium_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_request_std_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_request_std;
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
	case 0x0:
		return __parse_dump_uet_ses_no_op_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_uet_ses_request_write_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2:
		return __parse_dump_uet_ses_request_read_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_uet_ses_request_atomic_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_uet_ses_request_fetching_atomic_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5:
		return __parse_dump_uet_ses_request_send_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6:
		return __parse_dump_uet_ses_request_rendezvous_send_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x7:
		return __parse_dump_uet_ses_request_datagram_send_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x8:
		return __parse_dump_uet_ses_request_deferrable_send_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x9:
		return __parse_dump_uet_ses_request_tagged_send_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xa:
		return __parse_dump_uet_ses_request_rendezvous_tsend_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xb:
		return __parse_dump_uet_ses_request_deferrable_tsend_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xc:
		return __parse_dump_uet_ses_request_ready_restart_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xd:
		return __parse_dump_uet_ses_request_tsend_atomic_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xe:
		return __parse_dump_uet_ses_request_tsend_fetch_atomic_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xf:
		return __parse_dump_uet_ses_request_error_std_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_normal_nodata_response_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_normal_nodata_response;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_default_nodata_response_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_default_nodata_response;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_none_nodata_response_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_none_nodata_response;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_response_with_data_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_response_with_data;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_response_with_small_data_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_response_with_small_data;
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

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_response_tnode_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_response_tnode;
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
	case 0x1:
		return __parse_dump_uet_ses_normal_nodata_response_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x0:
		return __parse_dump_uet_ses_default_nodata_response_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_uet_ses_none_nodata_response_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_response_with_data_tnode_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_response_with_data_tnode;
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
	case 0x2:
		return __parse_dump_uet_ses_response_with_data_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_uet_ses_response_with_data_small_tnode_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&uet_ses_response_with_data_small_tnode;
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
	case 0x2:
		return __parse_dump_uet_ses_response_with_small_data_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_ether_node_root_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ether_node_root;
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
		return __parse_dump_ip_overlay_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xdd86:
		return __parse_dump_ip_overlay_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6488:
		return __parse_dump_pppoe_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xb88:
		return __parse_dump_ppp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xa888:
		return __parse_dump_e8021AD_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x81:
		return __parse_dump_e8021Q_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x608:
		return __parse_dump_arp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5865:
		return __parse_dump_ether_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5b88:
		return __parse_dump_sunh_node_alt_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_ether_node_xdp2_parse(
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
		return __parse_dump_ip_overlay_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xdd86:
		return __parse_dump_ip_overlay_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6488:
		return __parse_dump_pppoe_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xb88:
		return __parse_dump_ppp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xa888:
		return __parse_dump_e8021AD_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x81:
		return __parse_dump_e8021Q_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x608:
		return __parse_dump_arp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5865:
		return __parse_dump_ether_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5b88:
		return __parse_dump_sunh_node_alt_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_ip_overlay_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ip_overlay_node;
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
	case 0x4:
		return __parse_dump_ipv4_check_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6:
		return __parse_dump_ipv6_check_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_ip_overlay_by_key_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ip_overlay_by_key_node;
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
	case 0x4:
		return __parse_dump_ipv4_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6:
		return __parse_dump_ipv6_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_ipv4_node_xdp2_parse(
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
		return __parse_dump_tcp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x11:
		return __parse_dump_udp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2f:
		return __parse_dump_gre_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x73:
		return __parse_dump_l2tp_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_ipv4ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x29:
		return __parse_dump_ipv6ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_icmpv4_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x59:
		return __parse_dump_ospf_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_ipv4_check_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ipv4_check_node;
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



	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	return __parse_dump_ip_overlay_by_key_node_xdp2_parse(
		parser, hdr, len, metadata, frame, frame_num, ctrl, flags);
}

/* Parse function */
static inline __unused() int
	__parse_dump_ipv4ip_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ipv4ip_node;
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



	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	return __parse_dump_ipv4_node_xdp2_parse(
		parser, hdr, len, metadata, frame, frame_num, ctrl, flags);
}

/* Parse function */
static inline __unused() int
	__parse_dump_ipv6_node_xdp2_parse(
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
		return __parse_dump_tcp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x11:
		return __parse_dump_udp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2f:
		return __parse_dump_gre_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x73:
		return __parse_dump_l2tp_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_ipv4ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x29:
		return __parse_dump_ipv6ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3a:
		return __parse_dump_icmpv6_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x0:
		return __parse_dump_ipv6_hbh_options_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3c:
		return __parse_dump_ipv6_dest_options_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2b:
		return __parse_dump_ipv6_routing_header_node_check_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2c:
		return __parse_dump_ipv6_fragment_header_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x33:
		return __parse_dump_ipv6_ah_header_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xfd:
		return __parse_dump_superp_pdl_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_ipv6_check_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ipv6_check_node;
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



	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	return __parse_dump_ip_overlay_by_key_node_xdp2_parse(
		parser, hdr, len, metadata, frame, frame_num, ctrl, flags);
}

/* Parse function */
static inline __unused() int
	__parse_dump_ipv6ip_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ipv6ip_node;
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



	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	return __parse_dump_ipv6_node_xdp2_parse(
		parser, hdr, len, metadata, frame, frame_num, ctrl, flags);
}

/* Parse function */
static inline __unused() int
	__parse_dump_l2tp_base_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&l2tp_base_node;
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
	case 0x0:
		return __parse_dump_l2tp_v0_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_l2tp_v1_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2:
		return __parse_dump_l2tp_v2_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3:
		return __parse_dump_l2tp_v3_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_geneve_base_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&geneve_base_node;
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
	case 0x0:
		return __parse_dump_geneve_v0_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Template for parsing TLVs */
static inline __unused() __attribute__((unused)) int
	__parse_dump_geneve_v0_node_xdp2_parse_tlvs(
		const struct xdp2_parse_node *parse_node,
		void *hdr, size_t len, void *_metadata,
		void *frame, struct xdp2_ctrl_data *ctrl,
		unsigned int flags)
{
	const struct xdp2_proto_tlvs_def *proto_tlvs_def =
		(const struct xdp2_proto_tlvs_def *)parse_node->proto_def;
	const struct xdp2_parse_tlvs_node *parse_tlvs_node =
		(const struct xdp2_parse_tlvs_node*)&geneve_v0_node;
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
		case 0x0:
		{
			int ret;

			parse_tlv_node = &geneve_class_0_tlv_node;
			ops = &parse_tlv_node->tlv_ops;
			ret = xdp2_parse_tlv(parse_tlvs_node, parse_tlv_node,
					     cp, tlv_len, _metadata, frame,
					     ctrl, flags);
			if (ret != XDP2_OKAY)
				return ret;

			if (!parse_tlv_node->overlay_table)
				break;

			if (parse_tlv_node->proto_tlv_def->ops.overlay_type)
				type = parse_tlv_node->proto_tlv_def->
							ops.overlay_type(cp);
			else
				type = tlv_len;

			switch (type) {
			case 0x80:
				parse_tlv_node = &geneve_class_0_tlv_80_node;
				ret = xdp2_parse_tlv(parse_tlvs_node,
						     parse_tlv_node,
						     cp, tlv_len, _metadata,
						     frame, ctrl, flags);
				if (ret != XDP2_OKAY)
					return ret;
				break;
			default:
				break;
			 }

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
	__parse_dump_geneve_v0_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&geneve_v0_node;
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

	ret = __parse_dump_geneve_v0_node_xdp2_parse_tlvs(
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
		return __parse_dump_ip_overlay_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xdd86:
		return __parse_dump_ip_overlay_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6488:
		return __parse_dump_pppoe_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xb88:
		return __parse_dump_ppp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xa888:
		return __parse_dump_e8021AD_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x81:
		return __parse_dump_e8021Q_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x608:
		return __parse_dump_arp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5865:
		return __parse_dump_ether_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5b88:
		return __parse_dump_sunh_node_alt_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_ppp_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ppp_node;
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
	case 0x2100:
		return __parse_dump_ip_overlay_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x21c0:
		return __parse_dump_ppp_lcp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x23c0:
		return __parse_dump_ppp_pap_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x23c2:
		return __parse_dump_ppp_chap_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2180:
		return __parse_dump_ppp_icpc_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5700:
		return __parse_dump_ipv6_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_pppoe_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&pppoe_node;
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
	case 0x2100:
		return __parse_dump_ip_overlay_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x21c0:
		return __parse_dump_ppp_lcp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x23c0:
		return __parse_dump_ppp_pap_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x23c2:
		return __parse_dump_ppp_chap_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2180:
		return __parse_dump_ppp_icpc_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5700:
		return __parse_dump_ipv6_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_icmpv4_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&icmpv4_node;
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

/* Parse function */
static inline __unused() int
	__parse_dump_icmpv6_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&icmpv6_node;
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
	case 0x87:
		return __parse_dump_icmpv6_neigh_solicit_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x88:
		return __parse_dump_icmpv6_neigh_advert_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Template for parsing TLVs */
static inline __unused() __attribute__((unused)) int
	__parse_dump_icmpv6_neigh_solicit_xdp2_parse_tlvs(
		const struct xdp2_parse_node *parse_node,
		void *hdr, size_t len, void *_metadata,
		void *frame, struct xdp2_ctrl_data *ctrl,
		unsigned int flags)
{
	const struct xdp2_proto_tlvs_def *proto_tlvs_def =
		(const struct xdp2_proto_tlvs_def *)parse_node->proto_def;
	const struct xdp2_parse_tlvs_node *parse_tlvs_node =
		(const struct xdp2_parse_tlvs_node*)&icmpv6_neigh_solicit;
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
		case 0x1:
		{
			int ret;

			parse_tlv_node = &icmpv6_nd_target_addr_opt_node;
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
	__parse_dump_icmpv6_neigh_solicit_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&icmpv6_neigh_solicit;
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

	ret = __parse_dump_icmpv6_neigh_solicit_xdp2_parse_tlvs(
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

/* Parse function */
static inline __unused() int
	__parse_dump_icmpv6_neigh_advert_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&icmpv6_neigh_advert;
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

/* Parse function */
static inline __unused() int
	__parse_dump_vxlan_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&vxlan_node;
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



	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	return __parse_dump_ether_node_xdp2_parse(
		parser, hdr, len, metadata, frame, frame_num, ctrl, flags);
}

/* Template for parsing TLVs */
static inline __unused() __attribute__((unused)) int
	__parse_dump_protobufs1_node_xdp2_parse_tlvs(
		const struct xdp2_parse_node *parse_node,
		void *hdr, size_t len, void *_metadata,
		void *frame, struct xdp2_ctrl_data *ctrl,
		unsigned int flags)
{
	const struct xdp2_proto_tlvs_def *proto_tlvs_def =
		(const struct xdp2_proto_tlvs_def *)parse_node->proto_def;
	const struct xdp2_parse_tlvs_node *parse_tlvs_node =
		(const struct xdp2_parse_tlvs_node*)&protobufs1_node;
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
		case 0x1:
		{
			int ret;

			parse_tlv_node = &protobufs1_name_node;
			ret = xdp2_parse_tlv(parse_tlvs_node, parse_tlv_node,
					     cp, tlv_len, _metadata, frame,
					     ctrl, flags);
			if (ret != XDP2_OKAY)
				return ret;

			if (!parse_tlv_node->overlay_table)
				break;

		}
		case 0x2:
		{
			int ret;

			parse_tlv_node = &protobufs1_id_node;
			ret = xdp2_parse_tlv(parse_tlvs_node, parse_tlv_node,
					     cp, tlv_len, _metadata, frame,
					     ctrl, flags);
			if (ret != XDP2_OKAY)
				return ret;

			if (!parse_tlv_node->overlay_table)
				break;

		}
		case 0x3:
		{
			int ret;

			parse_tlv_node = &protobufs1_email_node;
			ret = xdp2_parse_tlv(parse_tlvs_node, parse_tlv_node,
					     cp, tlv_len, _metadata, frame,
					     ctrl, flags);
			if (ret != XDP2_OKAY)
				return ret;

			if (!parse_tlv_node->overlay_table)
				break;

		}
		case 0x4:
		{
			int ret;

			parse_tlv_node = &protobufs1_phones_node;
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
	__parse_dump_protobufs1_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&protobufs1_node;
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

	ret = __parse_dump_protobufs1_node_xdp2_parse_tlvs(
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

/* Template for parsing TLVs */
static inline __unused() __attribute__((unused)) int
	__parse_dump_protobufs2_node_xdp2_parse_tlvs(
		const struct xdp2_parse_node *parse_node,
		void *hdr, size_t len, void *_metadata,
		void *frame, struct xdp2_ctrl_data *ctrl,
		unsigned int flags)
{
	const struct xdp2_proto_tlvs_def *proto_tlvs_def =
		(const struct xdp2_proto_tlvs_def *)parse_node->proto_def;
	const struct xdp2_parse_tlvs_node *parse_tlvs_node =
		(const struct xdp2_parse_tlvs_node*)&protobufs2_node;
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
		case 0x1:
		{
			int ret;

			parse_tlv_node = &protobufs2_entry_node;
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
	__parse_dump_protobufs2_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&protobufs2_node;
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

	ret = __parse_dump_protobufs2_node_xdp2_parse_tlvs(
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

/* Parse function */
static inline __unused() int
	__parse_dump_ospf_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ospf_node;
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

/* Parse function */
static inline __unused() int
	__parse_dump_udp_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&udp_node;
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
	case 0xb822:
		return __parse_dump_protobufs1_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xf27:
		return __parse_dump_protobufs2_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xb512:
		return __parse_dump_vxlan_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xa506:
		return __parse_dump_l2tp_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xc117:
		return __parse_dump_geneve_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xb912:
		return __parse_dump_uet_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x611e:
		return __parse_dump_falcon_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x50d:
		return __parse_dump_sue_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5c11:
		return __parse_dump_superp_pdl_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_arp_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&arp_node;
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
	__parse_dump_protobufs1_phone_node_xdp2_parse_tlvs(
		const struct xdp2_parse_node *parse_node,
		void *hdr, size_t len, void *_metadata,
		void *frame, struct xdp2_ctrl_data *ctrl,
		unsigned int flags)
{
	const struct xdp2_proto_tlvs_def *proto_tlvs_def =
		(const struct xdp2_proto_tlvs_def *)parse_node->proto_def;
	const struct xdp2_parse_tlvs_node *parse_tlvs_node =
		(const struct xdp2_parse_tlvs_node*)&protobufs1_phone_node;
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
		case 0x1:
		{
			int ret;

			parse_tlv_node = &protobufs2_phone_number_node;
			ret = xdp2_parse_tlv(parse_tlvs_node, parse_tlv_node,
					     cp, tlv_len, _metadata, frame,
					     ctrl, flags);
			if (ret != XDP2_OKAY)
				return ret;

			if (!parse_tlv_node->overlay_table)
				break;

		}
		case 0x2:
		{
			int ret;

			parse_tlv_node = &protobufs2_phone_type_node;
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
	__parse_dump_protobufs1_phone_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&protobufs1_phone_node;
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

	ret = __parse_dump_protobufs1_phone_node_xdp2_parse_tlvs(
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

/* Template for parsing TLVs */
static inline __unused() __attribute__((unused)) int
	__parse_dump_tcp_node_xdp2_parse_tlvs(
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
		case 0x5:
		{
			int ret;

			parse_tlv_node = &tcp_opt_sack_node;
			ops = &parse_tlv_node->tlv_ops;
			ret = xdp2_parse_tlv(parse_tlvs_node, parse_tlv_node,
					     cp, tlv_len, _metadata, frame,
					     ctrl, flags);
			if (ret != XDP2_OKAY)
				return ret;

			if (!parse_tlv_node->overlay_table)
				break;

			if (parse_tlv_node->proto_tlv_def->ops.overlay_type)
				type = parse_tlv_node->proto_tlv_def->
							ops.overlay_type(cp);
			else
				type = tlv_len;

			switch (type) {
			case 0xa:
				parse_tlv_node = &tcp_opt_sack_1;
				ret = xdp2_parse_tlv(parse_tlvs_node,
						     parse_tlv_node,
						     cp, tlv_len, _metadata,
						     frame, ctrl, flags);
				if (ret != XDP2_OKAY)
					return ret;
				break;
			case 0x12:
				parse_tlv_node = &tcp_opt_sack_2;
				ret = xdp2_parse_tlv(parse_tlvs_node,
						     parse_tlv_node,
						     cp, tlv_len, _metadata,
						     frame, ctrl, flags);
				if (ret != XDP2_OKAY)
					return ret;
				break;
			case 0x1a:
				parse_tlv_node = &tcp_opt_sack_3;
				ret = xdp2_parse_tlv(parse_tlvs_node,
						     parse_tlv_node,
						     cp, tlv_len, _metadata,
						     frame, ctrl, flags);
				if (ret != XDP2_OKAY)
					return ret;
				break;
			case 0x22:
				parse_tlv_node = &tcp_opt_sack_4;
				ret = xdp2_parse_tlv(parse_tlvs_node,
						     parse_tlv_node,
						     cp, tlv_len, _metadata,
						     frame, ctrl, flags);
				if (ret != XDP2_OKAY)
					return ret;
				break;
			default:
				break;
			 }

			break;
		}
		case 0x2:
		{
			int ret;

			parse_tlv_node = &tcp_opt_mss_node;
			ret = xdp2_parse_tlv(parse_tlvs_node, parse_tlv_node,
					     cp, tlv_len, _metadata, frame,
					     ctrl, flags);
			if (ret != XDP2_OKAY)
				return ret;

			if (!parse_tlv_node->overlay_table)
				break;

		}
		case 0x3:
		{
			int ret;

			parse_tlv_node = &tcp_opt_wscale_node;
			ret = xdp2_parse_tlv(parse_tlvs_node, parse_tlv_node,
					     cp, tlv_len, _metadata, frame,
					     ctrl, flags);
			if (ret != XDP2_OKAY)
				return ret;

			if (!parse_tlv_node->overlay_table)
				break;

		}
		case 0x4:
		{
			int ret;

			parse_tlv_node = &tcp_opt_sack_permitted_node;
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
	__parse_dump_tcp_node_xdp2_parse(
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

	ret = __parse_dump_tcp_node_xdp2_parse_tlvs(
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

/* Parse function */
static inline __unused() int
	__parse_dump_okay_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&okay_node;
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

/* Parse function */
static inline __unused() int
	__parse_dump_fail_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&fail_node;
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

/* Parse function */
static inline __unused() int
	__parse_dump_atencap_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&atencap_node;
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

/* Parse function */
static inline __unused() int
	__parse_dump_gre_base_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&gre_base_node;
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
	case 0x0:
		return __parse_dump_gre_v0_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_gre_v1_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Template for parsing flag fields */
static inline __unused() __attribute__((always_inline)) int
	__parse_dump_gre_v0_node_xdp2_parse_flag_fields(
		const struct xdp2_parse_node *parse_node, void *hdr,
		size_t len, void *_metadata, void *frame,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_proto_flag_fields_def *proto_flag_fields_def;
	const struct xdp2_flag_field *flag_fields;
	const struct xdp2_flag_field *flag_field;
	__u32 fflags, mask;

	proto_flag_fields_def =
		(struct xdp2_proto_flag_fields_def *)parse_node->proto_def;
	flag_fields = proto_flag_fields_def->flag_fields->fields;
	fflags = proto_flag_fields_def->ops.get_flags(hdr);

	/* Position at start of field data */
	hdr += proto_flag_fields_def->ops.start_fields_offset(hdr);

	if (fflags) {
		flag_field = &flag_fields[0x0];
		mask = flag_field->mask ? flag_field->mask : flag_field->flag;
		if ((fflags & mask) == flag_field->flag) {
			if (gre_flag_csum_node.ops.extract_metadata)
				gre_flag_csum_node.ops.extract_metadata(
					hdr, flag_fields->size, _metadata,
					frame, ctrl);
			if(gre_flag_csum_node.ops.handler)
				gre_flag_csum_node.ops.handler(
					hdr, flag_fields->size, _metadata,
					frame, ctrl);
			hdr += flag_fields->size;
		}
		flag_field = &flag_fields[0x1];
		mask = flag_field->mask ? flag_field->mask : flag_field->flag;
		if ((fflags & mask) == flag_field->flag) {
			if (gre_flag_key_node.ops.extract_metadata)
				gre_flag_key_node.ops.extract_metadata(
					hdr, flag_fields->size, _metadata,
					frame, ctrl);
			if(gre_flag_key_node.ops.handler)
				gre_flag_key_node.ops.handler(
					hdr, flag_fields->size, _metadata,
					frame, ctrl);
			hdr += flag_fields->size;
		}
		flag_field = &flag_fields[0x2];
		mask = flag_field->mask ? flag_field->mask : flag_field->flag;
		if ((fflags & mask) == flag_field->flag) {
			if (gre_flag_seq_node.ops.extract_metadata)
				gre_flag_seq_node.ops.extract_metadata(
					hdr, flag_fields->size, _metadata,
					frame, ctrl);
			if(gre_flag_seq_node.ops.handler)
				gre_flag_seq_node.ops.handler(
					hdr, flag_fields->size, _metadata,
					frame, ctrl);
			hdr += flag_fields->size;
		}
	}
	return XDP2_OKAY;
}

/* Parse function */
static inline __unused() int
	__parse_dump_gre_v0_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&gre_v0_node;
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


	ret = __parse_dump_gre_v0_node_xdp2_parse_flag_fields(
			parse_node, hdr, hlen, metadata,
			*frame, ctrl, flags);
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
		return __parse_dump_ip_overlay_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xdd86:
		return __parse_dump_ip_overlay_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5865:
		return __parse_dump_ether_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6488:
		return __parse_dump_pppoe_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xb88:
		return __parse_dump_ppp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Template for parsing flag fields */
static inline __unused() __attribute__((always_inline)) int
	__parse_dump_gre_v1_node_xdp2_parse_flag_fields(
		const struct xdp2_parse_node *parse_node, void *hdr,
		size_t len, void *_metadata, void *frame,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_proto_flag_fields_def *proto_flag_fields_def;
	const struct xdp2_flag_field *flag_fields;
	const struct xdp2_flag_field *flag_field;
	__u32 fflags, mask;

	proto_flag_fields_def =
		(struct xdp2_proto_flag_fields_def *)parse_node->proto_def;
	flag_fields = proto_flag_fields_def->flag_fields->fields;
	fflags = proto_flag_fields_def->ops.get_flags(hdr);

	/* Position at start of field data */
	hdr += proto_flag_fields_def->ops.start_fields_offset(hdr);

	if (fflags) {
		flag_field = &flag_fields[0x0];
		mask = flag_field->mask ? flag_field->mask : flag_field->flag;
		if ((fflags & mask) == flag_field->flag) {
			if (XDP2_FLAG_NODE_NULL.ops.extract_metadata)
				XDP2_FLAG_NODE_NULL.ops.extract_metadata(
					hdr, flag_fields->size, _metadata,
					frame, ctrl);
			if(XDP2_FLAG_NODE_NULL.ops.handler)
				XDP2_FLAG_NODE_NULL.ops.handler(
					hdr, flag_fields->size, _metadata,
					frame, ctrl);
			hdr += flag_fields->size;
		}
		flag_field = &flag_fields[0x1];
		mask = flag_field->mask ? flag_field->mask : flag_field->flag;
		if ((fflags & mask) == flag_field->flag) {
			if (gre_pptp_flag_key_node.ops.extract_metadata)
				gre_pptp_flag_key_node.ops.extract_metadata(
					hdr, flag_fields->size, _metadata,
					frame, ctrl);
			if(gre_pptp_flag_key_node.ops.handler)
				gre_pptp_flag_key_node.ops.handler(
					hdr, flag_fields->size, _metadata,
					frame, ctrl);
			hdr += flag_fields->size;
		}
		flag_field = &flag_fields[0x2];
		mask = flag_field->mask ? flag_field->mask : flag_field->flag;
		if ((fflags & mask) == flag_field->flag) {
			if (gre_pptp_flag_seq_node.ops.extract_metadata)
				gre_pptp_flag_seq_node.ops.extract_metadata(
					hdr, flag_fields->size, _metadata,
					frame, ctrl);
			if(gre_pptp_flag_seq_node.ops.handler)
				gre_pptp_flag_seq_node.ops.handler(
					hdr, flag_fields->size, _metadata,
					frame, ctrl);
			hdr += flag_fields->size;
		}
		flag_field = &flag_fields[0x3];
		mask = flag_field->mask ? flag_field->mask : flag_field->flag;
		if ((fflags & mask) == flag_field->flag) {
			if (gre_pptp_flag_ack_node.ops.extract_metadata)
				gre_pptp_flag_ack_node.ops.extract_metadata(
					hdr, flag_fields->size, _metadata,
					frame, ctrl);
			if(gre_pptp_flag_ack_node.ops.handler)
				gre_pptp_flag_ack_node.ops.handler(
					hdr, flag_fields->size, _metadata,
					frame, ctrl);
			hdr += flag_fields->size;
		}
	}
	return XDP2_OKAY;
}

/* Parse function */
static inline __unused() int
	__parse_dump_gre_v1_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&gre_v1_node;
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


	ret = __parse_dump_gre_v1_node_xdp2_parse_flag_fields(
			parse_node, hdr, hlen, metadata,
			*frame, ctrl, flags);
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
		return __parse_dump_ipv4_check_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xdd86:
		return __parse_dump_ipv6_check_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5865:
		return __parse_dump_ether_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6488:
		return __parse_dump_pppoe_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xb88:
		return __parse_dump_ppp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_e8021AD_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&e8021AD_node;
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
		return __parse_dump_ip_overlay_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xdd86:
		return __parse_dump_ip_overlay_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6488:
		return __parse_dump_pppoe_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xb88:
		return __parse_dump_ppp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xa888:
		return __parse_dump_e8021AD_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x81:
		return __parse_dump_e8021Q_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x608:
		return __parse_dump_arp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5865:
		return __parse_dump_ether_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5b88:
		return __parse_dump_sunh_node_alt_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_e8021Q_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&e8021Q_node;
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
		return __parse_dump_ip_overlay_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xdd86:
		return __parse_dump_ip_overlay_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x6488:
		return __parse_dump_pppoe_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xb88:
		return __parse_dump_ppp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xa888:
		return __parse_dump_e8021AD_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x81:
		return __parse_dump_e8021Q_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x608:
		return __parse_dump_arp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5865:
		return __parse_dump_ether_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x5b88:
		return __parse_dump_sunh_node_alt_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_sunh_node_alt_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&sunh_node_alt;
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
		return __parse_dump_tcp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x11:
		return __parse_dump_udp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2f:
		return __parse_dump_gre_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x73:
		return __parse_dump_l2tp_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_ipv4ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x29:
		return __parse_dump_ipv6ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3a:
		return __parse_dump_icmpv6_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x0:
		return __parse_dump_ipv6_hbh_options_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3c:
		return __parse_dump_ipv6_dest_options_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2b:
		return __parse_dump_ipv6_routing_header_node_check_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2c:
		return __parse_dump_ipv6_fragment_header_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x33:
		return __parse_dump_ipv6_ah_header_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xfd:
		return __parse_dump_superp_pdl_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_ipv6_hbh_options_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ipv6_hbh_options_node;
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
		return __parse_dump_tcp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x11:
		return __parse_dump_udp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2f:
		return __parse_dump_gre_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x73:
		return __parse_dump_l2tp_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_ipv4ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x29:
		return __parse_dump_ipv6ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3a:
		return __parse_dump_icmpv6_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x0:
		return __parse_dump_ipv6_hbh_options_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3c:
		return __parse_dump_ipv6_dest_options_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2b:
		return __parse_dump_ipv6_routing_header_node_check_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2c:
		return __parse_dump_ipv6_fragment_header_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x33:
		return __parse_dump_ipv6_ah_header_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xfd:
		return __parse_dump_superp_pdl_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_ipv6_dest_options_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ipv6_dest_options_node;
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
		return __parse_dump_tcp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x11:
		return __parse_dump_udp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2f:
		return __parse_dump_gre_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x73:
		return __parse_dump_l2tp_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_ipv4ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x29:
		return __parse_dump_ipv6ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3a:
		return __parse_dump_icmpv6_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x0:
		return __parse_dump_ipv6_hbh_options_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3c:
		return __parse_dump_ipv6_dest_options_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2b:
		return __parse_dump_ipv6_routing_header_node_check_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2c:
		return __parse_dump_ipv6_fragment_header_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x33:
		return __parse_dump_ipv6_ah_header_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xfd:
		return __parse_dump_superp_pdl_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_ipv6_routing_header_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ipv6_routing_header_node;
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
		return __parse_dump_tcp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x11:
		return __parse_dump_udp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2f:
		return __parse_dump_gre_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x73:
		return __parse_dump_l2tp_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_ipv4ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x29:
		return __parse_dump_ipv6ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3a:
		return __parse_dump_icmpv6_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x0:
		return __parse_dump_ipv6_hbh_options_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3c:
		return __parse_dump_ipv6_dest_options_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2b:
		return __parse_dump_ipv6_routing_header_node_check_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2c:
		return __parse_dump_ipv6_fragment_header_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x33:
		return __parse_dump_ipv6_ah_header_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xfd:
		return __parse_dump_superp_pdl_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_ipv6_routing_header_node_check_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ipv6_routing_header_node_check;
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



	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	return __parse_dump_ipv6_routing_header_node_xdp2_parse(
		parser, hdr, len, metadata, frame, frame_num, ctrl, flags);
}

/* Parse function */
static inline __unused() int
	__parse_dump_ipv6_fragment_header_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ipv6_fragment_header_node;
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
		return __parse_dump_tcp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x11:
		return __parse_dump_udp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2f:
		return __parse_dump_gre_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x73:
		return __parse_dump_l2tp_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_ipv4ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x29:
		return __parse_dump_ipv6ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3a:
		return __parse_dump_icmpv6_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x0:
		return __parse_dump_ipv6_hbh_options_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3c:
		return __parse_dump_ipv6_dest_options_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2b:
		return __parse_dump_ipv6_routing_header_node_check_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2c:
		return __parse_dump_ipv6_fragment_header_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x33:
		return __parse_dump_ipv6_ah_header_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xfd:
		return __parse_dump_superp_pdl_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_ipv6_ah_header_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ipv6_ah_header_node;
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
		return __parse_dump_tcp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x11:
		return __parse_dump_udp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2f:
		return __parse_dump_gre_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x73:
		return __parse_dump_l2tp_base_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x4:
		return __parse_dump_ipv4ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x29:
		return __parse_dump_ipv6ip_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3a:
		return __parse_dump_icmpv6_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x0:
		return __parse_dump_ipv6_hbh_options_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x3c:
		return __parse_dump_ipv6_dest_options_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2b:
		return __parse_dump_ipv6_routing_header_node_check_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x2c:
		return __parse_dump_ipv6_fragment_header_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x33:
		return __parse_dump_ipv6_ah_header_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0xfd:
		return __parse_dump_superp_pdl_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_l2tp_v0_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&l2tp_v0_node;
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
	case 0x0:
		return __parse_dump_ppp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_l2tp_v0_offsz_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_l2tp_v0_offsz_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&l2tp_v0_offsz_node;
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



	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	return __parse_dump_ppp_node_xdp2_parse(
		parser, hdr, len, metadata, frame, frame_num, ctrl, flags);
}

/* Parse function */
static inline __unused() int
	__parse_dump_l2tp_v1_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&l2tp_v1_node;
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



	if (!proto_def->overlay) {
		hdr += hlen;
		len -= hlen;
	}

	return __parse_dump_ppp_node_xdp2_parse(
		parser, hdr, len, metadata, frame, frame_num, ctrl, flags);
}

/* Parse function */
static inline __unused() int
	__parse_dump_l2tp_v2_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&l2tp_v2_node;
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
	case 0x0:
		return __parse_dump_ppp_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	case 0x1:
		return __parse_dump_l2tp_v0_offsz_node_xdp2_parse(
			parser, hdr, len, metadata, frame, frame_num,
			ctrl, flags);
	}
	return parse_node->unknown_ret;
	}
}

/* Parse function */
static inline __unused() int
	__parse_dump_l2tp_v3_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&l2tp_v3_node;
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

/* Parse function */
static inline __unused() int
	__parse_dump_ppp_lcp_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ppp_lcp_node;
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

/* Parse function */
static inline __unused() int
	__parse_dump_ppp_pap_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ppp_pap_node;
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

/* Parse function */
static inline __unused() int
	__parse_dump_ppp_chap_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ppp_chap_node;
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

/* Parse function */
static inline __unused() int
	__parse_dump_ppp_icpc_node_xdp2_parse(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, void **frame, unsigned int frame_num,
		struct xdp2_ctrl_data *ctrl, unsigned int flags)
{
	const struct xdp2_parse_node *parse_node =
		(const struct xdp2_parse_node*)&ppp_icpc_node;
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

/* Parser entry function to commence parsing at the root */
static inline __unused() int
	parse_dump_xdp2_parse_ether_node_root(
		const struct xdp2_parser *parser, void *hdr, size_t len,
		void *metadata, struct xdp2_ctrl_data *ctrl,
		unsigned int flags)
{
	void *frame = metadata + parser->config.metameta_size;
	const struct xdp2_parse_node *parse_node;
	int ret;

	(void)&__parse_dump_falcon_base_node_xdp2_parse;
	(void)&__parse_dump_falcon_v1_node_xdp2_parse;
	(void)&__parse_dump_falcon_pull_request_xdp2_parse;
	(void)&__parse_dump_falcon_pull_data_xdp2_parse;
	(void)&__parse_dump_falcon_push_data_xdp2_parse;
	(void)&__parse_dump_falcon_resync_xdp2_parse;
	(void)&__parse_dump_falcon_back_xdp2_parse;
	(void)&__parse_dump_falcon_nack_xdp2_parse;
	(void)&__parse_dump_falcon_eack_xdp2_parse;
	(void)&__parse_dump_sue_base_node_xdp2_parse;
	(void)&__parse_dump_sue_v0_node_xdp2_parse;
	(void)&__parse_dump_sue_rh_ack_xdp2_parse;
	(void)&__parse_dump_sue_rh_nack_xdp2_parse;
	(void)&__parse_dump_sue_rh_invalid1_xdp2_parse;
	(void)&__parse_dump_sue_rh_invalid2_xdp2_parse;
	(void)&__parse_dump_sunh_node_xdp2_parse;
	(void)&__parse_dump_superp_no_op_node_xdp2_parse;
	(void)&__parse_dump_superp_tal_node_xdp2_parse;
	(void)&__parse_dump_superp_pdl_node_xdp2_parse;
	(void)&__parse_dump_uet_base_node_xdp2_parse;
	(void)&__parse_dump_pds_ack_cc_base_node_xdp2_parse;
	(void)&__parse_dump_pds_ack_cc_nscc_xdp2_parse;
	(void)&__parse_dump_pds_ack_cc_credit_xdp2_parse;
	(void)&__parse_dump_pds_rud_request_xdp2_parse;
	(void)&__parse_dump_pds_rod_request_xdp2_parse;
	(void)&__parse_dump_pds_rud_request_cc_xdp2_parse;
	(void)&__parse_dump_pds_rod_request_cc_xdp2_parse;
	(void)&__parse_dump_pds_rud_request_syn_xdp2_parse;
	(void)&__parse_dump_pds_rod_request_syn_xdp2_parse;
	(void)&__parse_dump_pds_rud_request_cc_syn_xdp2_parse;
	(void)&__parse_dump_pds_rod_request_cc_syn_xdp2_parse;
	(void)&__parse_dump_pds_ack_xdp2_parse;
	(void)&__parse_dump_pds_ack_ccx_xdp2_parse;
	(void)&__parse_dump_pds_nack_xdp2_parse;
	(void)&__parse_dump_pds_nack_ccx_xdp2_parse;
	(void)&__parse_dump_pds_control_xdp2_parse;
	(void)&__parse_dump_pds_control_syn_xdp2_parse;
	(void)&__parse_dump_pds_uud_req_xdp2_parse;
	(void)&__parse_dump_pds_rudi_req_xdp2_parse;
	(void)&__parse_dump_pds_rudi_resp_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_read_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_nosom_read_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_som_read_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_write_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_nosom_write_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_som_write_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_send_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_nosom_send_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_som_send_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_datagram_send_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_nosom_datagram_send_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_som_datagram_send_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_tagged_send_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_nosom_tagged_send_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_som_tagged_send_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_tsend_atomic_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_nosom_tsend_atomic_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_som_tsend_atomic_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_tsend_fetch_atomic_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_nosom_tsend_fetch_atomic_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_som_tsend_fetch_atomic_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_error_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_nosom_error_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_som_error_std_xdp2_parse;
	(void)&__parse_dump_atomic_switch_node_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_atomic_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_nosom_atomic_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_som_atomic_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_fetching_atomic_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_nosom_fetching_atomic_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_som_fetching_atomic_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_deferrable_send_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_deferrable_tsend_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_ready_restart_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_rendezvous_send_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_rendezvous_tsend_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_atomic_node_xdp2_parse;
	(void)&__parse_dump_uet_ses_atomic_cmp_swp_node_xdp2_parse;
	(void)&__parse_dump_uet_ses_no_op_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_write_medium_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_read_medium_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_send_medium_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_tsend_medium_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_datagram_send_medium_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_tsend_atomic_medium_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_tsend_fetch_atomic_medium_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_atomic_medium_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_fetching_atomic_medium_xdp2_parse;
	(void)&__parse_dump_uet_ses_msg_no_op_medium_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_write_small_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_read_small_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_atomic_small_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_fetching_atomic_small_xdp2_parse;
	(void)&__parse_dump_uet_ses_msg_no_op_small_xdp2_parse;
	(void)&__parse_dump_uet_ses_no_next_hdr_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_small_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_medium_xdp2_parse;
	(void)&__parse_dump_uet_ses_request_std_xdp2_parse;
	(void)&__parse_dump_uet_ses_normal_nodata_response_xdp2_parse;
	(void)&__parse_dump_uet_ses_default_nodata_response_xdp2_parse;
	(void)&__parse_dump_uet_ses_none_nodata_response_xdp2_parse;
	(void)&__parse_dump_uet_ses_response_with_data_xdp2_parse;
	(void)&__parse_dump_uet_ses_response_with_small_data_xdp2_parse;
	(void)&__parse_dump_uet_ses_response_tnode_xdp2_parse;
	(void)&__parse_dump_uet_ses_response_with_data_tnode_xdp2_parse;
	(void)&__parse_dump_uet_ses_response_with_data_small_tnode_xdp2_parse;
	(void)&__parse_dump_ether_node_root_xdp2_parse;
	(void)&__parse_dump_ether_node_xdp2_parse;
	(void)&__parse_dump_ip_overlay_node_xdp2_parse;
	(void)&__parse_dump_ip_overlay_by_key_node_xdp2_parse;
	(void)&__parse_dump_ipv4_node_xdp2_parse;
	(void)&__parse_dump_ipv4_check_node_xdp2_parse;
	(void)&__parse_dump_ipv4ip_node_xdp2_parse;
	(void)&__parse_dump_ipv6_node_xdp2_parse;
	(void)&__parse_dump_ipv6_check_node_xdp2_parse;
	(void)&__parse_dump_ipv6ip_node_xdp2_parse;
	(void)&__parse_dump_l2tp_base_node_xdp2_parse;
	(void)&__parse_dump_geneve_base_node_xdp2_parse;
	(void)&__parse_dump_geneve_v0_node_xdp2_parse;
	(void)&__parse_dump_ppp_node_xdp2_parse;
	(void)&__parse_dump_pppoe_node_xdp2_parse;
	(void)&__parse_dump_icmpv4_node_xdp2_parse;
	(void)&__parse_dump_icmpv6_node_xdp2_parse;
	(void)&__parse_dump_icmpv6_neigh_solicit_xdp2_parse;
	(void)&__parse_dump_icmpv6_neigh_advert_xdp2_parse;
	(void)&__parse_dump_vxlan_node_xdp2_parse;
	(void)&__parse_dump_protobufs1_node_xdp2_parse;
	(void)&__parse_dump_protobufs2_node_xdp2_parse;
	(void)&__parse_dump_ospf_node_xdp2_parse;
	(void)&__parse_dump_udp_node_xdp2_parse;
	(void)&__parse_dump_arp_node_xdp2_parse;
	(void)&__parse_dump_protobufs1_phone_node_xdp2_parse;
	(void)&__parse_dump_tcp_node_xdp2_parse;
	(void)&__parse_dump_okay_node_xdp2_parse;
	(void)&__parse_dump_fail_node_xdp2_parse;
	(void)&__parse_dump_atencap_node_xdp2_parse;
	(void)&__parse_dump_gre_base_node_xdp2_parse;
	(void)&__parse_dump_gre_v0_node_xdp2_parse;
	(void)&__parse_dump_gre_v1_node_xdp2_parse;
	(void)&__parse_dump_e8021AD_node_xdp2_parse;
	(void)&__parse_dump_e8021Q_node_xdp2_parse;
	(void)&__parse_dump_sunh_node_alt_xdp2_parse;
	(void)&__parse_dump_ipv6_hbh_options_node_xdp2_parse;
	(void)&__parse_dump_ipv6_dest_options_node_xdp2_parse;
	(void)&__parse_dump_ipv6_routing_header_node_xdp2_parse;
	(void)&__parse_dump_ipv6_routing_header_node_check_xdp2_parse;
	(void)&__parse_dump_ipv6_fragment_header_node_xdp2_parse;
	(void)&__parse_dump_ipv6_ah_header_node_xdp2_parse;
	(void)&__parse_dump_l2tp_v0_node_xdp2_parse;
	(void)&__parse_dump_l2tp_v0_offsz_node_xdp2_parse;
	(void)&__parse_dump_l2tp_v1_node_xdp2_parse;
	(void)&__parse_dump_l2tp_v2_node_xdp2_parse;
	(void)&__parse_dump_l2tp_v3_node_xdp2_parse;
	(void)&__parse_dump_ppp_lcp_node_xdp2_parse;
	(void)&__parse_dump_ppp_pap_node_xdp2_parse;
	(void)&__parse_dump_ppp_chap_node_xdp2_parse;
	(void)&__parse_dump_ppp_icpc_node_xdp2_parse;

	ret = __parse_dump_ether_node_root_xdp2_parse(
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
	parse_dump_opt,
	"",
	ether_node_root,
	parse_dump_xdp2_parse_ether_node_root,
	(
		.max_nodes = 255,
		.max_encaps = 4,
		.max_frames = 3,
		.metameta_size = 72,
		.frame_size = 96,
		.num_counters = 8,
		.num_keys = 7,
		.okay_node = &okay_node.pn,
		.fail_node = &fail_node.pn,
		.atencap_node = &atencap_node.pn,
	)
    );
