// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/*
 * Parser definition for the AF_XDP sample.
 * Parses Ethernet -> IPv4 -> TCP/UDP (same as flow_tracker_tmpl).
 * The parsed metadata is available in the XDP program callback but
 * the primary purpose here is classification for AF_XDP redirect.
 */

#include "common.h"

/* Metadata extractors: use canned templates for common protocols */
XDP2_METADATA_TEMP_ether(ether_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_ipv4(ipv4_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_ports(ports_metadata, xdp2_metadata_all)

/* Parse nodes */
XDP2_MAKE_PARSE_NODE(ether_node, xdp2_parse_ether, ether_table,
		     (.ops.extract_metadata = ether_metadata));
XDP2_MAKE_PARSE_NODE(ipv4_check_node, xdp2_parse_ip, ipv4_check_table, ());
XDP2_MAKE_PARSE_NODE(ipv4_node, xdp2_parse_ipv4, ipv4_table,
		     (.ops.extract_metadata = ipv4_metadata));
XDP2_MAKE_LEAF_PARSE_NODE(ports_node, xdp2_parse_ports,
			  (.ops.extract_metadata = ports_metadata));

/* Protocol routing tables */
XDP2_MAKE_PROTO_TABLE(ether_table,
	( __cpu_to_be16(ETH_P_IP), ipv4_check_node )
);

XDP2_MAKE_PROTO_TABLE(ipv4_check_table,
	( 4, ipv4_node )
);

XDP2_MAKE_PROTO_TABLE(ipv4_table,
	( IPPROTO_TCP, ports_node ),
	( IPPROTO_UDP, ports_node )
);

/* Name fixed to xdp2_parser_simple_tuple by the tail-call path in
 * XDP2_XDP_MAKE_PARSER_PROGRAM (src/include/xdp2/xdp_tmpl.h). Same
 * parse tree as flow_tracker_tmpl — the samples differ only in the
 * XDP action (redirect-to-XSKMAP here vs flow-table update there).
 */
XDP2_PARSER(xdp2_parser_simple_tuple, "XDP2 parser for AF_XDP redirect",
	     ether_node,
	     (.max_frames = 1,
	      .metameta_size = 0,
	      .frame_size = sizeof(struct xdp2_metadata_all)
	     )
);
