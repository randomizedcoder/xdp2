/* flow_dissector_nodes_l2.h — Extended L2 leaf nodes (userspace only)
 *
 * These nodes are excluded from XDP/BPF builds to keep the BPF program
 * within size limits. The #ifndef XDP2_XDP_BUILD guard is in parser.c,
 * not in this file.
 */

/* InfiniBand over Ethernet (RoCE v1): GRH → BTH */
XDP2_MAKE_LEAF_PARSE_NODE(ib_bth_node, xdp2_parse_ib_bth, ());
XDP2_MAKE_AUTONEXT_PARSE_NODE(ib_grh_node, xdp2_parse_ib_grh,
			      ib_bth_node, ());

/* Simple L2 leaf protocols */
XDP2_MAKE_LEAF_PARSE_NODE(profinet_node, xdp2_parse_profinet, ());
XDP2_MAKE_LEAF_PARSE_NODE(aoe_node, xdp2_parse_aoe, ());
XDP2_MAKE_LEAF_PARSE_NODE(ncsi_node, xdp2_parse_ncsi, ());
XDP2_MAKE_LEAF_PARSE_NODE(can_node, xdp2_parse_can, ());
XDP2_MAKE_LEAF_PARSE_NODE(canfd_node, xdp2_parse_canfd, ());
XDP2_MAKE_LEAF_PARSE_NODE(canxl_node, xdp2_parse_canxl, ());
XDP2_MAKE_LEAF_PARSE_NODE(phonet_node, xdp2_parse_phonet, ());
XDP2_MAKE_LEAF_PARSE_NODE(ieee802154_node, xdp2_parse_ieee802154, ());
XDP2_MAKE_LEAF_PARSE_NODE(atm_mpoa_node, xdp2_parse_atm, ());
XDP2_MAKE_LEAF_PARSE_NODE(ipx_node, xdp2_parse_ipx, ());
XDP2_MAKE_LEAF_PARSE_NODE(atalk_node, xdp2_parse_atalk, ());
XDP2_MAKE_LEAF_PARSE_NODE(x25_node, xdp2_parse_x25, ());
XDP2_MAKE_LEAF_PARSE_NODE(dsa_node, xdp2_parse_dsa, ());
XDP2_MAKE_PARSE_NODE(edsa_node, xdp2_parse_edsa, ether_table, ());

/* Ethertype dispatch node (L2 parser root) */
XDP2_MAKE_PARSE_NODE(etype_dispatch_node, etype_dispatch_def,
		     etype_table, ());
