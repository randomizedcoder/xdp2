/* graph_infiniband.h — InfiniBand parse graph
 *
 * Root: ib_lrh_node — dispatches on LNH (Link Next Header) field.
 * Also reachable via Ethernet: RoCE v1 (ETH_P_IBOE → ib_grh_node)
 * and RoCE v2 (UDP port 4791 → ib_bth_node).
 */

XDP2_MAKE_LEAF_PARSE_NODE(ib_raw_node, xdp2_parse_ib_bth, ());
XDP2_MAKE_PARSE_NODE(ib_lrh_node, xdp2_parse_ib_lrh,
		     ib_lnh_table, ());

XDP2_MAKE_PROTO_TABLE(ib_lnh_table,
		      ( IB_LNH_RAW, ib_raw_node ),
		      ( IB_LNH_IPV6, ip_check_node ),
		      ( IB_LNH_BTH, ib_bth_node ),
		      ( IB_LNH_GRH, ib_grh_node )
);
