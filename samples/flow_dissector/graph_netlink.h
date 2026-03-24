/* graph_netlink.h — Netlink parse graph
 *
 * Root: netlink_node — dispatches on nlmsg_type.
 * Known types (NOOP, ERROR, DONE) → leaf; others → table miss → stop.
 */

XDP2_MAKE_LEAF_PARSE_NODE(netlink_leaf_node, xdp2_parse_genetlink, ());
XDP2_MAKE_PARSE_NODE(netlink_node, xdp2_parse_netlink,
		     netlink_table, ());

XDP2_MAKE_PROTO_TABLE(netlink_table,
		      ( NLMSG_NOOP, netlink_leaf_node ),
		      ( NLMSG_ERROR, netlink_leaf_node ),
		      ( NLMSG_DONE, netlink_leaf_node )
);
