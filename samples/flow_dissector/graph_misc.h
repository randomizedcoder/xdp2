/* graph_misc.h — Miscellaneous non-Ethernet parse graph nodes
 *
 * Simple leaf nodes for: X.25, MCTP, ATM.
 * CAN, 802.15.4, and Phonet nodes are defined in flow_dissector_nodes_l2.h
 * (they're shared between Ethernet ethertype dispatch and standalone parsers).
 */

/* X.25: packet type dispatch (leaf for now) */
XDP2_MAKE_LEAF_PARSE_NODE(x25_pkt_node, xdp2_parse_x25, ());

/* MCTP (standalone graph root) */
XDP2_MAKE_LEAF_PARSE_NODE(mctp_node, xdp2_parse_mctp, ());

/* ATM (standalone graph root) */
XDP2_MAKE_LEAF_PARSE_NODE(atm_node, xdp2_parse_atm, ());
