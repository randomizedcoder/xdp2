/* graph_bluetooth.h — Bluetooth HCI parse graph
 *
 * Root: hci_node — dispatches on 1-byte packet type indicator.
 * ACL data chains to L2CAP; all others are leaf nodes.
 */

XDP2_MAKE_LEAF_PARSE_NODE(hci_cmd_node, xdp2_parse_hci_cmd, ());
XDP2_MAKE_LEAF_PARSE_NODE(hci_event_node, xdp2_parse_hci_event, ());
XDP2_MAKE_LEAF_PARSE_NODE(hci_sco_node, xdp2_parse_hci_sco, ());
XDP2_MAKE_LEAF_PARSE_NODE(hci_iso_node, xdp2_parse_hci_iso, ());
XDP2_MAKE_LEAF_PARSE_NODE(l2cap_node, xdp2_parse_l2cap, ());
XDP2_MAKE_AUTONEXT_PARSE_NODE(hci_acl_node, xdp2_parse_hci_acl,
			      l2cap_node, ());
XDP2_MAKE_PARSE_NODE(hci_node, xdp2_parse_hci, hci_table, ());

XDP2_MAKE_PROTO_TABLE(hci_table,
		      ( HCI_COMMAND_PKT, hci_cmd_node ),
		      ( HCI_ACLDATA_PKT, hci_acl_node ),
		      ( HCI_SCODATA_PKT, hci_sco_node ),
		      ( HCI_EVENT_PKT, hci_event_node ),
		      ( HCI_ISODATA_PKT, hci_iso_node )
);
