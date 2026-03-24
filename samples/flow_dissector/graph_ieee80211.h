/* graph_ieee80211.h — WiFi 802.11 parse graph
 *
 * Root: ieee80211_node — dispatches on frame_control & 0x000c.
 * Subtypes: management, control, data, extension (all leaf).
 */

XDP2_MAKE_LEAF_PARSE_NODE(ieee80211_mgmt_node,
			  xdp2_parse_ieee80211_mgmt, ());
XDP2_MAKE_LEAF_PARSE_NODE(ieee80211_data_node,
			  xdp2_parse_ieee80211_data, ());
XDP2_MAKE_LEAF_PARSE_NODE(ieee80211_ctl_node,
			  xdp2_parse_ieee80211_mgmt, ());
XDP2_MAKE_LEAF_PARSE_NODE(ieee80211_ext_node,
			  xdp2_parse_ieee80211_mgmt, ());
XDP2_MAKE_PARSE_NODE(ieee80211_node, xdp2_parse_ieee80211,
		     ieee80211_table, ());

XDP2_MAKE_PROTO_TABLE(ieee80211_table,
		      ( IEEE80211_FTYPE_MGMT, ieee80211_mgmt_node ),
		      ( IEEE80211_FTYPE_CTL, ieee80211_ctl_node ),
		      ( IEEE80211_FTYPE_DATA, ieee80211_data_node ),
		      ( IEEE80211_FTYPE_EXT, ieee80211_ext_node )
);
