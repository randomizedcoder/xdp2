/* flow_dissector_parsers.h — XDP2_PARSER() declarations
 *
 * 14 parsers: 1 L3 (always), 1 L2 + 12 non-Ethernet (userspace only).
 */

/* L3 parser: starts at ip_check_node (no Ethernet).
 * max_frames = 0: on encapsulation, inner metadata overwrites outer
 * metadata in the same frame — giving us the innermost flow's keys,
 * which is what a flow dissector needs.
 */
XDP2_PARSER(xdp2_parser_flow_dissector, "XDP2 BPF flow dissector",
	    ip_check_node,
	    (.metameta_size = 0,
	     .frame_size = sizeof(struct xdp2_metadata_all),
	     .max_frames = 0
	    )
);

#ifndef XDP2_XDP_BUILD

/* L2 parser: starts at etype_dispatch_node.
 * The benchmark passes data starting at the ethertype field
 * (2 bytes before L3 data). The etype_dispatch_node reads those
 * 2 bytes, advances by 2, and dispatches to the appropriate node.
 */
XDP2_PARSER(xdp2_parser_flow_dissector_l2,
	    "XDP2 flow dissector (L2)",
	    etype_dispatch_node,
	    (.metameta_size = 0,
	     .frame_size = sizeof(struct xdp2_metadata_all),
	     .max_frames = 0
	    )
);

/* ─── Non-Ethernet parse graphs ─── */

XDP2_PARSER(xdp2_parser_ieee80211, "XDP2 WiFi 802.11 parser",
	    ieee80211_node,
	    (.frame_size = sizeof(struct xdp2_metadata_all),
	     .max_frames = 0
	    )
);

XDP2_PARSER(xdp2_parser_hci, "XDP2 Bluetooth HCI parser",
	    hci_node,
	    (.frame_size = sizeof(struct xdp2_metadata_all),
	     .max_frames = 0
	    )
);

XDP2_PARSER(xdp2_parser_infiniband, "XDP2 InfiniBand parser",
	    ib_lrh_node,
	    (.frame_size = sizeof(struct xdp2_metadata_all),
	     .max_frames = 0
	    )
);

XDP2_PARSER(xdp2_parser_can, "XDP2 CAN 2.0 parser",
	    can_node,
	    (.frame_size = sizeof(struct xdp2_metadata_all),
	     .max_frames = 0
	    )
);

XDP2_PARSER(xdp2_parser_canfd, "XDP2 CAN FD parser",
	    canfd_node,
	    (.frame_size = sizeof(struct xdp2_metadata_all),
	     .max_frames = 0
	    )
);

XDP2_PARSER(xdp2_parser_canxl, "XDP2 CAN XL parser",
	    canxl_node,
	    (.frame_size = sizeof(struct xdp2_metadata_all),
	     .max_frames = 0
	    )
);

XDP2_PARSER(xdp2_parser_netlink, "XDP2 Netlink parser",
	    netlink_node,
	    (.frame_size = sizeof(struct xdp2_metadata_all),
	     .max_frames = 0
	    )
);

XDP2_PARSER(xdp2_parser_ieee802154, "XDP2 IEEE 802.15.4 parser",
	    ieee802154_node,
	    (.frame_size = sizeof(struct xdp2_metadata_all),
	     .max_frames = 0
	    )
);

XDP2_PARSER(xdp2_parser_phonet, "XDP2 Phonet (Nokia ISI) parser",
	    phonet_node,
	    (.frame_size = sizeof(struct xdp2_metadata_all),
	     .max_frames = 0
	    )
);

XDP2_PARSER(xdp2_parser_mctp, "XDP2 MCTP parser",
	    mctp_node,
	    (.frame_size = sizeof(struct xdp2_metadata_all),
	     .max_frames = 0
	    )
);

XDP2_PARSER(xdp2_parser_atm, "XDP2 ATM parser",
	    atm_node,
	    (.frame_size = sizeof(struct xdp2_metadata_all),
	     .max_frames = 0
	    )
);

XDP2_PARSER(xdp2_parser_x25, "XDP2 X.25 parser",
	    x25_pkt_node,
	    (.frame_size = sizeof(struct xdp2_metadata_all),
	     .max_frames = 0
	    )
);

#endif /* !XDP2_XDP_BUILD */
