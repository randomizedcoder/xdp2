/* flow_dissector_tables.h — Protocol dispatch tables
 *
 * All XDP2_MAKE_PROTO_TABLE and XDP2_MAKE_FLAG_FIELDS_TABLE definitions.
 * Contains ETHER_TABLE_CORE_ENTRIES / UDP_TUNNEL_TABLE_CORE_ENTRIES macros
 * for shared BPF/userspace table entries, with #ifdef XDP2_XDP_BUILD
 * conditionals for reduced BPF tables.
 */

XDP2_MAKE_PROTO_TABLE(ip_check_table,
		      ( 4, ipv4_node ),
		      ( 6, ipv6_node )
);

XDP2_MAKE_PROTO_TABLE(ipv4_table,
		      ( IPPROTO_TCP, ports_node ),
		      ( IPPROTO_UDP, udp_node ),
		      ( IPPROTO_UDPLITE, ports_node ),
		      ( IPPROTO_SCTP, ports_node ),
		      ( IPPROTO_DCCP, ports_node ),
		      ( IPPROTO_ICMP, icmpv4_node ),
		      ( IPPROTO_IGMP, igmp_node ),
		      ( IPPROTO_GRE, gre_base_node ),
		      ( IPPROTO_MPLS, mpls_node ),
		      ( IPPROTO_IPIP, ipv4ip_node ),
		      ( IPPROTO_IPV6, ipv6ip_node ),
		      ( IPPROTO_ESP, esp_node ),
		      ( IPPROTO_AH, ah_ipv4_node ),
		      ( IPPROTO_L2TP, l2tp_node )
);

XDP2_MAKE_PROTO_TABLE(ipv6_table,
		      ( IPPROTO_TCP, ports_node ),
		      ( IPPROTO_UDP, udp_node ),
		      ( IPPROTO_UDPLITE, ports_node ),
		      ( IPPROTO_SCTP, ports_node ),
		      ( IPPROTO_DCCP, ports_node ),
		      ( IPPROTO_ICMPV6, icmpv6_node ),
		      ( IPPROTO_HOPOPTS, ipv6_eh_node ),
		      ( IPPROTO_DSTOPTS, ipv6_eh_node ),
		      ( IPPROTO_ROUTING, ipv6_eh_node ),
		      ( IPPROTO_FRAGMENT, ipv6_frag_node ),
		      ( IPPROTO_GRE, gre_base_node ),
		      ( IPPROTO_MPLS, mpls_node ),
		      ( IPPROTO_IPIP, ipv4ip_node ),
		      ( IPPROTO_IPV6, ipv6ip_node ),
		      ( IPPROTO_ESP, esp_node ),
		      ( IPPROTO_AH, ah_ipv6_node ),
		      ( IPPROTO_L2TP, l2tp_node )
);

XDP2_MAKE_PROTO_TABLE(gre_base_table,
		      ( 0, gre_v0_node ),
		      ( 1, gre_v1_node )
);

XDP2_MAKE_PROTO_TABLE(gre_v0_table,
		      ( __cpu_to_be16(ETH_P_IP), ip_check_node ),
		      ( __cpu_to_be16(ETH_P_IPV6), ip_check_node ),
		      ( __cpu_to_be16(ETH_P_TEB), ether_inner_node ),
		      ( __cpu_to_be16(ETH_P_MPLS_UC), mpls_node ),
		      ( __cpu_to_be16(ETH_P_MPLS_MC), mpls_node ),
		      ( __cpu_to_be16(ETH_P_ERSPAN), erspan_node ),
		      ( __cpu_to_be16(ETH_P_ERSPAN2), erspan_node )
);

/* UDP tunnel dispatch: known tunnel dports → inner parsing,
 * unknown dports → table miss → XDP2_STOP_UNKNOWN_PROTO (ports extracted)
 */
#define UDP_TUNNEL_TABLE_CORE_ENTRIES				\
		      ( __cpu_to_be16(4789), vxlan_node ),	\
		      ( __cpu_to_be16(6081), geneve_node )

#ifdef XDP2_XDP_BUILD
XDP2_MAKE_PROTO_TABLE(udp_tunnel_table, UDP_TUNNEL_TABLE_CORE_ENTRIES);
#else
XDP2_MAKE_PROTO_TABLE(udp_tunnel_table,
		      UDP_TUNNEL_TABLE_CORE_ENTRIES,
		      ( __cpu_to_be16(4791), ib_bth_node )  /* RoCE v2 */
);
#endif

/* PPPoE → PPP protocol dispatch to inner IP */
XDP2_MAKE_PROTO_TABLE(pppoe_table,
		      ( __cpu_to_be16(PPP_IP), ip_check_node ),
		      ( __cpu_to_be16(PPP_IPV6), ip_check_node ),
		      ( __cpu_to_be16(PPP_MPLS_UC), mpls_node ),
		      ( __cpu_to_be16(PPP_MPLS_MC), mpls_node )
);

/* VXLAN always returns ETH_P_TEB → inner Ethernet */
XDP2_MAKE_PROTO_TABLE(vxlan_inner_table,
		      ( __cpu_to_be16(ETH_P_TEB), ether_inner_node )
);

/* Geneve returns the inner ethertype directly; ETH_P_TEB for bridging */
XDP2_MAKE_PROTO_TABLE(geneve_inner_table,
		      ( __cpu_to_be16(ETH_P_TEB), ether_inner_node ),
		      ( __cpu_to_be16(ETH_P_IP), ip_check_node ),
		      ( __cpu_to_be16(ETH_P_IPV6), ip_check_node )
);

/* NSH inner protocol dispatch */
XDP2_MAKE_PROTO_TABLE(nsh_inner_table,
		      ( __cpu_to_be16(ETH_P_IP), ip_check_node ),
		      ( __cpu_to_be16(ETH_P_IPV6), ip_check_node ),
		      ( __cpu_to_be16(ETH_P_TEB), ether_inner_node ),
		      ( __cpu_to_be16(ETH_P_MPLS_UC), mpls_node )
);

/* LLC dispatch table: DSAP-based dispatch.
 * DSAP 0xAA = SNAP, DSAP 0x42 = STP/RSTP/MSTP.
 */
XDP2_MAKE_PROTO_TABLE(llc_table,
		      ( 0xAA, snap_node ),
		      ( 0x42, stp_node )
);

/* Ether table used by VLAN nodes and inner Ethernet to recurse back
 * into the protocol stack. XDP/BPF builds use the core entries only
 * to keep the BPF program within instruction limits.
 */

/* Core ethertype entries shared by XDP and userspace builds */
#define ETHER_TABLE_CORE_ENTRIES					\
		      ( __cpu_to_be16(ETH_P_IP), ip_check_node ),	\
		      ( __cpu_to_be16(ETH_P_IPV6), ip_check_node ),	\
		      ( __cpu_to_be16(ETH_P_8021AD), e8021AD_node ),	\
		      ( __cpu_to_be16(ETH_P_8021Q), e8021Q_node ),	\
		      ( __cpu_to_be16(ETH_P_MPLS_UC), mpls_node ),	\
		      ( __cpu_to_be16(ETH_P_MPLS_MC), mpls_node ),	\
		      ( __cpu_to_be16(ETH_P_ARP), arp_node ),		\
		      ( __cpu_to_be16(ETH_P_RARP), rarp_node ),		\
		      ( __cpu_to_be16(ETH_P_TIPC), tipc_node ),		\
		      ( __cpu_to_be16(ETH_P_PPP_SES), pppoe_node ),	\
		      ( __cpu_to_be16(ETH_P_FCOE), fcoe_node ),		\
		      ( __cpu_to_be16(ETH_P_BATMAN), batman_node ),	\
		      ( __cpu_to_be16(ETH_P_LLDP), lldp_node ),	\
		      ( __cpu_to_be16(ETH_P_SLOW), slow_node ),		\
		      ( __cpu_to_be16(ETH_P_PAUSE), mac_control_node ),	\
		      ( __cpu_to_be16(ETH_P_PAE), eapol_node ),		\
		      ( __cpu_to_be16(ETH_P_1588), ptp_node ),		\
		      ( __cpu_to_be16(ETH_P_MVRP), mvrp_node ),	\
		      ( __cpu_to_be16(ETH_P_CFM), cfm_node ),		\
		      ( __cpu_to_be16(ETH_P_FIP), fip_node ),		\
		      ( __cpu_to_be16(ETH_P_MACSEC), macsec_node ),	\
		      ( __cpu_to_be16(ETH_P_ETHERCAT), ethercat_node ),	\
		      ( __cpu_to_be16(ETH_P_8021AH), pbb_node ),	\
		      ( __cpu_to_be16(ETH_P_TRILL), trill_node ),	\
		      ( __cpu_to_be16(ETH_P_HSR), hsr_node ),		\
		      ( __cpu_to_be16(ETH_P_PRP), hsr_node ),		\
		      ( __cpu_to_be16(ETH_P_NSH), nsh_node ),		\
		      ( __cpu_to_be16(ETH_P_802_2), llc_node )

/* Extended entries for userspace builds only */
#ifdef XDP2_XDP_BUILD

XDP2_MAKE_PROTO_TABLE(ether_table, ETHER_TABLE_CORE_ENTRIES);

#else /* !XDP2_XDP_BUILD */

XDP2_MAKE_PROTO_TABLE(ether_table,
		      ETHER_TABLE_CORE_ENTRIES,
		      ( __cpu_to_be16(ETH_P_IBOE), ib_grh_node ),
		      ( __cpu_to_be16(ETH_P_PROFINET), profinet_node ),
		      ( __cpu_to_be16(ETH_P_AOE), aoe_node ),
		      ( __cpu_to_be16(ETH_P_NCSI), ncsi_node ),
		      ( __cpu_to_be16(ETH_P_CAN), can_node ),
		      ( __cpu_to_be16(ETH_P_CANFD), canfd_node ),
		      ( __cpu_to_be16(ETH_P_CANXL), canxl_node ),
		      ( __cpu_to_be16(ETH_P_PHONET), phonet_node ),
		      ( __cpu_to_be16(ETH_P_IEEE802154), ieee802154_node ),
		      ( __cpu_to_be16(ETH_P_ATMMPOA), atm_mpoa_node ),
		      ( __cpu_to_be16(ETH_P_IPX), ipx_node ),
		      ( __cpu_to_be16(ETH_P_ATALK), atalk_node ),
		      ( __cpu_to_be16(ETH_P_X25), x25_node ),
		      ( __cpu_to_be16(ETH_P_DSA), dsa_node ),
		      ( __cpu_to_be16(ETH_P_EDSA), edsa_node )
);

/* Ethertype dispatch table — same entries as ether_table so both
 * L2-entry and VLAN-recursion paths work identically.
 */
XDP2_MAKE_PROTO_TABLE(etype_table,
		      ETHER_TABLE_CORE_ENTRIES,
		      ( __cpu_to_be16(ETH_P_IBOE), ib_grh_node ),
		      ( __cpu_to_be16(ETH_P_PROFINET), profinet_node ),
		      ( __cpu_to_be16(ETH_P_AOE), aoe_node ),
		      ( __cpu_to_be16(ETH_P_NCSI), ncsi_node ),
		      ( __cpu_to_be16(ETH_P_CAN), can_node ),
		      ( __cpu_to_be16(ETH_P_CANFD), canfd_node ),
		      ( __cpu_to_be16(ETH_P_CANXL), canxl_node ),
		      ( __cpu_to_be16(ETH_P_PHONET), phonet_node ),
		      ( __cpu_to_be16(ETH_P_IEEE802154), ieee802154_node ),
		      ( __cpu_to_be16(ETH_P_ATMMPOA), atm_mpoa_node ),
		      ( __cpu_to_be16(ETH_P_IPX), ipx_node ),
		      ( __cpu_to_be16(ETH_P_ATALK), atalk_node ),
		      ( __cpu_to_be16(ETH_P_X25), x25_node ),
		      ( __cpu_to_be16(ETH_P_DSA), dsa_node ),
		      ( __cpu_to_be16(ETH_P_EDSA), edsa_node )
);

#endif /* XDP2_XDP_BUILD */

/* GRE v0 flag-fields table */
XDP2_MAKE_FLAG_FIELDS_TABLE(gre_v0_flag_fields_table,
			    ( GRE_FLAGS_CSUM_IDX, gre_flag_csum_node ),
			    ( GRE_FLAGS_KEY_IDX, gre_flag_key_node ),
			    ( GRE_FLAGS_SEQ_IDX, gre_flag_seq_node )
);

/* PPTP GRE v1 flag-fields table */
XDP2_MAKE_FLAG_FIELDS_TABLE(pptp_gre_flag_fields_table,
			    ( GRE_PPTP_FLAGS_CSUM_IDX, pptp_flag_csum_node ),
			    ( GRE_PPTP_FLAGS_KEY_IDX, pptp_flag_key_node ),
			    ( GRE_PPTP_FLAGS_SEQ_IDX, pptp_flag_seq_node ),
			    ( GRE_PPTP_FLAGS_ACK_IDX, pptp_flag_ack_node )
);

/* PPTP inner table: GRE v1 always carries PPP */
XDP2_MAKE_PROTO_TABLE(pptp_inner_table,
		      ( GRE_PROTO_PPP, ppp_node )
);

/* PPP protocol dispatch (after PPTP GRE v1 decapsulation) */
XDP2_MAKE_PROTO_TABLE(pptp_ppp_table,
		      ( __cpu_to_be16(PPP_IP), ip_check_node ),
		      ( __cpu_to_be16(PPP_IPV6), ip_check_node )
);
