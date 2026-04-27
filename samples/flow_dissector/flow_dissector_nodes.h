/* flow_dissector_nodes.h — Core Ethernet/IP parse nodes
 *
 * ~40 parse nodes covering the Ethernet/IP protocol stack:
 * IPv4, IPv6, TCP/UDP/SCTP/DCCP, ICMP, GRE, VXLAN, Geneve,
 * MPLS, VLAN, PPPoE, TIPC, ESP, AH, L2TP, IP-in-IP, etc.
 */

/* IP overlay: checks version byte to dispatch IPv4 vs IPv6 */
XDP2_MAKE_PARSE_NODE(ip_check_node, xdp2_parse_ip, ip_check_table, ());

/* IPv4 and IPv6 */
XDP2_MAKE_PARSE_NODE(ipv4_node, xdp2_parse_ipv4, ipv4_table,
		     (.ops.extract_metadata = ipv4_metadata));
XDP2_MAKE_PARSE_NODE(ipv6_node, xdp2_parse_ipv6, ipv6_table,
		     (.ops.extract_metadata = ipv6_metadata));

/* IPv6 extension headers */
XDP2_MAKE_PARSE_NODE(ipv6_eh_node, xdp2_parse_ipv6_eh, ipv6_table,
		     (.ops.extract_metadata = ipv6_eh_metadata));
XDP2_MAKE_PARSE_NODE(ipv6_frag_node, xdp2_parse_ipv6_frag_eh, ipv6_table,
		     (.ops.extract_metadata = ipv6_frag_metadata));

/* Transport: ports (TCP/UDP/SCTP/DCCP) and ICMP */
XDP2_MAKE_LEAF_PARSE_NODE(ports_node, xdp2_parse_ports,
			  (.ops.extract_metadata = ports_metadata));
XDP2_MAKE_LEAF_PARSE_NODE(icmpv4_node, xdp2_parse_icmpv4,
			  (.ops.extract_metadata = icmp_metadata));
XDP2_MAKE_LEAF_PARSE_NODE(icmpv6_node, xdp2_parse_icmpv6,
			  (.ops.extract_metadata = icmp_metadata));

/* TCP with dport dispatch — extracts port metadata AND dispatches
 * on dport via tcp_app_table. Known app ports (3260→iSCSI,
 * 4420→NVMe/TCP) continue into application protocol parsing.
 * Unknown dports → XDP2_STOP_UNKNOWN_PROTO → parse stops with
 * ports already extracted (same as old leaf behavior).
 */
XDP2_MAKE_PARSE_NODE(tcp_node, tcp_dport_dispatch_def, tcp_app_table,
		     (.ops.extract_metadata = ports_metadata));

/* iSCSI (leaf — reached via TCP dport 3260) */
XDP2_MAKE_LEAF_PARSE_NODE(iscsi_node, xdp2_parse_iscsi, ());

/* NVMe/TCP (leaf — reached via TCP dport 4420) */
XDP2_MAKE_LEAF_PARSE_NODE(nvme_tcp_node, xdp2_parse_nvme_tcp, ());

/* IGMP (IPv4 only, leaf) */
XDP2_MAKE_LEAF_PARSE_NODE(igmp_node, xdp2_parse_igmp, ());

/* MPLS (leaf — matches kernel flow dissector behavior) */
XDP2_MAKE_LEAF_PARSE_NODE(mpls_node, xdp2_parse_mpls,
			  (.ops.extract_metadata = mpls_metadata));

/* ARP / RARP / TIPC (L2 leaf nodes — used via ether_table) */
XDP2_MAKE_LEAF_PARSE_NODE(arp_node, xdp2_parse_arp,
			  (.ops.extract_metadata = arp_metadata));
XDP2_MAKE_LEAF_PARSE_NODE(rarp_node, xdp2_parse_rarp,
			  (.ops.extract_metadata = arp_metadata));
XDP2_MAKE_LEAF_PARSE_NODE(tipc_node, xdp2_parse_tipc,
			  (.ops.extract_metadata = tipc_metadata));

/* PPPoE (L2 dispatch — PPP protocol to inner IP) */
XDP2_MAKE_PARSE_NODE(pppoe_node, xdp2_parse_pppoe, pppoe_table, ());

/* ESP (leaf — encrypted payload, no further parsing) */
XDP2_MAKE_LEAF_PARSE_NODE(esp_node, xdp2_parse_esp,
			  (.ops.extract_metadata = esp_metadata));

/* AH (chains to next IP protocol via ipv4_table or ipv6_table) */
XDP2_MAKE_PARSE_NODE(ah_ipv4_node, xdp2_parse_ah, ipv4_table,
		     (.ops.extract_metadata = ah_metadata));
XDP2_MAKE_PARSE_NODE(ah_ipv6_node, xdp2_parse_ah, ipv6_table,
		     (.ops.extract_metadata = ah_metadata));

/* L2TP (leaf — session_id extraction only) */
XDP2_MAKE_LEAF_PARSE_NODE(l2tp_node, l2tp_v3_session_def,
			  (.ops.extract_metadata = l2tp_metadata));

/* UDP with dport dispatch — extracts port metadata AND dispatches
 * on dport via udp_tunnel_table. Known tunnel ports (4789→VXLAN,
 * 6081→Geneve) continue into inner Ethernet. Unknown dports →
 * XDP2_STOP_UNKNOWN_PROTO → parse stops with ports already extracted
 * (same as old leaf behavior).
 */
XDP2_MAKE_PARSE_NODE(udp_node, xdp2_parse_udp, udp_tunnel_table,
		     (.ops.extract_metadata = ports_metadata));

/* VXLAN → inner Ethernet → full protocol stack */
XDP2_MAKE_PARSE_NODE(vxlan_node, xdp2_parse_vxlan, vxlan_inner_table, ());

/* Geneve → inner protocol dispatch (using simple proto_def, no TLV parsing) */
XDP2_MAKE_PARSE_NODE(geneve_node, geneve_simple_def, geneve_inner_table,
		     ());

/* Inner Ethernet (after VXLAN → ETH_P_TEB) → ether_table */
XDP2_MAKE_PARSE_NODE(ether_inner_node, xdp2_parse_ether, ether_table,
		     (.ops.extract_metadata = ether_metadata));

/* GRE */
XDP2_MAKE_PARSE_NODE(gre_base_node, xdp2_parse_gre_base,
		     gre_base_table, ());
XDP2_MAKE_FLAG_FIELDS_PARSE_NODE(gre_v0_node, xdp2_parse_gre_v0,
				 gre_v0_table, gre_v0_flag_fields_table,
				 (.ops.extract_metadata = gre_metadata), ());

/* GRE v1/PPTP — flag-fields node dispatching to PPP */
XDP2_MAKE_FLAG_FIELDS_PARSE_NODE(gre_v1_node, xdp2_parse_gre_v1,
				 pptp_inner_table, pptp_gre_flag_fields_table,
				 (.ops.extract_metadata = gre_metadata), ());

/* PPTP flag-field nodes (reuse GRE metadata extractors) */
XDP2_MAKE_FLAG_FIELD_PARSE_NODE(pptp_flag_csum_node,
				(.ops.extract_metadata =
						gre_checksum_metadata));
XDP2_MAKE_FLAG_FIELD_PARSE_NODE(pptp_flag_key_node,
				(.ops.extract_metadata =
						gre_keyid_metadata));
XDP2_MAKE_FLAG_FIELD_PARSE_NODE(pptp_flag_seq_node,
				(.ops.extract_metadata =
						gre_seq_metadata));
XDP2_MAKE_FLAG_FIELD_PARSE_NODE(pptp_flag_ack_node, ());

/* PPP dispatch node (after GRE v1 PPTP decapsulation) */
XDP2_MAKE_PARSE_NODE(ppp_node, xdp2_parse_ppp, pptp_ppp_table, ());

/* ERSPAN (leaf — carried inside GRE) */
XDP2_MAKE_LEAF_PARSE_NODE(erspan_node, xdp2_parse_erspan, ());

/* GRE v0 flag-field nodes */
XDP2_MAKE_FLAG_FIELD_PARSE_NODE(gre_flag_csum_node,
				(.ops.extract_metadata =
						gre_checksum_metadata));
XDP2_MAKE_FLAG_FIELD_PARSE_NODE(gre_flag_key_node,
				(.ops.extract_metadata =
						gre_keyid_metadata));
XDP2_MAKE_FLAG_FIELD_PARSE_NODE(gre_flag_seq_node,
				(.ops.extract_metadata =
						gre_seq_metadata));

/* IP-in-IP encapsulation */
XDP2_MAKE_AUTONEXT_PARSE_NODE(ipv4ip_node, xdp2_parse_ipv4ip,
			      ipv4_node, ());
XDP2_MAKE_AUTONEXT_PARSE_NODE(ipv6ip_node, xdp2_parse_ipv6ip,
			      ipv6_node, ());

/* VLAN */
XDP2_MAKE_PARSE_NODE(e8021Q_node, xdp2_parse_vlan, ether_table,
		     (.ops.extract_metadata = e8021Q_metadata));
XDP2_MAKE_PARSE_NODE(e8021AD_node, xdp2_parse_vlan, ether_table,
		     (.ops.extract_metadata = e8021AD_metadata));

/* FC sub-protocol leaf nodes */
XDP2_MAKE_LEAF_PARSE_NODE(fc_els_node, fc_els_leaf_def, ());
XDP2_MAKE_LEAF_PARSE_NODE(fc_fcp_node, fc_fcp_leaf_def, ());
XDP2_MAKE_LEAF_PARSE_NODE(fc_ct_node, fc_ct_leaf_def, ());

/* Fibre Channel frame dispatch (FC type → ELS/FCP/CT) */
XDP2_MAKE_PARSE_NODE(fc_node, xdp2_parse_fc, fc_type_table, ());

/* FCoE → FC frame dispatch (was leaf, now chains to FC) */
XDP2_MAKE_AUTONEXT_PARSE_NODE(fcoe_node, xdp2_parse_fcoe, fc_node, ());

/* Batman (chainable — inner Ethernet dispatch) */
XDP2_MAKE_PARSE_NODE(batman_node, xdp2_parse_batman, ether_table, ());

/* L2 management/control leaf protocols */
XDP2_MAKE_LEAF_PARSE_NODE(lldp_node, xdp2_parse_lldp, ());
XDP2_MAKE_LEAF_PARSE_NODE(slow_node, xdp2_parse_slow, ());
XDP2_MAKE_LEAF_PARSE_NODE(mac_control_node, xdp2_parse_mac_control, ());
XDP2_MAKE_LEAF_PARSE_NODE(eapol_node, xdp2_parse_eapol, ());
XDP2_MAKE_LEAF_PARSE_NODE(ptp_node, xdp2_parse_ptp, ());
XDP2_MAKE_LEAF_PARSE_NODE(mvrp_node, xdp2_parse_mvrp, ());
XDP2_MAKE_LEAF_PARSE_NODE(cfm_node, xdp2_parse_cfm, ());
XDP2_MAKE_LEAF_PARSE_NODE(fip_node, xdp2_parse_fip, ());
XDP2_MAKE_LEAF_PARSE_NODE(macsec_node, xdp2_parse_macsec, ());
XDP2_MAKE_LEAF_PARSE_NODE(ethercat_node, xdp2_parse_ethercat, ());

/* L2 chainable protocols */

/* PBB/MAC-in-MAC → inner Ethernet dispatch */
XDP2_MAKE_PARSE_NODE(pbb_node, xdp2_parse_pbb, ether_table, ());

/* TRILL → inner Ethernet dispatch */
XDP2_MAKE_PARSE_NODE(trill_node, xdp2_parse_trill, ether_table, ());

/* HSR → ethertype dispatch (ethertype in HSR tag) */
XDP2_MAKE_PARSE_NODE(hsr_node, xdp2_parse_hsr, ether_table, ());

/* NSH → IP/Ethernet/MPLS dispatch */
XDP2_MAKE_PARSE_NODE(nsh_node, xdp2_parse_nsh, nsh_inner_table, ());

/* LLC/SNAP/STP (local proto_defs) */

/* LLC dispatch on DSAP byte */
XDP2_MAKE_PARSE_NODE(llc_node, llc_dispatch_def, llc_table, ());

/* SNAP → ethertype dispatch (OUI 00:00:00 → ether_table) */
XDP2_MAKE_PARSE_NODE(snap_node, snap_dispatch_def, ether_table, ());

/* STP BPDU (leaf) */
XDP2_MAKE_LEAF_PARSE_NODE(stp_node, stp_bpdu_def, ());
