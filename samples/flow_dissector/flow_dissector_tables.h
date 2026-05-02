/* flow_dissector_tables.h — Protocol dispatch tables
 *
 * All XDP2_MAKE_PROTO_TABLE and XDP2_MAKE_FLAG_FIELDS_TABLE definitions.
 * Contains CORE_ENTRIES macros for shared BPF/userspace table entries,
 * with #ifdef XDP2_XDP_BUILD conditionals for reduced BPF tables.
 */

XDP2_MAKE_PROTO_TABLE(ip_check_table,
		      ( 4, ipv4_node ),
		      ( 6, ipv6_node )
);

/* Core IPv4 protocol entries shared by BPF and userspace */
#define IPV4_TABLE_CORE_ENTRIES					\
		      ( IPPROTO_TCP, tcp_node ),		\
		      ( IPPROTO_UDP, udp_node ),		\
		      ( IPPROTO_UDPLITE, ports_node ),		\
		      ( IPPROTO_SCTP, ports_node ),		\
		      ( IPPROTO_DCCP, ports_node ),		\
		      ( IPPROTO_ICMP, icmpv4_node ),		\
		      ( IPPROTO_IGMP, igmp_node ),		\
		      ( IPPROTO_GRE, gre_base_node ),		\
		      ( IPPROTO_MPLS, mpls_node ),		\
		      ( IPPROTO_IPIP, ipv4ip_node ),		\
		      ( IPPROTO_IPV6, ipv6ip_node ),		\
		      ( IPPROTO_ESP, esp_node ),		\
		      ( IPPROTO_AH, ah_ipv4_node ),		\
		      ( IPPROTO_L2TP, l2tp_node )

#ifdef XDP2_XDP_BUILD
XDP2_MAKE_PROTO_TABLE(ipv4_table, IPV4_TABLE_CORE_ENTRIES);
#else
XDP2_MAKE_PROTO_TABLE(ipv4_table,
		      IPV4_TABLE_CORE_ENTRIES,
		      ( IPPROTO_OSPF, ospf_node ),
		      ( IPPROTO_EIGRP, eigrp_node ),
		      ( IPPROTO_VRRP, vrrp_node ),
		      ( IPPROTO_PIM, pim_node ),
		      ( IPPROTO_RSVP, rsvp_node ),
		      ( IPPROTO_COMP, ipcomp_node ),
		      ( IPPROTO_PGM, pgm_node ),
		      ( IPPROTO_ETHERIP, etherip_node )
);
#endif

/* Core IPv6 protocol entries shared by BPF and userspace */
#define IPV6_TABLE_CORE_ENTRIES					\
		      ( IPPROTO_TCP, tcp_node ),		\
		      ( IPPROTO_UDP, udp_node ),		\
		      ( IPPROTO_UDPLITE, ports_node ),		\
		      ( IPPROTO_SCTP, ports_node ),		\
		      ( IPPROTO_DCCP, ports_node ),		\
		      ( IPPROTO_ICMPV6, icmpv6_node ),		\
		      ( IPPROTO_HOPOPTS, ipv6_eh_node ),	\
		      ( IPPROTO_DSTOPTS, ipv6_eh_node ),	\
		      ( IPPROTO_ROUTING, ipv6_eh_node ),	\
		      ( IPPROTO_FRAGMENT, ipv6_frag_node ),	\
		      ( IPPROTO_GRE, gre_base_node ),		\
		      ( IPPROTO_MPLS, mpls_node ),		\
		      ( IPPROTO_IPIP, ipv4ip_node ),		\
		      ( IPPROTO_IPV6, ipv6ip_node ),		\
		      ( IPPROTO_ESP, esp_node ),		\
		      ( IPPROTO_AH, ah_ipv6_node ),		\
		      ( IPPROTO_L2TP, l2tp_node )

#ifdef XDP2_XDP_BUILD
XDP2_MAKE_PROTO_TABLE(ipv6_table, IPV6_TABLE_CORE_ENTRIES);
#else
XDP2_MAKE_PROTO_TABLE(ipv6_table,
		      IPV6_TABLE_CORE_ENTRIES,
		      ( IPPROTO_OSPF, ospfv3_node ),
		      ( IPPROTO_EIGRP, eigrp_node ),
		      ( IPPROTO_VRRP, vrrp3_node ),
		      ( IPPROTO_PIM, pim_node ),
		      ( IPPROTO_RSVP, rsvp_node ),
		      ( IPPROTO_COMP, ipcomp_node ),
		      ( IPPROTO_PGM, pgm_node )
);
#endif

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

/* UDP tunnel/app dispatch: known dports → inner parsing or app leaf,
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
		      ( __cpu_to_be16(4791), ib_bth_node ),	/* RoCE v2 */
		      /* Tunnel/encap protocols */
		      ( __cpu_to_be16(2152), gtpu_node ),	/* GTP-U */
		      ( __cpu_to_be16(2123), gtpv2c_node ),	/* GTPv2-C */
		      ( __cpu_to_be16(4790), vxlan_gpe_node ),	/* VXLAN-GPE */
		      ( __cpu_to_be16(3544), teredo_node ),	/* Teredo */
		      ( __cpu_to_be16(4341), lisp_node ),	/* LISP */
		      ( __cpu_to_be16(5247), capwap_node ),	/* CAPWAP data */
		      ( __cpu_to_be16(6080), gue_node ),	/* GUE */
		      ( __cpu_to_be16(37008), tzsp_node ),	/* TZSP */
		      /* DNS / naming */
		      ( __cpu_to_be16(53), dns_udp_node ),	/* DNS */
		      ( __cpu_to_be16(137), nbns_node ),	/* NBNS */
		      ( __cpu_to_be16(5353), mdns_node ),	/* mDNS */
		      ( __cpu_to_be16(5355), llmnr_node ),	/* LLMNR */
		      /* DHCP */
		      ( __cpu_to_be16(67), dhcp_node ),		/* DHCP server */
		      ( __cpu_to_be16(68), dhcp_node ),		/* DHCP client */
		      ( __cpu_to_be16(546), dhcpv6_node ),	/* DHCPv6 client */
		      ( __cpu_to_be16(547), dhcpv6_node ),	/* DHCPv6 server */
		      /* Network management */
		      ( __cpu_to_be16(123), ntp_node ),		/* NTP */
		      ( __cpu_to_be16(161), snmp_node ),	/* SNMP */
		      ( __cpu_to_be16(162), snmp_node ),	/* SNMP trap */
		      ( __cpu_to_be16(69), tftp_node ),		/* TFTP */
		      ( __cpu_to_be16(514), syslog_node ),	/* Syslog */
		      /* Routing */
		      ( __cpu_to_be16(520), rip_node ),		/* RIP */
		      ( __cpu_to_be16(521), ripng_node ),	/* RIPng */
		      /* Security */
		      ( __cpu_to_be16(500), ikev2_node ),	/* IKEv2 */
		      ( __cpu_to_be16(4500), ikev2_node ),	/* IKEv2 NAT-T */
		      ( __cpu_to_be16(51820), wireguard_node ),	/* WireGuard */
		      ( __cpu_to_be16(4433), dtls_node ),	/* DTLS */
		      /* AAA */
		      ( __cpu_to_be16(1812), radius_node ),	/* RADIUS auth */
		      ( __cpu_to_be16(1813), radius_node ),	/* RADIUS acct */
		      /* Redundancy / failover */
		      ( __cpu_to_be16(1985), hsrp_node ),	/* HSRP */
		      ( __cpu_to_be16(3222), glbp_node ),	/* GLBP */
		      /* VoIP / media */
		      ( __cpu_to_be16(5060), sip_node ),	/* SIP */
		      ( __cpu_to_be16(5004), rtp_node ),	/* RTP */
		      ( __cpu_to_be16(5005), rtcp_node ),	/* RTCP */
		      ( __cpu_to_be16(2427), mgcp_node ),	/* MGCP */
		      /* IoT / constrained */
		      ( __cpu_to_be16(5683), coap_node ),	/* CoAP */
		      /* Testing / measurement */
		      ( __cpu_to_be16(3784), bfd_node ),	/* BFD */
		      ( __cpu_to_be16(3478), stun_node ),	/* STUN */
		      ( __cpu_to_be16(862), twamp_node ),	/* TWAMP */
		      /* Telco */
		      ( __cpu_to_be16(8805), pfcp_node ),	/* PFCP */
		      /* Flow telemetry */
		      ( __cpu_to_be16(6343), sflow_node ),	/* sFlow */
		      ( __cpu_to_be16(2055), cflow_node ),	/* CFLOW/NetFlow */
		      ( __cpu_to_be16(4739), ipfix_node ),	/* IPFIX */
		      /* Transport */
		      ( __cpu_to_be16(443), quic_node ),	/* QUIC */
		      /* Misc */
		      ( __cpu_to_be16(9), wol_udp_node ),	/* WOL */
		      ( __cpu_to_be16(47808), bacnet_node ),	/* BACnet */
		      ( __cpu_to_be16(1935), srt_node ),	/* SRT */
		      ( __cpu_to_be16(1234), mpeg_ts_node )	/* MPEG-TS */
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

/* FC type dispatch: FC frame type → sub-protocol leaf */
XDP2_MAKE_PROTO_TABLE(fc_type_table,
		      ( FC_TYPE_ELS, fc_els_node ),
		      ( FC_TYPE_FCP, fc_fcp_node ),
		      ( FC_TYPE_CT, fc_ct_node )
);

/* TCP application dispatch: known dports → app-layer protocol,
 * unknown dports → table miss → XDP2_STOP_UNKNOWN_PROTO (ports extracted)
 */
#define TCP_APP_TABLE_CORE_ENTRIES				\
		      ( __cpu_to_be16(3260), iscsi_node ),	\
		      ( __cpu_to_be16(NVME_TCP_PORT), nvme_tcp_node )

#ifdef XDP2_XDP_BUILD
XDP2_MAKE_PROTO_TABLE(tcp_app_table, TCP_APP_TABLE_CORE_ENTRIES);
#else
XDP2_MAKE_PROTO_TABLE(tcp_app_table,
		      TCP_APP_TABLE_CORE_ENTRIES,
		      /* Tunnel (TCP-based) */
		      ( __cpu_to_be16(7471), stt_node ),	/* STT */
		      /* DNS */
		      ( __cpu_to_be16(53), dns_tcp_node ),	/* DNS/TCP */
		      /* Web */
		      ( __cpu_to_be16(80), http_node ),		/* HTTP */
		      ( __cpu_to_be16(443), tls_node ),		/* TLS/HTTPS */
		      ( __cpu_to_be16(8080), http2_node ),	/* HTTP/2 */
		      /* Remote access */
		      ( __cpu_to_be16(22), ssh_node ),		/* SSH */
		      ( __cpu_to_be16(23), telnet_node ),	/* Telnet */
		      ( __cpu_to_be16(21), ftp_node ),		/* FTP */
		      /* Mail */
		      ( __cpu_to_be16(25), smtp_node ),		/* SMTP */
		      ( __cpu_to_be16(143), imap_node ),	/* IMAP */
		      /* Routing */
		      ( __cpu_to_be16(179), bgp_node ),		/* BGP */
		      ( __cpu_to_be16(646), ldp_node ),		/* LDP */
		      ( __cpu_to_be16(639), msdp_node ),	/* MSDP */
		      /* Directory / AAA */
		      ( __cpu_to_be16(389), ldap_node ),	/* LDAP */
		      ( __cpu_to_be16(88), kerberos_node ),	/* Kerberos */
		      ( __cpu_to_be16(49), tacacs_node ),	/* TACACS+ */
		      /* RPC / file sharing */
		      ( __cpu_to_be16(111), onc_rpc_node ),	/* ONC-RPC */
		      ( __cpu_to_be16(2049), nfs_node ),	/* NFS */
		      ( __cpu_to_be16(445), smb_node ),		/* SMB */
		      /* Message queues */
		      ( __cpu_to_be16(6379), redis_node ),	/* Redis */
		      ( __cpu_to_be16(9092), kafka_node ),	/* Kafka */
		      ( __cpu_to_be16(1883), mqtt_node ),	/* MQTT */
		      ( __cpu_to_be16(5672), amqp_node ),	/* AMQP */
		      ( __cpu_to_be16(11211), memcache_node ),	/* Memcached */
		      ( __cpu_to_be16(5555), zeromq_node ),	/* ZeroMQ */
		      /* Industrial */
		      ( __cpu_to_be16(502), modbus_tcp_node ),	/* Modbus/TCP */
		      ( __cpu_to_be16(20000), dnp3_node ),	/* DNP3 */
		      ( __cpu_to_be16(44818), enip_node ),	/* EtherNet/IP */
		      ( __cpu_to_be16(4840), opc_ua_node ),	/* OPC-UA */
		      /* Telecom / VoIP */
		      ( __cpu_to_be16(3868), diameter_node ),	/* Diameter */
		      ( __cpu_to_be16(554), rtsp_node ),	/* RTSP */
		      ( __cpu_to_be16(2000), skinny_node ),	/* Skinny/SCCP */
		      ( __cpu_to_be16(1723), pptp_node ),	/* PPTP */
		      /* SDN */
		      ( __cpu_to_be16(6653), openflow_node ),	/* OpenFlow */
		      /* Security */
		      ( __cpu_to_be16(4500), ikev2_tcp_node )	/* IKEv2/TCP */
);
#endif

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
		      ( __cpu_to_be16(ETH_P_EDSA), edsa_node ),
		      ( __cpu_to_be16(ETH_P_IEC61850_GOOSE), iec_goose_node ),
		      ( __cpu_to_be16(ETH_P_IEC61850_SV), iec_sv_node ),
		      ( __cpu_to_be16(ETH_P_HOMEPLUG_AV), homeplug_av_node ),
		      ( __cpu_to_be16(ETH_P_LLTD), lltd_node ),
		      ( __cpu_to_be16(ETH_P_WOL), wol_node )
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
		      ( __cpu_to_be16(ETH_P_EDSA), edsa_node ),
		      ( __cpu_to_be16(ETH_P_IEC61850_GOOSE), iec_goose_node ),
		      ( __cpu_to_be16(ETH_P_IEC61850_SV), iec_sv_node ),
		      ( __cpu_to_be16(ETH_P_HOMEPLUG_AV), homeplug_av_node ),
		      ( __cpu_to_be16(ETH_P_LLTD), lltd_node ),
		      ( __cpu_to_be16(ETH_P_WOL), wol_node )
);

#endif /* XDP2_XDP_BUILD */

/* ============================================================
 * Tunnel inner dispatch tables (userspace only — nodes are in
 * flow_dissector_nodes_app.h which is guarded by !XDP2_XDP_BUILD)
 * ============================================================ */

#ifndef XDP2_XDP_BUILD

/* GTP-U inner: IP version nibble → IPv4 or IPv6 */
XDP2_MAKE_PROTO_TABLE(gtpu_inner_table,
		      ( __cpu_to_be16(ETH_P_IP), ip_check_node ),
		      ( __cpu_to_be16(ETH_P_IPV6), ip_check_node )
);

/* VXLAN-GPE inner: next_protocol → IP/Ethernet/NSH */
XDP2_MAKE_PROTO_TABLE(vxlan_gpe_inner_table,
		      ( __cpu_to_be16(ETH_P_IP), ip_check_node ),
		      ( __cpu_to_be16(ETH_P_IPV6), ip_check_node ),
		      ( __cpu_to_be16(ETH_P_TEB), ether_inner_node ),
		      ( __cpu_to_be16(ETH_P_NSH), nsh_node )
);

/* Teredo inner: always IPv6 */
XDP2_MAKE_PROTO_TABLE(teredo_inner_table,
		      ( __cpu_to_be16(ETH_P_IPV6), ipv6_node )
);

/* LISP inner: IP version nibble → IPv4 or IPv6 */
XDP2_MAKE_PROTO_TABLE(lisp_inner_table,
		      ( __cpu_to_be16(ETH_P_IP), ip_check_node ),
		      ( __cpu_to_be16(ETH_P_IPV6), ip_check_node )
);

/* CAPWAP inner: always Ethernet */
XDP2_MAKE_PROTO_TABLE(capwap_inner_table,
		      ( ETH_P_TEB, ether_inner_node )
);

/* GUE inner: IP protocol number → IPv4/IPv6 dispatch */
XDP2_MAKE_PROTO_TABLE(gue_inner_table,
		      ( IPPROTO_IPIP, ipv4ip_node ),
		      ( IPPROTO_IPV6, ipv6ip_node )
);

/* STT inner: always Ethernet */
XDP2_MAKE_PROTO_TABLE(stt_inner_table,
		      ( __cpu_to_be16(ETH_P_TEB), ether_inner_node )
);

/* TZSP inner: encap_proto field (Ethernet link types) */
XDP2_MAKE_PROTO_TABLE(tzsp_inner_table,
		      ( __cpu_to_be16(ETH_P_IP), ip_check_node ),
		      ( __cpu_to_be16(ETH_P_IPV6), ip_check_node ),
		      ( __cpu_to_be16(ETH_P_TEB), ether_inner_node )
);

#endif /* !XDP2_XDP_BUILD */

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
