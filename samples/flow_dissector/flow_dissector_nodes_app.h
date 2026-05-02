/* flow_dissector_nodes_app.h — Application-layer parse nodes (userspace only)
 *
 * ~90 leaf nodes for application-layer protocols dispatched via TCP/UDP
 * dport tables and IP protocol tables (userspace only — excluded from
 * BPF builds). Plus tunnel/encap nodes with inner dispatch tables.
 *
 * The #ifndef XDP2_XDP_BUILD guard is in parser.c, not in this file.
 */

/* ============================================================
 * IP protocol leaf nodes (OSPF, EIGRP, VRRP, PIM, etc.)
 * Reached via ipv4_table / ipv6_table entries.
 * ============================================================ */

XDP2_MAKE_LEAF_PARSE_NODE(ospf_node, xdp2_parse_ospf, ());
XDP2_MAKE_LEAF_PARSE_NODE(ospfv3_node, xdp2_parse_ospfv3, ());
XDP2_MAKE_LEAF_PARSE_NODE(eigrp_node, xdp2_parse_eigrp, ());
XDP2_MAKE_LEAF_PARSE_NODE(vrrp_node, xdp2_parse_vrrp, ());
XDP2_MAKE_LEAF_PARSE_NODE(vrrp3_node, xdp2_parse_vrrp3, ());
XDP2_MAKE_LEAF_PARSE_NODE(pim_node, xdp2_parse_pim, ());
XDP2_MAKE_LEAF_PARSE_NODE(rsvp_node, xdp2_parse_rsvp, ());
XDP2_MAKE_LEAF_PARSE_NODE(ipcomp_node, xdp2_parse_ipcomp, ());
XDP2_MAKE_LEAF_PARSE_NODE(pgm_node, xdp2_parse_pgm, ());
XDP2_MAKE_LEAF_PARSE_NODE(carp_node, xdp2_parse_carp, ());
XDP2_MAKE_LEAF_PARSE_NODE(etherip_node, xdp2_parse_etherip, ());

/* ============================================================
 * TCP dport leaf nodes
 * Reached via tcp_app_table entries.
 * ============================================================ */

/* DNS over TCP (port 53) */
XDP2_MAKE_LEAF_PARSE_NODE(dns_tcp_node, xdp2_parse_dns, ());

/* HTTP (port 80) */
XDP2_MAKE_LEAF_PARSE_NODE(http_node, xdp2_parse_http, ());

/* HTTP/2 (port 8080) */
XDP2_MAKE_LEAF_PARSE_NODE(http2_node, xdp2_parse_http2, ());

/* TLS (port 443) */
XDP2_MAKE_LEAF_PARSE_NODE(tls_node, xdp2_parse_tls, ());

/* SSH (port 22) */
XDP2_MAKE_LEAF_PARSE_NODE(ssh_node, xdp2_parse_ssh, ());

/* BGP (port 179) */
XDP2_MAKE_LEAF_PARSE_NODE(bgp_node, xdp2_parse_bgp, ());

/* SMTP (port 25) */
XDP2_MAKE_LEAF_PARSE_NODE(smtp_node, xdp2_parse_smtp, ());

/* FTP (port 21) */
XDP2_MAKE_LEAF_PARSE_NODE(ftp_node, xdp2_parse_ftp, ());

/* Telnet (port 23) */
XDP2_MAKE_LEAF_PARSE_NODE(telnet_node, xdp2_parse_telnet, ());

/* IMAP (port 143) */
XDP2_MAKE_LEAF_PARSE_NODE(imap_node, xdp2_parse_imap, ());

/* LDAP (port 389) */
XDP2_MAKE_LEAF_PARSE_NODE(ldap_node, xdp2_parse_ldap, ());

/* LDP (port 646) */
XDP2_MAKE_LEAF_PARSE_NODE(ldp_node, xdp2_parse_ldp, ());

/* Redis (port 6379) */
XDP2_MAKE_LEAF_PARSE_NODE(redis_node, xdp2_parse_redis, ());

/* Kafka (port 9092) */
XDP2_MAKE_LEAF_PARSE_NODE(kafka_node, xdp2_parse_kafka, ());

/* MQTT (port 1883) */
XDP2_MAKE_LEAF_PARSE_NODE(mqtt_node, xdp2_parse_mqtt, ());

/* AMQP (port 5672) */
XDP2_MAKE_LEAF_PARSE_NODE(amqp_node, xdp2_parse_amqp, ());

/* Modbus/TCP (port 502) */
XDP2_MAKE_LEAF_PARSE_NODE(modbus_tcp_node, xdp2_parse_modbus_tcp, ());

/* SMB (port 445) */
XDP2_MAKE_LEAF_PARSE_NODE(smb_node, xdp2_parse_smb, ());

/* SMB2 (port 445 — same port, detected by negotiate) */
XDP2_MAKE_LEAF_PARSE_NODE(smb2_node, xdp2_parse_smb2, ());

/* NFS (port 2049) */
XDP2_MAKE_LEAF_PARSE_NODE(nfs_node, xdp2_parse_nfs, ());

/* ONC-RPC (port 111) */
XDP2_MAKE_LEAF_PARSE_NODE(onc_rpc_node, xdp2_parse_onc_rpc, ());

/* Memcached (port 11211) */
XDP2_MAKE_LEAF_PARSE_NODE(memcache_node, xdp2_parse_memcache, ());

/* OpenFlow (port 6653) */
XDP2_MAKE_LEAF_PARSE_NODE(openflow_node, xdp2_parse_openflow, ());

/* Diameter (port 3868) */
XDP2_MAKE_LEAF_PARSE_NODE(diameter_node, xdp2_parse_diameter, ());

/* RTSP (port 554) */
XDP2_MAKE_LEAF_PARSE_NODE(rtsp_node, xdp2_parse_rtsp, ());

/* Skinny/SCCP (port 2000) */
XDP2_MAKE_LEAF_PARSE_NODE(skinny_node, xdp2_parse_skinny, ());

/* PPTP (port 1723) */
XDP2_MAKE_LEAF_PARSE_NODE(pptp_node, xdp2_parse_pptp, ());

/* OPC-UA (port 4840) */
XDP2_MAKE_LEAF_PARSE_NODE(opc_ua_node, xdp2_parse_opc_ua, ());

/* DNP3 (port 20000) */
XDP2_MAKE_LEAF_PARSE_NODE(dnp3_node, xdp2_parse_dnp3, ());

/* EtherNet/IP CIP (port 44818) */
XDP2_MAKE_LEAF_PARSE_NODE(enip_node, xdp2_parse_enip, ());

/* Kerberos (port 88) */
XDP2_MAKE_LEAF_PARSE_NODE(kerberos_node, xdp2_parse_kerberos, ());

/* TACACS+ (port 49) */
XDP2_MAKE_LEAF_PARSE_NODE(tacacs_node, xdp2_parse_tacacs, ());

/* ZeroMQ (port 5555) */
XDP2_MAKE_LEAF_PARSE_NODE(zeromq_node, xdp2_parse_zeromq, ());

/* IKEv2 over TCP (port 4500) */
XDP2_MAKE_LEAF_PARSE_NODE(ikev2_tcp_node, xdp2_parse_ikev2, ());

/* MSDP (port 639) */
XDP2_MAKE_LEAF_PARSE_NODE(msdp_node, xdp2_parse_msdp, ());

/* ============================================================
 * UDP dport leaf nodes
 * Reached via udp_tunnel_table entries (userspace extension).
 * ============================================================ */

/* DNS (port 53) */
XDP2_MAKE_LEAF_PARSE_NODE(dns_udp_node, xdp2_parse_dns, ());

/* DHCP (port 67/68) */
XDP2_MAKE_LEAF_PARSE_NODE(dhcp_node, xdp2_parse_dhcp, ());

/* DHCPv6 (port 546/547) */
XDP2_MAKE_LEAF_PARSE_NODE(dhcpv6_node, xdp2_parse_dhcpv6, ());

/* NTP (port 123) */
XDP2_MAKE_LEAF_PARSE_NODE(ntp_node, xdp2_parse_ntp, ());

/* SNMP (port 161/162) */
XDP2_MAKE_LEAF_PARSE_NODE(snmp_node, xdp2_parse_snmp, ());

/* TFTP (port 69) */
XDP2_MAKE_LEAF_PARSE_NODE(tftp_node, xdp2_parse_tftp, ());

/* Syslog (port 514) */
XDP2_MAKE_LEAF_PARSE_NODE(syslog_node, xdp2_parse_syslog, ());

/* RIP (port 520) */
XDP2_MAKE_LEAF_PARSE_NODE(rip_node, xdp2_parse_rip, ());

/* RIPng (port 521) */
XDP2_MAKE_LEAF_PARSE_NODE(ripng_node, xdp2_parse_ripng, ());

/* RADIUS (port 1812/1813) */
XDP2_MAKE_LEAF_PARSE_NODE(radius_node, xdp2_parse_radius, ());

/* BFD (port 3784) */
XDP2_MAKE_LEAF_PARSE_NODE(bfd_node, xdp2_parse_bfd, ());

/* STUN (port 3478) */
XDP2_MAKE_LEAF_PARSE_NODE(stun_node, xdp2_parse_stun, ());

/* SIP (port 5060) */
XDP2_MAKE_LEAF_PARSE_NODE(sip_node, xdp2_parse_sip, ());

/* RTP (port 5004) */
XDP2_MAKE_LEAF_PARSE_NODE(rtp_node, xdp2_parse_rtp, ());

/* RTCP (port 5005) */
XDP2_MAKE_LEAF_PARSE_NODE(rtcp_node, xdp2_parse_rtcp, ());

/* CoAP (port 5683) */
XDP2_MAKE_LEAF_PARSE_NODE(coap_node, xdp2_parse_coap, ());

/* sFlow (port 6343) */
XDP2_MAKE_LEAF_PARSE_NODE(sflow_node, xdp2_parse_sflow, ());

/* CFLOW (port 2055) */
XDP2_MAKE_LEAF_PARSE_NODE(cflow_node, xdp2_parse_cflow, ());

/* NetFlow v5 — shares CFLOW port, separate node for completeness */
XDP2_MAKE_LEAF_PARSE_NODE(netflow_v5_node, xdp2_parse_netflow_v5, ());

/* NetFlow v9 (port 2055 — same as CFLOW) */
XDP2_MAKE_LEAF_PARSE_NODE(netflow_v9_node, xdp2_parse_netflow_v9, ());

/* IPFIX (port 4739) */
XDP2_MAKE_LEAF_PARSE_NODE(ipfix_node, xdp2_parse_ipfix, ());

/* HSRP (port 1985) */
XDP2_MAKE_LEAF_PARSE_NODE(hsrp_node, xdp2_parse_hsrp, ());

/* GLBP (port 3222) */
XDP2_MAKE_LEAF_PARSE_NODE(glbp_node, xdp2_parse_glbp, ());

/* NBNS (port 137) */
XDP2_MAKE_LEAF_PARSE_NODE(nbns_node, xdp2_parse_nbns, ());

/* mDNS (port 5353) */
XDP2_MAKE_LEAF_PARSE_NODE(mdns_node, xdp2_parse_mdns, ());

/* LLMNR (port 5355) */
XDP2_MAKE_LEAF_PARSE_NODE(llmnr_node, xdp2_parse_llmnr, ());

/* MGCP (port 2427) */
XDP2_MAKE_LEAF_PARSE_NODE(mgcp_node, xdp2_parse_mgcp, ());

/* TWAMP (port 862) */
XDP2_MAKE_LEAF_PARSE_NODE(twamp_node, xdp2_parse_twamp, ());

/* PFCP (port 8805) */
XDP2_MAKE_LEAF_PARSE_NODE(pfcp_node, xdp2_parse_pfcp, ());

/* WireGuard (port 51820) */
XDP2_MAKE_LEAF_PARSE_NODE(wireguard_node, xdp2_parse_wireguard, ());

/* DTLS (port 4433) */
XDP2_MAKE_LEAF_PARSE_NODE(dtls_node, xdp2_parse_dtls, ());

/* IKEv2 (port 500/4500) */
XDP2_MAKE_LEAF_PARSE_NODE(ikev2_node, xdp2_parse_ikev2, ());

/* QUIC (port 443) */
XDP2_MAKE_LEAF_PARSE_NODE(quic_node, xdp2_parse_quic, ());

/* WOL (port 9 — also via ethertype) */
XDP2_MAKE_LEAF_PARSE_NODE(wol_udp_node, xdp2_parse_wol, ());

/* BACnet (port 47808) */
XDP2_MAKE_LEAF_PARSE_NODE(bacnet_node, xdp2_parse_bacnet, ());

/* SRT (port 1935) */
XDP2_MAKE_LEAF_PARSE_NODE(srt_node, xdp2_parse_srt, ());

/* MPEG-TS (port 1234) */
XDP2_MAKE_LEAF_PARSE_NODE(mpeg_ts_node, xdp2_parse_mpeg_ts, ());

/* ============================================================
 * Tunnel/encap nodes with inner dispatch tables
 * ============================================================ */

/* GTP-U (UDP 2152) → inner IP dispatch by version nibble */
XDP2_MAKE_PARSE_NODE(gtpu_node, xdp2_parse_gtpu, gtpu_inner_table, ());

/* GTP-C (UDP 2123) — leaf */
XDP2_MAKE_LEAF_PARSE_NODE(gtpc_node, xdp2_parse_gtpc, ());

/* GTPv2-C (UDP 2123 — same port as GTP-C v1) — leaf */
XDP2_MAKE_LEAF_PARSE_NODE(gtpv2c_node, xdp2_parse_gtpv2_c, ());

/* VXLAN-GPE (UDP 4790) → inner dispatch by next_protocol */
XDP2_MAKE_PARSE_NODE(vxlan_gpe_node, xdp2_parse_vxlan_gpe,
		     vxlan_gpe_inner_table, ());

/* Teredo (UDP 3544) → always IPv6 inner */
XDP2_MAKE_PARSE_NODE(teredo_node, xdp2_parse_teredo,
		     teredo_inner_table, ());

/* LISP (UDP 4341) → inner IP dispatch by version nibble */
XDP2_MAKE_PARSE_NODE(lisp_node, xdp2_parse_lisp, lisp_inner_table, ());

/* CAPWAP data (UDP 5247) → inner Ethernet */
XDP2_MAKE_PARSE_NODE(capwap_node, xdp2_parse_capwap,
		     capwap_inner_table, ());

/* GUE (UDP 6080) → inner IP dispatch by proto_ctype */
XDP2_MAKE_PARSE_NODE(gue_node, xdp2_parse_gue, gue_inner_table, ());

/* STT (TCP 7471) → inner Ethernet */
XDP2_MAKE_PARSE_NODE(stt_node, xdp2_parse_stt, stt_inner_table, ());

/* TZSP (UDP 37008) → dispatch by encap_proto */
XDP2_MAKE_PARSE_NODE(tzsp_node, xdp2_parse_tzsp, tzsp_inner_table, ());

/* ============================================================
 * Ethertype leaf nodes (IEC, HomePlug, LLTD, WOL)
 * ============================================================ */

/* IEC-GOOSE (ethertype 0x88B8) */
XDP2_MAKE_LEAF_PARSE_NODE(iec_goose_node, xdp2_parse_iec_goose, ());

/* IEC-SV (ethertype 0x88BA) */
XDP2_MAKE_LEAF_PARSE_NODE(iec_sv_node, xdp2_parse_iec_sv, ());

/* HomePlug-AV (ethertype 0x88E1) */
XDP2_MAKE_LEAF_PARSE_NODE(homeplug_av_node, xdp2_parse_homeplug_av, ());

/* LLTD (ethertype 0x893A) */
XDP2_MAKE_LEAF_PARSE_NODE(lltd_node, xdp2_parse_lltd, ());

/* WOL (ethertype 0x0842) */
XDP2_MAKE_LEAF_PARSE_NODE(wol_node, xdp2_parse_wol, ());

/* LLDP-MED (leaf — shares LLDP ethertype but separate node identity) */
XDP2_MAKE_LEAF_PARSE_NODE(lldp_med_node, xdp2_parse_lldp_med, ());

/* Diameter-S6a (TCP 3868 — shares Diameter port) */
XDP2_MAKE_LEAF_PARSE_NODE(diameter_s6a_node, xdp2_parse_diameter_s6a, ());
