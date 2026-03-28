use super::ProtocolNames;

type PN = ProtocolNames;

/// Build the complete protocol name mapping table.
pub fn protocol_table() -> Vec<ProtocolNames> {
    vec![
        // ── Layer 2 ──
        PN::new("Ethernet", 14)
            .xdp2("xdp2_parse_ether")
            .kernel("ethhdr", "linux/if_ether.h")
            .scapy("Ether")
            .tshark("eth")
            .etherparse("Ethernet2Header", "etherparse/src/link/ethernet2_header.rs"),
        PN::new("VLAN", 4)
            .xdp2("xdp2_parse_vlan")
            .kernel("vlan_hdr", "linux/if_vlan.h")
            .scapy("Dot1Q")
            .tshark("vlan")
            .etherparse("SingleVlanHeader", "etherparse/src/link/single_vlan_header.rs")
            .libpcap("vlan_tag", "pcap/vlan.h"),
        PN::new("PBB", 18)
            .xdp2("xdp2_parse_pbb")
            .scapy("PBB")
            .tshark("ieee8021ah"),
        // ── Layer 3 ──
        PN::new("IPv4", 20)
            .xdp2("xdp2_parse_ipv4")
            .kernel("iphdr", "linux/ip.h")
            .scapy("IP")
            .tshark("ip")
            .etherparse("Ipv4Header", "etherparse/src/net/ipv4_header.rs")
            .libpcap("IPv4", "gencode.c")
            .variable(),
        PN::new("IPv6", 40)
            .xdp2("xdp2_parse_ipv6")
            .kernel("ipv6hdr", "linux/ipv6.h")
            .scapy("IPv6")
            .tshark("ipv6")
            .etherparse("Ipv6Header", "etherparse/src/net/ipv6_header.rs")
            .libpcap("IPv6", "gencode.c"),
        PN::new("ARP", 8)
            .xdp2("xdp2_parse_arp")
            .kernel("arphdr", "linux/if_arp.h")
            .scapy("ARP")
            .tshark("arp")
            .etherparse("ArpPacket", "etherparse/src/net/arp_packet.rs")
            .libpcap("ARP", "gencode.c")
            .variable(),
        PN::new("RARP", 8)
            .xdp2("xdp2_parse_rarp")
            .kernel("arphdr", "linux/if_arp.h")
            .scapy("ARP")
            .tshark("rarp")
            .libpcap("RARP", "gencode.c")
            .variable(),
        PN::new("ICMPv4", 8)
            .xdp2("xdp2_parse_icmpv4")
            .kernel("icmphdr", "linux/icmp.h")
            .scapy("ICMP")
            .tshark("icmp")
            .etherparse("Icmpv4Header", "etherparse/src/transport/icmpv4_header.rs"),
        PN::new("ICMPv6", 8)
            .xdp2("xdp2_parse_icmpv6")
            .kernel("icmp6hdr", "linux/icmpv6.h")
            .scapy("ICMPv6Unknown")
            .tshark("icmpv6")
            .etherparse("Icmpv6Header", "etherparse/src/transport/icmpv6_header.rs"),
        PN::new("IGMP", 8)
            .xdp2("xdp2_parse_igmp")
            .kernel("igmphdr", "linux/igmp.h")
            .scapy("IGMP")
            .tshark("igmp")
            .etherparse("IgmpHeader", "src/proto_audit/igmp.rs")
            .libpcap("igmp_header", "pcap/proto_audit/igmp.h"),
        // ── Layer 4 ──
        PN::new("TCP", 20)
            .xdp2("xdp2_parse_tcp_notlvs")
            .kernel("tcphdr", "linux/tcp.h")
            .scapy("TCP")
            .tshark("tcp")
            .etherparse("TcpHeader", "etherparse/src/transport/tcp_header.rs")
            .libpcap("TCP", "gencode.c")
            .variable(),
        PN::new("UDP", 8)
            .xdp2("xdp2_parse_udp")
            .kernel("udphdr", "linux/udp.h")
            .scapy("UDP")
            .tshark("udp")
            .etherparse("UdpHeader", "etherparse/src/transport/udp_header.rs")
            .libpcap("UDP", "gencode.c"),
        // ── Tunneling ──
        PN::new("GRE", 4)
            .xdp2("xdp2_parse_gre")
            .kernel("gre_base_hdr", "linux/gre.h")
            .scapy("GRE")
            .tshark("gre")
            .etherparse("GreHeader", "src/proto_audit/gre.rs")
            .libpcap("gre_header", "pcap/proto_audit/gre.h")
            .variable(),
        PN::new("VXLAN", 8)
            .xdp2("xdp2_parse_vxlan")
            .kernel("vxlanhdr", "linux/vxlan.h")
            .scapy("VXLAN")
            .tshark("vxlan")
            .etherparse("VxlanHeader", "src/proto_audit/vxlan.rs")
            .libpcap("vxlan_header", "pcap/proto_audit/vxlan.h"),
        PN::new("Geneve", 8)
            .xdp2("xdp2_parse_geneve")
            .kernel("genevehdr", "linux/geneve.h")
            .scapy("GENEVE")
            .tshark("geneve")
            .etherparse("GeneveHeader", "src/proto_audit/geneve.rs")
            .libpcap("geneve_header", "pcap/proto_audit/geneve.h")
            .variable(),
        PN::new("MPLS", 4)
            .xdp2("xdp2_parse_mpls")
            .kernel("mpls_label", "linux/mpls.h")
            .scapy("MPLS")
            .tshark("mpls")
            .etherparse("MplsHeader", "src/proto_audit/mpls.rs")
            .libpcap("mpls_header", "pcap/proto_audit/mpls.h"),
        PN::new("PPP", 2)
            .xdp2("xdp2_parse_ppp")
            .kernel_header_only("linux/ppp_defs.h")
            .scapy("PPP")
            .tshark("ppp")
            .etherparse("PppHeader", "src/proto_audit/ppp.rs")
            .libpcap("ppp_header", "pcap/proto_audit/ppp.h"),
        PN::new("PPPoE", 6)
            .xdp2("xdp2_parse_pppoe")
            .kernel("pppoe_hdr", "linux/ppp_defs.h")
            .scapy("PPPoE")
            .tshark("pppoes")
            .etherparse("PppoeHeader", "src/proto_audit/pppoe.rs")
            .libpcap("pppoe_header", "pcap/proto_audit/pppoe.h"),
        PN::new("L2TP", 6)
            .xdp2("xdp2_parse_l2tp")
            .kernel("l2tp_control_hdr", "linux/l2tp.h")
            .scapy("L2TP")
            .tshark("l2tp")
            .etherparse("L2tpHeader", "src/proto_audit/l2tp.rs")
            .libpcap("l2tp_header", "pcap/proto_audit/l2tp.h")
            .variable(),
        PN::new("ERSPAN", 8)
            .xdp2("xdp2_parse_erspan")
            .kernel("erspan_base_hdr", "linux/erspan.h")
            .scapy("ERSPAN_II")
            .tshark("erspan")
            .etherparse("ErspanHeader", "src/proto_audit/erspan.rs")
            .libpcap("erspan_header", "pcap/proto_audit/erspan.h"),
        PN::new("NSH", 8)
            .xdp2("xdp2_parse_nsh")
            .kernel("nshhdr", "linux/nsh.h")
            .scapy("NSH")
            .tshark("nsh")
            .etherparse("NshHeader", "src/proto_audit/nsh.rs")
            .libpcap("nsh_header", "pcap/proto_audit/nsh.h")
            .variable(),
        PN::new("HSR", 6)
            .xdp2("xdp2_parse_hsr")
            .kernel("hsr_tag", "linux/hsr_tag.h")
            .scapy("HSRTag")
            .tshark("hsr")
            .etherparse("HsrHeader", "src/proto_audit/hsr.rs")
            .libpcap("hsr_header", "pcap/proto_audit/hsr.h"),
        // ── Security ──
        PN::new("ESP", 8)
            .xdp2("xdp2_parse_esp")
            .kernel("ip_esp_hdr", "linux/ip.h")
            .scapy("ESP")
            .tshark("esp")
            .etherparse("EspHeader", "src/proto_audit/esp.rs")
            .libpcap("esp_header", "pcap/proto_audit/esp.h")
            .variable(),
        PN::new("AH", 12)
            .xdp2("xdp2_parse_ah")
            .kernel("ip_auth_hdr", "linux/ip.h")
            .scapy("AH")
            .tshark("ah")
            .etherparse("AhHeader", "src/proto_audit/ah.rs")
            .libpcap("ah_header", "pcap/proto_audit/ah.h")
            .variable(),
        PN::new("MACsec", 8)
            .xdp2("xdp2_parse_macsec")
            .kernel("macsec_sci", "linux/if_macsec.h")
            .scapy("MACsecSCI")
            .tshark("macsec")
            .etherparse("MacsecHeader", "src/proto_audit/macsec.rs"),
        // ── Management ──
        PN::new("LLDP", 2)
            .xdp2("xdp2_parse_lldp")
            .scapy("LLDPDU")
            .tshark("lldp")
            .variable(),
        PN::new("PTP", 34)
            .xdp2("xdp2_parse_ptp")
            .kernel("ptp_header", "linux/ptp_classify.h")
            .scapy("PTP")
            .tshark("ptp")
            .etherparse("PtpHeader", "src/proto_audit/ptp.rs"),
        // ── SRv6 ──
        PN::new("SRv6", 8)
            .xdp2("xdp2_parse_srv6")
            .kernel("ipv6_sr_hdr", "linux/seg6.h")
            .scapy("IPv6ExtHdrSegmentRouting")
            .tshark("ipv6.routing.srh")
            .variable(),
        // ── Storage ──
        PN::new("AoE", 10)
            .xdp2("xdp2_parse_aoe")
            .kernel("aoe_hdr", "linux/aoe.h")
            .scapy("AOE")
            .tshark("aoe")
            .variable(),
        PN::new("FCoE", 14)
            .xdp2("xdp2_parse_fcoe")
            .kernel("fcoe_hdr", "linux/fcoe.h")
            .scapy("FCoE")
            .tshark("fcoe"),
        PN::new("EtherCAT", 2)
            .xdp2("xdp2_parse_ethercat")
            .scapy("EtherCat")
            .tshark("ecat")
            .variable(),
        // ── Wireless ──
        PN::new("IEEE802.11", 24)
            .xdp2("xdp2_parse_ieee80211")
            .kernel("ieee80211_hdr", "linux/ieee80211.h")
            .scapy("Dot11")
            .tshark("wlan")
            .variable(),
        // ── CAN bus ──
        PN::new("CAN", 16)
            .xdp2("xdp2_parse_can")
            .kernel("can_frame", "linux/can.h")
            .scapy("CAN")
            .tshark("can")
            .etherparse("CanHeader", "src/proto_audit/can.rs"),
        PN::new("CAN_FD", 72)
            .xdp2("xdp2_parse_canfd")
            .kernel("canfd_frame", "linux/can.h")
            .scapy("CANFD")
            .tshark("can")
            .etherparse("CanFdHeader", "src/proto_audit/can_fd.rs"),
        // ── Bluetooth ──
        PN::new("HCI", 1)
            .xdp2("xdp2_parse_hci")
            .kernel("hci_command_hdr", "net/bluetooth/hci.h")
            .scapy("HCI_Hdr")
            .tshark("bthci_cmd")
            .variable(),
        PN::new("L2CAP", 4)
            .xdp2("xdp2_parse_l2cap")
            .kernel("l2cap_hdr", "net/bluetooth/l2cap.h")
            .scapy("L2CAP_Hdr")
            .tshark("btl2cap")
            .variable(),
        // ── InfiniBand ──
        PN::new("IB_LRH", 8)
            .xdp2("xdp2_parse_ib_lrh")
            .scapy("IB_LRH")
            .tshark("infiniband.lrh"),
        PN::new("IB_GRH", 40)
            .xdp2("xdp2_parse_ib_grh")
            .scapy("IB_GRH")
            .tshark("infiniband.grh"),
        PN::new("IB_BTH", 12)
            .xdp2("xdp2_parse_ib_bth")
            .scapy("IB_BTH")
            .tshark("infiniband.bth"),
        // ── Netlink ──
        PN::new("Netlink", 16)
            .xdp2("xdp2_parse_netlink")
            .kernel("nlmsghdr", "linux/netlink.h")
            .scapy("NetlinkHeader")
            .tshark("netlink")
            .variable(),
        // ── Legacy ──
        PN::new("IPX", 30)
            .xdp2("xdp2_parse_ipx")
            .kernel("ipxhdr", "linux/ipx.h")
            .scapy("IPX")
            .tshark("ipx"),
        PN::new("AppleTalk", 5)
            .xdp2("xdp2_parse_atalk")
            .kernel("atalk_addr", "linux/atalk.h")
            .scapy("DDP")
            .tshark("ddp"),
        // ── IPv6 Extensions ──
        PN::new("IPv6_EH", 2)
            .xdp2("xdp2_parse_ipv6_eh")
            .kernel("ipv6_opt_hdr", "linux/ipv6.h")
            .scapy("IPv6ExtHdrHopByHop")
            .tshark("ipv6.hop")
            .variable(),
        PN::new("IPv6_ND", 24)
            .xdp2("xdp2_parse_ipv6_nd")
            .kernel("nd_msg", "linux/neighbour.h")
            .scapy("ICMPv6ND_NS")
            .tshark("icmpv6")
            .variable(),
        // ── IEEE 802.15.4 ──
        PN::new("IEEE802154", 3)
            .xdp2("xdp2_parse_ieee802154")
            .kernel("ieee802154_hdr_fc", "linux/ieee802154.h")
            .scapy("Dot15d4")
            .tshark("wpan")
            .variable(),
        // ── MCTP ──
        PN::new("MCTP", 4)
            .xdp2("xdp2_parse_mctp")
            .kernel("mctp_hdr", "linux/mctp.h")
            .scapy("MCTP")
            .tshark("mctp"),
        // ── Phonet ──
        PN::new("Phonet", 7)
            .xdp2("xdp2_parse_phonet")
            .kernel("phonethdr", "linux/phonet.h")
            .scapy("Phonet")
            .tshark("phonet"),
        // ── Generic Netlink ──
        PN::new("GenNetlink", 4)
            .xdp2("xdp2_parse_genetlink")
            .kernel("genlmsghdr", "linux/genetlink.h")
            .scapy("GenlMsgHdr")
            .tshark("genl"),
        PN::new("NLAttr", 4)
            .xdp2("xdp2_parse_nlattr")
            .kernel("nlattr", "linux/netlink.h")
            .scapy("NLAttr"),
        // ── TIPC ──
        PN::new("TIPC", 16)
            .xdp2("xdp2_parse_tipc")
            .kernel("tipc_basic_hdr", "linux/tipc.h")
            .scapy("TIPC")
            .tshark("tipc"),
        // ── Bluetooth Variants ──
        PN::new("HCI_CMD", 3)
            .xdp2("xdp2_parse_hci_cmd")
            .kernel("hci_command_hdr", "net/bluetooth/hci.h")
            .scapy("HCI_Command_Hdr")
            .tshark("bthci_cmd"),
        PN::new("HCI_ACL", 4)
            .xdp2("xdp2_parse_hci_acl")
            .kernel("hci_acl_hdr", "net/bluetooth/hci.h")
            .scapy("HCI_ACL_Hdr")
            .tshark("bthci_acl"),
        PN::new("HCI_Event", 2)
            .xdp2("xdp2_parse_hci_event")
            .kernel("hci_event_hdr", "net/bluetooth/hci.h")
            .scapy("HCI_Event_Hdr")
            .tshark("bthci_evt"),
        PN::new("HCI_SCO", 3)
            .xdp2("xdp2_parse_hci_sco")
            .kernel("hci_sco_hdr", "net/bluetooth/hci.h")
            .scapy("HCI_SCO_Hdr")
            .tshark("bthci_sco"),
        PN::new("HCI_ISO", 4)
            .xdp2("xdp2_parse_hci_iso")
            .kernel("hci_iso_hdr", "net/bluetooth/hci.h")
            .scapy("HCI_ISO_Hdr")
            .tshark("bthci_iso"),
        // ── EAPOL ──
        PN::new("EAPOL", 4)
            .xdp2("xdp2_parse_eapol")
            .scapy("EAPOL")
            .tshark("eapol")
            .etherparse("EapolHeader", "src/proto_audit/eapol.rs")
            .libpcap("eapol_header", "pcap/proto_audit/eapol.h"),
        // ── CAN XL ──
        PN::new("CAN_XL", 12)
            .xdp2("xdp2_parse_canxl")
            .scapy("CANXL")
            .tshark("can"),
        // ── Management & Industrial ──
        PN::new("TRILL", 6)
            .xdp2("xdp2_parse_trill")
            .scapy("TRILL")
            .tshark("trill"),
        PN::new("BATMAN", 10)
            .xdp2("xdp2_parse_batman")
            .scapy("BATMAN_OGM")
            .tshark("batadv"),
        PN::new("DSA", 4)
            .xdp2("xdp2_parse_dsa")
            .scapy("DSA")
            .tshark("dsa"),
        PN::new("EDSA", 10)
            .xdp2("xdp2_parse_edsa")
            .scapy("EDSA")
            .tshark("edsa"),
        PN::new("CFM", 4)
            .xdp2("xdp2_parse_cfm")
            .scapy("CFM")
            .tshark("cfm"),
        PN::new("FIP", 10)
            .xdp2("xdp2_parse_fip")
            .scapy("FIP")
            .tshark("fip"),
        PN::new("MAC_Control", 4)
            .xdp2("xdp2_parse_mac_control")
            .scapy("MACControlPause")
            .tshark("macc"),
        PN::new("MVRP", 1)
            .xdp2("xdp2_parse_mvrp")
            .scapy("MVRP")
            .tshark("mvrp"),
        PN::new("NC_SI", 8)
            .xdp2("xdp2_parse_ncsi")
            .scapy("NCSI")
            .tshark("ncsi"),
        PN::new("Slow_Protocols", 2)
            .xdp2("xdp2_parse_slow")
            .scapy("SlowProtocol")
            .tshark("slow"),
        // ── Remaining Legacy/Niche ──
        PN::new("PROFINET", 2)
            .xdp2("xdp2_parse_profinet")
            .scapy("ProfinetIO")
            .tshark("pn_rt"),
        PN::new("X25", 3)
            .xdp2("xdp2_parse_x25")
            .scapy("X25")
            .tshark("x25"),
        PN::new("ATM", 5)
            .xdp2("xdp2_parse_atm")
            .scapy("ATM")
            .tshark("atm"),
        // ── Redundancy ──
        PN::new("VRRP", 8).scapy("VRRPv3").tshark("vrrp").variable(),
        PN::new("HSRP", 20).scapy("HSRP").tshark("hsrp"),
        // ── Discovery ──
        PN::new("CDP", 4).scapy("CDPv2_HDR").tshark("cdp").variable(),
        // ── Routing ──
        PN::new("RIP", 4).scapy("RIP").tshark("rip").variable(),
        PN::new("OSPF", 24).scapy("OSPF_Hdr").tshark("ospf"),
        PN::new("ISIS", 8).scapy("ISIS_CommonHdr").tshark("isis").variable(),
        PN::new("BGP", 19).scapy("BGPHeader").tshark("bgp").variable(),
        PN::new("EIGRP", 20).scapy("EIGRP").tshark("eigrp").variable(),
        // ── Bluetooth (upper layers) ──
        PN::new("BT_ATT", 1).scapy("ATT_Hdr").tshark("btatt").variable(),
        PN::new("BT_SMP", 1).scapy("SM_Hdr").tshark("btsmp").variable(),
        PN::new("BT_RFCOMM", 4).scapy("RFCOMM_Hdr").tshark("btrfcomm").variable(),
        PN::new("BT_BNEP", 3).scapy("BNEP").tshark("btbnep").variable(),
        PN::new("BT_SDP", 3).scapy("SDP_Hdr").tshark("btsdp").variable(),
        PN::new("BT_AVDTP", 2).scapy("AVDTP_Hdr").tshark("btavdtp").variable(),
        // ── InfiniBand (extended transport headers) ──
        PN::new("IB_DETH", 8).scapy("IB_DETH").tshark("infiniband.deth"),
        PN::new("IB_RETH", 16).scapy("IB_RETH").tshark("infiniband.reth"),
        PN::new("IB_AETH", 4).scapy("IB_AETH").tshark("infiniband.aeth"),
        PN::new("IB_RDETH", 4).scapy("IB_RDETH").tshark("infiniband.rdeth"),
        PN::new("IB_AtomicETH", 28).scapy("IB_AtomicETH").tshark("infiniband.atomiceth"),
        PN::new("IB_ImmDt", 4).scapy("IB_ImmDt").tshark("infiniband.immdt"),
        PN::new("IB_MAD", 24).scapy("IB_MAD").tshark("infiniband.mad").variable(),
        // ── Multicast ──
        PN::new("IGMPv3_Query", 12)
            .kernel("igmpv3_query", "linux/igmp.h")
            .scapy("IGMPv3")
            .tshark("igmp")
            .variable(),
        PN::new("IGMPv3_Report", 8)
            .kernel("igmpv3_report", "linux/igmp.h")
            .scapy("IGMPv3mr")
            .tshark("igmp")
            .variable(),
        PN::new("MLD", 24)
            .kernel("mld_msg", "net/mld.h")
            .scapy("ICMPv6MLQuery")
            .tshark("icmpv6"),
        PN::new("MLDv2_Query", 28)
            .kernel("mld2_query", "net/mld.h")
            .scapy("ICMPv6MLQuery2")
            .tshark("icmpv6")
            .variable(),
        PN::new("MLDv2_Report", 8)
            .kernel("mld2_report", "net/mld.h")
            .scapy("ICMPv6MLReport2")
            .tshark("icmpv6")
            .variable(),
        // ── Media/Streaming ──
        PN::new("MPEG_TS", 188).scapy("MPEG_TS").tshark("mp2t"),
        PN::new("RTP", 12).scapy("RTP").tshark("rtp")
            .etherparse("RtpHeader", "src/proto_audit/rtp.rs").variable(),
        PN::new("SRT", 16).scapy("SRT").tshark("srt").variable(),
        // ── UDP Application Protocols ──
        PN::new("DNS", 12).scapy("DNS").tshark("dns")
            .etherparse("DnsHeader", "src/proto_audit/dns.rs")
            .libpcap("dns_header", "pcap/proto_audit/dns.h").variable(),
        PN::new("NTP", 48).scapy("NTPHeader").tshark("ntp")
            .etherparse("NtpHeader", "src/proto_audit/ntp.rs")
            .libpcap("ntp_header", "pcap/proto_audit/ntp.h").variable(),
        PN::new("SNMP", 10).scapy("SNMP").tshark("snmp").variable(),
        PN::new("DHCP", 236).scapy("BOOTP").tshark("dhcp").variable(),
        PN::new("DHCPv6", 4).scapy("DHCP6").tshark("dhcpv6").variable(),
        PN::new("QUIC", 20).scapy("QUIC_Initial").tshark("quic").variable(),
        // ── Storage Protocols ──
        PN::new("iSCSI", 48)
            .kernel("iscsi_hdr", "scsi/iscsi_proto.h")
            .scapy("iSCSI_BHS")
            .tshark("iscsi")
            .variable(),
        PN::new("NVMe", 64)
            .kernel("nvme_common_command", "linux/nvme.h")
            .scapy("NVMe_Command")
            .tshark("nvme"),
        PN::new("FC", 24)
            .kernel("fc_frame_header", "uapi/scsi/fc/fc_fs.h")
            .scapy("FCFrame")
            .tshark("fc"),
        PN::new("SCSI", 8)
            .kernel("scsi_lun", "scsi/scsi_proto.h")
            .scapy("SCSI_LUN")
            .tshark("scsi")
            .variable(),
        PN::new("iSER", 28)
            .kernel("iser_ctrl", "scsi/iser.h")
            .scapy("iSER_Ctrl")
            .tshark("iser"),
        // ── Network Storage Protocols ──
        PN::new("NFS", 4).scapy("NFS_Call").tshark("nfs").variable(),
        PN::new("SMB", 32).scapy("SMB_Header").tshark("smb").variable(),
        PN::new("SMB2", 64).scapy("SMB2_Header").tshark("smb2").variable(),
        PN::new("ONC_RPC", 4).scapy("RPC").tshark("rpc").variable(),
        // ── Capture Layer / L1 Encapsulations ──
        PN::new("SLL", 16)
            .scapy("CookedLinux")
            .tshark("sll")
            .libpcap("sll_header", "pcap/sll.h"),
        PN::new("SLL2", 20)
            .scapy("CookedLinuxV2")
            .tshark("sll")
            .libpcap("sll2_header", "pcap/sll.h"),
        PN::new("ERF", 18).scapy("ERF").tshark("erf").variable(),
        // ── Layer 2 Additions ──
        PN::new("LLC", 3)
            .kernel("llc_snap_hdr", "linux/llc.h")
            .scapy("LLC")
            .tshark("llc")
            .etherparse("LlcHeader", "src/proto_audit/llc.rs")
            .libpcap("llc_header", "pcap/proto_audit/llc.h"),
        PN::new("SNAP", 5).scapy("SNAP").tshark("llc")
            .etherparse("SnapHeader", "src/proto_audit/snap.rs"),
        PN::new("STP", 35).scapy("STP").tshark("stp")
            .etherparse("StpHeader", "src/proto_audit/stp.rs"),
        PN::new("LACP", 110).scapy("SlowProtocol").tshark("lacp"),
        PN::new("QinQ", 8)
            .kernel("vlan_hdr", "linux/if_vlan.h")
            .scapy("Dot1AD")
            .tshark("vlan"),
        PN::new("WOL", 102).tshark("wol"),
        PN::new("HomePlug_AV", 4).scapy("HomePlugAV").tshark("homeplug-av").variable(),
        // ── Layer 3 Additions ──
        PN::new("SCTP", 12)
            .kernel("sctphdr", "linux/sctp.h")
            .scapy("SCTP")
            .tshark("sctp")
            .etherparse("SctpHeader", "src/proto_audit/sctp.rs")
            .libpcap("SCTP", "gencode.c")
            .variable(),
        PN::new("DCCP", 12)
            .kernel("dccp_hdr", "linux/dccp.h")
            .scapy("DCCP")
            .tshark("dccp")
            .etherparse("DccpHeader", "src/proto_audit/dccp.rs")
            .variable(),
        PN::new("GTP_U", 8).scapy("GTP_U_Header").tshark("gtp").variable(),
        PN::new("GTP_C", 8).scapy("GTPHeader").tshark("gtpv2").variable(),
        PN::new("PIM", 4).scapy("PIM").tshark("pim").variable(),
        PN::new("IPv6_Fragment", 8)
            .kernel("frag_hdr", "linux/ipv6.h")
            .scapy("IPv6ExtHdrFragment")
            .tshark("ipv6.fraghdr"),
        PN::new("IPv6_DestOpts", 2)
            .kernel("ipv6_opt_hdr", "linux/ipv6.h")
            .scapy("IPv6ExtHdrDestOpt")
            .tshark("ipv6.dstopts")
            .variable(),
        PN::new("IPv6_Routing", 4)
            .kernel("ipv6_rt_hdr", "linux/ipv6.h")
            .scapy("IPv6ExtHdrRouting")
            .tshark("ipv6.routing")
            .variable(),
        // ── Layer 4 Additions ──
        PN::new("UDPLite", 8).tshark("udplite"),
        PN::new("SCTP_Chunk", 4)
            .kernel("sctp_chunkhdr", "linux/sctp.h")
            .scapy("SCTPChunkData")
            .tshark("sctp.chunk")
            .variable(),
        // ── Tunneling Additions ──
        PN::new("WireGuard", 4).scapy("WireGuard").tshark("wireguard")
            .etherparse("WireGuardHeader", "src/proto_audit/wire_guard.rs").variable(),
        PN::new("IP_in_IP", 20).scapy("IP").tshark("ipip").variable(),
        PN::new("NVGRE", 8).scapy("NVGRE").tshark("nvgre")
            .etherparse("NvgreHeader", "src/proto_audit/nvgre.rs"),
        PN::new("LISP", 8).scapy("LISP").tshark("lisp").variable(),
        PN::new("STT", 18).tshark("stt").variable(),
        PN::new("Teredo", 2).tshark("teredo").variable(),
        PN::new("GUE", 4).tshark("gue").variable(),
        PN::new("VXLAN_GPE", 8).scapy("VXLAN_GPE").tshark("vxlan")
            .etherparse("VxlanGpeHeader", "src/proto_audit/vxlan_gpe.rs"),
        // ── Security Additions ──
        PN::new("TLS", 5).scapy("TLS").tshark("tls").variable(),
        PN::new("DTLS", 13).scapy("DTLS").tshark("dtls").variable(),
        PN::new("IKEv2", 28).scapy("IKEv2").tshark("isakmp").variable(),
        PN::new("EAP", 4).scapy("EAP").tshark("eap").variable(),
        // ── DNS Family & Discovery ──
        PN::new("mDNS", 12).scapy("DNS").tshark("mdns").variable(),
        PN::new("LLMNR", 12).scapy("DNS").tshark("llmnr").variable(),
        PN::new("NBNS", 12).scapy("NBNSQueryRequest").tshark("nbns").variable(),
        PN::new("PPPoED", 6).scapy("PPPoED").tshark("pppoed").variable(),
        PN::new("LLTD", 14).tshark("lltd").variable(),
        // ── VoIP / Telephony ──
        PN::new("SIP", 20).scapy("SIP").tshark("sip").variable(),
        PN::new("RTCP", 8).scapy("RTCP").tshark("rtcp").variable(),
        PN::new("RTSP", 12).tshark("rtsp").variable(),
        PN::new("STUN", 20).scapy("STUN").tshark("stun"),
        PN::new("Skinny", 12).scapy("Skinny").tshark("skinny").variable(),
        PN::new("MGCP", 4).tshark("mgcp").variable(),
        // ── IoT / Industrial ──
        PN::new("MQTT", 2).scapy("MQTT").tshark("mqtt").variable(),
        PN::new("CoAP", 4).scapy("CoAP").tshark("coap").variable(),
        PN::new("MODBUS_TCP", 7).scapy("ModbusADU").tshark("modbus").variable(),
        PN::new("BACnet", 4).scapy("BVLC").tshark("bacnet").variable(),
        PN::new("DNP3", 10).scapy("DNP3").tshark("dnp3").variable(),
        PN::new("ENIP", 24).scapy("ENIP_TCP").tshark("enip").variable(),
        PN::new("CIP", 2).scapy("CIP").tshark("cip").variable(),
        PN::new("OPC_UA", 8).tshark("opcua").variable(),
        PN::new("IEC_GOOSE", 8).scapy("GOOSE").tshark("goose").variable(),
        // ── ICS / Power & Zigbee ──
        PN::new("IEC_SV", 8).tshark("sv").variable(),
        PN::new("IEC_MMS", 4).tshark("mms").variable(),
        PN::new("Zigbee_NWK", 2).scapy("ZigbeeNWK").tshark("zbee_nwk").variable(),
        PN::new("Zigbee_APS", 2).scapy("ZigbeeAppDataPayload").tshark("zbee_aps").variable(),
        // ── Network Management ──
        PN::new("RADIUS", 20).scapy("Radius").tshark("radius")
            .etherparse("RadiusHeader", "src/proto_audit/radius.rs").variable(),
        PN::new("Diameter", 20).scapy("DiamG").tshark("diameter").variable(),
        PN::new("TACACS", 12).scapy("TACACS").tshark("tacacs").variable(),
        PN::new("Syslog", 1).scapy("Syslog").tshark("syslog").variable(),
        PN::new("TFTP", 4).scapy("TFTP").tshark("tftp").variable(),
        PN::new("NetFlow_v5", 24).scapy("NetflowHeaderV5").tshark("cflow").variable(),
        PN::new("NetFlow_v9", 20).scapy("NetflowHeaderV9").tshark("cflow").variable(),
        PN::new("IPFIX", 16).scapy("IPFIXHeader").tshark("cflow").variable(),
        // ── Auth & Directory ──
        PN::new("LDAP", 1).tshark("ldap").variable(),
        PN::new("Kerberos", 4).scapy("Kerberos").tshark("kerberos").variable(),
        PN::new("NTLMSSP", 12).tshark("ntlmssp").variable(),
        PN::new("OCSP", 1).tshark("ocsp").variable(),
        // ── File Transfer & Web ──
        PN::new("HTTP", 16).scapy("HTTP").tshark("http").variable(),
        PN::new("HTTP2", 9).scapy("HTTP2").tshark("http2").variable(),
        PN::new("FTP", 4).tshark("ftp").variable(),
        PN::new("SSH", 5).tshark("ssh").variable(),
        PN::new("Telnet", 1).tshark("telnet").variable(),
        PN::new("SMTP", 4).tshark("smtp").variable(),
        PN::new("IMAP", 1).tshark("imap").variable(),
        // ── Message Queuing ──
        PN::new("AMQP", 7).tshark("amqp").variable(),
        PN::new("Kafka", 12).tshark("kafka").variable(),
        PN::new("ZeroMQ", 2).tshark("zmtp").variable(),
        PN::new("Memcache", 24).tshark("memcache").variable(),
        PN::new("Redis", 1).tshark("resp").variable(),
        // ── Routing & Misc ──
        PN::new("BFD", 24).scapy("BFD").tshark("bfd")
            .etherparse("BfdHeader", "src/proto_audit/bfd.rs"),
        PN::new("LDP", 10).scapy("LDP").tshark("ldp").variable(),
        PN::new("RSVP", 8).scapy("RSVP").tshark("rsvp").variable(),
        PN::new("MPLS_OAM", 4).tshark("mpls-echo").variable(),
        PN::new("CARP", 8).scapy("VRRPv3").tshark("carp").variable(),
        PN::new("GLBP", 2).tshark("glbp").variable(),
        PN::new("OpenFlow", 8).scapy("OFPTHello").tshark("openflow_v4").variable(),
        PN::new("TZSP", 4).tshark("tzsp").variable(),
        PN::new("GRE_PPTP", 8).scapy("GRE_PPTP").tshark("pptp").variable(),
        PN::new("CAPWAP", 8).scapy("CAPWAP_CTRL").tshark("capwap").variable(),
        PN::new("LWAPP", 6).scapy("LWAPP").tshark("lwapp").variable(),
        PN::new("TPLINK_SMARTHOME", 4).tshark("tplink_smarthome").variable(),
    ]
}
