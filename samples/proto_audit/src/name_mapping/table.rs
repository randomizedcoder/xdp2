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
            .etherparse("Ethernet2Header", "etherparse/src/link/ethernet2_header.rs")
            .ieee(&["802.3-2022"])
            .iana_registry("ieee-802-numbers")
            .libpcap("ethernet_header", "pcap/proto_audit/ethernet.h"),
        PN::new("VLAN", 4)
            .xdp2("xdp2_parse_vlan")
            .kernel("vlan_hdr", "linux/if_vlan.h")
            .scapy("Dot1Q")
            .tshark("vlan")
            .etherparse("SingleVlanHeader", "etherparse/src/link/single_vlan_header.rs")
            .libpcap("vlan_tag", "pcap/vlan.h")
            .ieee(&["802.1Q-2022", "802.1Q-2014"]),
        PN::new("PBB", 18)
            .xdp2("xdp2_parse_pbb")
            .scapy("PBB")
            .tshark("ieee8021ah")
            .ieee(&["802.1ah-2008", "802.1Q-2022"])
            .etherparse("PBBHeader", "src/proto_audit/pbb.rs")
            .libpcap("pbb_header", "pcap/proto_audit/pbb.h"),
        // ── Layer 3 ──
        PN::new("IPv4", 20)
            .xdp2("xdp2_parse_ipv4")
            .kernel("iphdr", "linux/ip.h")
            .scapy("IP")
            .tshark("ip")
            .etherparse("Ipv4Header", "etherparse/src/net/ipv4_header.rs")
            .libpcap("IPv4", "gencode.c")
            .variable()
            .rfcs(&[791, 2474, 3168, 6864])
            .iana_registry("protocol-numbers"),
        PN::new("IPv6", 40)
            .xdp2("xdp2_parse_ipv6")
            .kernel("ipv6hdr", "linux/ipv6.h")
            .scapy("IPv6")
            .tshark("ipv6")
            .etherparse("Ipv6Header", "etherparse/src/net/ipv6_header.rs")
            .libpcap("IPv6", "gencode.c")
            .rfcs(&[8200, 4291, 4443, 6437, 8021])
            .iana_registry("protocol-numbers"),
        PN::new("ARP", 8)
            .xdp2("xdp2_parse_arp")
            .kernel("arphdr", "linux/if_arp.h")
            .scapy("ARP")
            .tshark("arp")
            .etherparse("ArpPacket", "etherparse/src/net/arp_packet.rs")
            .libpcap("ARP", "gencode.c")
            .variable()
            .rfcs(&[826, 5227]),
        PN::new("RARP", 8)
            .xdp2("xdp2_parse_rarp")
            .kernel("arphdr", "linux/if_arp.h")
            .scapy("ARP")
            .tshark("rarp")
            .libpcap("RARP", "gencode.c")
            .variable()
            .rfcs(&[903])
            .etherparse("ARPHeader", "src/proto_audit/rarp.rs"),
        PN::new("ICMPv4", 8)
            .xdp2("xdp2_parse_icmpv4")
            .kernel("icmphdr", "linux/icmp.h")
            .scapy("ICMP")
            .tshark("icmp")
            .etherparse("Icmpv4Header", "etherparse/src/transport/icmpv4_header.rs")
            .libpcap("icmpv4_header", "pcap/proto_audit/icmpv4.h")
            .rfcs(&[792, 1122, 4884]),
        PN::new("ICMPv6", 8)
            .xdp2("xdp2_parse_icmpv6")
            .kernel("icmp6hdr", "linux/icmpv6.h")
            .scapy("ICMPv6Unknown")
            .tshark("icmpv6")
            .etherparse("Icmpv6Header", "etherparse/src/transport/icmpv6_header.rs")
            .rfcs(&[4443, 4861, 4862])
            .libpcap("icmpv6_header", "pcap/proto_audit/icmpv6.h"),
        PN::new("IGMP", 8)
            .xdp2("xdp2_parse_igmp")
            .kernel("igmphdr", "linux/igmp.h")
            .scapy("IGMP")
            .tshark("igmp")
            .etherparse("IgmpHeader", "src/proto_audit/igmp.rs")
            .libpcap("igmp_header", "pcap/proto_audit/igmp.h")
            .rfcs(&[1112, 2236, 3376]),
        // ── Layer 4 ──
        PN::new("TCP", 20)
            .xdp2("xdp2_parse_tcp_notlvs")
            .kernel("tcphdr", "linux/tcp.h")
            .scapy("TCP")
            .tshark("tcp")
            .etherparse("TcpHeader", "etherparse/src/transport/tcp_header.rs")
            .libpcap("TCP", "gencode.c")
            .variable()
            .rfcs(&[9293, 793, 1122, 5681, 7323, 7414])
            .iana_registry("service-name-port-numbers"),
        PN::new("UDP", 8)
            .xdp2("xdp2_parse_udp")
            .kernel("udphdr", "linux/udp.h")
            .scapy("UDP")
            .tshark("udp")
            .etherparse("UdpHeader", "etherparse/src/transport/udp_header.rs")
            .libpcap("UDP", "gencode.c")
            .rfcs(&[768])
            .iana_registry("service-name-port-numbers"),
        // ── Tunneling ──
        PN::new("GRE", 4)
            .xdp2("xdp2_parse_gre")
            .kernel("gre_base_hdr", "linux/gre.h")
            .scapy("GRE")
            .tshark("gre")
            .etherparse("GreHeader", "src/proto_audit/gre.rs")
            .libpcap("gre_header", "pcap/proto_audit/gre.h")
            .variable()
            .rfcs(&[2784, 2890]),
        PN::new("VXLAN", 8)
            .xdp2("xdp2_parse_vxlan")
            .kernel("vxlanhdr", "linux/vxlan.h")
            .scapy("VXLAN")
            .tshark("vxlan")
            .etherparse("VxlanHeader", "src/proto_audit/vxlan.rs")
            .libpcap("vxlan_header", "pcap/proto_audit/vxlan.h")
            .rfcs(&[7348]),
        PN::new("Geneve", 8)
            .xdp2("xdp2_parse_geneve")
            .kernel("genevehdr", "linux/geneve.h")
            .scapy("GENEVE")
            .tshark("geneve")
            .etherparse("GeneveHeader", "src/proto_audit/geneve.rs")
            .libpcap("geneve_header", "pcap/proto_audit/geneve.h")
            .variable()
            .rfcs(&[8926]),
        PN::new("MPLS", 4)
            .xdp2("xdp2_parse_mpls")
            .kernel("mpls_label", "linux/mpls.h")
            .scapy("MPLS")
            .tshark("mpls")
            .etherparse("MplsHeader", "src/proto_audit/mpls.rs")
            .libpcap("mpls_header", "pcap/proto_audit/mpls.h")
            .rfcs(&[3031, 3032, 5462]),
        PN::new("PPP", 2)
            .xdp2("xdp2_parse_ppp")
            .kernel_header_only("linux/ppp_defs.h")
            .scapy("PPP")
            .tshark("ppp")
            .etherparse("PppHeader", "src/proto_audit/ppp.rs")
            .libpcap("ppp_header", "pcap/proto_audit/ppp.h")
            .rfcs(&[1661, 1662]),
        PN::new("PPPoE", 6)
            .xdp2("xdp2_parse_pppoe")
            .kernel("pppoe_hdr", "linux/ppp_defs.h")
            .scapy("PPPoE")
            .tshark("pppoes")
            .etherparse("PppoeHeader", "src/proto_audit/pppoe.rs")
            .libpcap("pppoe_header", "pcap/proto_audit/pppoe.h")
            .rfcs(&[2516]),
        PN::new("L2TP", 6)
            .xdp2("xdp2_parse_l2tp")
            .kernel("l2tp_control_hdr", "linux/l2tp.h")
            .scapy("L2TP")
            .tshark("l2tp")
            .etherparse("L2tpHeader", "src/proto_audit/l2tp.rs")
            .libpcap("l2tp_header", "pcap/proto_audit/l2tp.h")
            .variable()
            .rfcs(&[3931, 2661]),
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
            .variable()
            .rfcs(&[8300]),
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
            .variable()
            .rfcs(&[4303, 2406]),
        PN::new("AH", 12)
            .xdp2("xdp2_parse_ah")
            .kernel("ip_auth_hdr", "linux/ip.h")
            .scapy("AH")
            .tshark("ah")
            .etherparse("AhHeader", "src/proto_audit/ah.rs")
            .libpcap("ah_header", "pcap/proto_audit/ah.h")
            .variable()
            .rfcs(&[4302, 2402]),
        PN::new("MACsec", 8)
            .xdp2("xdp2_parse_macsec")
            .kernel("macsec_sci", "linux/if_macsec.h")
            .scapy("MACsecSCI")
            .tshark("macsec")
            .etherparse("MacsecHeader", "src/proto_audit/macsec.rs")
            .ieee(&["802.1AE-2018"])
            .libpcap("macsec_header", "pcap/proto_audit/macsec.h"),
        // ── Management ──
        PN::new("LLDP", 2)
            .xdp2("xdp2_parse_lldp")
            .scapy("LLDPDU")
            .tshark("lldp")
            .variable()
            .ieee(&["802.1AB-2016"])
            .etherparse("LLDPDUHeader", "src/proto_audit/lldp.rs")
            .libpcap("lldp_header", "pcap/proto_audit/lldp.h"),
        PN::new("PTP", 34)
            .xdp2("xdp2_parse_ptp")
            .kernel("ptp_header", "linux/ptp_classify.h")
            .scapy("PTP")
            .tshark("ptp")
            .etherparse("PtpHeader", "src/proto_audit/ptp.rs")
            .libpcap("ptp_header", "pcap/proto_audit/ptp.h")
            .ieee(&["1588-2019"]),
        // ── SRv6 ──
        PN::new("SRv6", 8)
            .xdp2("xdp2_parse_srv6")
            .kernel("ipv6_sr_hdr", "linux/seg6.h")
            .scapy("IPv6ExtHdrSegmentRouting")
            .tshark("ipv6.routing.srh")
            .variable()
            .rfcs(&[8754, 8986])
            .etherparse("IPv6ExtHdrSegmentRoutingHeader", "src/proto_audit/srv6.rs")
            .libpcap("srv6_header", "pcap/proto_audit/srv6.h"),
        // ── Storage ──
        PN::new("AoE", 10)
            .xdp2("xdp2_parse_aoe")
            .kernel("aoe_hdr", "linux/aoe.h")
            .scapy("AOE")
            .tshark("aoe")
            .variable()
            .etherparse("AOEHeader", "src/proto_audit/aoe.rs")
            .libpcap("aoe_header", "pcap/proto_audit/aoe.h"),
        PN::new("FCoE", 14)
            .xdp2("xdp2_parse_fcoe")
            .kernel("fcoe_hdr", "linux/fcoe.h")
            .scapy("FCoE")
            .tshark("fcoe")
            .libpcap("fcoe_header", "pcap/proto_audit/fcoe.h")
            .etherparse("FCoEHeader", "src/proto_audit/fcoe.rs"),
        PN::new("EtherCAT", 2)
            .xdp2("xdp2_parse_ethercat")
            .scapy("EtherCat")
            .tshark("ecat")
            .variable()
            .etherparse("EtherCatHeader", "src/proto_audit/ethercat.rs")
            .libpcap("ethercat_header", "pcap/proto_audit/ethercat.h"),
        // ── Wireless ──
        PN::new("IEEE802.11", 24)
            .xdp2("xdp2_parse_ieee80211")
            .kernel("ieee80211_hdr", "linux/ieee80211.h")
            .scapy("Dot11")
            .tshark("wlan")
            .variable()
            .ieee(&["802.11-2020", "802.11ax-2021", "802.11be"])
            .etherparse("IEEE80211Header", "src/proto_audit/ieee802_11.rs")
            .libpcap("ieee802_11_header", "pcap/proto_audit/ieee802_11.h"),
        // ── CAN bus ──
        PN::new("CAN", 16)
            .xdp2("xdp2_parse_can")
            .kernel("can_frame", "linux/can.h")
            .scapy("CAN")
            .tshark("can")
            .etherparse("CanHeader", "src/proto_audit/can.rs")
            .libpcap("can_header", "pcap/proto_audit/can.h"),
        PN::new("CAN_FD", 72)
            .xdp2("xdp2_parse_canfd")
            .kernel("canfd_frame", "linux/can.h")
            .scapy("CANFD")
            .tshark("can")
            .etherparse("CanFdHeader", "src/proto_audit/can_fd.rs")
            .libpcap("can_fd_header", "pcap/proto_audit/can_fd.h"),
        // ── Bluetooth ──
        PN::new("HCI", 1)
            .xdp2("xdp2_parse_hci")
            .kernel("hci_command_hdr", "net/bluetooth/hci.h")
            .scapy("HCI_Hdr")
            .tshark("bthci_cmd")
            .variable()
            .etherparse("HCIHeader", "src/proto_audit/hci.rs")
            .libpcap("hci_header", "pcap/proto_audit/hci.h"),
        PN::new("L2CAP", 4)
            .xdp2("xdp2_parse_l2cap")
            .kernel("l2cap_hdr", "net/bluetooth/l2cap.h")
            .scapy("L2CAP_Hdr")
            .tshark("btl2cap")
            .variable()
            .etherparse("L2CAPHeader", "src/proto_audit/l2cap.rs")
            .libpcap("l2cap_header", "pcap/proto_audit/l2cap.h"),
        // ── InfiniBand ──
        PN::new("IB_LRH", 8)
            .xdp2("xdp2_parse_ib_lrh")
            .scapy("IB_LRH")
            .tshark("infiniband.lrh")
            .etherparse("IB_LRHHeader", "src/proto_audit/ib_lrh.rs")
            .libpcap("ib_lrh_header", "pcap/proto_audit/ib_lrh.h"),
        PN::new("IB_GRH", 40)
            .xdp2("xdp2_parse_ib_grh")
            .scapy("IB_GRH")
            .tshark("infiniband.grh")
            .etherparse("IB_GRHHeader", "src/proto_audit/ib_grh.rs")
            .libpcap("ib_grh_header", "pcap/proto_audit/ib_grh.h"),
        PN::new("IB_BTH", 12)
            .xdp2("xdp2_parse_ib_bth")
            .scapy("IB_BTH")
            .tshark("infiniband.bth")
            .etherparse("IB_BTHHeader", "src/proto_audit/ib_bth.rs")
            .libpcap("ib_bth_header", "pcap/proto_audit/ib_bth.h"),
        // ── Netlink ──
        PN::new("Netlink", 16)
            .xdp2("xdp2_parse_netlink")
            .kernel("nlmsghdr", "linux/netlink.h")
            .scapy("NetlinkHeader")
            .tshark("netlink")
            .variable()
            .rfcs(&[3549])
            .etherparse("NetlinkHeader", "src/proto_audit/netlink.rs")
            .libpcap("netlink_header", "pcap/proto_audit/netlink.h"),
        // ── Legacy ──
        PN::new("IPX", 30)
            .xdp2("xdp2_parse_ipx")
            .kernel("ipxhdr", "linux/ipx.h")
            .scapy("IPX")
            .tshark("ipx")
            .libpcap("ipx_header", "pcap/proto_audit/ipx.h")
            .etherparse("IPXHeader", "src/proto_audit/ipx.rs"),
        PN::new("AppleTalk", 5)
            .xdp2("xdp2_parse_atalk")
            .kernel("atalk_addr", "linux/atalk.h")
            .scapy("DDP")
            .tshark("ddp")
            .etherparse("AppleTalkHeader", "src/proto_audit/appletalk.rs")
            .libpcap("appletalk_header", "pcap/proto_audit/appletalk.h"),
        // ── IPv6 Extensions ──
        PN::new("IPv6_EH", 2)
            .xdp2("xdp2_parse_ipv6_eh")
            .kernel("ipv6_opt_hdr", "linux/ipv6.h")
            .scapy("IPv6ExtHdrHopByHop")
            .tshark("ipv6.hop")
            .variable()
            .rfcs(&[8200])
            .etherparse("IPv6ExtHdrHopByHopHeader", "src/proto_audit/ipv6_eh.rs")
            .libpcap("ipv6_eh_header", "pcap/proto_audit/ipv6_eh.h"),
        PN::new("IPv6_ND", 24)
            .xdp2("xdp2_parse_ipv6_nd")
            .kernel("nd_msg", "linux/neighbour.h")
            .scapy("ICMPv6ND_NS")
            .tshark("icmpv6")
            .variable()
            .rfcs(&[4861, 4862])
            .etherparse("ICMPv6ND_NSHeader", "src/proto_audit/ipv6_nd.rs")
            .libpcap("ipv6_nd_header", "pcap/proto_audit/ipv6_nd.h"),
        // ── IEEE 802.15.4 ──
        PN::new("IEEE802154", 3)
            .xdp2("xdp2_parse_ieee802154")
            .kernel("ieee802154_hdr_fc", "linux/ieee802154.h")
            .scapy("Dot15d4")
            .tshark("wpan")
            .libpcap("ieee802154_header", "pcap/proto_audit/ieee802154.h")
            .variable()
            .ieee(&["802.15.4-2020"])
            .etherparse("IEEE802154Header", "src/proto_audit/ieee802154.rs"),
        // ── MCTP ──
        PN::new("MCTP", 4)
            .xdp2("xdp2_parse_mctp")
            .kernel("mctp_hdr", "linux/mctp.h")
            .scapy("MCTP")
            .tshark("mctp")
            .etherparse("MCTPHeader", "src/proto_audit/mctp.rs")
            .libpcap("mctp_header", "pcap/proto_audit/mctp.h"),
        // ── Phonet ──
        PN::new("Phonet", 7)
            .xdp2("xdp2_parse_phonet")
            .kernel("phonethdr", "linux/phonet.h")
            .scapy("Phonet")
            .tshark("phonet")
            .etherparse("PhonetHeader", "src/proto_audit/phonet.rs")
            .libpcap("phonet_header", "pcap/proto_audit/phonet.h"),
        // ── Generic Netlink ──
        PN::new("GenNetlink", 4)
            .xdp2("xdp2_parse_genetlink")
            .kernel("genlmsghdr", "linux/genetlink.h")
            .scapy("GenlMsgHdr")
            .tshark("genl")
            .etherparse("GenNetlinkHeader", "src/proto_audit/gennetlink.rs")
            .libpcap("gennetlink_header", "pcap/proto_audit/gennetlink.h"),
        PN::new("NLAttr", 4)
            .xdp2("xdp2_parse_nlattr")
            .kernel("nlattr", "linux/netlink.h")
            .scapy("NLAttr")
            .etherparse("NLAttrHeader", "src/proto_audit/nlattr.rs")
            .libpcap("nlattr_header", "pcap/proto_audit/nlattr.h"),
        // ── TIPC ──
        PN::new("TIPC", 16)
            .xdp2("xdp2_parse_tipc")
            .kernel("tipc_basic_hdr", "linux/tipc.h")
            .scapy("TIPC")
            .tshark("tipc")
            .libpcap("tipc_header", "pcap/proto_audit/tipc.h")
            .etherparse("TIPCHeader", "src/proto_audit/tipc.rs"),
        // ── Bluetooth Variants ──
        PN::new("HCI_CMD", 3)
            .xdp2("xdp2_parse_hci_cmd")
            .kernel("hci_command_hdr", "net/bluetooth/hci.h")
            .scapy("HCI_Command_Hdr")
            .tshark("bthci_cmd")
            .etherparse("HCI_CMDHeader", "src/proto_audit/hci_cmd.rs")
            .libpcap("hci_cmd_header", "pcap/proto_audit/hci_cmd.h"),
        PN::new("HCI_ACL", 4)
            .xdp2("xdp2_parse_hci_acl")
            .kernel("hci_acl_hdr", "net/bluetooth/hci.h")
            .scapy("HCI_ACL_Hdr")
            .tshark("bthci_acl")
            .etherparse("HCI_ACL_HdrHeader", "src/proto_audit/hci_acl.rs")
            .libpcap("hci_acl_header", "pcap/proto_audit/hci_acl.h"),
        PN::new("HCI_Event", 2)
            .xdp2("xdp2_parse_hci_event")
            .kernel("hci_event_hdr", "net/bluetooth/hci.h")
            .scapy("HCI_Event_Hdr")
            .tshark("bthci_evt")
            .etherparse("HCI_EventHeader", "src/proto_audit/hci_event.rs")
            .libpcap("hci_event_header", "pcap/proto_audit/hci_event.h"),
        PN::new("HCI_SCO", 3)
            .xdp2("xdp2_parse_hci_sco")
            .kernel("hci_sco_hdr", "net/bluetooth/hci.h")
            .scapy("HCI_SCO_Hdr")
            .tshark("bthci_sco")
            .etherparse("HCI_SCOHeader", "src/proto_audit/hci_sco.rs")
            .libpcap("hci_sco_header", "pcap/proto_audit/hci_sco.h"),
        PN::new("HCI_ISO", 4)
            .xdp2("xdp2_parse_hci_iso")
            .kernel("hci_iso_hdr", "net/bluetooth/hci.h")
            .scapy("HCI_ISO_Hdr")
            .tshark("bthci_iso")
            .etherparse("HCI_ISOHeader", "src/proto_audit/hci_iso.rs")
            .libpcap("hci_iso_header", "pcap/proto_audit/hci_iso.h"),
        // ── EAPOL ──
        PN::new("EAPOL", 4)
            .xdp2("xdp2_parse_eapol")
            .scapy("EAPOL")
            .tshark("eapol")
            .etherparse("EapolHeader", "src/proto_audit/eapol.rs")
            .libpcap("eapol_header", "pcap/proto_audit/eapol.h")
            .ieee(&["802.1X-2020"]),
        // ── CAN XL ──
        PN::new("CAN_XL", 12)
            .xdp2("xdp2_parse_canxl")
            .scapy("CANXL")
            .tshark("can")
            .etherparse("CAN_XLHeader", "src/proto_audit/can_xl.rs")
            .libpcap("can_xl_header", "pcap/proto_audit/can_xl.h"),
        // ── Management & Industrial ──
        PN::new("TRILL", 6)
            .xdp2("xdp2_parse_trill")
            .scapy("TRILL")
            .tshark("trill")
            .rfcs(&[6325, 7177, 7780])
            .etherparse("TRILLHeader", "src/proto_audit/trill.rs")
            .libpcap("trill_header", "pcap/proto_audit/trill.h"),
        PN::new("BATMAN", 10)
            .xdp2("xdp2_parse_batman")
            .scapy("BATMAN_OGM")
            .tshark("batadv")
            .etherparse("BATMANHeader", "src/proto_audit/batman.rs")
            .libpcap("batman_header", "pcap/proto_audit/batman.h"),
        PN::new("DSA", 4)
            .xdp2("xdp2_parse_dsa")
            .scapy("DSA")
            .tshark("dsa")
            .etherparse("DSAHeader", "src/proto_audit/dsa.rs")
            .libpcap("dsa_header", "pcap/proto_audit/dsa.h"),
        PN::new("EDSA", 10)
            .xdp2("xdp2_parse_edsa")
            .scapy("EDSA")
            .tshark("edsa")
            .etherparse("EDSAHeader", "src/proto_audit/edsa.rs")
            .libpcap("edsa_header", "pcap/proto_audit/edsa.h"),
        PN::new("CFM", 4)
            .xdp2("xdp2_parse_cfm")
            .scapy("CFM")
            .tshark("cfm")
            .ieee(&["802.1ag-2007"])
            .etherparse("CFMHeader", "src/proto_audit/cfm.rs")
            .libpcap("cfm_header", "pcap/proto_audit/cfm.h"),
        PN::new("FIP", 10)
            .xdp2("xdp2_parse_fip")
            .scapy("FIP")
            .tshark("fip")
            .etherparse("FIPHeader", "src/proto_audit/fip.rs")
            .libpcap("fip_header", "pcap/proto_audit/fip.h"),
        PN::new("MAC_Control", 4)
            .xdp2("xdp2_parse_mac_control")
            .scapy("MACControlPause")
            .tshark("macc")
            .ieee(&["802.3-2022"])
            .etherparse("MAC_ControlHeader", "src/proto_audit/mac_control.rs")
            .libpcap("mac_control_header", "pcap/proto_audit/mac_control.h"),
        PN::new("MVRP", 1)
            .xdp2("xdp2_parse_mvrp")
            .scapy("MVRP")
            .tshark("mvrp")
            .ieee(&["802.1Q-2022"])
            .etherparse("MVRPHeader", "src/proto_audit/mvrp.rs")
            .libpcap("mvrp_header", "pcap/proto_audit/mvrp.h"),
        PN::new("NC_SI", 8)
            .xdp2("xdp2_parse_ncsi")
            .scapy("NCSI")
            .tshark("ncsi")
            .etherparse("NC_SIHeader", "src/proto_audit/nc_si.rs")
            .libpcap("nc_si_header", "pcap/proto_audit/nc_si.h"),
        PN::new("Slow_Protocols", 2)
            .xdp2("xdp2_parse_slow")
            .scapy("SlowProtocol")
            .tshark("slow")
            .ieee(&["802.3-2022"])
            .etherparse("SlowProtocolHeader", "src/proto_audit/slow_protocols.rs")
            .libpcap("slow_protocols_header", "pcap/proto_audit/slow_protocols.h"),
        // ── Remaining Legacy/Niche ──
        PN::new("PROFINET", 2)
            .xdp2("xdp2_parse_profinet")
            .scapy("ProfinetIO")
            .tshark("pn_rt")
            .etherparse("ProfinetIOHeader", "src/proto_audit/profinet.rs")
            .libpcap("profinet_header", "pcap/proto_audit/profinet.h"),
        PN::new("X25", 3)
            .xdp2("xdp2_parse_x25")
            .scapy("X25")
            .tshark("x25")
            .etherparse("X25Header", "src/proto_audit/x25.rs")
            .libpcap("x25_header", "pcap/proto_audit/x25.h"),
        PN::new("ATM", 5)
            .xdp2("xdp2_parse_atm")
            .scapy("ATM")
            .tshark("atm")
            .etherparse("ATMHeader", "src/proto_audit/atm.rs")
            .libpcap("atm_header", "pcap/proto_audit/atm.h"),
        // ── Redundancy ──
        PN::new("VRRP", 8).scapy("VRRPv3").tshark("vrrp")
            .libpcap("vrrp_header", "pcap/proto_audit/vrrp.h")
            .variable()
            .rfcs(&[5798, 9568])
            .etherparse("VRRPHeader", "src/proto_audit/vrrp.rs"),
        PN::new("HSRP", 20).scapy("HSRP").tshark("hsrp")
            .libpcap("hsrp_header", "pcap/proto_audit/hsrp.h")
            .rfcs(&[2281])
            .etherparse("HSRPHeader", "src/proto_audit/hsrp.rs"),
        // ── Discovery ──
        PN::new("CDP", 4).scapy("CDPv2_HDR").tshark("cdp").variable()
            .etherparse("CDPHeader", "src/proto_audit/cdp.rs")
            .libpcap("cdp_header", "pcap/proto_audit/cdp.h"),
        // ── Routing ──
        PN::new("RIP", 4).scapy("RIP").tshark("rip")
            .libpcap("rip_header", "pcap/proto_audit/rip.h")
            .variable()
            .rfcs(&[2453, 1058])
            .etherparse("RIPHeader", "src/proto_audit/rip.rs"),
        PN::new("OSPF", 24).scapy("OSPF_Hdr").tshark("ospf")
            .libpcap("ospf_header", "pcap/proto_audit/ospf.h")
            .rfcs(&[2328, 5340])
            .etherparse("OSPF_HdrHeader", "src/proto_audit/ospf.rs"),
        PN::new("ISIS", 8).scapy("ISIS_CommonHdr").tshark("isis").variable()
            .libpcap("isis_header", "pcap/proto_audit/isis.h")
            .rfcs(&[1195])
            .etherparse("ISISHeader", "src/proto_audit/isis.rs"),
        PN::new("BGP", 19).scapy("BGPHeader").tshark("bgp").variable()
            .rfcs(&[4271, 7606, 8654, 9072])
            .etherparse("BGPHeader", "src/proto_audit/bgp.rs")
            .libpcap("bgp_header", "pcap/proto_audit/bgp.h"),
        PN::new("EIGRP", 20).scapy("EIGRP").tshark("eigrp")
            .libpcap("eigrp_header", "pcap/proto_audit/eigrp.h")
            .variable()
            .etherparse("EIGRPHeader", "src/proto_audit/eigrp.rs"),
        // ── Bluetooth (upper layers) ──
        PN::new("BT_ATT", 1).scapy("ATT_Hdr").tshark("btatt").variable()
            .etherparse("ATT_HdrHeader", "src/proto_audit/bt_att.rs")
            .libpcap("bt_att_header", "pcap/proto_audit/bt_att.h"),
        PN::new("BT_SMP", 1).scapy("SM_Hdr").tshark("btsmp").variable()
            .etherparse("SM_HdrHeader", "src/proto_audit/bt_smp.rs")
            .libpcap("bt_smp_header", "pcap/proto_audit/bt_smp.h"),
        PN::new("BT_RFCOMM", 4).scapy("RFCOMM_Hdr").tshark("btrfcomm").variable()
            .etherparse("BT_RFCOMMHeader", "src/proto_audit/bt_rfcomm.rs")
            .libpcap("bt_rfcomm_header", "pcap/proto_audit/bt_rfcomm.h"),
        PN::new("BT_BNEP", 3).scapy("BNEP").tshark("btbnep").variable()
            .etherparse("BT_BNEPHeader", "src/proto_audit/bt_bnep.rs")
            .libpcap("bt_bnep_header", "pcap/proto_audit/bt_bnep.h"),
        PN::new("BT_SDP", 3).scapy("SDP_Hdr").tshark("btsdp").variable()
            .etherparse("BT_SDPHeader", "src/proto_audit/bt_sdp.rs")
            .libpcap("bt_sdp_header", "pcap/proto_audit/bt_sdp.h"),
        PN::new("BT_AVDTP", 2).scapy("AVDTP_Hdr").tshark("btavdtp").variable()
            .etherparse("BT_AVDTPHeader", "src/proto_audit/bt_avdtp.rs")
            .libpcap("bt_avdtp_header", "pcap/proto_audit/bt_avdtp.h"),
        // ── InfiniBand (extended transport headers) ──
        PN::new("IB_DETH", 8).scapy("IB_DETH").tshark("infiniband.deth")
            .etherparse("IB_DETHHeader", "src/proto_audit/ib_deth.rs")
            .libpcap("ib_deth_header", "pcap/proto_audit/ib_deth.h"),
        PN::new("IB_RETH", 16).scapy("IB_RETH").tshark("infiniband.reth")
            .etherparse("IB_RETHHeader", "src/proto_audit/ib_reth.rs")
            .libpcap("ib_reth_header", "pcap/proto_audit/ib_reth.h"),
        PN::new("IB_AETH", 4).scapy("IB_AETH").tshark("infiniband.aeth")
            .etherparse("IB_AETHHeader", "src/proto_audit/ib_aeth.rs")
            .libpcap("ib_aeth_header", "pcap/proto_audit/ib_aeth.h"),
        PN::new("IB_RDETH", 4).scapy("IB_RDETH").tshark("infiniband.rdeth")
            .etherparse("IB_RDETHHeader", "src/proto_audit/ib_rdeth.rs")
            .libpcap("ib_rdeth_header", "pcap/proto_audit/ib_rdeth.h"),
        PN::new("IB_AtomicETH", 28).scapy("IB_AtomicETH").tshark("infiniband.atomiceth")
            .etherparse("IB_AtomicETHHeader", "src/proto_audit/ib_atomiceth.rs")
            .libpcap("ib_atomiceth_header", "pcap/proto_audit/ib_atomiceth.h"),
        PN::new("IB_ImmDt", 4).scapy("IB_ImmDt").tshark("infiniband.immdt")
            .etherparse("IB_ImmDtHeader", "src/proto_audit/ib_immdt.rs")
            .libpcap("ib_immdt_header", "pcap/proto_audit/ib_immdt.h"),
        PN::new("IB_MAD", 24).scapy("IB_MAD").tshark("infiniband.mad").variable()
            .etherparse("IB_MADHeader", "src/proto_audit/ib_mad.rs")
            .libpcap("ib_mad_header", "pcap/proto_audit/ib_mad.h"),
        // ── Multicast ──
        PN::new("IGMPv3_Query", 12)
            .xdp2("xdp2_parse_igmpv3_query")
            .kernel("igmpv3_query", "linux/igmp.h")
            .scapy("IGMPv3")
            .tshark("igmp")
            .variable()
            .rfcs(&[3376])
            .etherparse("IGMPv3_QueryHeader", "src/proto_audit/igmpv3_query.rs")
            .libpcap("igmpv3_query_header", "pcap/proto_audit/igmpv3_query.h"),
        PN::new("IGMPv3_Report", 8)
            .xdp2("xdp2_parse_igmpv3_report")
            .kernel("igmpv3_report", "linux/igmp.h")
            .scapy("IGMPv3mr")
            .tshark("igmp")
            .variable()
            .rfcs(&[3376])
            .etherparse("IGMPv3_ReportHeader", "src/proto_audit/igmpv3_report.rs")
            .libpcap("igmpv3_report_header", "pcap/proto_audit/igmpv3_report.h"),
        PN::new("MLD", 24)
            .xdp2("xdp2_parse_mld")
            .kernel("mld_msg", "net/mld.h")
            .scapy("ICMPv6MLQuery")
            .tshark("icmpv6")
            .rfcs(&[2710])
            .etherparse("ICMPv6MLQueryHeader", "src/proto_audit/mld.rs")
            .libpcap("mld_header", "pcap/proto_audit/mld.h"),
        PN::new("MLDv2_Query", 28)
            .xdp2("xdp2_parse_mldv2_query")
            .kernel("mld2_query", "net/mld.h")
            .scapy("ICMPv6MLQuery2")
            .tshark("icmpv6")
            .variable()
            .rfcs(&[3810])
            .etherparse("ICMPv6MLQuery2Header", "src/proto_audit/mldv2_query.rs")
            .libpcap("mldv2_query_header", "pcap/proto_audit/mldv2_query.h"),
        PN::new("MLDv2_Report", 8)
            .xdp2("xdp2_parse_mldv2_report")
            .kernel("mld2_report", "net/mld.h")
            .scapy("ICMPv6MLReport2")
            .tshark("icmpv6")
            .variable()
            .rfcs(&[3810])
            .etherparse("MLDv2_ReportHeader", "src/proto_audit/mldv2_report.rs")
            .libpcap("mldv2_report_header", "pcap/proto_audit/mldv2_report.h"),
        // ── Media/Streaming ──
        PN::new("MPEG_TS", 188).scapy("MPEG_TS").tshark("mp2t")
            .etherparse("MPEG_TSHeader", "src/proto_audit/mpeg_ts.rs")
            .libpcap("mpeg_ts_header", "pcap/proto_audit/mpeg_ts.h"),
        PN::new("RTP", 12).scapy("RTP").tshark("rtp")
            .etherparse("RtpHeader", "src/proto_audit/rtp.rs")
            .libpcap("rtp_header", "pcap/proto_audit/rtp.h")
            .variable()
            .rfcs(&[3550, 3551]),
        PN::new("SRT", 16).scapy("SRT").tshark("srt").variable()
            .etherparse("SRTHeader", "src/proto_audit/srt.rs")
            .libpcap("srt_header", "pcap/proto_audit/srt.h"),
        // ── UDP Application Protocols ──
        PN::new("DNS", 12).scapy("DNS").tshark("dns")
            .etherparse("DnsHeader", "src/proto_audit/dns.rs")
            .libpcap("dns_header", "pcap/proto_audit/dns.h").variable()
            .rfcs(&[1035, 2671, 6891, 8484]),
        PN::new("NTP", 48).scapy("NTPHeader").tshark("ntp")
            .etherparse("NtpHeader", "src/proto_audit/ntp.rs")
            .libpcap("ntp_header", "pcap/proto_audit/ntp.h").variable()
            .rfcs(&[5905]),
        PN::new("SNMP", 10).scapy("SNMP").tshark("snmp").variable()
            .rfcs(&[3411, 3412, 3414, 3416])
            .etherparse("SNMPHeader", "src/proto_audit/snmp.rs")
            .libpcap("snmp_header", "pcap/proto_audit/snmp.h"),
        PN::new("DHCP", 236).scapy("BOOTP").tshark("dhcp")
            .libpcap("dhcp_header", "pcap/proto_audit/dhcp.h")
            .variable()
            .rfcs(&[2131, 2132])
            .etherparse("DHCPHeader", "src/proto_audit/dhcp.rs"),
        PN::new("DHCPv6", 4).scapy("DHCP6").tshark("dhcpv6").variable()
            .rfcs(&[8415])
            .etherparse("DHCPv6Header", "src/proto_audit/dhcpv6.rs")
            .libpcap("dhcpv6_header", "pcap/proto_audit/dhcpv6.h"),
        PN::new("QUIC", 20).scapy("QUIC_Initial").tshark("quic").variable()
            .rfcs(&[9000, 9001, 9002])
            .etherparse("QUIC_InitialHeader", "src/proto_audit/quic.rs")
            .libpcap("quic_header", "pcap/proto_audit/quic.h"),
        // ── Storage Protocols ──
        PN::new("iSCSI", 48)
            .xdp2("xdp2_parse_iscsi")
            .kernel("iscsi_hdr", "scsi/iscsi_proto.h")
            .scapy("iSCSI_BHS")
            .tshark("iscsi")
            .libpcap("iscsi_header", "pcap/proto_audit/iscsi.h")
            .variable()
            .rfcs(&[7143, 3720])
            .etherparse("iSCSIHeader", "src/proto_audit/iscsi.rs"),
        PN::new("NVMe", 64)
            .xdp2("xdp2_parse_nvme")
            .kernel("nvme_common_command", "linux/nvme.h")
            .scapy("NVMe_Command")
            .tshark("nvme")
            .etherparse("NVMeHeader", "src/proto_audit/nvme.rs")
            .libpcap("nvme_header", "pcap/proto_audit/nvme.h"),
        PN::new("FC", 24)
            .xdp2("xdp2_parse_fc")
            .kernel("fc_frame_header", "uapi/scsi/fc/fc_fs.h")
            .scapy("FCFrame")
            .tshark("fc")
            .libpcap("fc_header", "pcap/proto_audit/fc.h")
            .etherparse("FCHeader", "src/proto_audit/fc.rs"),
        PN::new("SCSI", 8)
            .xdp2("xdp2_parse_scsi")
            .kernel("scsi_lun", "scsi/scsi_proto.h")
            .scapy("SCSI_LUN")
            .tshark("scsi")
            .variable()
            .etherparse("SCSIHeader", "src/proto_audit/scsi.rs")
            .libpcap("scsi_header", "pcap/proto_audit/scsi.h"),
        PN::new("iSER", 28)
            .xdp2("xdp2_parse_iser")
            .kernel("iser_ctrl", "scsi/iser.h")
            .scapy("iSER_Ctrl")
            .tshark("iser")
            .rfcs(&[7145, 5046])
            .etherparse("iSERHeader", "src/proto_audit/iser.rs")
            .libpcap("iser_header", "pcap/proto_audit/iser.h"),
        // ── Network Storage Protocols ──
        PN::new("NFS", 4).scapy("NFS_Call").tshark("nfs").variable()
            .rfcs(&[7530, 8881])
            .etherparse("NFSHeader", "src/proto_audit/nfs.rs")
            .libpcap("nfs_header", "pcap/proto_audit/nfs.h"),
        PN::new("SMB", 32).scapy("SMB_Header").tshark("smb").variable()
            .etherparse("SMB_HeaderHeader", "src/proto_audit/smb.rs")
            .libpcap("smb_header", "pcap/proto_audit/smb.h"),
        PN::new("SMB2", 64).scapy("SMB2_Header").tshark("smb2").variable()
            .etherparse("SMB2_HeaderHeader", "src/proto_audit/smb2.rs")
            .libpcap("smb2_header", "pcap/proto_audit/smb2.h"),
        PN::new("ONC_RPC", 4).scapy("RPC").tshark("rpc").variable()
            .rfcs(&[5531, 1831])
            .etherparse("ONC_RPCHeader", "src/proto_audit/onc_rpc.rs")
            .libpcap("onc_rpc_header", "pcap/proto_audit/onc_rpc.h"),
        // ── Capture Layer / L1 Encapsulations ──
        PN::new("SLL", 16)
            .scapy("CookedLinux")
            .tshark("sll")
            .libpcap("sll_header", "pcap/sll.h")
            .etherparse("CookedLinuxHeader", "src/proto_audit/sll.rs"),
        PN::new("SLL2", 20)
            .scapy("CookedLinuxV2")
            .tshark("sll")
            .libpcap("sll2_header", "pcap/sll.h")
            .etherparse("SLL2Header", "src/proto_audit/sll2.rs"),
        PN::new("ERF", 18).scapy("ERF").tshark("erf").variable()
            .etherparse("ERFHeader", "src/proto_audit/erf.rs")
            .libpcap("erf_header", "pcap/proto_audit/erf.h"),
        // ── Layer 2 Additions ──
        PN::new("LLC", 3)
            .xdp2("xdp2_parse_llc")
            .kernel("llc_snap_hdr", "linux/llc.h")
            .scapy("LLC")
            .tshark("llc")
            .etherparse("LlcHeader", "src/proto_audit/llc.rs")
            .libpcap("llc_header", "pcap/proto_audit/llc.h")
            .ieee(&["802.2-1998"]),
        PN::new("SNAP", 5).scapy("SNAP").tshark("llc")
            .etherparse("SnapHeader", "src/proto_audit/snap.rs")
            .ieee(&["802.2-1998"])
            .libpcap("snap_header", "pcap/proto_audit/snap.h"),
        PN::new("STP", 35).scapy("STP").tshark("stp")
            .etherparse("StpHeader", "src/proto_audit/stp.rs")
            .libpcap("stp_header", "pcap/proto_audit/stp.h")
            .ieee(&["802.1D-2004"]),
        PN::new("LACP", 110).scapy("SlowProtocol").tshark("lacp")
            .libpcap("lacp_header", "pcap/proto_audit/lacp.h")
            .ieee(&["802.1AX-2020"])
            .etherparse("LACPHeader", "src/proto_audit/lacp.rs"),
        PN::new("QinQ", 8)
            .kernel("vlan_hdr", "linux/if_vlan.h")
            .scapy("Dot1AD")
            .tshark("vlan")
            .ieee(&["802.1ad-2005", "802.1Q-2022"])
            .etherparse("QinQHeader", "src/proto_audit/qinq.rs")
            .libpcap("qinq_header", "pcap/proto_audit/qinq.h"),
        PN::new("WOL", 102).tshark("wol")
            .etherparse("WOLHeader", "src/proto_audit/wol.rs")
            .libpcap("wol_header", "pcap/proto_audit/wol.h"),
        PN::new("HomePlug_AV", 4).scapy("HomePlugAV").tshark("homeplug-av").variable()
            .etherparse("HomePlug_AVHeader", "src/proto_audit/homeplug_av.rs")
            .libpcap("homeplug_av_header", "pcap/proto_audit/homeplug_av.h"),
        // ── Layer 3 Additions ──
        PN::new("SCTP", 12)
            .xdp2("xdp2_parse_sctp")
            .kernel("sctphdr", "linux/sctp.h")
            .scapy("SCTP")
            .tshark("sctp")
            .etherparse("SctpHeader", "src/proto_audit/sctp.rs")
            .libpcap("SCTP", "gencode.c")
            .variable()
            .rfcs(&[9260, 4960]),
        PN::new("DCCP", 12)
            .xdp2("xdp2_parse_dccp")
            .kernel("dccp_hdr", "linux/dccp.h")
            .scapy("DCCP")
            .tshark("dccp")
            .etherparse("DccpHeader", "src/proto_audit/dccp.rs")
            .libpcap("dccp_header", "pcap/proto_audit/dccp.h")
            .variable()
            .rfcs(&[4340, 5595]),
        PN::new("GTP_U", 8).scapy("GTP_U_Header").tshark("gtp")
            .libpcap("gtp_u_header", "pcap/proto_audit/gtp.h")
            .variable()
            .rfcs(&[2152])
            .etherparse("GTP_UHeader", "src/proto_audit/gtp_u.rs"),
        PN::new("GTP_C", 8).scapy("GTPHeader").tshark("gtpv2")
            .libpcap("gtp_c_header", "pcap/proto_audit/gtp.h")
            .variable()
            .etherparse("GTP_CHeader", "src/proto_audit/gtp_c.rs"),
        PN::new("PIM", 4).scapy("PIM").tshark("pim")
            .libpcap("pim_header", "pcap/proto_audit/pim.h")
            .variable()
            .rfcs(&[7761, 4601])
            .etherparse("PIMHeader", "src/proto_audit/pim.rs"),
        PN::new("IPv6_Fragment", 8)
            .kernel("frag_hdr", "linux/ipv6.h")
            .scapy("IPv6ExtHdrFragment")
            .tshark("ipv6.fraghdr")
            .rfcs(&[8200])
            .etherparse("IPv6ExtHdrFragmentHeader", "src/proto_audit/ipv6_fragment.rs")
            .libpcap("ipv6_fragment_header", "pcap/proto_audit/ipv6_fragment.h"),
        PN::new("IPv6_DestOpts", 2)
            .kernel("ipv6_opt_hdr", "linux/ipv6.h")
            .scapy("IPv6ExtHdrDestOpt")
            .tshark("ipv6.dstopts")
            .variable()
            .rfcs(&[8200])
            .etherparse("IPv6ExtHdrDestOptHeader", "src/proto_audit/ipv6_destopts.rs")
            .libpcap("ipv6_destopts_header", "pcap/proto_audit/ipv6_destopts.h"),
        PN::new("IPv6_Routing", 4)
            .kernel("ipv6_rt_hdr", "linux/ipv6.h")
            .scapy("IPv6ExtHdrRouting")
            .tshark("ipv6.routing")
            .variable()
            .rfcs(&[8200, 6554])
            .etherparse("IPv6ExtHdrRoutingHeader", "src/proto_audit/ipv6_routing.rs")
            .libpcap("ipv6_routing_header", "pcap/proto_audit/ipv6_routing.h"),
        // ── Layer 4 Additions ──
        PN::new("UDPLite", 8).tshark("udplite")
            .rfcs(&[3828])
            .etherparse("UDPLiteHeader", "src/proto_audit/udplite.rs")
            .libpcap("udplite_header", "pcap/proto_audit/udplite.h"),
        PN::new("SCTP_Chunk", 4)
            .xdp2("xdp2_parse_sctp_chunk")
            .kernel("sctp_chunkhdr", "linux/sctp.h")
            .scapy("SCTPChunkData")
            .tshark("sctp.chunk")
            .variable()
            .rfcs(&[9260])
            .etherparse("SCTPChunkDataHeader", "src/proto_audit/sctp_chunk.rs")
            .libpcap("sctp_chunk_header", "pcap/proto_audit/sctp_chunk.h"),
        // ── Tunneling Additions ──
        PN::new("WireGuard", 4).scapy("WireGuard").tshark("wireguard")
            .etherparse("WireGuardHeader", "src/proto_audit/wire_guard.rs").variable()
            .rfcs(&[7301])
            .libpcap("wireguard_header", "pcap/proto_audit/wireguard.h"),
        PN::new("IP_in_IP", 20).scapy("IP").tshark("ipip").variable()
            .rfcs(&[2003, 1853])
            .etherparse("IPHeader", "src/proto_audit/ip_in_ip.rs")
            .libpcap("ip_in_ip_header", "pcap/proto_audit/ip_in_ip.h"),
        PN::new("NVGRE", 8).scapy("NVGRE").tshark("nvgre")
            .etherparse("NvgreHeader", "src/proto_audit/nvgre.rs")
            .rfcs(&[7637])
            .libpcap("nvgre_header", "pcap/proto_audit/nvgre.h"),
        PN::new("LISP", 8).scapy("LISP").tshark("lisp").variable()
            .rfcs(&[9300, 9301, 6830])
            .etherparse("LISPHeader", "src/proto_audit/lisp.rs")
            .libpcap("lisp_header", "pcap/proto_audit/lisp.h"),
        PN::new("STT", 18).tshark("stt").variable()
            .etherparse("STTHeader", "src/proto_audit/stt.rs")
            .libpcap("stt_header", "pcap/proto_audit/stt.h"),
        PN::new("Teredo", 2).tshark("teredo").variable()
            .rfcs(&[4380])
            .etherparse("TeredoHeader", "src/proto_audit/teredo.rs")
            .libpcap("teredo_header", "pcap/proto_audit/teredo.h"),
        PN::new("GUE", 4).tshark("gue").variable()
            .etherparse("GUEHeader", "src/proto_audit/gue.rs")
            .libpcap("gue_header", "pcap/proto_audit/gue.h"),
        PN::new("VXLAN_GPE", 8).scapy("VXLAN_GPE").tshark("vxlan")
            .etherparse("VxlanGpeHeader", "src/proto_audit/vxlan_gpe.rs")
            .libpcap("vxlan_gpe_header", "pcap/proto_audit/vxlan_gpe.h"),
        // ── Security Additions ──
        PN::new("TLS", 5).scapy("TLS").tshark("tls").variable()
            .rfcs(&[8446, 5246, 8447])
            .etherparse("TLSHeader", "src/proto_audit/tls.rs")
            .libpcap("tls_header", "pcap/proto_audit/tls.h"),
        PN::new("DTLS", 13).scapy("DTLS").tshark("dtls").variable()
            .rfcs(&[9147, 6347])
            .etherparse("DTLSHeader", "src/proto_audit/dtls.rs")
            .libpcap("dtls_header", "pcap/proto_audit/dtls.h"),
        PN::new("IKEv2", 28).scapy("IKEv2").tshark("isakmp").variable()
            .rfcs(&[7296, 4306])
            .etherparse("IKEv2Header", "src/proto_audit/ikev2.rs")
            .libpcap("ikev2_header", "pcap/proto_audit/ikev2.h"),
        PN::new("EAP", 4).scapy("EAP").tshark("eap").variable()
            .rfcs(&[3748, 5247])
            .etherparse("EAPHeader", "src/proto_audit/eap.rs")
            .libpcap("eap_header", "pcap/proto_audit/eap.h"),
        // ── DNS Family & Discovery ──
        PN::new("mDNS", 12).scapy("DNS").tshark("mdns").variable()
            .rfcs(&[6762])
            .etherparse("mDNSHeader", "src/proto_audit/mdns.rs")
            .libpcap("mdns_header", "pcap/proto_audit/mdns.h"),
        PN::new("LLMNR", 12).scapy("DNS").tshark("llmnr").variable()
            .rfcs(&[4795])
            .etherparse("LLMNRHeader", "src/proto_audit/llmnr.rs")
            .libpcap("llmnr_header", "pcap/proto_audit/llmnr.h"),
        PN::new("NBNS", 12).scapy("NBNSQueryRequest").tshark("nbns").variable()
            .rfcs(&[1002])
            .etherparse("NBNSHeader", "src/proto_audit/nbns.rs")
            .libpcap("nbns_header", "pcap/proto_audit/nbns.h"),
        PN::new("PPPoED", 6).scapy("PPPoED").tshark("pppoed").variable()
            .rfcs(&[2516])
            .etherparse("PPPoEDHeader", "src/proto_audit/pppoed.rs")
            .libpcap("pppoed_header", "pcap/proto_audit/pppoed.h"),
        PN::new("LLTD", 14).tshark("lltd").variable()
            .etherparse("LLTDHeader", "src/proto_audit/lltd.rs")
            .libpcap("lltd_header", "pcap/proto_audit/lltd.h"),
        // ── VoIP / Telephony ──
        PN::new("SIP", 20).scapy("SIP").tshark("sip").variable()
            .rfcs(&[3261, 6026])
            .etherparse("SIPHeader", "src/proto_audit/sip.rs")
            .libpcap("sip_header", "pcap/proto_audit/sip.h"),
        PN::new("RTCP", 8).scapy("RTCP").tshark("rtcp").variable()
            .rfcs(&[3550])
            .etherparse("RTCPHeader", "src/proto_audit/rtcp.rs")
            .libpcap("rtcp_header", "pcap/proto_audit/rtcp.h"),
        PN::new("RTSP", 12).tshark("rtsp").variable()
            .rfcs(&[7826, 2326])
            .etherparse("RTSPHeader", "src/proto_audit/rtsp.rs")
            .libpcap("rtsp_header", "pcap/proto_audit/rtsp.h"),
        PN::new("STUN", 20).scapy("STUN").tshark("stun")
            .libpcap("stun_header", "pcap/proto_audit/stun.h")
            .rfcs(&[8489, 5389])
            .etherparse("STUNHeader", "src/proto_audit/stun.rs"),
        PN::new("Skinny", 12).scapy("Skinny").tshark("skinny").variable()
            .etherparse("SkinnyHeader", "src/proto_audit/skinny.rs")
            .libpcap("skinny_header", "pcap/proto_audit/skinny.h"),
        PN::new("MGCP", 4).tshark("mgcp").variable()
            .rfcs(&[3435])
            .etherparse("MGCPHeader", "src/proto_audit/mgcp.rs")
            .libpcap("mgcp_header", "pcap/proto_audit/mgcp.h"),
        // ── IoT / Industrial ──
        PN::new("MQTT", 2).scapy("MQTT").tshark("mqtt")
            .libpcap("mqtt_header", "pcap/proto_audit/mqtt.h")
            .variable()
            .etherparse("MQTTHeader", "src/proto_audit/mqtt.rs"),
        PN::new("CoAP", 4).scapy("CoAP").tshark("coap").variable()
            .rfcs(&[7252, 7641, 8323])
            .etherparse("CoAPHeader", "src/proto_audit/coap.rs")
            .libpcap("coap_header", "pcap/proto_audit/coap.h"),
        PN::new("MODBUS_TCP", 7).scapy("ModbusADU").tshark("modbus")
            .libpcap("modbus_tcp_header", "pcap/proto_audit/modbus.h")
            .variable()
            .etherparse("MODBUS_TCPHeader", "src/proto_audit/modbus_tcp.rs"),
        PN::new("BACnet", 4).scapy("BVLC").tshark("bacnet").variable()
            .etherparse("BACnetHeader", "src/proto_audit/bacnet.rs")
            .libpcap("bacnet_header", "pcap/proto_audit/bacnet.h"),
        PN::new("DNP3", 10).scapy("DNP3").tshark("dnp3").variable()
            .ieee(&["1815-2012"])
            .etherparse("DNP3Header", "src/proto_audit/dnp3.rs")
            .libpcap("dnp3_header", "pcap/proto_audit/dnp3.h"),
        PN::new("ENIP", 24).scapy("ENIP_TCP").tshark("enip").variable()
            .etherparse("ENIPHeader", "src/proto_audit/enip.rs")
            .libpcap("enip_header", "pcap/proto_audit/enip.h"),
        PN::new("CIP", 2).scapy("CIP").tshark("cip").variable()
            .etherparse("CIPHeader", "src/proto_audit/cip.rs")
            .libpcap("cip_header", "pcap/proto_audit/cip.h"),
        PN::new("OPC_UA", 8).tshark("opcua").variable()
            .etherparse("OPC_UAHeader", "src/proto_audit/opc_ua.rs")
            .libpcap("opc_ua_header", "pcap/proto_audit/opc_ua.h"),
        PN::new("IEC_GOOSE", 8).scapy("GOOSE").tshark("goose").variable()
            .etherparse("IEC_GOOSEHeader", "src/proto_audit/iec_goose.rs")
            .libpcap("iec_goose_header", "pcap/proto_audit/iec_goose.h"),
        // ── ICS / Power & Zigbee ──
        PN::new("IEC_SV", 8).tshark("sv").variable()
            .etherparse("IEC_SVHeader", "src/proto_audit/iec_sv.rs")
            .libpcap("iec_sv_header", "pcap/proto_audit/iec_sv.h"),
        PN::new("IEC_MMS", 4).tshark("mms").variable()
            .etherparse("IEC_MMSHeader", "src/proto_audit/iec_mms.rs")
            .libpcap("iec_mms_header", "pcap/proto_audit/iec_mms.h"),
        PN::new("Zigbee_NWK", 2).scapy("ZigbeeNWK").tshark("zbee_nwk").variable()
            .etherparse("Zigbee_NWKHeader", "src/proto_audit/zigbee_nwk.rs")
            .libpcap("zigbee_nwk_header", "pcap/proto_audit/zigbee_nwk.h"),
        PN::new("Zigbee_APS", 2).scapy("ZigbeeAppDataPayload").tshark("zbee_aps").variable()
            .etherparse("ZigbeeAppDataPayloadHeader", "src/proto_audit/zigbee_aps.rs")
            .libpcap("zigbee_aps_header", "pcap/proto_audit/zigbee_aps.h"),
        // ── Network Management ──
        PN::new("RADIUS", 20).scapy("Radius").tshark("radius")
            .etherparse("RadiusHeader", "src/proto_audit/radius.rs")
            .libpcap("radius_header", "pcap/proto_audit/radius.h")
            .variable()
            .rfcs(&[2865, 2866]),
        PN::new("Diameter", 20).scapy("DiamG").tshark("diameter").variable()
            .rfcs(&[6733])
            .etherparse("DiamGHeader", "src/proto_audit/diameter.rs")
            .libpcap("diameter_header", "pcap/proto_audit/diameter.h"),
        PN::new("TACACS", 12).scapy("TACACS").tshark("tacacs").variable()
            .rfcs(&[8907])
            .etherparse("TacplusHeader", "src/proto_audit/tacplus.rs")
            .libpcap("tacacs_header", "pcap/proto_audit/tacacs.h"),
        PN::new("Syslog", 1).scapy("Syslog").tshark("syslog").variable()
            .rfcs(&[5424, 3164])
            .etherparse("SyslogHeader", "src/proto_audit/syslog.rs")
            .libpcap("syslog_header", "pcap/proto_audit/syslog.h"),
        PN::new("TFTP", 4).scapy("TFTP").tshark("tftp").variable()
            .rfcs(&[1350])
            .etherparse("TFTPHeader", "src/proto_audit/tftp.rs")
            .libpcap("tftp_header", "pcap/proto_audit/tftp.h"),
        PN::new("NetFlow_v5", 24).scapy("NetflowHeaderV5").tshark("cflow").variable()
            .etherparse("NetflowHeaderV5Header", "src/proto_audit/netflow_v5.rs")
            .libpcap("netflow_v5_header", "pcap/proto_audit/netflow_v5.h"),
        PN::new("NetFlow_v9", 20).scapy("NetflowHeaderV9").tshark("cflow").variable()
            .rfcs(&[3954])
            .etherparse("NetflowHeaderV9Header", "src/proto_audit/netflow_v9.rs")
            .libpcap("netflow_v9_header", "pcap/proto_audit/netflow_v9.h"),
        PN::new("IPFIX", 16).scapy("IPFIXHeader").tshark("cflow").variable()
            .rfcs(&[7011, 5101])
            .etherparse("IPFIXHeader", "src/proto_audit/ipfix.rs")
            .libpcap("ipfix_header", "pcap/proto_audit/ipfix.h"),
        // ── Auth & Directory ──
        PN::new("LDAP", 1).tshark("ldap").variable()
            .rfcs(&[4511, 4510])
            .etherparse("LDAPHeader", "src/proto_audit/ldap.rs")
            .libpcap("ldap_header", "pcap/proto_audit/ldap.h"),
        PN::new("Kerberos", 4).scapy("Kerberos").tshark("kerberos").variable()
            .rfcs(&[4120, 4121])
            .etherparse("KerberosHeader", "src/proto_audit/kerberos.rs")
            .libpcap("kerberos_header", "pcap/proto_audit/kerberos.h"),
        PN::new("NTLMSSP", 12).tshark("ntlmssp").variable()
            .etherparse("NTLMSSPHeader", "src/proto_audit/ntlmssp.rs")
            .libpcap("ntlmssp_header", "pcap/proto_audit/ntlmssp.h"),
        PN::new("OCSP", 1).tshark("ocsp").variable()
            .rfcs(&[6960, 2560])
            .etherparse("OCSPHeader", "src/proto_audit/ocsp.rs")
            .libpcap("ocsp_header", "pcap/proto_audit/ocsp.h"),
        // ── File Transfer & Web ──
        PN::new("HTTP", 16).scapy("HTTP").tshark("http").variable()
            .rfcs(&[9110, 9112])
            .etherparse("HTTPHeader", "src/proto_audit/http.rs")
            .libpcap("http_header", "pcap/proto_audit/http.h"),
        PN::new("HTTP2", 9).scapy("HTTP2").tshark("http2").variable()
            .rfcs(&[9113, 7540])
            .etherparse("HTTP2Header", "src/proto_audit/http2.rs")
            .libpcap("http2_header", "pcap/proto_audit/http2.h"),
        PN::new("FTP", 4).tshark("ftp").variable()
            .rfcs(&[959])
            .etherparse("FTPHeader", "src/proto_audit/ftp.rs")
            .libpcap("ftp_header", "pcap/proto_audit/ftp.h"),
        PN::new("SSH", 5).tshark("ssh").variable()
            .rfcs(&[4253, 4251, 4252])
            .etherparse("SSHHeader", "src/proto_audit/ssh.rs")
            .libpcap("ssh_header", "pcap/proto_audit/ssh.h"),
        PN::new("Telnet", 1).tshark("telnet").variable()
            .rfcs(&[854, 855])
            .etherparse("TelnetHeader", "src/proto_audit/telnet.rs")
            .libpcap("telnet_header", "pcap/proto_audit/telnet.h"),
        PN::new("SMTP", 4).tshark("smtp").variable()
            .rfcs(&[5321])
            .etherparse("SMTPHeader", "src/proto_audit/smtp.rs")
            .libpcap("smtp_header", "pcap/proto_audit/smtp.h"),
        PN::new("IMAP", 1).tshark("imap").variable()
            .rfcs(&[9051, 3501])
            .etherparse("IMAPHeader", "src/proto_audit/imap.rs")
            .libpcap("imap_header", "pcap/proto_audit/imap.h"),
        // ── Message Queuing ──
        PN::new("AMQP", 7).tshark("amqp").variable()
            .etherparse("AMQPHeader", "src/proto_audit/amqp.rs")
            .libpcap("amqp_header", "pcap/proto_audit/amqp.h"),
        PN::new("Kafka", 12).tshark("kafka").variable()
            .etherparse("KafkaHeader", "src/proto_audit/kafka.rs")
            .libpcap("kafka_header", "pcap/proto_audit/kafka.h"),
        PN::new("ZeroMQ", 2).tshark("zmtp").variable()
            .etherparse("ZeroMQHeader", "src/proto_audit/zeromq.rs")
            .libpcap("zeromq_header", "pcap/proto_audit/zeromq.h"),
        PN::new("Memcache", 24).tshark("memcache").variable()
            .etherparse("MemcacheHeader", "src/proto_audit/memcache.rs")
            .libpcap("memcache_header", "pcap/proto_audit/memcache.h"),
        PN::new("Redis", 1).tshark("resp").variable()
            .etherparse("RedisHeader", "src/proto_audit/redis.rs")
            .libpcap("redis_header", "pcap/proto_audit/redis.h"),
        // ── Routing & Misc ──
        PN::new("BFD", 24).scapy("BFD").tshark("bfd")
            .etherparse("BfdHeader", "src/proto_audit/bfd.rs")
            .libpcap("bfd_header", "pcap/proto_audit/bfd.h")
            .rfcs(&[5880, 5881]),
        PN::new("LDP", 10).scapy("LDP").tshark("ldp").variable()
            .rfcs(&[5036, 3036])
            .etherparse("LDPHeader", "src/proto_audit/ldp.rs")
            .libpcap("ldp_header", "pcap/proto_audit/ldp.h"),
        PN::new("RSVP", 8).scapy("RSVP").tshark("rsvp")
            .libpcap("rsvp_header", "pcap/proto_audit/rsvp.h")
            .variable()
            .rfcs(&[2205, 3209])
            .etherparse("RSVPHeader", "src/proto_audit/rsvp.rs"),
        PN::new("MPLS_OAM", 4).tshark("mpls-echo").variable()
            .rfcs(&[8029, 4379])
            .etherparse("MPLS_OAMHeader", "src/proto_audit/mpls_oam.rs")
            .libpcap("mpls_oam_header", "pcap/proto_audit/mpls_oam.h"),
        PN::new("CARP", 8).scapy("VRRPv3").tshark("carp").variable()
            .etherparse("VRRPv3Header", "src/proto_audit/carp.rs")
            .libpcap("carp_header", "pcap/proto_audit/carp.h"),
        PN::new("GLBP", 2).tshark("glbp").variable()
            .etherparse("GLBPHeader", "src/proto_audit/glbp.rs")
            .libpcap("glbp_header", "pcap/proto_audit/glbp.h"),
        PN::new("OpenFlow", 8).scapy("OFPTHello").tshark("openflow_v4").variable()
            .etherparse("OFPTHelloHeader", "src/proto_audit/openflow.rs")
            .libpcap("openflow_header", "pcap/proto_audit/openflow.h"),
        PN::new("TZSP", 4).tshark("tzsp").variable()
            .etherparse("TZSPHeader", "src/proto_audit/tzsp.rs")
            .libpcap("tzsp_header", "pcap/proto_audit/tzsp.h"),
        PN::new("GRE_PPTP", 8).scapy("GRE_PPTP").tshark("pptp").variable()
            .rfcs(&[2637])
            .etherparse("GRE_PPTPHeader", "src/proto_audit/gre_pptp.rs")
            .libpcap("gre_pptp_header", "pcap/proto_audit/gre_pptp.h"),
        PN::new("CAPWAP", 8).scapy("CAPWAP_CTRL").tshark("capwap").variable()
            .rfcs(&[5415, 5416])
            .etherparse("CAPWAPHeader", "src/proto_audit/capwap.rs")
            .libpcap("capwap_header", "pcap/proto_audit/capwap.h"),
        PN::new("LWAPP", 6).scapy("LWAPP").tshark("lwapp").variable()
            .etherparse("LWAPPHeader", "src/proto_audit/lwapp.rs")
            .libpcap("lwapp_header", "pcap/proto_audit/lwapp.h"),
        PN::new("TPLINK_SMARTHOME", 4).tshark("tplink_smarthome").variable()
            .etherparse("TPLINK_SMARTHOMEHeader", "src/proto_audit/tplink_smarthome.rs")
            .libpcap("tplink_smarthome_header", "pcap/proto_audit/tplink_smarthome.h"),
    ]
}
