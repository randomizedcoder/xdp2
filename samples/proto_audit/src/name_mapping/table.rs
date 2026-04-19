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
            .kaitai("ethernet_frame", "ethernet_frame.ksy")
            .dpdk("rte_ether_hdr", "rte_ether.h")
            .ndpi("ndpi_ethhdr", "ndpi_typedefs.h")
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
            .kaitai("ieee_802_1q", "ieee_802_1q.ksy")
            .dpdk("rte_vlan_hdr", "rte_ether.h")
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
            .kaitai("ipv4_packet", "ipv4_packet.ksy")
            .dpdk("rte_ipv4_hdr", "rte_ip4.h")
            .ndpi("ndpi_iphdr", "ndpi_typedefs.h")
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
            .kaitai("ipv6_packet", "ipv6_packet.ksy")
            .dpdk("rte_ipv6_hdr", "rte_ip6.h")
            .ndpi("ndpi_ipv6hdr", "ndpi_typedefs.h")
            .rfcs(&[8200, 4291, 4443, 6437, 8021])
            .iana_registry("protocol-numbers"),
        PN::new("ARP", 8)
            .xdp2("xdp2_parse_arp")
            .kernel("arphdr", "linux/if_arp.h")
            .scapy("ARP")
            .tshark("arp")
            .etherparse("ArpPacket", "etherparse/src/net/arp_packet.rs")
            .libpcap("ARP", "gencode.c")
            .kaitai("arp", "arp.ksy")
            .dpdk("rte_arp_hdr", "rte_arp.h")
            .ndpi("ndpi_arphdr", "ndpi_typedefs.h")
            .variable()
            .rfcs(&[826, 5227]),
        PN::new("RARP", 8)
            .xdp2("xdp2_parse_rarp")
            .kernel("arphdr", "linux/if_arp.h")
            .scapy("ARP")
            .tshark("arp")
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
            .kaitai("icmp_packet", "icmp_packet.ksy")
            .dpdk("rte_icmp_hdr", "rte_icmp.h")
            .ndpi("ndpi_icmphdr", "ndpi_typedefs.h")
            .rfcs(&[792, 1122, 4884]),
        PN::new("ICMPv6", 8)
            .xdp2("xdp2_parse_icmpv6")
            .kernel("icmp6hdr", "linux/icmpv6.h")
            .scapy("ICMPv6Unknown")
            .tshark("icmpv6")
            .etherparse("Icmpv6Header", "etherparse/src/transport/icmpv6_header.rs")
            .ndpi("ndpi_icmp6hdr", "ndpi_typedefs.h")
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
            .kaitai("tcp_segment", "tcp_segment.ksy")
            .dpdk("rte_tcp_hdr", "rte_tcp.h")
            .ndpi("ndpi_tcphdr", "ndpi_typedefs.h")
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
            .kaitai("udp_datagram", "udp_datagram.ksy")
            .dpdk("rte_udp_hdr", "rte_udp.h")
            .ndpi("ndpi_udphdr", "ndpi_typedefs.h")
            .rfcs(&[768])
            .iana_registry("service-name-port-numbers"),
        // ── Tunneling ──
        PN::new("GRE", 4)
            .xdp2("xdp2_parse_gre_base")
            .kernel("gre_base_hdr", "linux/gre.h")
            .scapy("GRE")
            .tshark("gre")
            .etherparse("GreHeader", "src/proto_audit/gre.rs")
            .libpcap("gre_header", "pcap/proto_audit/gre.h")
            .dpdk("rte_gre_hdr", "rte_gre.h")
            .ndpi("ndpi_gre_basehdr", "ndpi_typedefs.h")
            .variable()
            .rfcs(&[2784, 2890]),
        PN::new("VXLAN", 8)
            .xdp2("xdp2_parse_vxlan")
            .kernel("vxlanhdr", "linux/vxlan.h")
            .scapy("VXLAN")
            .tshark("vxlan")
            .etherparse("VxlanHeader", "src/proto_audit/vxlan.rs")
            .libpcap("vxlan_header", "pcap/proto_audit/vxlan.h")
            .dpdk("rte_vxlan_hdr", "rte_vxlan.h")
            .ndpi("ndpi_vxlanhdr", "ndpi_typedefs.h")
            .rfcs(&[7348]),
        PN::new("Geneve", 8)
            .xdp2("xdp2_parse_geneve_base")
            .kernel("genevehdr", "linux/geneve.h")
            .scapy("GENEVE")
            .tshark("geneve")
            .etherparse("GeneveHeader", "src/proto_audit/geneve.rs")
            .libpcap("geneve_header", "pcap/proto_audit/geneve.h")
            .dpdk("rte_geneve_hdr", "rte_geneve.h")
            .variable()
            .rfcs(&[8926]),
        PN::new("MPLS", 4)
            .xdp2("xdp2_parse_mpls")
            .kernel("mpls_label", "linux/mpls.h")
            .scapy("MPLS")
            .tshark("mpls")
            .etherparse("MplsHeader", "src/proto_audit/mpls.rs")
            .libpcap("mpls_header", "pcap/proto_audit/mpls.h")
            .dpdk("rte_mpls_hdr", "rte_mpls.h")
            .ndpi("ndpi_mpls_header", "ndpi_typedefs.h")
            .rfcs(&[3031, 3032, 5462]),
        PN::new("PPP", 2)
            .xdp2("xdp2_parse_ppp")
            .kernel_header_only("linux/ppp_defs.h")
            .scapy("PPP")
            .tshark("ppp")
            .etherparse("PppHeader", "src/proto_audit/ppp.rs")
            .libpcap("ppp_header", "pcap/proto_audit/ppp.h")
            .dpdk("rte_ppp_hdr", "rte_ppp.h")
            .pppd("PPP")
            .rfcs(&[1661, 1662]),
        PN::new("PPPoE", 6)
            .xdp2("xdp2_parse_pppoe")
            .kernel("pppoe_hdr", "linux/ppp_defs.h")
            .scapy("PPPoE")
            .tshark("pppoes")
            .etherparse("PppoeHeader", "src/proto_audit/pppoe.rs")
            .libpcap("pppoe_header", "pcap/proto_audit/pppoe.h")
            .dpdk("rte_pppoe_hdr", "rte_ppp.h")
            .rfcs(&[2516]),
        PN::new("L2TP", 6)
            .xdp2("xdp2_parse_l2tp_base")
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
            .dpdk("rte_esp_hdr", "rte_esp.h")
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
            .dpdk("rte_macsec_hdr", "rte_macsec.h")
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
            .tshark("hci_h4")
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
            .tshark("ipv6.hopopts")
            .variable()
            .rfcs(&[8200])
            .etherparse("IPv6ExtHdrHopByHopHeader", "src/proto_audit/ipv6_eh.rs")
            .libpcap("ipv6_eh_header", "pcap/proto_audit/ipv6_eh.h"),
        PN::new("IPv6_ND", 24)
            .xdp2("xdp2_parse_icmpv6_nd_solicit")
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
            .tshark("mrp-mvrp")
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
        PN::new("VRRP", 8)
            .xdp2("xdp2_parse_vrrp").scapy("VRRPv3").tshark("vrrp")
            .libpcap("vrrp_header", "pcap/proto_audit/vrrp.h")
            .variable()
            .rfcs(&[5798, 9568])
            .etherparse("VRRPHeader", "src/proto_audit/vrrp.rs"),
        PN::new("HSRP", 20)
            .xdp2("xdp2_parse_hsrp").scapy("HSRP").tshark("hsrp")
            .libpcap("hsrp_header", "pcap/proto_audit/hsrp.h")
            .rfcs(&[2281])
            .etherparse("HSRPHeader", "src/proto_audit/hsrp.rs"),
        // ── Discovery ──
        PN::new("CDP", 4)
            .xdp2("xdp2_parse_cdp").scapy("CDPv2_HDR").tshark("cdp").variable()
            .etherparse("CDPHeader", "src/proto_audit/cdp.rs")
            .libpcap("cdp_header", "pcap/proto_audit/cdp.h"),
        // ── Routing ──
        PN::new("RIP", 4)
            .xdp2("xdp2_parse_rip").scapy("RIP").tshark("rip")
            .libpcap("rip_header", "pcap/proto_audit/rip.h")
            .variable()
            .rfcs(&[2453, 1058])
            .etherparse("RIPHeader", "src/proto_audit/rip.rs"),
        PN::new("OSPF", 24)
            .xdp2("xdp2_parse_ospf").scapy("OSPF_Hdr").tshark("ospf")
            .libpcap("ospf_header", "pcap/proto_audit/ospf.h")
            .rfcs(&[2328, 5340])
            .etherparse("OSPF_HdrHeader", "src/proto_audit/ospf.rs"),
        PN::new("ISIS", 8)
            .xdp2("xdp2_parse_isis").scapy("ISIS_CommonHdr").tshark("isis").variable()
            .libpcap("isis_header", "pcap/proto_audit/isis.h")
            .rfcs(&[1195])
            .etherparse("ISISHeader", "src/proto_audit/isis.rs"),
        PN::new("BGP", 19)
            .xdp2("xdp2_parse_bgp").scapy("BGPHeader").tshark("bgp").variable()
            .rfcs(&[4271, 7606, 8654, 9072])
            .etherparse("BGPHeader", "src/proto_audit/bgp.rs")
            .libpcap("bgp_header", "pcap/proto_audit/bgp.h"),
        PN::new("EIGRP", 20)
            .xdp2("xdp2_parse_eigrp").scapy("EIGRP").tshark("eigrp")
            .libpcap("eigrp_header", "pcap/proto_audit/eigrp.h")
            .variable()
            .etherparse("EIGRPHeader", "src/proto_audit/eigrp.rs"),
        // ── Bluetooth (upper layers) ──
        PN::new("BT_ATT", 1)
            .xdp2("xdp2_parse_bt_att").scapy("ATT_Hdr").tshark("btatt").variable()
            .etherparse("ATT_HdrHeader", "src/proto_audit/bt_att.rs")
            .libpcap("bt_att_header", "pcap/proto_audit/bt_att.h"),
        PN::new("BT_SMP", 1)
            .xdp2("xdp2_parse_bt_smp").scapy("SM_Hdr").tshark("btsmp").variable()
            .etherparse("SM_HdrHeader", "src/proto_audit/bt_smp.rs")
            .libpcap("bt_smp_header", "pcap/proto_audit/bt_smp.h"),
        PN::new("BT_RFCOMM", 4)
            .xdp2("xdp2_parse_bt_rfcomm").scapy("RFCOMM_Hdr").tshark("btrfcomm").variable()
            .etherparse("BT_RFCOMMHeader", "src/proto_audit/bt_rfcomm.rs")
            .libpcap("bt_rfcomm_header", "pcap/proto_audit/bt_rfcomm.h"),
        PN::new("BT_BNEP", 3)
            .xdp2("xdp2_parse_bt_bnep").scapy("BNEP").tshark("btbnep").variable()
            .etherparse("BT_BNEPHeader", "src/proto_audit/bt_bnep.rs")
            .libpcap("bt_bnep_header", "pcap/proto_audit/bt_bnep.h"),
        PN::new("BT_SDP", 3)
            .xdp2("xdp2_parse_bt_sdp").scapy("SDP_Hdr").tshark("btsdp").variable()
            .etherparse("BT_SDPHeader", "src/proto_audit/bt_sdp.rs")
            .libpcap("bt_sdp_header", "pcap/proto_audit/bt_sdp.h"),
        PN::new("BT_AVDTP", 2)
            .xdp2("xdp2_parse_bt_avdtp").scapy("AVDTP_Hdr").tshark("btavdtp").variable()
            .etherparse("BT_AVDTPHeader", "src/proto_audit/bt_avdtp.rs")
            .libpcap("bt_avdtp_header", "pcap/proto_audit/bt_avdtp.h"),
        // ── InfiniBand (extended transport headers) ──
        PN::new("IB_DETH", 8)
            .xdp2("xdp2_parse_ib_deth").scapy("IB_DETH").tshark("infiniband.deth")
            .etherparse("IB_DETHHeader", "src/proto_audit/ib_deth.rs")
            .libpcap("ib_deth_header", "pcap/proto_audit/ib_deth.h"),
        PN::new("IB_RETH", 16)
            .xdp2("xdp2_parse_ib_reth").scapy("IB_RETH").tshark("infiniband.reth")
            .etherparse("IB_RETHHeader", "src/proto_audit/ib_reth.rs")
            .libpcap("ib_reth_header", "pcap/proto_audit/ib_reth.h"),
        PN::new("IB_AETH", 4)
            .xdp2("xdp2_parse_ib_aeth").scapy("IB_AETH").tshark("infiniband.aeth")
            .etherparse("IB_AETHHeader", "src/proto_audit/ib_aeth.rs")
            .libpcap("ib_aeth_header", "pcap/proto_audit/ib_aeth.h"),
        PN::new("IB_RDETH", 4)
            .xdp2("xdp2_parse_ib_rdeth").scapy("IB_RDETH").tshark("infiniband.rdeth")
            .etherparse("IB_RDETHHeader", "src/proto_audit/ib_rdeth.rs")
            .libpcap("ib_rdeth_header", "pcap/proto_audit/ib_rdeth.h"),
        PN::new("IB_AtomicETH", 28)
            .xdp2("xdp2_parse_ib_atomiceth").scapy("IB_AtomicETH").tshark("infiniband.atomiceth")
            .etherparse("IB_AtomicETHHeader", "src/proto_audit/ib_atomiceth.rs")
            .libpcap("ib_atomiceth_header", "pcap/proto_audit/ib_atomiceth.h"),
        PN::new("IB_ImmDt", 4)
            .xdp2("xdp2_parse_ib_immdt").scapy("IB_ImmDt").tshark("infiniband.immdt")
            .etherparse("IB_ImmDtHeader", "src/proto_audit/ib_immdt.rs")
            .libpcap("ib_immdt_header", "pcap/proto_audit/ib_immdt.h"),
        PN::new("IB_MAD", 24)
            .xdp2("xdp2_parse_ib_mad").scapy("IB_MAD").tshark("infiniband.mad").variable()
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
        PN::new("MPEG_TS", 188)
            .xdp2("xdp2_parse_mpeg_ts").scapy("MPEG_TS").tshark("mp2t")
            .etherparse("MPEG_TSHeader", "src/proto_audit/mpeg_ts.rs")
            .libpcap("mpeg_ts_header", "pcap/proto_audit/mpeg_ts.h"),
        PN::new("RTP", 12)
            .xdp2("xdp2_parse_rtp").scapy("RTP").tshark("rtp")
            .etherparse("RtpHeader", "src/proto_audit/rtp.rs")
            .libpcap("rtp_header", "pcap/proto_audit/rtp.h")
            .kaitai("rtp_packet", "rtp_packet.ksy")
            .variable()
            .rfcs(&[3550, 3551]),
        PN::new("SRT", 16)
            .xdp2("xdp2_parse_srt").scapy("SRT").tshark("srt").variable()
            .etherparse("SRTHeader", "src/proto_audit/srt.rs")
            .libpcap("srt_header", "pcap/proto_audit/srt.h"),
        // ── UDP Application Protocols ──
        PN::new("DNS", 12)
            .xdp2("xdp2_parse_dns").scapy("DNS").tshark("dns")
            .etherparse("DnsHeader", "src/proto_audit/dns.rs")
            .libpcap("dns_header", "pcap/proto_audit/dns.h")
            .kaitai("dns_packet", "dns_packet.ksy")
            .suricata("dns", "DnsHeader")
            .ndpi("ndpi_dns_packet_header", "ndpi_typedefs.h")
            .variable()
            .rfcs(&[1035, 2671, 6891, 8484]),
        PN::new("NTP", 48)
            .xdp2("xdp2_parse_ntp").scapy("NTPHeader").tshark("ntp")
            .etherparse("NtpHeader", "src/proto_audit/ntp.rs")
            .libpcap("ntp_header", "pcap/proto_audit/ntp.h")
            .suricata("ntp", "NtpHeader")
            .variable()
            .rfcs(&[5905]),
        PN::new("SNMP", 10)
            .xdp2("xdp2_parse_snmp").scapy("SNMP").tshark("snmp").variable()
            .suricata("snmp", "SnmpHeader")
            .rfcs(&[3411, 3412, 3414, 3416])
            .etherparse("SNMPHeader", "src/proto_audit/snmp.rs")
            .libpcap("snmp_header", "pcap/proto_audit/snmp.h"),
        PN::new("DHCP", 236)
            .xdp2("xdp2_parse_dhcp").scapy("BOOTP").tshark("dhcp")
            .libpcap("dhcp_header", "pcap/proto_audit/dhcp.h")
            .suricata("dhcp", "DHCPHeader")
            .ndpi("ndpi_dhcphdr", "ndpi_typedefs.h")
            .variable()
            .rfcs(&[2131, 2132])
            .etherparse("DHCPHeader", "src/proto_audit/dhcp.rs"),
        PN::new("DHCPv6", 4)
            .xdp2("xdp2_parse_dhcpv6").scapy("DHCP6").tshark("dhcpv6").variable()
            .rfcs(&[8415])
            .etherparse("DHCPv6Header", "src/proto_audit/dhcpv6.rs")
            .libpcap("dhcpv6_header", "pcap/proto_audit/dhcpv6.h"),
        PN::new("QUIC", 20)
            .xdp2("xdp2_parse_quic").scapy("QUIC_Initial").tshark("quic").variable()
            .suricata("quic", "QuicHeader")
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
        PN::new("NFS", 4)
            .xdp2("xdp2_parse_nfs").scapy("NFS_Call").tshark("nfs").variable()
            .rfcs(&[7530, 8881])
            .etherparse("NFSHeader", "src/proto_audit/nfs.rs")
            .libpcap("nfs_header", "pcap/proto_audit/nfs.h"),
        PN::new("SMB", 32)
            .xdp2("xdp2_parse_smb").scapy("SMB_Header").tshark("smb").variable()
            .suricata("smb", "SmbHeader")
            .etherparse("SMB_HeaderHeader", "src/proto_audit/smb.rs")
            .libpcap("smb_header", "pcap/proto_audit/smb.h"),
        PN::new("SMB2", 64)
            .xdp2("xdp2_parse_smb2").scapy("SMB2_Header").tshark("smb2").variable()
            .etherparse("SMB2_HeaderHeader", "src/proto_audit/smb2.rs")
            .libpcap("smb2_header", "pcap/proto_audit/smb2.h"),
        PN::new("ONC_RPC", 4)
            .xdp2("xdp2_parse_onc_rpc").scapy("RPC").tshark("rpc").variable()
            .rfcs(&[5531, 1831])
            .etherparse("ONC_RPCHeader", "src/proto_audit/onc_rpc.rs")
            .libpcap("onc_rpc_header", "pcap/proto_audit/onc_rpc.h"),
        // ── Capture Layer / L1 Encapsulations ──
        PN::new("SLL", 16)
            .xdp2("xdp2_parse_sll")
            .scapy("CookedLinux")
            .tshark("sll")
            .libpcap("sll_header", "pcap/sll.h")
            .etherparse("CookedLinuxHeader", "src/proto_audit/sll.rs"),
        PN::new("SLL2", 20)
            .xdp2("xdp2_parse_sll2")
            .scapy("CookedLinuxV2")
            .tshark("sll")
            .libpcap("sll2_header", "pcap/sll.h")
            .etherparse("SLL2Header", "src/proto_audit/sll2.rs"),
        PN::new("ERF", 18)
            .xdp2("xdp2_parse_erf").scapy("ERF").tshark("erf").variable()
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
        PN::new("SNAP", 5).xdp2("xdp2_parse_llc_snap").scapy("SNAP").tshark("llc")
            .etherparse("SnapHeader", "src/proto_audit/snap.rs")
            .ieee(&["802.2-1998"])
            .libpcap("snap_header", "pcap/proto_audit/snap.h"),
        PN::new("STP", 35)
            .xdp2("xdp2_parse_stp").scapy("STP").tshark("stp")
            .etherparse("StpHeader", "src/proto_audit/stp.rs")
            .libpcap("stp_header", "pcap/proto_audit/stp.h")
            .ieee(&["802.1D-2004"]),
        PN::new("LACP", 110)
            .xdp2("xdp2_parse_lacp").scapy("SlowProtocol").tshark("slow")
            .libpcap("lacp_header", "pcap/proto_audit/lacp.h")
            .ieee(&["802.1AX-2020"])
            .etherparse("LACPHeader", "src/proto_audit/lacp.rs"),
        PN::new("QinQ", 8)
            .xdp2("xdp2_parse_qinq")
            .kernel("vlan_hdr", "linux/if_vlan.h")
            .scapy("Dot1AD")
            .tshark("ieee8021ad")
            .ieee(&["802.1ad-2005", "802.1Q-2022"])
            .etherparse("QinQHeader", "src/proto_audit/qinq.rs")
            .libpcap("qinq_header", "pcap/proto_audit/qinq.h"),
        PN::new("WOL", 102)
            .xdp2("xdp2_parse_wol").tshark("wol")
            .etherparse("WOLHeader", "src/proto_audit/wol.rs")
            .libpcap("wol_header", "pcap/proto_audit/wol.h"),
        PN::new("HomePlug_AV", 4)
            .xdp2("xdp2_parse_homeplug_av").scapy("HomePlugAV").tshark("homeplug-av").variable()
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
            .dpdk("rte_sctp_hdr", "rte_sctp.h")
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
        PN::new("GTP_U", 8)
            .xdp2("xdp2_parse_gtpu").scapy("GTP_U_Header").tshark("gtp")
            .libpcap("gtp_u_header", "pcap/proto_audit/gtp.h")
            .dpdk("rte_gtp_hdr", "rte_gtp.h")
            .variable()
            .rfcs(&[2152])
            .etherparse("GTP_UHeader", "src/proto_audit/gtp_u.rs"),
        PN::new("GTP_C", 8)
            .xdp2("xdp2_parse_gtp_c").scapy("GTPHeader").tshark("gtpv2")
            .libpcap("gtp_c_header", "pcap/proto_audit/gtp.h")
            .variable()
            .etherparse("GTP_CHeader", "src/proto_audit/gtp_c.rs"),
        PN::new("PIM", 4)
            .xdp2("xdp2_parse_pim").scapy("PIM").tshark("pim")
            .libpcap("pim_header", "pcap/proto_audit/pim.h")
            .variable()
            .rfcs(&[7761, 4601])
            .etherparse("PIMHeader", "src/proto_audit/pim.rs"),
        PN::new("IPv6_Fragment", 8)
            .xdp2("xdp2_parse_ipv6_frag_eh")
            .kernel("frag_hdr", "linux/ipv6.h")
            .scapy("IPv6ExtHdrFragment")
            .tshark("ipv6.fraghdr")
            .rfcs(&[8200])
            .etherparse("IPv6ExtHdrFragmentHeader", "src/proto_audit/ipv6_fragment.rs")
            .libpcap("ipv6_fragment_header", "pcap/proto_audit/ipv6_fragment.h"),
        PN::new("IPv6_DestOpts", 2)
            .xdp2("xdp2_parse_ipv6_eh")
            .kernel("ipv6_opt_hdr", "linux/ipv6.h")
            .scapy("IPv6ExtHdrDestOpt")
            .tshark("ipv6.dstopts")
            .variable()
            .rfcs(&[8200])
            .etherparse("IPv6ExtHdrDestOptHeader", "src/proto_audit/ipv6_destopts.rs")
            .libpcap("ipv6_destopts_header", "pcap/proto_audit/ipv6_destopts.h"),
        PN::new("IPv6_Routing", 4)
            .xdp2("xdp2_parse_ipv6_routing_hdr")
            .kernel("ipv6_rt_hdr", "linux/ipv6.h")
            .scapy("IPv6ExtHdrRouting")
            .tshark("ipv6.routing")
            .variable()
            .rfcs(&[8200, 6554])
            .etherparse("IPv6ExtHdrRoutingHeader", "src/proto_audit/ipv6_routing.rs")
            .libpcap("ipv6_routing_header", "pcap/proto_audit/ipv6_routing.h"),
        // ── Layer 4 Additions ──
        PN::new("UDPLite", 8)
            .xdp2("xdp2_parse_udplite").tshark("udplite")
            .rfcs(&[3828])
            .etherparse("UDPLiteHeader", "src/proto_audit/udplite.rs")
            .libpcap("udplite_header", "pcap/proto_audit/udplite.h"),
        PN::new("SCTP_Chunk", 4)
            .xdp2("xdp2_parse_sctp_chunks")
            .kernel("sctp_chunkhdr", "linux/sctp.h")
            .scapy("SCTPChunkData")
            .tshark("sctp.chunk")
            .variable()
            .rfcs(&[9260])
            .etherparse("SCTPChunkDataHeader", "src/proto_audit/sctp_chunk.rs")
            .libpcap("sctp_chunk_header", "pcap/proto_audit/sctp_chunk.h"),
        // ── Tunneling Additions ──
        PN::new("WireGuard", 4)
            .xdp2("xdp2_parse_wireguard").scapy("Wireguard").tshark("wg")
            .etherparse("WireGuardHeader", "src/proto_audit/wire_guard.rs").variable()
            .rfcs(&[7301])
            .libpcap("wireguard_header", "pcap/proto_audit/wireguard.h"),
        PN::new("IP_in_IP", 20).xdp2("xdp2_parse_ip_in_ip").scapy("IP").tshark("ip").variable()
            .rfcs(&[2003, 1853])
            .etherparse("IPHeader", "src/proto_audit/ip_in_ip.rs")
            .libpcap("ip_in_ip_header", "pcap/proto_audit/ip_in_ip.h"),
        PN::new("NVGRE", 8)
            .xdp2("xdp2_parse_nvgre").scapy("NVGRE").tshark("nvgre")
            .etherparse("NvgreHeader", "src/proto_audit/nvgre.rs")
            .rfcs(&[7637])
            .libpcap("nvgre_header", "pcap/proto_audit/nvgre.h"),
        PN::new("LISP", 8)
            .xdp2("xdp2_parse_lisp").scapy("LISP").tshark("lisp").variable()
            .rfcs(&[9300, 9301, 6830])
            .etherparse("LISPHeader", "src/proto_audit/lisp.rs")
            .libpcap("lisp_header", "pcap/proto_audit/lisp.h"),
        PN::new("STT", 18)
            .xdp2("xdp2_parse_stt").tshark("stt").variable()
            .etherparse("STTHeader", "src/proto_audit/stt.rs")
            .libpcap("stt_header", "pcap/proto_audit/stt.h"),
        PN::new("Teredo", 2)
            .xdp2("xdp2_parse_teredo").tshark("teredo").variable()
            .rfcs(&[4380])
            .etherparse("TeredoHeader", "src/proto_audit/teredo.rs")
            .libpcap("teredo_header", "pcap/proto_audit/teredo.h"),
        PN::new("GUE", 4)
            .xdp2("xdp2_parse_gue").tshark("gue").variable()
            .etherparse("GUEHeader", "src/proto_audit/gue.rs")
            .libpcap("gue_header", "pcap/proto_audit/gue.h"),
        PN::new("VXLAN_GPE", 8)
            .xdp2("xdp2_parse_vxlan_gpe").scapy("VXLAN_GPE").tshark("vxlan")
            .etherparse("VxlanGpeHeader", "src/proto_audit/vxlan_gpe.rs")
            .libpcap("vxlan_gpe_header", "pcap/proto_audit/vxlan_gpe.h")
            .dpdk("rte_vxlan_gpe_hdr", "rte_vxlan.h"),
        // ── Security Additions ──
        PN::new("TLS", 5)
            .xdp2("xdp2_parse_tls").scapy("TLS").tshark("tls").variable()
            .dpdk("rte_tls_hdr", "rte_tls.h")
            .rfcs(&[8446, 5246, 8447])
            .etherparse("TLSHeader", "src/proto_audit/tls.rs")
            .libpcap("tls_header", "pcap/proto_audit/tls.h"),
        PN::new("DTLS", 13)
            .xdp2("xdp2_parse_dtls").scapy("DTLS").tshark("dtls").variable()
            .dpdk("rte_dtls_hdr", "rte_dtls.h")
            .rfcs(&[9147, 6347])
            .etherparse("DTLSHeader", "src/proto_audit/dtls.rs")
            .libpcap("dtls_header", "pcap/proto_audit/dtls.h"),
        PN::new("IKEv2", 28)
            .xdp2("xdp2_parse_ikev2").scapy("IKEv2").tshark("isakmp").variable()
            .suricata("ike", "IsakmpHeader")
            .rfcs(&[7296, 4306])
            .etherparse("IKEv2Header", "src/proto_audit/ikev2.rs")
            .libpcap("ikev2_header", "pcap/proto_audit/ikev2.h"),
        PN::new("EAP", 4)
            .xdp2("xdp2_parse_eap").scapy("EAP").tshark("eap").variable()
            .rfcs(&[3748, 5247])
            .etherparse("EAPHeader", "src/proto_audit/eap.rs")
            .libpcap("eap_header", "pcap/proto_audit/eap.h"),
        // ── DNS Family & Discovery ──
        PN::new("mDNS", 12)
            .xdp2("xdp2_parse_mdns").scapy("DNS").tshark("mdns").variable()
            .suricata("mdns", "MdnsHeader")
            .rfcs(&[6762])
            .etherparse("mDNSHeader", "src/proto_audit/mdns.rs")
            .libpcap("mdns_header", "pcap/proto_audit/mdns.h"),
        PN::new("LLMNR", 12)
            .xdp2("xdp2_parse_llmnr").scapy("DNS").tshark("llmnr").variable()
            .rfcs(&[4795])
            .etherparse("LLMNRHeader", "src/proto_audit/llmnr.rs")
            .libpcap("llmnr_header", "pcap/proto_audit/llmnr.h"),
        PN::new("NBNS", 12)
            .xdp2("xdp2_parse_nbns").scapy("NBNSQueryRequest").tshark("nbns").variable()
            .rfcs(&[1002])
            .etherparse("NBNSHeader", "src/proto_audit/nbns.rs")
            .libpcap("nbns_header", "pcap/proto_audit/nbns.h"),
        PN::new("PPPoED", 6)
            .xdp2("xdp2_parse_ppoed").scapy("PPPoED").tshark("pppoed").variable()
            .rfcs(&[2516])
            .etherparse("PPPoEDHeader", "src/proto_audit/pppoed.rs")
            .libpcap("pppoed_header", "pcap/proto_audit/pppoed.h"),
        PN::new("LLTD", 14)
            .xdp2("xdp2_parse_lltd").tshark("lltd").variable()
            .etherparse("LLTDHeader", "src/proto_audit/lltd.rs")
            .libpcap("lltd_header", "pcap/proto_audit/lltd.h"),
        // ── VoIP / Telephony ──
        PN::new("SIP", 20)
            .xdp2("xdp2_parse_sip").scapy("SIP").tshark("sip").variable()
            .suricata("sip", "SipHeader")
            .rfcs(&[3261, 6026])
            .etherparse("SIPHeader", "src/proto_audit/sip.rs")
            .libpcap("sip_header", "pcap/proto_audit/sip.h"),
        PN::new("RTCP", 8)
            .xdp2("xdp2_parse_rtcp").scapy("RTCP").tshark("rtcp").variable()
            .kaitai("rtcp_packet", "rtcp_packet.ksy")
            .rfcs(&[3550])
            .etherparse("RTCPHeader", "src/proto_audit/rtcp.rs")
            .libpcap("rtcp_header", "pcap/proto_audit/rtcp.h"),
        PN::new("RTSP", 12)
            .xdp2("xdp2_parse_rtsp").tshark("rtsp").variable()
            .rfcs(&[7826, 2326])
            .etherparse("RTSPHeader", "src/proto_audit/rtsp.rs")
            .libpcap("rtsp_header", "pcap/proto_audit/rtsp.h"),
        PN::new("STUN", 20)
            .xdp2("xdp2_parse_stun").scapy("STUN").tshark("stun")
            .libpcap("stun_header", "pcap/proto_audit/stun.h")
            .rfcs(&[8489, 5389])
            .etherparse("STUNHeader", "src/proto_audit/stun.rs"),
        PN::new("Skinny", 12)
            .xdp2("xdp2_parse_skinny").scapy("Skinny").tshark("skinny").variable()
            .etherparse("SkinnyHeader", "src/proto_audit/skinny.rs")
            .libpcap("skinny_header", "pcap/proto_audit/skinny.h"),
        PN::new("MGCP", 4)
            .xdp2("xdp2_parse_mgcp").tshark("mgcp").variable()
            .rfcs(&[3435])
            .etherparse("MGCPHeader", "src/proto_audit/mgcp.rs")
            .libpcap("mgcp_header", "pcap/proto_audit/mgcp.h"),
        // ── IoT / Industrial ──
        PN::new("MQTT", 2)
            .xdp2("xdp2_parse_mqtt").scapy("MQTT").tshark("mqtt")
            .libpcap("mqtt_header", "pcap/proto_audit/mqtt.h")
            .suricata("mqtt", "FixedHeader")
            .variable()
            .etherparse("MQTTHeader", "src/proto_audit/mqtt.rs"),
        PN::new("CoAP", 4)
            .xdp2("xdp2_parse_coap").scapy("CoAP").tshark("coap").variable()
            .rfcs(&[7252, 7641, 8323])
            .etherparse("CoAPHeader", "src/proto_audit/coap.rs")
            .libpcap("coap_header", "pcap/proto_audit/coap.h"),
        PN::new("MODBUS_TCP", 7)
            .xdp2("xdp2_parse_modbus_tcp").scapy("ModbusADU").tshark("modbus")
            .libpcap("modbus_tcp_header", "pcap/proto_audit/modbus.h")
            .suricata("modbus", "ModbusHeader")
            .variable()
            .etherparse("MODBUS_TCPHeader", "src/proto_audit/modbus_tcp.rs"),
        PN::new("BACnet", 4)
            .xdp2("xdp2_parse_bacnet").scapy("BVLC").tshark("bacnet").variable()
            .etherparse("BACnetHeader", "src/proto_audit/bacnet.rs")
            .libpcap("bacnet_header", "pcap/proto_audit/bacnet.h"),
        PN::new("DNP3", 10)
            .xdp2("xdp2_parse_dnp3").scapy("DNP3").tshark("dnp3").variable()
            .ieee(&["1815-2012"])
            .etherparse("DNP3Header", "src/proto_audit/dnp3.rs")
            .libpcap("dnp3_header", "pcap/proto_audit/dnp3.h"),
        PN::new("ENIP", 24)
            .xdp2("xdp2_parse_enip").scapy("ENIP_TCP").tshark("enip").variable()
            .suricata("enip", "EnipHeader")
            .etherparse("ENIPHeader", "src/proto_audit/enip.rs")
            .libpcap("enip_header", "pcap/proto_audit/enip.h"),
        PN::new("CIP", 2)
            .xdp2("xdp2_parse_cip").scapy("CIP").tshark("cip").variable()
            .etherparse("CIPHeader", "src/proto_audit/cip.rs")
            .libpcap("cip_header", "pcap/proto_audit/cip.h"),
        PN::new("OPC_UA", 8)
            .xdp2("xdp2_parse_opc_ua").tshark("opcua").variable()
            .etherparse("OPC_UAHeader", "src/proto_audit/opc_ua.rs")
            .libpcap("opc_ua_header", "pcap/proto_audit/opc_ua.h"),
        PN::new("IEC_GOOSE", 8)
            .xdp2("xdp2_parse_iec_goose").scapy("GOOSE").tshark("goose").variable()
            .etherparse("IEC_GOOSEHeader", "src/proto_audit/iec_goose.rs")
            .libpcap("iec_goose_header", "pcap/proto_audit/iec_goose.h"),
        // ── ICS / Power & Zigbee ──
        PN::new("IEC_SV", 8)
            .xdp2("xdp2_parse_iec_sv").tshark("sv").variable()
            .etherparse("IEC_SVHeader", "src/proto_audit/iec_sv.rs")
            .libpcap("iec_sv_header", "pcap/proto_audit/iec_sv.h"),
        PN::new("IEC_MMS", 4)
            .xdp2("xdp2_parse_iec_mms").tshark("mms").variable()
            .etherparse("IEC_MMSHeader", "src/proto_audit/iec_mms.rs")
            .libpcap("iec_mms_header", "pcap/proto_audit/iec_mms.h"),
        PN::new("Zigbee_NWK", 2)
            .xdp2("xdp2_parse_zigbee_nwk").scapy("ZigbeeNWK").tshark("zbee_nwk").variable()
            .etherparse("Zigbee_NWKHeader", "src/proto_audit/zigbee_nwk.rs")
            .libpcap("zigbee_nwk_header", "pcap/proto_audit/zigbee_nwk.h"),
        PN::new("Zigbee_APS", 2)
            .xdp2("xdp2_parse_zigbee_aps").scapy("ZigbeeAppDataPayload").tshark("zbee_aps").variable()
            .etherparse("ZigbeeAppDataPayloadHeader", "src/proto_audit/zigbee_aps.rs")
            .libpcap("zigbee_aps_header", "pcap/proto_audit/zigbee_aps.h"),
        // ── Network Management ──
        PN::new("RADIUS", 20)
            .xdp2("xdp2_parse_radius").scapy("Radius").tshark("radius")
            .etherparse("RadiusHeader", "src/proto_audit/radius.rs")
            .libpcap("radius_header", "pcap/proto_audit/radius.h")
            .variable()
            .rfcs(&[2865, 2866]),
        PN::new("Diameter", 20)
            .xdp2("xdp2_parse_diameter").scapy("DiamG").tshark("diameter").variable()
            .rfcs(&[6733])
            .etherparse("DiamGHeader", "src/proto_audit/diameter.rs")
            .libpcap("diameter_header", "pcap/proto_audit/diameter.h"),
        PN::new("TACACS", 12)
            .xdp2("xdp2_parse_tacacs").scapy("TACACS").tshark("tacacs").variable()
            .rfcs(&[8907])
            .etherparse("TacplusHeader", "src/proto_audit/tacplus.rs")
            .libpcap("tacacs_header", "pcap/proto_audit/tacacs.h"),
        PN::new("Syslog", 1)
            .xdp2("xdp2_parse_syslog").scapy("Syslog").tshark("syslog").variable()
            .rfcs(&[5424, 3164])
            .etherparse("SyslogHeader", "src/proto_audit/syslog.rs")
            .libpcap("syslog_header", "pcap/proto_audit/syslog.h"),
        PN::new("TFTP", 4)
            .xdp2("xdp2_parse_tftp").scapy("TFTP").tshark("tftp").variable()
            .suricata("tftp", "TftpHeader")
            .rfcs(&[1350])
            .etherparse("TFTPHeader", "src/proto_audit/tftp.rs")
            .libpcap("tftp_header", "pcap/proto_audit/tftp.h"),
        PN::new("NetFlow_v5", 24)
            .xdp2("xdp2_parse_netflow_v5").scapy("NetflowHeaderV5").tshark("cflow").variable()
            .etherparse("NetflowHeaderV5Header", "src/proto_audit/netflow_v5.rs")
            .libpcap("netflow_v5_header", "pcap/proto_audit/netflow_v5.h"),
        PN::new("NetFlow_v9", 20)
            .xdp2("xdp2_parse_netflow_v9").scapy("NetflowHeaderV9").tshark("cflow").variable()
            .rfcs(&[3954])
            .etherparse("NetflowHeaderV9Header", "src/proto_audit/netflow_v9.rs")
            .libpcap("netflow_v9_header", "pcap/proto_audit/netflow_v9.h"),
        PN::new("IPFIX", 16)
            .xdp2("xdp2_parse_ipfix").scapy("IPFIXHeader").tshark("cflow").variable()
            .rfcs(&[7011, 5101])
            .etherparse("IPFIXHeader", "src/proto_audit/ipfix.rs")
            .libpcap("ipfix_header", "pcap/proto_audit/ipfix.h"),
        // ── Auth & Directory ──
        PN::new("LDAP", 1)
            .xdp2("xdp2_parse_ldap").tshark("ldap").variable()
            .suricata("ldap", "LdapHeader")
            .rfcs(&[4511, 4510])
            .etherparse("LDAPHeader", "src/proto_audit/ldap.rs")
            .libpcap("ldap_header", "pcap/proto_audit/ldap.h"),
        PN::new("Kerberos", 4)
            .xdp2("xdp2_parse_kerberos").scapy("Kerberos").tshark("kerberos").variable()
            .suricata("krb", "KerberosHeader")
            .rfcs(&[4120, 4121])
            .etherparse("KerberosHeader", "src/proto_audit/kerberos.rs")
            .libpcap("kerberos_header", "pcap/proto_audit/kerberos.h"),
        PN::new("NTLMSSP", 12)
            .xdp2("xdp2_parse_ntlmssp").tshark("ntlmssp").variable()
            .etherparse("NTLMSSPHeader", "src/proto_audit/ntlmssp.rs")
            .libpcap("ntlmssp_header", "pcap/proto_audit/ntlmssp.h"),
        PN::new("OCSP", 1)
            .xdp2("xdp2_parse_ocsp").tshark("ocsp").variable()
            .rfcs(&[6960, 2560])
            .etherparse("OCSPHeader", "src/proto_audit/ocsp.rs")
            .libpcap("ocsp_header", "pcap/proto_audit/ocsp.h"),
        // ── File Transfer & Web ──
        PN::new("HTTP", 16)
            .xdp2("xdp2_parse_http").scapy("HTTP").tshark("http").variable()
            .rfcs(&[9110, 9112])
            .etherparse("HTTPHeader", "src/proto_audit/http.rs")
            .libpcap("http_header", "pcap/proto_audit/http.h"),
        PN::new("HTTP2", 9)
            .xdp2("xdp2_parse_http2").scapy("H2Frame").tshark("http2").variable()
            .suricata("http2", "HTTP2FrameHeader")
            .rfcs(&[9113, 7540])
            .etherparse("HTTP2Header", "src/proto_audit/http2.rs")
            .libpcap("http2_header", "pcap/proto_audit/http2.h"),
        PN::new("FTP", 4)
            .xdp2("xdp2_parse_ftp").tshark("ftp").variable()
            .suricata("ftp", "FtpHeader")
            .rfcs(&[959])
            .etherparse("FTPHeader", "src/proto_audit/ftp.rs")
            .libpcap("ftp_header", "pcap/proto_audit/ftp.h"),
        PN::new("SSH", 5)
            .xdp2("xdp2_parse_ssh").tshark("ssh").variable()
            .suricata("ssh", "SshRecordHeader")
            .rfcs(&[4253, 4251, 4252])
            .etherparse("SSHHeader", "src/proto_audit/ssh.rs")
            .libpcap("ssh_header", "pcap/proto_audit/ssh.h"),
        PN::new("Telnet", 1)
            .xdp2("xdp2_parse_telnet").tshark("telnet").variable()
            .suricata("telnet", "TelnetHeader")
            .rfcs(&[854, 855])
            .etherparse("TelnetHeader", "src/proto_audit/telnet.rs")
            .libpcap("telnet_header", "pcap/proto_audit/telnet.h"),
        PN::new("SMTP", 4)
            .xdp2("xdp2_parse_smtp").tshark("smtp").variable()
            .rfcs(&[5321])
            .etherparse("SMTPHeader", "src/proto_audit/smtp.rs")
            .libpcap("smtp_header", "pcap/proto_audit/smtp.h"),
        PN::new("IMAP", 1)
            .xdp2("xdp2_parse_imap").tshark("imap").variable()
            .rfcs(&[9051, 3501])
            .etherparse("IMAPHeader", "src/proto_audit/imap.rs")
            .libpcap("imap_header", "pcap/proto_audit/imap.h"),
        // ── Message Queuing ──
        PN::new("AMQP", 7)
            .xdp2("xdp2_parse_amqp").tshark("amqp").variable()
            .etherparse("AMQPHeader", "src/proto_audit/amqp.rs")
            .libpcap("amqp_header", "pcap/proto_audit/amqp.h"),
        PN::new("Kafka", 12)
            .xdp2("xdp2_parse_kafka").tshark("kafka").variable()
            .etherparse("KafkaHeader", "src/proto_audit/kafka.rs")
            .libpcap("kafka_header", "pcap/proto_audit/kafka.h"),
        PN::new("ZeroMQ", 2)
            .xdp2("xdp2_parse_zeromq").tshark("zmtp").variable()
            .etherparse("ZeroMQHeader", "src/proto_audit/zeromq.rs")
            .libpcap("zeromq_header", "pcap/proto_audit/zeromq.h"),
        PN::new("Memcache", 24)
            .xdp2("xdp2_parse_memcache").tshark("memcache").variable()
            .etherparse("MemcacheHeader", "src/proto_audit/memcache.rs")
            .libpcap("memcache_header", "pcap/proto_audit/memcache.h"),
        PN::new("Redis", 1)
            .xdp2("xdp2_parse_redis").tshark("resp").variable()
            .etherparse("RedisHeader", "src/proto_audit/redis.rs")
            .libpcap("redis_header", "pcap/proto_audit/redis.h"),
        // ── Routing & Misc ──
        PN::new("BFD", 24)
            .xdp2("xdp2_parse_bfd").scapy("BFD").tshark("bfd")
            .etherparse("BfdHeader", "src/proto_audit/bfd.rs")
            .libpcap("bfd_header", "pcap/proto_audit/bfd.h")
            .rfcs(&[5880, 5881]),
        PN::new("LDP", 10)
            .xdp2("xdp2_parse_ldp").scapy("LDP").tshark("ldp").variable()
            .rfcs(&[5036, 3036])
            .etherparse("LDPHeader", "src/proto_audit/ldp.rs")
            .libpcap("ldp_header", "pcap/proto_audit/ldp.h"),
        PN::new("RSVP", 8)
            .xdp2("xdp2_parse_rsvp").scapy("RSVP").tshark("rsvp")
            .libpcap("rsvp_header", "pcap/proto_audit/rsvp.h")
            .variable()
            .rfcs(&[2205, 3209])
            .etherparse("RSVPHeader", "src/proto_audit/rsvp.rs"),
        PN::new("MPLS_OAM", 4)
            .xdp2("xdp2_parse_mpls_oam").tshark("mpls-echo").variable()
            .rfcs(&[8029, 4379])
            .etherparse("MPLS_OAMHeader", "src/proto_audit/mpls_oam.rs")
            .libpcap("mpls_oam_header", "pcap/proto_audit/mpls_oam.h"),
        PN::new("CARP", 8)
            .xdp2("xdp2_parse_carp").scapy("VRRPv3").tshark("carp").variable()
            .etherparse("VRRPv3Header", "src/proto_audit/carp.rs")
            .libpcap("carp_header", "pcap/proto_audit/carp.h"),
        PN::new("GLBP", 2)
            .xdp2("xdp2_parse_glbp").tshark("glbp").variable()
            .etherparse("GLBPHeader", "src/proto_audit/glbp.rs")
            .libpcap("glbp_header", "pcap/proto_audit/glbp.h"),
        PN::new("OpenFlow", 8)
            .xdp2("xdp2_parse_openflow").scapy("OFPTHello").tshark("openflow_v4").variable()
            .etherparse("OFPTHelloHeader", "src/proto_audit/openflow.rs")
            .libpcap("openflow_header", "pcap/proto_audit/openflow.h"),
        PN::new("TZSP", 4)
            .xdp2("xdp2_parse_tzsp").tshark("tzsp").variable()
            .etherparse("TZSPHeader", "src/proto_audit/tzsp.rs")
            .libpcap("tzsp_header", "pcap/proto_audit/tzsp.h"),
        PN::new("GRE_PPTP", 8)
            .xdp2("xdp2_parse_gre_pptp").scapy("GRE_PPTP").tshark("gre").variable()
            .rfcs(&[2637])
            .etherparse("GRE_PPTPHeader", "src/proto_audit/gre_pptp.rs")
            .libpcap("gre_pptp_header", "pcap/proto_audit/gre_pptp.h"),
        PN::new("CAPWAP", 8)
            .xdp2("xdp2_parse_capwap").scapy("CAPWAP_CTRL").tshark("capwap").variable()
            .rfcs(&[5415, 5416])
            .etherparse("CAPWAPHeader", "src/proto_audit/capwap.rs")
            .libpcap("capwap_header", "pcap/proto_audit/capwap.h"),
        PN::new("LWAPP", 6)
            .xdp2("xdp2_parse_lwapp").scapy("LWAPP").tshark("lwapp").variable()
            .etherparse("LWAPPHeader", "src/proto_audit/lwapp.rs")
            .libpcap("lwapp_header", "pcap/proto_audit/lwapp.h"),
        PN::new("TPLINK_SMARTHOME", 4)
            .xdp2("xdp2_parse_tplink_smarthome").tshark("tplink_smarthome").variable()
            .etherparse("TPLINK_SMARTHOMEHeader", "src/proto_audit/tplink_smarthome.rs")
            .libpcap("tplink_smarthome_header", "pcap/proto_audit/tplink_smarthome.h"),
        // ── Phase 5: Additional curated protocols ──
        PN::new("IPComp", 4)
            .xdp2("xdp2_parse_ipcomp")
            .kernel("ip_comp_hdr", "linux/types.h")
            .scapy("IPComp").tshark("ipcomp").variable()
            .rfcs(&[3173, 2393])
            .etherparse("IPCompHeader", "src/proto_audit/ipcomp.rs")
            .libpcap("ipcomp_header", "pcap/proto_audit/ipcomp.h"),
        PN::new("FDDI", 13)
            .xdp2("xdp2_parse_fddi")
            .kernel("fddihdr", "linux/if_fddi.h")
            .tshark("fddi")
            .rfcs(&[1188])
            .etherparse("FDDIHeader", "src/proto_audit/fddi.rs")
            .libpcap("fddi_header", "pcap/proto_audit/fddi.h"),
        PN::new("PGM", 16)
            .xdp2("xdp2_parse_pgm")
            .scapy("PGM").tshark("pgm").variable()
            .rfcs(&[3208])
            .etherparse("PGMHeader", "src/proto_audit/pgm.rs")
            .libpcap("pgm_header", "pcap/proto_audit/pgm.h"),
        PN::new("PPTP", 16)
            .xdp2("xdp2_parse_pptp")
            .scapy("PPTP").tshark("pptp").variable()
            .rfcs(&[2637])
            .etherparse("PPTPHeader", "src/proto_audit/pptp.rs")
            .libpcap("pptp_header", "pcap/proto_audit/pptp.h"),
        PN::new("RIPng", 4)
            .xdp2("xdp2_parse_ripng")
            .tshark("ripng").variable()
            .rfcs(&[2080])
            .etherparse("RIPngHeader", "src/proto_audit/ripng.rs")
            .libpcap("ripng_header", "pcap/proto_audit/ripng.h"),
        PN::new("OSPFv3", 16)
            .xdp2("xdp2_parse_ospfv3")
            .tshark("ospf").variable()
            .rfcs(&[5340, 2740])
            .etherparse("OSPFv3Header", "src/proto_audit/ospfv3.rs")
            .libpcap("ospfv3_header", "pcap/proto_audit/ospfv3.h"),
        PN::new("TWAMP", 14)
            .xdp2("xdp2_parse_twamp")
            .tshark("twamp").variable()
            .rfcs(&[5357])
            .etherparse("TWAMPHeader", "src/proto_audit/twamp.rs")
            .libpcap("twamp_header", "pcap/proto_audit/twamp.h"),
        PN::new("OWAMP", 14)
            .xdp2("xdp2_parse_owamp")
            .tshark("owamp").variable()
            .rfcs(&[4656])
            .etherparse("OWAMPHeader", "src/proto_audit/owamp.rs")
            .libpcap("owamp_header", "pcap/proto_audit/owamp.h"),
        PN::new("CFLOW", 2)
            .xdp2("xdp2_parse_cflow")
            .tshark("cflow").variable()
            .etherparse("CFLOWHeader", "src/proto_audit/cflow.rs")
            .libpcap("cflow_header", "pcap/proto_audit/cflow.h"),
        PN::new("sFlow", 4)
            .xdp2("xdp2_parse_sflow")
            .tshark("sflow").variable()
            .rfcs(&[3176])
            .etherparse("sFlowHeader", "src/proto_audit/sflow.rs")
            .libpcap("sflow_header", "pcap/proto_audit/sflow.h"),
        PN::new("GTPv2_C", 8)
            .xdp2("xdp2_parse_gtpv2_c")
            .tshark("gtpv2").variable()
            .rfcs(&[5765])
            .etherparse("GTPv2CHeader", "src/proto_audit/gtpv2_c.rs")
            .libpcap("gtpv2_c_header", "pcap/proto_audit/gtpv2_c.h"),
        PN::new("Diameter_S6a", 20)
            .xdp2("xdp2_parse_diameter_s6a")
            .tshark("diameter").variable()
            .rfcs(&[6733])
            .etherparse("DiameterS6aHeader", "src/proto_audit/diameter_s6a.rs")
            .libpcap("diameter_s6a_header", "pcap/proto_audit/diameter_s6a.h"),
        PN::new("PFCP", 8)
            .xdp2("xdp2_parse_pfcp")
            .tshark("pfcp").variable()
            .rfcs(&[8805])
            .etherparse("PFCPHeader", "src/proto_audit/pfcp.rs")
            .libpcap("pfcp_header", "pcap/proto_audit/pfcp.h"),
        PN::new("GRE6", 4)
            .xdp2("xdp2_parse_gre6")
            .tshark("gre").variable()
            .rfcs(&[2784, 2890])
            .etherparse("GRE6Header", "src/proto_audit/gre6.rs")
            .libpcap("gre6_header", "pcap/proto_audit/gre6.h"),
        PN::new("L2TPv3", 12)
            .xdp2("xdp2_parse_l2tpv3")
            .tshark("l2tp").variable()
            .rfcs(&[3931])
            .etherparse("L2TPv3Header", "src/proto_audit/l2tpv3.rs")
            .libpcap("l2tpv3_header", "pcap/proto_audit/l2tpv3.h"),
        PN::new("EtherIP", 2)
            .xdp2("xdp2_parse_etherip")
            .tshark("etherip").variable()
            .rfcs(&[3378])
            .etherparse("EtherIPHeader", "src/proto_audit/etherip.rs")
            .libpcap("etherip_header", "pcap/proto_audit/etherip.h"),
        PN::new("LLDP_MED", 4)
            .xdp2("xdp2_parse_lldp_med")
            .tshark("lldp").variable()
            .etherparse("LLDP_MEDHeader", "src/proto_audit/lldp_med.rs")
            .libpcap("lldp_med_header", "pcap/proto_audit/lldp_med.h"),
        PN::new("VRRP3", 8)
            .xdp2("xdp2_parse_vrrp3")
            .scapy("VRRPv3").tshark("vrrp").variable()
            .rfcs(&[5798])
            .etherparse("VRRPv3Header", "src/proto_audit/vrrp3.rs")
            .libpcap("vrrp3_header", "pcap/proto_audit/vrrp3.h"),
        PN::new("MSDP", 3)
            .xdp2("xdp2_parse_msdp")
            .tshark("msdp").variable()
            .rfcs(&[3618])
            .etherparse("MSDPHeader", "src/proto_audit/msdp.rs")
            .libpcap("msdp_header", "pcap/proto_audit/msdp.h"),
        // ── Phase 5b: Telecom / Signaling ──
        PN::new("SCCP", 5)
            .xdp2("xdp2_parse_sccp").tshark("sccp").variable()
            .etherparse("SCCPHeader", "src/proto_audit/sccp.rs")
            .libpcap("sccp_header", "pcap/proto_audit/sccp.h"),
        PN::new("M3UA", 8)
            .xdp2("xdp2_parse_m3ua").scapy("M3UA").tshark("m3ua").variable()
            .rfcs(&[4666])
            .etherparse("M3UAHeader", "src/proto_audit/m3ua.rs")
            .libpcap("m3ua_header", "pcap/proto_audit/m3ua.h"),
        PN::new("M2PA", 8)
            .xdp2("xdp2_parse_m2pa").tshark("m2pa").variable()
            .rfcs(&[4165])
            .etherparse("M2PAHeader", "src/proto_audit/m2pa.rs")
            .libpcap("m2pa_header", "pcap/proto_audit/m2pa.h"),
        PN::new("SUA", 8)
            .xdp2("xdp2_parse_sua").tshark("sua").variable()
            .rfcs(&[3868])
            .etherparse("SUAHeader", "src/proto_audit/sua.rs")
            .libpcap("sua_header", "pcap/proto_audit/sua.h"),
        PN::new("ISUP", 3)
            .xdp2("xdp2_parse_isup").tshark("isup").variable()
            .etherparse("ISUPHeader", "src/proto_audit/isup.rs")
            .libpcap("isup_header", "pcap/proto_audit/isup.h"),
        PN::new("TCAP", 2)
            .xdp2("xdp2_parse_tcap").tshark("tcap").variable()
            .etherparse("TCAPHeader", "src/proto_audit/tcap.rs")
            .libpcap("tcap_header", "pcap/proto_audit/tcap.h"),
        PN::new("GTP_Prime", 6)
            .xdp2("xdp2_parse_gtp_prime").tshark("gtp_prime").variable()
            .etherparse("GTPPrimeHeader", "src/proto_audit/gtp_prime.rs")
            .libpcap("gtp_prime_header", "pcap/proto_audit/gtp_prime.h"),
        PN::new("BSSGP", 3)
            .xdp2("xdp2_parse_bssgp").tshark("bssgp").variable()
            .etherparse("BSSGPHeader", "src/proto_audit/bssgp.rs")
            .libpcap("bssgp_header", "pcap/proto_audit/bssgp.h"),
        PN::new("NAS_EPS", 2)
            .xdp2("xdp2_parse_nas_eps").tshark("nas-eps").variable()
            .etherparse("NASEPSHeader", "src/proto_audit/nas_eps.rs")
            .libpcap("nas_eps_header", "pcap/proto_audit/nas_eps.h"),
        PN::new("NAS_5GS", 2)
            .xdp2("xdp2_parse_nas_5gs").tshark("nas-5gs").variable()
            .etherparse("NAS5GSHeader", "src/proto_audit/nas_5gs.rs")
            .libpcap("nas_5gs_header", "pcap/proto_audit/nas_5gs.h"),
        PN::new("S1AP", 3)
            .xdp2("xdp2_parse_s1ap").tshark("s1ap").variable()
            .etherparse("S1APHeader", "src/proto_audit/s1ap.rs")
            .libpcap("s1ap_header", "pcap/proto_audit/s1ap.h"),
        PN::new("NGAP", 3)
            .xdp2("xdp2_parse_ngap").tshark("ngap").variable()
            .etherparse("NGAPHeader", "src/proto_audit/ngap.rs")
            .libpcap("ngap_header", "pcap/proto_audit/ngap.h"),
        PN::new("RANAP", 3)
            .xdp2("xdp2_parse_ranap").tshark("ranap").variable()
            .etherparse("RANAPHeader", "src/proto_audit/ranap.rs")
            .libpcap("ranap_header", "pcap/proto_audit/ranap.h"),
        // ── VoIP / Media ──
        PN::new("MEGACO", 4)
            .xdp2("xdp2_parse_megaco").scapy("MEGACO").tshark("megaco").variable()
            .rfcs(&[3525])
            .etherparse("MEGACOHeader", "src/proto_audit/megaco.rs")
            .libpcap("megaco_header", "pcap/proto_audit/megaco.h"),
        PN::new("H323", 3)
            .xdp2("xdp2_parse_h323").tshark("h323").variable()
            .etherparse("H323Header", "src/proto_audit/h323.rs")
            .libpcap("h323_header", "pcap/proto_audit/h323.h"),
        PN::new("H225", 3)
            .xdp2("xdp2_parse_h225").tshark("h225").variable()
            .etherparse("H225Header", "src/proto_audit/h225.rs")
            .libpcap("h225_header", "pcap/proto_audit/h225.h"),
        PN::new("H245", 3)
            .xdp2("xdp2_parse_h245").tshark("h245").variable()
            .etherparse("H245Header", "src/proto_audit/h245.rs")
            .libpcap("h245_header", "pcap/proto_audit/h245.h"),
        PN::new("T38", 2)
            .xdp2("xdp2_parse_t38").tshark("t38").variable()
            .rfcs(&[4612])
            .etherparse("T38Header", "src/proto_audit/t38.rs")
            .libpcap("t38_header", "pcap/proto_audit/t38.h"),
        PN::new("SDP", 4)
            .xdp2("xdp2_parse_sdp").scapy("SDP").tshark("sdp").variable()
            .rfcs(&[8866, 4566])
            .etherparse("SDPHeader", "src/proto_audit/sdp.rs")
            .libpcap("sdp_header", "pcap/proto_audit/sdp.h"),
        PN::new("RTMP", 12)
            .xdp2("xdp2_parse_rtmp").tshark("rtmp").variable()
            .etherparse("RTMPHeader", "src/proto_audit/rtmp.rs")
            .libpcap("rtmp_header", "pcap/proto_audit/rtmp.h"),
        // ── Modern Web / RPC ──
        PN::new("gRPC", 5)
            .xdp2("xdp2_parse_grpc").tshark("grpc").variable()
            .etherparse("gRPCHeader", "src/proto_audit/grpc.rs")
            .libpcap("grpc_header", "pcap/proto_audit/grpc.h"),
        PN::new("WebSocket", 2)
            .xdp2("xdp2_parse_websocket").tshark("websocket").variable()
            .rfcs(&[6455])
            .etherparse("WebSocketHeader", "src/proto_audit/websocket.rs")
            .libpcap("websocket_header", "pcap/proto_audit/websocket.h"),
        PN::new("HTTP3", 1)
            .xdp2("xdp2_parse_http3").tshark("http3").variable()
            .rfcs(&[9114])
            .etherparse("HTTP3Header", "src/proto_audit/http3.rs")
            .libpcap("http3_header", "pcap/proto_audit/http3.h"),
        // ── Automotive / Industrial ──
        PN::new("SOME_IP", 8)
            .xdp2("xdp2_parse_some_ip").tshark("someip").variable()
            .etherparse("SOMEIPHeader", "src/proto_audit/some_ip.rs")
            .libpcap("some_ip_header", "pcap/proto_audit/some_ip.h"),
        PN::new("DoIP", 8)
            .xdp2("xdp2_parse_doip").tshark("doip").variable()
            .etherparse("DoIPHeader", "src/proto_audit/doip.rs")
            .libpcap("doip_header", "pcap/proto_audit/doip.h"),
        PN::new("UDS", 3)
            .xdp2("xdp2_parse_uds").tshark("uds").variable()
            .etherparse("UDSHeader", "src/proto_audit/uds.rs")
            .libpcap("uds_header", "pcap/proto_audit/uds.h"),
        PN::new("XCP", 4)
            .xdp2("xdp2_parse_xcp").tshark("xcp").variable()
            .etherparse("XCPHeader", "src/proto_audit/xcp.rs")
            .libpcap("xcp_header", "pcap/proto_audit/xcp.h"),
        PN::new("S7COMM", 10)
            .xdp2("xdp2_parse_s7comm").tshark("s7comm").variable()
            .etherparse("S7COMMHeader", "src/proto_audit/s7comm.rs")
            .libpcap("s7comm_header", "pcap/proto_audit/s7comm.h"),
        PN::new("IEC_104", 6)
            .xdp2("xdp2_parse_iec_104").tshark("iec60870_104").variable()
            .etherparse("IEC104Header", "src/proto_audit/iec_104.rs")
            .libpcap("iec_104_header", "pcap/proto_audit/iec_104.h"),
        PN::new("PROFINET_DCP", 10)
            .xdp2("xdp2_parse_profinet_dcp").tshark("pn_dcp").variable()
            .etherparse("PROFINETDCPHeader", "src/proto_audit/profinet_dcp.rs")
            .libpcap("profinet_dcp_header", "pcap/proto_audit/profinet_dcp.h"),
        // ── Wireless / IoT ──
        PN::new("Radiotap", 8)
            .xdp2("xdp2_parse_radiotap").scapy("RadioTap").tshark("radiotap").variable()
            .etherparse("RadiotapHeader", "src/proto_audit/radiotap.rs")
            .libpcap("radiotap_header", "pcap/proto_audit/radiotap.h"),
        PN::new("PPI", 8)
            .xdp2("xdp2_parse_ppi").tshark("ppi").variable()
            .etherparse("PPIHeader", "src/proto_audit/ppi.rs")
            .libpcap("ppi_header", "pcap/proto_audit/ppi.h"),
        PN::new("AVTP", 12)
            .xdp2("xdp2_parse_avtp").scapy("AVTP").tshark("avtp").variable()
            .ieee(&["1722-2016"])
            .etherparse("AVTPHeader", "src/proto_audit/avtp.rs")
            .libpcap("avtp_header", "pcap/proto_audit/avtp.h"),
        PN::new("gPTP", 34)
            .xdp2("xdp2_parse_gptp").tshark("gptp").variable()
            .ieee(&["802.1AS-2020"])
            .etherparse("gPTPHeader", "src/proto_audit/gptp.rs")
            .libpcap("gptp_header", "pcap/proto_audit/gptp.h"),
        PN::new("LoRaWAN", 1)
            .xdp2("xdp2_parse_lorawan").scapy("LoRa").tshark("lorawan").variable()
            .etherparse("LoRaWANHeader", "src/proto_audit/lorawan.rs")
            .libpcap("lorawan_header", "pcap/proto_audit/lorawan.h"),
        PN::new("SixLoWPAN", 1)
            .xdp2("xdp2_parse_6lowpan").scapy("SixLoWPAN").tshark("6lowpan").variable()
            .rfcs(&[4944, 6282])
            .etherparse("SixLoWPANHeader", "src/proto_audit/sixlowpan.rs")
            .libpcap("sixlowpan_header", "pcap/proto_audit/sixlowpan.h"),
        // ── Routing extensions ──
        PN::new("Babel", 4)
            .xdp2("xdp2_parse_babel").tshark("babel").variable()
            .rfcs(&[8966])
            .etherparse("BabelHeader", "src/proto_audit/babel.rs")
            .libpcap("babel_header", "pcap/proto_audit/babel.h"),
        PN::new("RPKI_RTR", 8)
            .xdp2("xdp2_parse_rpki_rtr").tshark("rpkirtr").variable()
            .rfcs(&[8210, 6810])
            .etherparse("RPKIRTRHeader", "src/proto_audit/rpki_rtr.rs")
            .libpcap("rpki_rtr_header", "pcap/proto_audit/rpki_rtr.h"),
        PN::new("PCP", 24)
            .xdp2("xdp2_parse_pcp").tshark("portcontrol").variable()
            .rfcs(&[6887])
            .etherparse("PCPHeader", "src/proto_audit/pcp.rs")
            .libpcap("pcp_header", "pcap/proto_audit/pcp.h"),
        PN::new("COPS", 8)
            .xdp2("xdp2_parse_cops").tshark("cops").variable()
            .rfcs(&[2748])
            .etherparse("COPSHeader", "src/proto_audit/cops.rs")
            .libpcap("cops_header", "pcap/proto_audit/cops.h"),
        // ── Database / Application ──
        PN::new("MySQL", 4)
            .xdp2("xdp2_parse_mysql").tshark("mysql").variable()
            .etherparse("MySQLHeader", "src/proto_audit/mysql.rs")
            .libpcap("mysql_header", "pcap/proto_audit/mysql.h"),
        PN::new("PostgreSQL", 5)
            .xdp2("xdp2_parse_postgresql").tshark("pgsql").variable()
            .etherparse("PostgreSQLHeader", "src/proto_audit/postgresql.rs")
            .libpcap("postgresql_header", "pcap/proto_audit/postgresql.h"),
        PN::new("MongoDB", 16)
            .xdp2("xdp2_parse_mongodb").tshark("mongo").variable()
            .etherparse("MongoDBHeader", "src/proto_audit/mongodb.rs")
            .libpcap("mongodb_header", "pcap/proto_audit/mongodb.h"),
        PN::new("Cassandra", 9)
            .xdp2("xdp2_parse_cassandra").tshark("cql").variable()
            .etherparse("CassandraHeader", "src/proto_audit/cassandra.rs")
            .libpcap("cassandra_header", "pcap/proto_audit/cassandra.h"),
        PN::new("Elasticsearch", 4)
            .xdp2("xdp2_parse_elasticsearch").tshark("elasticsearch").variable()
            .etherparse("ElasticsearchHeader", "src/proto_audit/elasticsearch.rs")
            .libpcap("elasticsearch_header", "pcap/proto_audit/elasticsearch.h"),
        PN::new("NATS", 4)
            .xdp2("xdp2_parse_nats").tshark("nats").variable()
            .etherparse("NATSHeader", "src/proto_audit/nats.rs")
            .libpcap("nats_header", "pcap/proto_audit/nats.h"),
        // ── Messaging / Chat ──
        PN::new("IRC", 1)
            .xdp2("xdp2_parse_irc").tshark("irc").variable()
            .rfcs(&[1459, 2812])
            .etherparse("IRCHeader", "src/proto_audit/irc.rs")
            .libpcap("irc_header", "pcap/proto_audit/irc.h"),
        PN::new("XMPP", 1)
            .xdp2("xdp2_parse_xmpp").tshark("xmpp").variable()
            .rfcs(&[6120, 6121])
            .etherparse("XMPPHeader", "src/proto_audit/xmpp.rs")
            .libpcap("xmpp_header", "pcap/proto_audit/xmpp.h"),
        PN::new("POP3", 1)
            .xdp2("xdp2_parse_pop3").tshark("pop").variable()
            .rfcs(&[1939])
            .etherparse("POP3Header", "src/proto_audit/pop3.rs")
            .libpcap("pop3_header", "pcap/proto_audit/pop3.h"),
        PN::new("NNTP", 1)
            .xdp2("xdp2_parse_nntp").tshark("nntp").variable()
            .rfcs(&[3977])
            .etherparse("NNTPHeader", "src/proto_audit/nntp.rs")
            .libpcap("nntp_header", "pcap/proto_audit/nntp.h"),
        // ── Monitoring / Telemetry ──
        PN::new("Collectd", 4)
            .xdp2("xdp2_parse_collectd").tshark("collectd").variable()
            .etherparse("CollectdHeader", "src/proto_audit/collectd.rs")
            .libpcap("collectd_header", "pcap/proto_audit/collectd.h"),
        PN::new("RADIUS_ACCT", 20)
            .xdp2("xdp2_parse_radius_acct").tshark("radius").variable()
            .rfcs(&[2866])
            .etherparse("RADIUSAcctHeader", "src/proto_audit/radius_acct.rs")
            .libpcap("radius_acct_header", "pcap/proto_audit/radius_acct.h"),
        // ── Maritime / Aviation ──
        PN::new("AIS", 1)
            .xdp2("xdp2_parse_ais").tshark("ais").variable()
            .etherparse("AISHeader", "src/proto_audit/ais.rs")
            .libpcap("ais_header", "pcap/proto_audit/ais.h"),
        PN::new("ASTERIX", 3)
            .xdp2("xdp2_parse_asterix").tshark("asterix").variable()
            .etherparse("ASTERIXHeader", "src/proto_audit/asterix.rs")
            .libpcap("asterix_header", "pcap/proto_audit/asterix.h"),
        // ── TSN / Automotive Ethernet ──
        PN::new("MRP", 3)
            .xdp2("xdp2_parse_mrp").tshark("mrp").variable()
            .ieee(&["802.1Q-2022"])
            .etherparse("MRPHeader", "src/proto_audit/mrp.rs")
            .libpcap("mrp_header", "pcap/proto_audit/mrp.h"),
        PN::new("CAN_TP", 1)
            .xdp2("xdp2_parse_can_tp").tshark("iso15765").variable()
            .etherparse("CANTPHeader", "src/proto_audit/can_tp.rs")
            .libpcap("can_tp_header", "pcap/proto_audit/can_tp.h"),
        // ── Additional Security/Auth ──
        PN::new("ACME", 1)
            .xdp2("xdp2_parse_acme").tshark("acme").variable()
            .rfcs(&[8555])
            .etherparse("ACMEHeader", "src/proto_audit/acme.rs")
            .libpcap("acme_header", "pcap/proto_audit/acme.h"),
        PN::new("EST", 4)
            .xdp2("xdp2_parse_est").tshark("est").variable()
            .rfcs(&[7030])
            .etherparse("ESTHeader", "src/proto_audit/est.rs")
            .libpcap("est_header", "pcap/proto_audit/est.h"),
        PN::new("CMP", 3)
            .xdp2("xdp2_parse_cmp").tshark("cmp").variable()
            .rfcs(&[4210])
            .etherparse("CMPHeader", "src/proto_audit/cmp.rs")
            .libpcap("cmp_header", "pcap/proto_audit/cmp.h"),
        // ── Network Management ──
        PN::new("LLDP_802_1AB", 2)
            .xdp2("xdp2_parse_lldp_802_1ab").tshark("lldp").variable()
            .ieee(&["802.1AB-2016"])
            .etherparse("LLDP8021ABHeader", "src/proto_audit/lldp_802_1ab.rs")
            .libpcap("lldp_802_1ab_header", "pcap/proto_audit/lldp_802_1ab.h"),
        PN::new("RMON", 4)
            .xdp2("xdp2_parse_rmon").tshark("rmon").variable()
            .rfcs(&[2819])
            .etherparse("RMONHeader", "src/proto_audit/rmon.rs")
            .libpcap("rmon_header", "pcap/proto_audit/rmon.h"),
        // ── More tunneling ──
        PN::new("AYIYA", 8)
            .xdp2("xdp2_parse_ayiya").tshark("ayiya").variable()
            .etherparse("AYIYAHeader", "src/proto_audit/ayiya.rs")
            .libpcap("ayiya_header", "pcap/proto_audit/ayiya.h"),
        PN::new("SixToFour", 20)
            .xdp2("xdp2_parse_6to4").tshark("6to4").variable()
            .rfcs(&[3056])
            .etherparse("SixToFourHeader", "src/proto_audit/sixto4.rs")
            .libpcap("sixto4_header", "pcap/proto_audit/sixto4.h"),
        PN::new("SixInFour", 20)
            .xdp2("xdp2_parse_6in4").tshark("6in4").variable()
            .rfcs(&[4213])
            .etherparse("SixInFourHeader", "src/proto_audit/sixin4.rs")
            .libpcap("sixin4_header", "pcap/proto_audit/sixin4.h"),
        PN::new("AMT", 8)
            .xdp2("xdp2_parse_amt").tshark("amt").variable()
            .rfcs(&[7450])
            .etherparse("AMTHeader", "src/proto_audit/amt.rs")
            .libpcap("amt_header", "pcap/proto_audit/amt.h"),
        // ── Batch 3: Additional well-known protocols ──
        // ── MPLS/Segment Routing ──
        PN::new("MPLS_Echo", 4)
            .xdp2("xdp2_parse_mpls_echo").tshark("mpls_echo").variable()
            .rfcs(&[8029])
            .etherparse("MPLSEchoHeader", "src/proto_audit/mpls_echo.rs")
            .libpcap("mpls_echo_header", "pcap/proto_audit/mpls_echo.h"),
        PN::new("LMP", 12)
            .xdp2("xdp2_parse_lmp").tshark("lmp").variable()
            .rfcs(&[4204])
            .etherparse("LMPHeader", "src/proto_audit/lmp.rs")
            .libpcap("lmp_header", "pcap/proto_audit/lmp.h"),
        PN::new("PCEP", 4)
            .xdp2("xdp2_parse_pcep").tshark("pcep").variable()
            .rfcs(&[5440])
            .etherparse("PCEPHeader", "src/proto_audit/pcep.rs")
            .libpcap("pcep_header", "pcap/proto_audit/pcep.h"),
        // ── More routing / control ──
        PN::new("BMP", 6)
            .xdp2("xdp2_parse_bmp").tshark("bmp").variable()
            .rfcs(&[7854])
            .etherparse("BMPHeader", "src/proto_audit/bmp.rs")
            .libpcap("bmp_header", "pcap/proto_audit/bmp.h"),
        PN::new("VRRP_IPv6", 8)
            .xdp2("xdp2_parse_vrrp_ipv6").tshark("vrrp").variable()
            .rfcs(&[5798])
            .etherparse("VRRPIPv6Header", "src/proto_audit/vrrp_ipv6.rs")
            .libpcap("vrrp_ipv6_header", "pcap/proto_audit/vrrp_ipv6.h"),
        PN::new("PIMv6", 4)
            .xdp2("xdp2_parse_pimv6").tshark("pim").variable()
            .rfcs(&[7761])
            .etherparse("PIMv6Header", "src/proto_audit/pimv6.rs")
            .libpcap("pimv6_header", "pcap/proto_audit/pimv6.h"),
        PN::new("VXLAN_GPB", 8)
            .xdp2("xdp2_parse_vxlan_gpb").tshark("vxlan").variable()
            .etherparse("VXLANGPBHeader", "src/proto_audit/vxlan_gpb.rs")
            .libpcap("vxlan_gpb_header", "pcap/proto_audit/vxlan_gpb.h"),
        // ── DNS variants ──
        PN::new("DNS_TCP", 12)
            .xdp2("xdp2_parse_dns_tcp").tshark("dns").variable()
            .etherparse("DNSTCPHeader", "src/proto_audit/dns_tcp.rs")
            .libpcap("dns_tcp_header", "pcap/proto_audit/dns_tcp.h"),
        PN::new("DoH", 1)
            .xdp2("xdp2_parse_doh").tshark("dns").variable()
            .rfcs(&[8484])
            .etherparse("DoHHeader", "src/proto_audit/doh.rs")
            .libpcap("doh_header", "pcap/proto_audit/doh.h"),
        PN::new("DoT", 12)
            .xdp2("xdp2_parse_dot").tshark("dns").variable()
            .rfcs(&[7858])
            .etherparse("DoTHeader", "src/proto_audit/dot.rs")
            .libpcap("dot_header", "pcap/proto_audit/dot.h"),
        // ── Storage / SAN ──
        PN::new("FCP", 24)
            .xdp2("xdp2_parse_fcp").tshark("fcp").variable()
            .etherparse("FCPHeader", "src/proto_audit/fcp.rs")
            .libpcap("fcp_header", "pcap/proto_audit/fcp.h"),
        PN::new("FCOE_FIP", 2)
            .xdp2("xdp2_parse_fcoe_fip").tshark("fip").variable()
            .etherparse("FCOEFIPHeader", "src/proto_audit/fcoe_fip.rs")
            .libpcap("fcoe_fip_header", "pcap/proto_audit/fcoe_fip.h"),
        PN::new("RDMA_CM", 36)
            .xdp2("xdp2_parse_rdma_cm").tshark("iwarp_mpa").variable()
            .rfcs(&[5044])
            .etherparse("RDMACMHeader", "src/proto_audit/rdma_cm.rs")
            .libpcap("rdma_cm_header", "pcap/proto_audit/rdma_cm.h"),
        // ── Carrier Ethernet / Telecom ──
        PN::new("Y1731", 4)
            .xdp2("xdp2_parse_y1731").tshark("cfm").variable()
            .etherparse("Y1731Header", "src/proto_audit/y1731.rs")
            .libpcap("y1731_header", "pcap/proto_audit/y1731.h"),
        PN::new("G8032", 32)
            .xdp2("xdp2_parse_g8032").tshark("elmi").variable()
            .etherparse("G8032Header", "src/proto_audit/g8032.rs")
            .libpcap("g8032_header", "pcap/proto_audit/g8032.h"),
        PN::new("ELMI", 4)
            .xdp2("xdp2_parse_elmi").tshark("elmi").variable()
            .rfcs(&[7369])
            .etherparse("ELMIHeader", "src/proto_audit/elmi.rs")
            .libpcap("elmi_header", "pcap/proto_audit/elmi.h"),
        // ── More VoIP/Telephony ──
        PN::new("MGCP_NCS", 1)
            .xdp2("xdp2_parse_mgcp_ncs").tshark("mgcp").variable()
            .etherparse("MGCPNCSHeader", "src/proto_audit/mgcp_ncs.rs")
            .libpcap("mgcp_ncs_header", "pcap/proto_audit/mgcp_ncs.h"),
        PN::new("SCTP_Init", 20)
            .xdp2("xdp2_parse_sctp_init").tshark("sctp").variable()
            .etherparse("SCTPInitHeader", "src/proto_audit/sctp_init.rs")
            .libpcap("sctp_init_header", "pcap/proto_audit/sctp_init.h"),
        // ── More Industrial / SCADA ──
        PN::new("GOOSE", 8)
            .xdp2("xdp2_parse_goose").tshark("goose").variable()
            .ieee(&["61850-8-1"])
            .etherparse("GOOSEHeader", "src/proto_audit/goose.rs")
            .libpcap("goose_header", "pcap/proto_audit/goose.h"),
        PN::new("R_GOOSE", 8)
            .xdp2("xdp2_parse_r_goose").tshark("r-goose").variable()
            .etherparse("RGOOSEHeader", "src/proto_audit/r_goose.rs")
            .libpcap("r_goose_header", "pcap/proto_audit/r_goose.h"),
        PN::new("OPC_DA", 1)
            .xdp2("xdp2_parse_opc_da").tshark("opc-da").variable()
            .etherparse("OPCDAHeader", "src/proto_audit/opc_da.rs")
            .libpcap("opc_da_header", "pcap/proto_audit/opc_da.h"),
        PN::new("EtherNet_IP", 24)
            .xdp2("xdp2_parse_ethernet_ip").tshark("enip").variable()
            .etherparse("EtherNetIPHeader", "src/proto_audit/ethernet_ip.rs")
            .libpcap("ethernet_ip_header", "pcap/proto_audit/ethernet_ip.h"),
        // ── Additional Tunnel / Encap ──
        PN::new("GTP_V0", 20)
            .xdp2("xdp2_parse_gtp_v0").tshark("gtp").variable()
            .rfcs(&[2944])
            .etherparse("GTPV0Header", "src/proto_audit/gtp_v0.rs")
            .libpcap("gtp_v0_header", "pcap/proto_audit/gtp_v0.h"),
        PN::new("LISP_Control", 8)
            .xdp2("xdp2_parse_lisp_control").tshark("lisp").variable()
            .rfcs(&[6830])
            .etherparse("LISPControlHeader", "src/proto_audit/lisp_control.rs")
            .libpcap("lisp_control_header", "pcap/proto_audit/lisp_control.h"),
        PN::new("MPLS_TP", 4)
            .xdp2("xdp2_parse_mpls_tp").tshark("mpls").variable()
            .rfcs(&[5921])
            .etherparse("MPLSTPHeader", "src/proto_audit/mpls_tp.rs")
            .libpcap("mpls_tp_header", "pcap/proto_audit/mpls_tp.h"),
        PN::new("PWE3", 4)
            .xdp2("xdp2_parse_pwe3").tshark("pw_eth_cw").variable()
            .rfcs(&[3985, 4385])
            .etherparse("PWE3Header", "src/proto_audit/pwe3.rs")
            .libpcap("pwe3_header", "pcap/proto_audit/pwe3.h"),
        // ── Network Management / Monitoring ──
        PN::new("LLDP_EXT_DOT1", 2)
            .xdp2("xdp2_parse_lldp_ext_dot1").tshark("lldp").variable()
            .ieee(&["802.1AB-2016"])
            .etherparse("LLDPExtDot1Header", "src/proto_audit/lldp_ext_dot1.rs")
            .libpcap("lldp_ext_dot1_header", "pcap/proto_audit/lldp_ext_dot1.h"),
        PN::new("LLDP_EXT_DOT3", 2)
            .xdp2("xdp2_parse_lldp_ext_dot3").tshark("lldp").variable()
            .ieee(&["802.1AB-2016"])
            .etherparse("LLDPExtDot3Header", "src/proto_audit/lldp_ext_dot3.rs")
            .libpcap("lldp_ext_dot3_header", "pcap/proto_audit/lldp_ext_dot3.h"),
        PN::new("SFLOW_V5", 28)
            .xdp2("xdp2_parse_sflow_v5").tshark("sflow").variable()
            .rfcs(&[3176])
            .etherparse("SFLOWV5Header", "src/proto_audit/sflow_v5.rs")
            .libpcap("sflow_v5_header", "pcap/proto_audit/sflow_v5.h"),
        // ── Wireless ──
        PN::new("IEEE802_11_Beacon", 12)
            .xdp2("xdp2_parse_ieee802_11_beacon").tshark("wlan_mgt").variable()
            .ieee(&["802.11-2020"])
            .etherparse("IEEE80211BeaconHeader", "src/proto_audit/ieee802_11_beacon.rs")
            .libpcap("ieee802_11_beacon_header", "pcap/proto_audit/ieee802_11_beacon.h"),
        PN::new("IEEE802_11_Data", 24)
            .xdp2("xdp2_parse_ieee802_11_data").tshark("wlan").variable()
            .ieee(&["802.11-2020"])
            .etherparse("IEEE80211DataHeader", "src/proto_audit/ieee802_11_data.rs")
            .libpcap("ieee802_11_data_header", "pcap/proto_audit/ieee802_11_data.h"),
        PN::new("WPA_EAPOL_Key", 95)
            .xdp2("xdp2_parse_wpa_eapol_key").tshark("eapol").variable()
            .ieee(&["802.11i-2004"])
            .etherparse("WPAEAPOLKeyHeader", "src/proto_audit/wpa_eapol_key.rs")
            .libpcap("wpa_eapol_key_header", "pcap/proto_audit/wpa_eapol_key.h"),
        // ── IoT ──
        PN::new("Thread", 1)
            .xdp2("xdp2_parse_thread").tshark("thread").variable()
            .etherparse("ThreadHeader", "src/proto_audit/thread.rs")
            .libpcap("thread_header", "pcap/proto_audit/thread.h"),
        PN::new("Matter", 1)
            .xdp2("xdp2_parse_matter").tshark("matter").variable()
            .etherparse("MatterHeader", "src/proto_audit/matter.rs")
            .libpcap("matter_header", "pcap/proto_audit/matter.h"),
        PN::new("Zigbee_ZCL", 3)
            .xdp2("xdp2_parse_zigbee_zcl").tshark("zbee_zcl").variable()
            .etherparse("ZigbeeZCLHeader", "src/proto_audit/zigbee_zcl.rs")
            .libpcap("zigbee_zcl_header", "pcap/proto_audit/zigbee_zcl.h"),
        PN::new("Zigbee_ZDP", 2)
            .xdp2("xdp2_parse_zigbee_zdp").tshark("zbee_zdp").variable()
            .etherparse("ZigbeeZDPHeader", "src/proto_audit/zigbee_zdp.rs")
            .libpcap("zigbee_zdp_header", "pcap/proto_audit/zigbee_zdp.h"),
        PN::new("BLE_LL", 2)
            .xdp2("xdp2_parse_ble_ll").tshark("btle").variable()
            .etherparse("BLELLHeader", "src/proto_audit/ble_ll.rs")
            .libpcap("ble_ll_header", "pcap/proto_audit/ble_ll.h"),
        // ── More security / PKI ──
        PN::new("OCSP_Response", 4)
            .xdp2("xdp2_parse_ocsp_response").tshark("ocsp").variable()
            .rfcs(&[6960])
            .etherparse("OCSPResponseHeader", "src/proto_audit/ocsp_response.rs")
            .libpcap("ocsp_response_header", "pcap/proto_audit/ocsp_response.h"),
        PN::new("DTLS_13", 1)
            .xdp2("xdp2_parse_dtls_13").tshark("dtls").variable()
            .rfcs(&[9147])
            .etherparse("DTLS13Header", "src/proto_audit/dtls_13.rs")
            .libpcap("dtls_13_header", "pcap/proto_audit/dtls_13.h"),
        // ── More Ethernet ──
        PN::new("EtherType_TSN", 14)
            .xdp2("xdp2_parse_tsn").tshark("ieee8021cb").variable()
            .ieee(&["802.1CB-2017"])
            .etherparse("TSNHeader", "src/proto_audit/tsn.rs")
            .libpcap("tsn_header", "pcap/proto_audit/tsn.h"),
        PN::new("LLDP_CDP", 2)
            .xdp2("xdp2_parse_lldp_cdp").tshark("cdp").variable()
            .etherparse("LLDPCDPHeader", "src/proto_audit/lldp_cdp.rs")
            .libpcap("lldp_cdp_header", "pcap/proto_audit/lldp_cdp.h"),
        // ── Batch 4: Toward 400 protocols ──
        // ── QUIC / HTTP/3 ──
        PN::new("QUIC_Initial", 1)
            .xdp2("xdp2_parse_quic_initial").tshark("quic").variable()
            .rfcs(&[9000]),
        PN::new("QUIC_Retry", 1)
            .xdp2("xdp2_parse_quic_retry").tshark("quic").variable()
            .rfcs(&[9000]),
        // ── More IPv6 ──
        PN::new("IPv6_HopByHop", 2)
            .xdp2("xdp2_parse_ipv6_hopbyhop").tshark("ipv6.hop_opt").variable()
            .rfcs(&[8200]),
        PN::new("IPv6_MobileIP", 6)
            .xdp2("xdp2_parse_ipv6_mobileip").tshark("mip6").variable()
            .rfcs(&[6275]),
        PN::new("MLD_Report_v1", 20)
            .xdp2("xdp2_parse_mld_report_v1").tshark("icmpv6").variable()
            .rfcs(&[2710]),
        // ── Additional SCTP ──
        PN::new("SCTP_Data", 16)
            .xdp2("xdp2_parse_sctp_data").tshark("sctp").variable()
            .rfcs(&[9260]),
        PN::new("SCTP_Sack", 16)
            .xdp2("xdp2_parse_sctp_sack").tshark("sctp").variable()
            .rfcs(&[9260]),
        // ── GRE variants ──
        PN::new("GRE_Cisco", 8)
            .xdp2("xdp2_parse_gre_cisco").tshark("gre").variable(),
        PN::new("GRE_WCCPv2", 8)
            .xdp2("xdp2_parse_gre_wccpv2").tshark("wccp").variable()
            .rfcs(&[7001]),
        // ── MPLS variants ──
        PN::new("MPLS_PW_ETH", 4)
            .xdp2("xdp2_parse_mpls_pw_eth").tshark("pw_eth_cw").variable()
            .rfcs(&[4448]),
        // ── More tunnels ──
        PN::new("GTP_U_V1", 8)
            .xdp2("xdp2_parse_gtp_u_v1").tshark("gtp").variable()
            .rfcs(&[2944]),
        PN::new("L2TP_AVP", 6)
            .xdp2("xdp2_parse_l2tp_avp").tshark("l2tp").variable()
            .rfcs(&[2661]),
        PN::new("GENEVE_OPT", 4)
            .xdp2("xdp2_parse_geneve_opt").tshark("geneve").variable()
            .rfcs(&[8926]),
        // ── PPP variants ──
        PN::new("PPP_LCP", 4)
            .xdp2("xdp2_parse_ppp_lcp").tshark("lcp").variable()
            .rfcs(&[1661]),
        PN::new("PPP_IPCP", 4)
            .xdp2("xdp2_parse_ppp_ipcp").tshark("ipcp").variable()
            .rfcs(&[1332]),
        PN::new("PPP_IPv6CP", 4)
            .xdp2("xdp2_parse_ppp_ipv6cp").tshark("ipv6cp").variable()
            .rfcs(&[5072]),
        PN::new("PPP_CCP", 4)
            .xdp2("xdp2_parse_ppp_ccp").tshark("ccp").variable()
            .rfcs(&[1962]),
        PN::new("PPP_CHAP", 4)
            .xdp2("xdp2_parse_ppp_chap").tshark("chap").variable()
            .rfcs(&[1994]),
        PN::new("PPP_PAP", 4)
            .xdp2("xdp2_parse_ppp_pap").tshark("pap").variable()
            .rfcs(&[1334]),
        // ── Multicast ──
        PN::new("PIM_BSR", 8)
            .xdp2("xdp2_parse_pim_bsr").tshark("pim").variable()
            .rfcs(&[5059]),
        PN::new("PIM_Assert", 12)
            .xdp2("xdp2_parse_pim_assert").tshark("pim").variable()
            .rfcs(&[7761]),
        PN::new("MSDP_SA", 20)
            .xdp2("xdp2_parse_msdp_sa").tshark("msdp").variable()
            .rfcs(&[3618]),
        // ── STP variants ──
        PN::new("RSTP", 36)
            .xdp2("xdp2_parse_rstp").tshark("rstp").variable()
            .ieee(&["802.1D-2004"]),
        PN::new("MSTP", 38)
            .xdp2("xdp2_parse_mstp").tshark("mstp").variable()
            .ieee(&["802.1Q-2022"]),
        PN::new("PVST", 35)
            .xdp2("xdp2_parse_pvst").tshark("stp").variable(),
        // ── VPN / IPsec ──
        PN::new("IKEv1", 28)
            .xdp2("xdp2_parse_ikev1").tshark("isakmp").variable()
            .rfcs(&[2409]),
        PN::new("ESP_NULL", 8)
            .xdp2("xdp2_parse_esp_null").tshark("esp").variable()
            .rfcs(&[2410]),
        // ── Link Aggregation ──
        PN::new("MARKER", 50)
            .xdp2("xdp2_parse_marker").tshark("slow").variable()
            .ieee(&["802.3ad"]),
        PN::new("OAM_LBM", 4)
            .xdp2("xdp2_parse_oam_lbm").tshark("cfm").variable()
            .ieee(&["802.1ag-2007"]),
        PN::new("OAM_LTM", 4)
            .xdp2("xdp2_parse_oam_ltm").tshark("cfm").variable()
            .ieee(&["802.1ag-2007"]),
        // ── Authentication ──
        PN::new("EAP_TLS", 6)
            .xdp2("xdp2_parse_eap_tls").tshark("eap").variable()
            .rfcs(&[5216]),
        PN::new("EAP_TTLS", 6)
            .xdp2("xdp2_parse_eap_ttls").tshark("eap").variable()
            .rfcs(&[5281]),
        PN::new("EAP_PEAP", 6)
            .xdp2("xdp2_parse_eap_peap").tshark("eap").variable(),
        PN::new("EAP_SIM", 8)
            .xdp2("xdp2_parse_eap_sim").tshark("eap-sim").variable()
            .rfcs(&[4186]),
        PN::new("EAP_AKA", 8)
            .xdp2("xdp2_parse_eap_aka").tshark("eap-aka").variable()
            .rfcs(&[4187]),
        // ── NTP variants ──
        PN::new("NTS", 4)
            .xdp2("xdp2_parse_nts").tshark("ntp").variable()
            .rfcs(&[8915]),
        PN::new("PTP_V1", 40)
            .xdp2("xdp2_parse_ptp_v1").tshark("ptp").variable()
            .ieee(&["1588-2002"]),
        // ── DHCP variants ──
        PN::new("DHCP_Option", 2)
            .xdp2("xdp2_parse_dhcp_option").tshark("dhcp").variable()
            .rfcs(&[2132]),
        PN::new("DHCPv6_Option", 4)
            .xdp2("xdp2_parse_dhcpv6_option").tshark("dhcpv6").variable()
            .rfcs(&[8415]),
        // ── Additional applications ──
        PN::new("SOCKS", 3)
            .xdp2("xdp2_parse_socks").tshark("socks").variable()
            .rfcs(&[1928]),
        PN::new("WHOIS", 1)
            .xdp2("xdp2_parse_whois").tshark("whois").variable()
            .rfcs(&[3912]),
        PN::new("FINGER", 1)
            .xdp2("xdp2_parse_finger").tshark("finger").variable()
            .rfcs(&[1288]),
        PN::new("DAYTIME", 1)
            .xdp2("xdp2_parse_daytime").tshark("daytime").variable()
            .rfcs(&[867]),
        PN::new("CHARGEN", 1)
            .xdp2("xdp2_parse_chargen").tshark("chargen").variable()
            .rfcs(&[864]),
        PN::new("ECHO", 1)
            .xdp2("xdp2_parse_echo_proto").tshark("echo").variable()
            .rfcs(&[862]),
        PN::new("DISCARD", 1)
            .xdp2("xdp2_parse_discard").tshark("discard").variable()
            .rfcs(&[863]),
        PN::new("TIME", 4)
            .xdp2("xdp2_parse_time_proto").tshark("time").variable()
            .rfcs(&[868]),
        PN::new("NETCONF", 1)
            .xdp2("xdp2_parse_netconf").tshark("netconf").variable()
            .rfcs(&[6241]),
        PN::new("gNMI", 1)
            .xdp2("xdp2_parse_gnmi").tshark("grpc").variable(),
        PN::new("gNOI", 1)
            .xdp2("xdp2_parse_gnoi").tshark("grpc").variable(),
        // ── Streaming / Media ──
        PN::new("RTP_MPEG", 4)
            .xdp2("xdp2_parse_rtp_mpeg").tshark("mpeg-pes").variable()
            .rfcs(&[2250]),
        PN::new("RTP_H264", 1)
            .xdp2("xdp2_parse_rtp_h264").tshark("h264").variable()
            .rfcs(&[6184]),
        PN::new("RTP_H265", 2)
            .xdp2("xdp2_parse_rtp_h265").tshark("h265").variable()
            .rfcs(&[7798]),
        PN::new("RTP_OPUS", 1)
            .xdp2("xdp2_parse_rtp_opus").tshark("opus").variable()
            .rfcs(&[7587]),
        PN::new("RTCP_SR", 24)
            .xdp2("xdp2_parse_rtcp_sr").tshark("rtcp").variable()
            .rfcs(&[3550]),
        PN::new("RTCP_RR", 8)
            .xdp2("xdp2_parse_rtcp_rr").tshark("rtcp").variable()
            .rfcs(&[3550]),
        // ── Network File Systems ──
        PN::new("NFSv4", 12)
            .xdp2("xdp2_parse_nfsv4").tshark("nfs").variable()
            .rfcs(&[7530]),
        PN::new("CIFS", 4)
            .xdp2("xdp2_parse_cifs").tshark("smb").variable(),
        // ── More RADIUS ──
        PN::new("RADIUS_COA", 20)
            .xdp2("xdp2_parse_radius_coa").tshark("radius").variable()
            .rfcs(&[5176]),
        // ── More management ──
        PN::new("SNMPv3", 1)
            .xdp2("xdp2_parse_snmpv3").tshark("snmp").variable()
            .rfcs(&[3412]),
        PN::new("SNMP_Trap", 1)
            .xdp2("xdp2_parse_snmp_trap").tshark("snmp").variable()
            .rfcs(&[3416]),
        // ── VLAN / Bridging ──
        PN::new("GVRP", 2)
            .xdp2("xdp2_parse_gvrp").tshark("gvrp").variable()
            .ieee(&["802.1Q-2022"]),
        PN::new("MMRP", 2)
            .xdp2("xdp2_parse_mmrp").tshark("mmrp").variable()
            .ieee(&["802.1Q-2022"]),
        // ── DCB / Data Center ──
        PN::new("DCBX", 2)
            .xdp2("xdp2_parse_dcbx").tshark("lldp").variable()
            .ieee(&["802.1Qaz-2011"]),
        PN::new("FCoE_Init", 36)
            .xdp2("xdp2_parse_fcoe_init").tshark("fcoe").variable(),
        // ── CAN variants ──
        PN::new("CAN_J1939", 8)
            .xdp2("xdp2_parse_can_j1939").tshark("j1939").variable(),
        PN::new("CAN_OBD2", 8)
            .xdp2("xdp2_parse_can_obd2").tshark("obd-ii").variable(),
        // ── Misc well-known ──
        PN::new("TZSP_V2", 4)
            .xdp2("xdp2_parse_tzsp_v2").tshark("tzsp").variable(),
        PN::new("ERSPAN_V3", 12)
            .xdp2("xdp2_parse_erspan_v3").tshark("erspan").variable(),
        PN::new("VXLAN_GBP", 8)
            .xdp2("xdp2_parse_vxlan_gbp").tshark("vxlan").variable(),

        // ── Trading Protocols (OMI) ──
        // Open Markets Initiative auto-generated packed C struct headers.
        // One entry per wire message type; dispatch via MessageType char field.

        // SoupBinTCP transport (wraps ITCH/OUCH payloads)
        PN::new("SoupBinTCP_PacketHeader", 3)
            .omi("PacketHeaderT", "nasdaq/Nasdaq.Common.SoupBinTcp.Ouch.v3.0.h"),
        PN::new("SoupBinTCP_LoginRequest", 46)
            .omi("LoginRequestPacketT", "nasdaq/Nasdaq.Common.SoupBinTcp.Ouch.v3.0.h"),
        PN::new("SoupBinTCP_LoginAccepted", 30)
            .omi("LoginAcceptedPacketT", "nasdaq/Nasdaq.Common.SoupBinTcp.Ouch.v3.0.h"),
        PN::new("SoupBinTCP_LoginRejected", 1)
            .omi("LoginRejectedPacketT", "nasdaq/Nasdaq.Common.SoupBinTcp.Ouch.v3.0.h"),
        PN::new("SoupBinTCP_SequencedData", 1)
            .omi("SequencedDataPacketT", "nasdaq/Nasdaq.Common.SoupBinTcp.Ouch.v3.0.h"),

        // Nasdaq ITCH v5.0 (TotalView) — market data feed
        PN::new("ITCH_v5_SystemEvent", 6)
            .xdp2("xdp2_parse_itch_v5_system_event")
            .omi("SystemEventMessageT", "nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h"),
        PN::new("ITCH_v5_StockDirectory", 26)
            .xdp2("xdp2_parse_itch_v5_stock_directory")
            .omi("StockDirectoryMessageT", "nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h"),
        // tshark dissector name for ITCH v5.0 OMI Lua (shared across all messages).
        // Per-message sub-field extraction is a Phase 2b refinement; current
        // extraction returns a superset of the packet including session/seq/header.
        PN::new("ITCH_v5_StockTradingAction", 19)
            .xdp2("xdp2_parse_itch_v5_stock_trading_action")
            .omi("StockTradingActionMessageT", "nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h")
            .tshark("nasdaq.nsmequities.totalview.itch.v5.0.lua")
            .omi_tshark(
                "Nasdaq/Nasdaq_NsmEquities_TotalView_Itch_v5_0_Dissector.lua",
                "Nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0/StockTradingActionMessage.pcap",
                "nasdaq.nsmequities.totalview.itch.v5.0.stocktradingactionmessage",
            ),
        PN::new("ITCH_v5_AddOrder", 30)
            .xdp2("xdp2_parse_itch_v5_add_order")
            .omi("AddOrderNoMpidAttributionMessageT", "nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h")
            .tshark("nasdaq.nsmequities.totalview.itch.v5.0.lua")
            .omi_tshark(
                "Nasdaq/Nasdaq_NsmEquities_TotalView_Itch_v5_0_Dissector.lua",
                "Nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0/AddOrderNoMpidAttributionMessage.pcap",
                "nasdaq.nsmequities.totalview.itch.v5.0.addordernompidattributionmessage",
            ),
        PN::new("ITCH_v5_AddOrderMPID", 34)
            .xdp2("xdp2_parse_itch_v5_add_order_mpid")
            .omi("AddOrderWithMpidAttributionMessageT", "nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h"),
        PN::new("ITCH_v5_OrderExecuted", 25)
            .xdp2("xdp2_parse_itch_v5_order_executed")
            .omi("OrderExecutedMessageT", "nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h")
            .tshark("nasdaq.nsmequities.totalview.itch.v5.0.lua")
            .omi_tshark(
                "Nasdaq/Nasdaq_NsmEquities_TotalView_Itch_v5_0_Dissector.lua",
                "Nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0/OrderExecutedMessage.pcap",
                "nasdaq.nsmequities.totalview.itch.v5.0.orderexecutedmessage",
            ),
        PN::new("ITCH_v5_OrderExecutedWithPrice", 30)
            .xdp2("xdp2_parse_itch_v5_order_executed_with_price")
            .omi("OrderExecutedWithPriceMessageT", "nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h"),
        PN::new("ITCH_v5_OrderCancel", 17)
            .xdp2("xdp2_parse_itch_v5_order_cancel")
            .omi("OrderCancelMessageT", "nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h"),
        PN::new("ITCH_v5_OrderDelete", 13)
            .xdp2("xdp2_parse_itch_v5_order_delete")
            .omi("OrderDeleteMessageT", "nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h")
            .tshark("nasdaq.nsmequities.totalview.itch.v5.0.lua")
            .omi_tshark(
                "Nasdaq/Nasdaq_NsmEquities_TotalView_Itch_v5_0_Dissector.lua",
                "Nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0/OrderDeleteMessage.pcap",
                "nasdaq.nsmequities.totalview.itch.v5.0.orderdeletemessage",
            ),
        PN::new("ITCH_v5_OrderReplace", 29)
            .xdp2("xdp2_parse_itch_v5_order_replace")
            .omi("OrderReplaceMessageT", "nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h")
            .tshark("nasdaq.nsmequities.totalview.itch.v5.0.lua")
            .omi_tshark(
                "Nasdaq/Nasdaq_NsmEquities_TotalView_Itch_v5_0_Dissector.lua",
                "Nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0/OrderReplaceMessage.pcap",
                "nasdaq.nsmequities.totalview.itch.v5.0.orderreplacemessage",
            ),
        PN::new("ITCH_v5_NonCrossTrade", 38)
            .xdp2("xdp2_parse_itch_v5_non_cross_trade")
            .omi("NonCrossTradeMessageT", "nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h"),
        PN::new("ITCH_v5_CrossTrade", 39)
            .xdp2("xdp2_parse_itch_v5_cross_trade")
            .omi("CrossTradeMessageT", "nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h"),
        PN::new("ITCH_v5_BrokenTrade", 19)
            .xdp2("xdp2_parse_itch_v5_broken_trade")
            .omi("BrokenTradeMessageT", "nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h"),

        // CBOE PITCH v2 (BYX Equities Depth-of-Book — chosen because OMI ships
        // Byx sample PCAPs; Bzx has identical wire layout but no PCAPs.)
        PN::new("PITCH_v2_AddOrderShort", 26)
            .xdp2("xdp2_parse_pitch_v2_add_order_short")
            .omi("AddOrderShortMessageT", "cboe/Cboe.Byx.Equities.DepthOfBook.Pitch.v2.41.29.h")
            .tshark("cboe.byx.equities.depthofbook.pitch.v2.41.29.lua")
            .omi_tshark(
                "Cboe/Cboe_Byx_Equities_DepthOfBook_Pitch_v2_41_29_Dissector.lua",
                "Cboe/Byx.Equities.DepthOfBook.Pitch.v2.41/AddOrderShortMessage.pcap",
                "cboe.byx.equities.depthofbook.pitch.v2.41.29.addordershortmessage",
            ),
        PN::new("PITCH_v2_AddOrderLong", 34)
            .xdp2("xdp2_parse_pitch_v2_add_order_long")
            .omi("AddOrderLongMessageT", "cboe/Cboe.Byx.Equities.DepthOfBook.Pitch.v2.41.29.h"),
        PN::new("PITCH_v2_OrderExecuted", 26)
            .xdp2("xdp2_parse_pitch_v2_order_executed")
            .omi("OrderExecutedMessageT", "cboe/Cboe.Byx.Equities.DepthOfBook.Pitch.v2.41.29.h"),

        // CME Simple Binary Encoding (MDP 3.0) — little-endian
        PN::new("SBE_MDP3_MessageHeader", 8)
            .omi("MessageHeaderT", "cme/Cme.Futures.Mdp3.Sbe.v1.13.h"),
        PN::new("SBE_MDP3_BinaryPacketHeader", 12)
            .omi("BinaryPacketHeaderT", "cme/Cme.Futures.Mdp3.Sbe.v1.13.h"),

        // Eurex T7 EOBI (Enhanced Order Book Interface) — little-endian
        // v12.0 entry kept for c-struct coverage; no sample PCAPs in omi-data-packets for v12.
        PN::new("EOBI_TradeReport", 16)
            .omi("TradeReportT", "eurex/Eurex.Derivatives.Eobi.T7.v12.0.h"),

        // Eurex T7 EOBI v3.0 — messages with full c-struct + Lua + PCAP triangle.
        // Lua proto name lowercased = `eurex.derivatives.eobi.t7.v3.0.lua`;
        // per-message PDML field follows the same struct-name lowercase pattern.
        PN::new("EOBI_v3_OrderAdd", 40)
            .omi("OrderAddT", "eurex/Eurex.Derivatives.Eobi.T7.v3.0.h")
            .tshark("eurex.derivatives.eobi.t7.v3.0.lua")
            .omi_tshark(
                "Eurex/Eurex_Derivatives_Eobi_T7_v3_0_Dissector.lua",
                "Eurex/Eobi.T7.v3.0/OrderAdd.pcap",
                "eurex.derivatives.eobi.t7.v3.0.orderadd",
            ),
        PN::new("EOBI_v3_SnapshotOrder", 24)
            .omi("SnapshotOrderT", "eurex/Eurex.Derivatives.Eobi.T7.v3.0.h")
            .tshark("eurex.derivatives.eobi.t7.v3.0.lua")
            .omi_tshark(
                "Eurex/Eurex_Derivatives_Eobi_T7_v3_0_Dissector.lua",
                "Eurex/Eobi.T7.v3.0/SnapshotOrder.pcap",
                "eurex.derivatives.eobi.t7.v3.0.snapshotorder",
            ),
        PN::new("EOBI_v3_Heartbeat", 8)
            .omi("HeartbeatT", "eurex/Eurex.Derivatives.Eobi.T7.v3.0.h")
            .tshark("eurex.derivatives.eobi.t7.v3.0.lua")
            .omi_tshark(
                "Eurex/Eurex_Derivatives_Eobi_T7_v3_0_Dissector.lua",
                "Eurex/Eobi.T7.v3.0/Heartbeat.pcap",
                "eurex.derivatives.eobi.t7.v3.0.heartbeat",
            ),
    ]
}
