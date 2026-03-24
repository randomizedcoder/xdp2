/* flow_dissector_metadata.h — Metadata extraction functions
 *
 * Each XDP2_METADATA_TEMP_* instantiation generates a static inline function
 * that extracts protocol-specific fields into xdp2_metadata_all. These are
 * referenced by parse nodes via .ops.extract_metadata.
 */

XDP2_METADATA_TEMP_ipv4(ipv4_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_ipv6(ipv6_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_ipv6_eh(ipv6_eh_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_ipv6_frag(ipv6_frag_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_ports(ports_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_icmp(icmp_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_mpls(mpls_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_gre(gre_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_gre_checksum(gre_checksum_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_gre_keyid(gre_keyid_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_gre_seq(gre_seq_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_vlan_8021Q(e8021Q_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_vlan_8021AD(e8021AD_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_arp_rarp(arp_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_tipc(tipc_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_esp(esp_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_ah(ah_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_l2tp_v3(l2tp_metadata, xdp2_metadata_all)
XDP2_METADATA_TEMP_ether(ether_metadata, xdp2_metadata_all)
