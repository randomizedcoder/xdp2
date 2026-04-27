/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2025 Tom Herbert
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* Include for all defined proto nodes */

/* Don't use header file guard here */

/* IP family (proto_icmp.h before proto_ipv6_nd.h — ND needs icmp6hdr) */
#include "xdp2/proto_defs/ip/proto_arp_rarp.h"
#include "xdp2/proto_defs/ip/proto_ip.h"
#include "xdp2/proto_defs/ip/proto_ipv4.h"
#include "xdp2/proto_defs/ip/proto_ipv4ip.h"
#include "xdp2/proto_defs/ip/proto_ipv6.h"
#include "xdp2/proto_defs/ip/proto_ipv6_eh.h"
#include "xdp2/proto_defs/ip/proto_ipv6ip.h"
#include "xdp2/proto_defs/ip/proto_icmp.h"
#include "xdp2/proto_defs/ip/proto_ipv6_nd.h"
#include "xdp2/proto_defs/ip/proto_igmp.h"
#include "xdp2/proto_defs/ip/proto_igmpv3.h"
#include "xdp2/proto_defs/ip/proto_mld.h"
#include "xdp2/proto_defs/ip/proto_pim.h"
#include "xdp2/proto_defs/ip/proto_rsvp.h"
#include "xdp2/proto_defs/ip/proto_rtcp.h"
#include "xdp2/proto_defs/ip/proto_rtp.h"
#include "xdp2/proto_defs/ip/proto_srv6.h"
#include "xdp2/proto_defs/ip/proto_ipcomp.h"
#include "xdp2/proto_defs/ip/proto_pgm.h"

/* Ethernet family */
#include "xdp2/proto_defs/ethernet/proto_ether.h"
#include "xdp2/proto_defs/ethernet/proto_vlan.h"
#include "xdp2/proto_defs/ethernet/proto_qinq.h"
#include "xdp2/proto_defs/ethernet/proto_pbb.h"
#include "xdp2/proto_defs/ethernet/proto_edsa.h"
#include "xdp2/proto_defs/ethernet/proto_llc.h"
#include "xdp2/proto_defs/ethernet/proto_ppoed.h"
#include "xdp2/proto_defs/ethernet/proto_sll.h"
#include "xdp2/proto_defs/ethernet/proto_sll2.h"

/* Transport */
#include "xdp2/proto_defs/transport/proto_tcp.h"
#include "xdp2/proto_defs/transport/proto_udp.h"
#include "xdp2/proto_defs/transport/proto_ports.h"
#include "xdp2/proto_defs/transport/proto_tipc.h"
#include "xdp2/proto_defs/transport/proto_l2tp.h"
#include "xdp2/proto_defs/transport/proto_l2tp_v0.h"
#include "xdp2/proto_defs/transport/proto_dccp.h"
#include "xdp2/proto_defs/transport/proto_quic.h"
#include "xdp2/proto_defs/transport/proto_sctp.h"
#include "xdp2/proto_defs/transport/proto_sctp_chunk.h"
#include "xdp2/proto_defs/transport/proto_udplite.h"

/* Tunnel / encapsulation */
#include "xdp2/proto_defs/tunnel/proto_gre.h"
#include "xdp2/proto_defs/tunnel/proto_gre_pptp.h"
#include "xdp2/proto_defs/tunnel/proto_vxlan.h"
#include "xdp2/proto_defs/tunnel/proto_vxlan_gpe.h"
#include "xdp2/proto_defs/tunnel/proto_geneve.h"
#include "xdp2/proto_defs/tunnel/proto_mpls.h"
#include "xdp2/proto_defs/tunnel/proto_erspan.h"
#include "xdp2/proto_defs/tunnel/proto_nsh.h"
#include "xdp2/proto_defs/tunnel/proto_ppp.h"
#include "xdp2/proto_defs/tunnel/proto_pppoe.h"
#include "xdp2/proto_defs/tunnel/proto_hsr.h"
#include "xdp2/proto_defs/tunnel/proto_ip_in_ip.h"
#include "xdp2/proto_defs/tunnel/proto_capwap.h"
#include "xdp2/proto_defs/tunnel/proto_gtp.h"
#include "xdp2/proto_defs/tunnel/proto_gtp_c.h"
#include "xdp2/proto_defs/tunnel/proto_gue.h"
#include "xdp2/proto_defs/tunnel/proto_lisp.h"
#include "xdp2/proto_defs/tunnel/proto_lwapp.h"
#include "xdp2/proto_defs/tunnel/proto_nvgre.h"
#include "xdp2/proto_defs/tunnel/proto_stt.h"
#include "xdp2/proto_defs/tunnel/proto_teredo.h"
#include "xdp2/proto_defs/tunnel/proto_tzsp.h"
#include "xdp2/proto_defs/tunnel/proto_gtpv2_c.h"
#include "xdp2/proto_defs/tunnel/proto_gre6.h"
#include "xdp2/proto_defs/tunnel/proto_l2tpv3.h"
#include "xdp2/proto_defs/tunnel/proto_etherip.h"

/* Security */
#include "xdp2/proto_defs/security/proto_esp.h"
#include "xdp2/proto_defs/security/proto_ah.h"
#include "xdp2/proto_defs/security/proto_macsec.h"
#include "xdp2/proto_defs/security/proto_eapol.h"
#include "xdp2/proto_defs/security/proto_dtls.h"
#include "xdp2/proto_defs/security/proto_eap.h"
#include "xdp2/proto_defs/security/proto_ikev2.h"
#include "xdp2/proto_defs/security/proto_kerberos.h"
#include "xdp2/proto_defs/security/proto_ntlmssp.h"
#include "xdp2/proto_defs/security/proto_ocsp.h"
#include "xdp2/proto_defs/security/proto_ssh.h"
#include "xdp2/proto_defs/security/proto_tacacs.h"
#include "xdp2/proto_defs/security/proto_tls.h"
#include "xdp2/proto_defs/security/proto_wireguard.h"

/* Management / control / application */
#include "xdp2/proto_defs/management/proto_lldp.h"
#include "xdp2/proto_defs/management/proto_slow.h"
#include "xdp2/proto_defs/management/proto_mac_control.h"
#include "xdp2/proto_defs/management/proto_ptp.h"
#include "xdp2/proto_defs/management/proto_mvrp.h"
#include "xdp2/proto_defs/management/proto_cfm.h"
#include "xdp2/proto_defs/management/proto_fip.h"
#include "xdp2/proto_defs/management/proto_profinet.h"
#include "xdp2/proto_defs/management/proto_ncsi.h"
#include "xdp2/proto_defs/management/proto_trill.h"
#include "xdp2/proto_defs/management/proto_amqp.h"
#include "xdp2/proto_defs/management/proto_bacnet.h"
#include "xdp2/proto_defs/management/proto_bfd.h"
#include "xdp2/proto_defs/management/proto_bgp.h"
#include "xdp2/proto_defs/management/proto_carp.h"
#include "xdp2/proto_defs/management/proto_cdp.h"
#include "xdp2/proto_defs/management/proto_cip.h"
#include "xdp2/proto_defs/management/proto_coap.h"
#include "xdp2/proto_defs/management/proto_dhcp.h"
#include "xdp2/proto_defs/management/proto_dhcpv6.h"
#include "xdp2/proto_defs/management/proto_diameter.h"
#include "xdp2/proto_defs/management/proto_dnp3.h"
#include "xdp2/proto_defs/management/proto_dns.h"
#include "xdp2/proto_defs/management/proto_eigrp.h"
#include "xdp2/proto_defs/management/proto_enip.h"
#include "xdp2/proto_defs/management/proto_ftp.h"
#include "xdp2/proto_defs/management/proto_glbp.h"
#include "xdp2/proto_defs/management/proto_homeplug_av.h"
#include "xdp2/proto_defs/management/proto_hsrp.h"
#include "xdp2/proto_defs/management/proto_http.h"
#include "xdp2/proto_defs/management/proto_http2.h"
#include "xdp2/proto_defs/management/proto_iec_goose.h"
#include "xdp2/proto_defs/management/proto_iec_mms.h"
#include "xdp2/proto_defs/management/proto_iec_sv.h"
#include "xdp2/proto_defs/management/proto_imap.h"
#include "xdp2/proto_defs/management/proto_ipfix.h"
#include "xdp2/proto_defs/management/proto_isis.h"
#include "xdp2/proto_defs/management/proto_kafka.h"
#include "xdp2/proto_defs/management/proto_lacp.h"
#include "xdp2/proto_defs/management/proto_ldap.h"
#include "xdp2/proto_defs/management/proto_ldp.h"
#include "xdp2/proto_defs/management/proto_llmnr.h"
#include "xdp2/proto_defs/management/proto_lltd.h"
#include "xdp2/proto_defs/management/proto_mdns.h"
#include "xdp2/proto_defs/management/proto_memcache.h"
#include "xdp2/proto_defs/management/proto_mgcp.h"
#include "xdp2/proto_defs/management/proto_modbus_tcp.h"
#include "xdp2/proto_defs/management/proto_mpls_oam.h"
#include "xdp2/proto_defs/management/proto_mqtt.h"
#include "xdp2/proto_defs/management/proto_nbns.h"
#include "xdp2/proto_defs/management/proto_netflow_v5.h"
#include "xdp2/proto_defs/management/proto_netflow_v9.h"
#include "xdp2/proto_defs/management/proto_nfs.h"
#include "xdp2/proto_defs/management/proto_ntp.h"
#include "xdp2/proto_defs/management/proto_onc_rpc.h"
#include "xdp2/proto_defs/management/proto_opc_ua.h"
#include "xdp2/proto_defs/management/proto_openflow.h"
#include "xdp2/proto_defs/management/proto_ospf.h"
#include "xdp2/proto_defs/management/proto_radius.h"
#include "xdp2/proto_defs/management/proto_redis.h"
#include "xdp2/proto_defs/management/proto_rip.h"
#include "xdp2/proto_defs/management/proto_rtsp.h"
#include "xdp2/proto_defs/management/proto_sip.h"
#include "xdp2/proto_defs/management/proto_skinny.h"
#include "xdp2/proto_defs/management/proto_smb.h"
#include "xdp2/proto_defs/management/proto_smb2.h"
#include "xdp2/proto_defs/management/proto_smtp.h"
#include "xdp2/proto_defs/management/proto_snmp.h"
#include "xdp2/proto_defs/management/proto_stp.h"
#include "xdp2/proto_defs/management/proto_stun.h"
#include "xdp2/proto_defs/management/proto_syslog.h"
#include "xdp2/proto_defs/management/proto_telnet.h"
#include "xdp2/proto_defs/management/proto_tftp.h"
#include "xdp2/proto_defs/management/proto_vrrp.h"
#include "xdp2/proto_defs/management/proto_wol.h"
#include "xdp2/proto_defs/management/proto_zeromq.h"
#include "xdp2/proto_defs/management/proto_pptp.h"
#include "xdp2/proto_defs/management/proto_ripng.h"
#include "xdp2/proto_defs/management/proto_ospfv3.h"
#include "xdp2/proto_defs/management/proto_twamp.h"
#include "xdp2/proto_defs/management/proto_owamp.h"
#include "xdp2/proto_defs/management/proto_cflow.h"
#include "xdp2/proto_defs/management/proto_sflow.h"
#include "xdp2/proto_defs/management/proto_diameter_s6a.h"
#include "xdp2/proto_defs/management/proto_pfcp.h"
#include "xdp2/proto_defs/management/proto_lldp_med.h"
#include "xdp2/proto_defs/management/proto_vrrp3.h"
#include "xdp2/proto_defs/management/proto_msdp.h"
#include "xdp2/proto_defs/management/proto_zigbee_aps.h"
#include "xdp2/proto_defs/management/proto_zigbee_nwk.h"

/* Storage */
#include "xdp2/proto_defs/storage/proto_aoe.h"
#include "xdp2/proto_defs/storage/proto_ethercat.h"
#include "xdp2/proto_defs/storage/proto_fc.h"
#include "xdp2/proto_defs/storage/proto_iscsi.h"
#include "xdp2/proto_defs/storage/proto_iser.h"
#include "xdp2/proto_defs/storage/proto_nvme.h"
#include "xdp2/proto_defs/storage/proto_nvme_tcp.h"
#include "xdp2/proto_defs/storage/proto_scsi.h"

/* Wireless (802.11) */
#include "xdp2/proto_defs/wireless/proto_ieee80211.h"
#include "xdp2/proto_defs/wireless/proto_ieee80211_mgmt.h"
#include "xdp2/proto_defs/wireless/proto_ieee80211_data.h"

/* Bluetooth */
#include "xdp2/proto_defs/bluetooth/proto_hci.h"
#include "xdp2/proto_defs/bluetooth/proto_hci_cmd.h"
#include "xdp2/proto_defs/bluetooth/proto_hci_event.h"
#include "xdp2/proto_defs/bluetooth/proto_hci_acl.h"
#include "xdp2/proto_defs/bluetooth/proto_hci_sco.h"
#include "xdp2/proto_defs/bluetooth/proto_hci_iso.h"
#include "xdp2/proto_defs/bluetooth/proto_l2cap.h"
#include "xdp2/proto_defs/bluetooth/proto_bt_att.h"
#include "xdp2/proto_defs/bluetooth/proto_bt_avdtp.h"
#include "xdp2/proto_defs/bluetooth/proto_bt_bnep.h"
#include "xdp2/proto_defs/bluetooth/proto_bt_rfcomm.h"
#include "xdp2/proto_defs/bluetooth/proto_bt_sdp.h"
#include "xdp2/proto_defs/bluetooth/proto_bt_smp.h"

/* InfiniBand */
#include "xdp2/proto_defs/infiniband/proto_ib_lrh.h"
#include "xdp2/proto_defs/infiniband/proto_ib_grh.h"
#include "xdp2/proto_defs/infiniband/proto_ib_bth.h"
#include "xdp2/proto_defs/infiniband/proto_ib_aeth.h"
#include "xdp2/proto_defs/infiniband/proto_ib_atomiceth.h"
#include "xdp2/proto_defs/infiniband/proto_ib_deth.h"
#include "xdp2/proto_defs/infiniband/proto_ib_immdt.h"
#include "xdp2/proto_defs/infiniband/proto_ib_mad.h"
#include "xdp2/proto_defs/infiniband/proto_ib_rdeth.h"
#include "xdp2/proto_defs/infiniband/proto_ib_reth.h"

/* CAN bus */
#include "xdp2/proto_defs/can/proto_can.h"
#include "xdp2/proto_defs/can/proto_canfd.h"
#include "xdp2/proto_defs/can/proto_canxl.h"

/* Netlink */
#include "xdp2/proto_defs/netlink/proto_netlink.h"
#include "xdp2/proto_defs/netlink/proto_genetlink.h"
#include "xdp2/proto_defs/netlink/proto_nlattr.h"

/* Legacy / niche */
#include "xdp2/proto_defs/legacy/proto_batman.h"
#include "xdp2/proto_defs/legacy/proto_ipx.h"
#include "xdp2/proto_defs/legacy/proto_atalk.h"
#include "xdp2/proto_defs/legacy/proto_x25.h"
#include "xdp2/proto_defs/legacy/proto_atm.h"
#include "xdp2/proto_defs/legacy/proto_phonet.h"
#include "xdp2/proto_defs/legacy/proto_mctp.h"
#include "xdp2/proto_defs/legacy/proto_dsa.h"
#include "xdp2/proto_defs/legacy/proto_ieee802154.h"
#include "xdp2/proto_defs/legacy/proto_protobuf.h"
#include "xdp2/proto_defs/legacy/proto_fddi.h"

/* Other */
#include "xdp2/proto_defs/other/proto_fcoe.h"
#include "xdp2/proto_defs/other/proto_erf.h"
#include "xdp2/proto_defs/other/proto_mpeg_ts.h"
#include "xdp2/proto_defs/other/proto_srt.h"
#include "xdp2/proto_defs/other/proto_tplink_smarthome.h"
