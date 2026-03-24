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
#include "xdp2/proto_defs/ip/proto_srv6.h"

/* Ethernet family */
#include "xdp2/proto_defs/ethernet/proto_ether.h"
#include "xdp2/proto_defs/ethernet/proto_vlan.h"
#include "xdp2/proto_defs/ethernet/proto_pbb.h"
#include "xdp2/proto_defs/ethernet/proto_edsa.h"

/* Transport */
#include "xdp2/proto_defs/transport/proto_tcp.h"
#include "xdp2/proto_defs/transport/proto_udp.h"
#include "xdp2/proto_defs/transport/proto_ports.h"
#include "xdp2/proto_defs/transport/proto_tipc.h"
#include "xdp2/proto_defs/transport/proto_l2tp.h"
#include "xdp2/proto_defs/transport/proto_l2tp_v0.h"

/* Tunnel / encapsulation */
#include "xdp2/proto_defs/tunnel/proto_gre.h"
#include "xdp2/proto_defs/tunnel/proto_vxlan.h"
#include "xdp2/proto_defs/tunnel/proto_geneve.h"
#include "xdp2/proto_defs/tunnel/proto_mpls.h"
#include "xdp2/proto_defs/tunnel/proto_erspan.h"
#include "xdp2/proto_defs/tunnel/proto_nsh.h"
#include "xdp2/proto_defs/tunnel/proto_ppp.h"
#include "xdp2/proto_defs/tunnel/proto_pppoe.h"
#include "xdp2/proto_defs/tunnel/proto_hsr.h"

/* Security */
#include "xdp2/proto_defs/security/proto_esp.h"
#include "xdp2/proto_defs/security/proto_ah.h"
#include "xdp2/proto_defs/security/proto_macsec.h"
#include "xdp2/proto_defs/security/proto_eapol.h"

/* Management / control */
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

/* Storage */
#include "xdp2/proto_defs/storage/proto_aoe.h"
#include "xdp2/proto_defs/storage/proto_ethercat.h"

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

/* InfiniBand */
#include "xdp2/proto_defs/infiniband/proto_ib_lrh.h"
#include "xdp2/proto_defs/infiniband/proto_ib_grh.h"
#include "xdp2/proto_defs/infiniband/proto_ib_bth.h"

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

/* Other */
#include "xdp2/proto_defs/other/proto_fcoe.h"
