// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/*
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

/* XDP2 multi-graph parser — flow dissector + non-Ethernet protocol families
 *
 * This file orchestrates the parse graph by including component fragments.
 * All fragments are #include'd (not separately compiled) because parse nodes
 * and tables are static const with internal linkage — they must share a
 * single translation unit.
 *
 * For BPF builds, parser_xdp.c does:
 *   #define XDP2_XDP_BUILD
 *   #include "parser.c"
 * which compiles only the L3 root parser (no L2 or non-Ethernet graphs).
 *
 * 14 parsers with dedicated roots covering ~70 protocol types:
 *
 * Ethernet/IP parsers:
 * 1. xdp2_parser_flow_dissector — root at ip_check_node (L3 entry).
 * 2. xdp2_parser_flow_dissector_l2 — root at etype_dispatch_node (L2 entry).
 *
 * Non-Ethernet parsers (userspace only):
 * 3.  xdp2_parser_ieee80211    — WiFi 802.11 (frame type dispatch)
 * 4.  xdp2_parser_hci          — Bluetooth HCI (packet type dispatch)
 * 5.  xdp2_parser_infiniband   — InfiniBand (LNH dispatch)
 * 6.  xdp2_parser_can          — CAN 2.0
 * 7.  xdp2_parser_canfd        — CAN FD
 * 8.  xdp2_parser_canxl        — CAN XL (SDT dispatch)
 * 9.  xdp2_parser_netlink      — Netlink (nlmsg_type dispatch)
 * 10. xdp2_parser_ieee802154   — IEEE 802.15.4 WPAN
 * 11. xdp2_parser_phonet       — Phonet (Nokia ISI)
 * 12. xdp2_parser_mctp         — MCTP
 * 13. xdp2_parser_atm          — ATM
 * 14. xdp2_parser_x25          — X.25
 *
 * Layout:
 *   flow_dissector_metadata.h     - Metadata extractors (18 XDP2_METADATA_TEMP_*)
 *   flow_dissector_proto_defs.h   - Local proto_defs (6 custom protocol defs)
 *   flow_dissector_nodes.h        - Core Ethernet/IP parse nodes (~40 nodes)
 *   flow_dissector_nodes_l2.h     - Extended L2 leaf nodes (userspace only)
 *   flow_dissector_tables.h       - Protocol dispatch tables (~15 tables)
 *   graph_ieee80211.h             - WiFi 802.11 parse graph
 *   graph_bluetooth.h             - Bluetooth HCI parse graph
 *   graph_infiniband.h            - InfiniBand parse graph
 *   graph_netlink.h               - Netlink parse graph
 *   graph_misc.h                  - X.25, MCTP, ATM standalone roots
 *   flow_dissector_parsers.h      - XDP2_PARSER() declarations (14 parsers)
 */

#include "xdp2/parser.h"

/* Ethertype constants not in all kernel headers */
#ifndef ETH_P_PROFINET
#define ETH_P_PROFINET	0x8892
#endif
#ifndef ETH_P_CANXL
#define ETH_P_CANXL	0x000E
#endif
#ifndef ETH_P_MCTP
#define ETH_P_MCTP	0x00FA
#endif
#ifndef ETH_P_IEC61850_GOOSE
#define ETH_P_IEC61850_GOOSE	0x88B8
#endif
#ifndef ETH_P_IEC61850_SV
#define ETH_P_IEC61850_SV	0x88BA
#endif
#ifndef ETH_P_HOMEPLUG_AV
#define ETH_P_HOMEPLUG_AV	0x88E1
#endif
#ifndef ETH_P_LLTD
#define ETH_P_LLTD	0x893A
#endif
#ifndef ETH_P_WOL
#define ETH_P_WOL	0x0842
#endif

/* IP protocol numbers not in all kernel headers */
#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF	89
#endif
#ifndef IPPROTO_EIGRP
#define IPPROTO_EIGRP	88
#endif
#ifndef IPPROTO_VRRP
#define IPPROTO_VRRP	112
#endif
#ifndef IPPROTO_PIM
#define IPPROTO_PIM	103
#endif
#ifndef IPPROTO_RSVP
#define IPPROTO_RSVP	46
#endif
#ifndef IPPROTO_PGM
#define IPPROTO_PGM	113
#endif
#ifndef IPPROTO_COMP
#define IPPROTO_COMP	108
#endif
#ifndef IPPROTO_ETHERIP
#define IPPROTO_ETHERIP	97
#endif
#include "xdp2/parser_metadata.h"
#include "xdp2/proto_defs_define.h"
#include "xdp2/utility.h"

/* === Metadata extractors === */
#include "flow_dissector_metadata.h"

/* === Local proto_defs (custom protocol definitions) === */
#include "flow_dissector_proto_defs.h"

/* === Core Ethernet/IP parse nodes === */
#include "flow_dissector_nodes.h"

/* === Extended L2 nodes (userspace only) === */
#ifndef XDP2_XDP_BUILD
#include "flow_dissector_nodes_l2.h"
#include "flow_dissector_nodes_app.h"
#endif

/* === Protocol dispatch tables === */
#include "flow_dissector_tables.h"

/* === Non-Ethernet parse graphs (userspace only) === */
#ifndef XDP2_XDP_BUILD
#include "graph_ieee80211.h"
#include "graph_bluetooth.h"
#include "graph_infiniband.h"
#include "graph_netlink.h"
#include "graph_misc.h"
#endif

/* === Parser declarations === */
#include "flow_dissector_parsers.h"

/* === R3 — monolithic-codegen reference parser (userspace only) ===
 *
 * Hand-written single-function form of the L2 flow_dissector graph.
 * Provides a ground-truth reference for the R3 codegen template.
 * See xdp2-rs/docs/dispatch-architecture-cost.md for R-phase plan.
 *
 * R3.3.3: when USE_GENERATED_MONO is defined, the generated
 * parser.mono.c provides xdp2_parser_flow_dissector_l2_mono and we
 * skip the hand-written reference to avoid the duplicate-definition
 * clash. Retired entirely in R3.3.7 once generated matches the
 * reference on parity AND perf. */
#if !defined(XDP2_XDP_BUILD) && !defined(USE_GENERATED_MONO)
#include "flow_dissector_mono.h"
#endif
