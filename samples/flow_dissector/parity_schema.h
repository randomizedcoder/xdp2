/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * parity_schema.h — C-side ParityRecord for the flow-dissector parity gate
 * (Phase 17.A of docs/flow-dissector-matrix-progress.md).
 *
 * Used by samples/flow_dissector/{benchmark,benchmark_bpf}.c when the
 * `-D <jsonl_path>` flag is set. Each parser invocation writes one JSONL
 * line per packet conforming to the canonical schema documented in
 * samples/flow_dissector/parity_scope.json.
 *
 * Lifecycle per packet:
 *   1. parity_record_init(rec, parser_id, pcap, idx)
 *   2. parity_record_set_accepted(rec, true|false [, reject_reason])
 *   3. parity_record_set_addr_ipv4(rec, src, dst)   etc.
 *   4. parity_record_emit_jsonl(fp, rec)
 *
 * Setters mark each field as "present"; the serializer omits absent
 * fields so the comparator can distinguish "out of scope" from "value
 * is zero". The fixed-size struct avoids per-packet malloc.
 *
 * Schema version is checked at the comparator side; bump when the field
 * set or representation changes.
 */

#ifndef SAMPLES_FLOW_DISSECTOR_PARITY_SCHEMA_H
#define SAMPLES_FLOW_DISSECTOR_PARITY_SCHEMA_H

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PARITY_SCHEMA_VERSION 1
#define PARITY_VLAN_MAX 2
#define PARITY_MPLS_MAX 8

/* Field-presence bits. Keep in field-name order. Bumping this list
 * requires bumping PARITY_SCHEMA_VERSION and updating parity_scope.json.
 */
enum parity_field {
    PF_addr_type, PF_ip_proto,
    PF_ipv4_src, PF_ipv4_dst, PF_ipv6_src, PF_ipv6_dst, PF_tipc_key,
    PF_sport, PF_dport,
    PF_thoff, PF_is_frag, PF_is_first_frag, PF_flow_label,
    PF_eth_proto, PF_eth_dst, PF_eth_src,
    PF_ip_tos, PF_ip_ttl, PF_tcp_flags,
    PF_vlan, PF_mpls,
    PF_arp_sip, PF_arp_tip, PF_arp_op,
    PF_gre_proto, PF_gre_keyid,
    PF_esp_spi, PF_ah_spi, PF_l2tp_session_id,
    PF_icmp_type, PF_icmp_code, PF_icmp_id, PF_icmp_seq,
    PF_l2_off, PF_l3_off, PF_l4_off,
    PF_COUNT
};

enum parity_addr_type {
    PARITY_ADDR_NULL = 0,
    PARITY_ADDR_IPV4,
    PARITY_ADDR_IPV6,
    PARITY_ADDR_TIPC,
    PARITY_ADDR_SUNH,
};

struct parity_vlan {
    uint16_t tci, tpid, vid;
};

struct parity_mpls {
    uint32_t label;
    uint8_t tc;
    bool s;
    uint8_t ttl;
};

struct parity_record {
    /* Header — always emitted. */
    const char *parser_id;          /* e.g. "rust-graph-enum"; pointer to static string */
    const char *parser_kind;        /* "c"|"rust"|"bpf"|"bpf-with-fallback" */
    const char *pcap;               /* basename of input pcap */
    uint32_t packet_index;          /* 0-based index into pcap */
    bool accepted;                  /* parser fully processed this packet */
    const char *accept_path;        /* "fast"|"slow"|"fallback"|NULL */
    const char *reject_reason;      /* set when accepted=false; NULL otherwise */

    /* Field-presence bitmap. Set the bit when calling a setter; the
     * serializer iterates and emits only set fields. */
    uint64_t present_lo;            /* covers PF_0 .. PF_63 */
    uint64_t present_hi;            /* covers PF_64+ (reserved for growth) */

    /* Field values. Optional (consult presence bits before reading). */
    enum parity_addr_type addr_type;
    uint8_t  ip_proto;
    uint32_t ipv4_src;              /* network byte order */
    uint32_t ipv4_dst;
    uint8_t  ipv6_src[16];
    uint8_t  ipv6_dst[16];
    uint32_t tipc_key;
    uint16_t sport;                 /* host byte order */
    uint16_t dport;
    uint16_t thoff;
    bool is_frag;
    bool is_first_frag;
    uint32_t flow_label;
    uint16_t eth_proto;
    uint8_t  eth_dst[6];
    uint8_t  eth_src[6];
    uint8_t  ip_tos;
    uint8_t  ip_ttl;
    uint8_t  tcp_flags;
    uint8_t  vlan_count;
    struct parity_vlan vlan[PARITY_VLAN_MAX];
    uint8_t  mpls_count;
    struct parity_mpls mpls[PARITY_MPLS_MAX];
    uint32_t arp_sip;
    uint32_t arp_tip;
    uint16_t arp_op;
    uint16_t gre_proto;
    uint32_t gre_keyid;
    uint32_t esp_spi;
    uint32_t ah_spi;
    uint32_t l2tp_session_id;
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    uint16_t icmp_id;
    uint16_t icmp_seq;
    uint16_t l2_off;
    uint16_t l3_off;
    uint16_t l4_off;
};

/* ─── presence helpers ──────────────────────────────────────────── */

static inline void parity_set(struct parity_record *r, enum parity_field f)
{
    if ((unsigned)f < 64)
        r->present_lo |= (uint64_t)1 << (unsigned)f;
    else
        r->present_hi |= (uint64_t)1 << ((unsigned)f - 64);
}

static inline bool parity_has(const struct parity_record *r, enum parity_field f)
{
    if ((unsigned)f < 64)
        return (r->present_lo >> (unsigned)f) & 1;
    return (r->present_hi >> ((unsigned)f - 64)) & 1;
}

/* ─── lifecycle ─────────────────────────────────────────────────── */

static inline void parity_record_init(struct parity_record *r,
                                      const char *parser_id,
                                      const char *parser_kind,
                                      const char *pcap,
                                      uint32_t packet_index)
{
    memset(r, 0, sizeof(*r));
    r->parser_id = parser_id;
    r->parser_kind = parser_kind;
    r->pcap = pcap;
    r->packet_index = packet_index;
    /* Sentinels: caller must call parity_record_set_accepted() before emit. */
    r->accept_path = NULL;
    r->reject_reason = NULL;
}

static inline void parity_record_set_accepted(struct parity_record *r,
                                              bool accepted,
                                              const char *reject_reason)
{
    r->accepted = accepted;
    r->reject_reason = accepted ? NULL : reject_reason;
}

static inline void parity_record_set_accept_path(struct parity_record *r,
                                                 const char *path)
{
    r->accept_path = path;  /* "fast"|"slow"|"fallback"|NULL */
}

/* ─── typed setters (mark presence) ─────────────────────────────── */

static inline void parity_set_addr_type(struct parity_record *r,
                                        enum parity_addr_type t)
{
    r->addr_type = t;
    parity_set(r, PF_addr_type);
}

static inline void parity_set_ip_proto(struct parity_record *r, uint8_t v)
{ r->ip_proto = v; parity_set(r, PF_ip_proto); }

static inline void parity_set_ipv4(struct parity_record *r, uint32_t s, uint32_t d)
{
    r->ipv4_src = s; r->ipv4_dst = d;
    parity_set(r, PF_ipv4_src); parity_set(r, PF_ipv4_dst);
}

static inline void parity_set_ipv6(struct parity_record *r,
                                   const void *s16, const void *d16)
{
    memcpy(r->ipv6_src, s16, 16); memcpy(r->ipv6_dst, d16, 16);
    parity_set(r, PF_ipv6_src); parity_set(r, PF_ipv6_dst);
}

static inline void parity_set_tipc_key(struct parity_record *r, uint32_t k)
{ r->tipc_key = k; parity_set(r, PF_tipc_key); }

static inline void parity_set_ports(struct parity_record *r, uint16_t sp, uint16_t dp)
{
    r->sport = sp; r->dport = dp;
    parity_set(r, PF_sport); parity_set(r, PF_dport);
}

static inline void parity_set_thoff(struct parity_record *r, uint16_t v)
{ r->thoff = v; parity_set(r, PF_thoff); }

static inline void parity_set_frag(struct parity_record *r, bool f, bool first)
{
    r->is_frag = f; r->is_first_frag = first;
    parity_set(r, PF_is_frag); parity_set(r, PF_is_first_frag);
}

static inline void parity_set_flow_label(struct parity_record *r, uint32_t l)
{ r->flow_label = l; parity_set(r, PF_flow_label); }

static inline void parity_set_eth_proto(struct parity_record *r, uint16_t v)
{ r->eth_proto = v; parity_set(r, PF_eth_proto); }

static inline void parity_set_eth_addrs(struct parity_record *r,
                                        const void *dst6, const void *src6)
{
    memcpy(r->eth_dst, dst6, 6); memcpy(r->eth_src, src6, 6);
    parity_set(r, PF_eth_dst); parity_set(r, PF_eth_src);
}

static inline void parity_set_ip_tos_ttl(struct parity_record *r, uint8_t tos, uint8_t ttl)
{
    r->ip_tos = tos; r->ip_ttl = ttl;
    parity_set(r, PF_ip_tos); parity_set(r, PF_ip_ttl);
}

static inline void parity_set_tcp_flags(struct parity_record *r, uint8_t v)
{ r->tcp_flags = v; parity_set(r, PF_tcp_flags); }

static inline void parity_push_vlan(struct parity_record *r,
                                    uint16_t tci, uint16_t tpid, uint16_t vid)
{
    if (r->vlan_count >= PARITY_VLAN_MAX) return;
    r->vlan[r->vlan_count].tci  = tci;
    r->vlan[r->vlan_count].tpid = tpid;
    r->vlan[r->vlan_count].vid  = vid;
    r->vlan_count++;
    parity_set(r, PF_vlan);
}

static inline void parity_push_mpls(struct parity_record *r,
                                    uint32_t label, uint8_t tc, bool s, uint8_t ttl)
{
    if (r->mpls_count >= PARITY_MPLS_MAX) return;
    r->mpls[r->mpls_count].label = label;
    r->mpls[r->mpls_count].tc    = tc;
    r->mpls[r->mpls_count].s     = s;
    r->mpls[r->mpls_count].ttl   = ttl;
    r->mpls_count++;
    parity_set(r, PF_mpls);
}

static inline void parity_set_arp(struct parity_record *r,
                                  uint32_t sip, uint32_t tip, uint16_t op)
{
    r->arp_sip = sip; r->arp_tip = tip; r->arp_op = op;
    parity_set(r, PF_arp_sip); parity_set(r, PF_arp_tip); parity_set(r, PF_arp_op);
}

static inline void parity_set_gre(struct parity_record *r, uint16_t proto, uint32_t keyid)
{
    r->gre_proto = proto; r->gre_keyid = keyid;
    parity_set(r, PF_gre_proto); parity_set(r, PF_gre_keyid);
}

static inline void parity_set_keyid(struct parity_record *r, uint32_t k)
{ r->gre_keyid = k; parity_set(r, PF_gre_keyid); }

static inline void parity_set_esp_spi(struct parity_record *r, uint32_t v)
{ r->esp_spi = v; parity_set(r, PF_esp_spi); }
static inline void parity_set_ah_spi(struct parity_record *r, uint32_t v)
{ r->ah_spi = v; parity_set(r, PF_ah_spi); }
static inline void parity_set_l2tp(struct parity_record *r, uint32_t sid)
{ r->l2tp_session_id = sid; parity_set(r, PF_l2tp_session_id); }

static inline void parity_set_icmp(struct parity_record *r,
                                   uint8_t t, uint8_t c, uint16_t id, uint16_t seq)
{
    r->icmp_type = t; r->icmp_code = c; r->icmp_id = id; r->icmp_seq = seq;
    parity_set(r, PF_icmp_type); parity_set(r, PF_icmp_code);
    parity_set(r, PF_icmp_id);   parity_set(r, PF_icmp_seq);
}

static inline void parity_set_offsets(struct parity_record *r,
                                      uint16_t l2, uint16_t l3, uint16_t l4)
{
    r->l2_off = l2; r->l3_off = l3; r->l4_off = l4;
    parity_set(r, PF_l2_off); parity_set(r, PF_l3_off); parity_set(r, PF_l4_off);
}

/* ─── JSONL serializer ──────────────────────────────────────────── */

/* Write IPv4 dotted-quad (host-byte-order input → "a.b.c.d"). */
static inline void parity_write_ipv4(char buf[16], uint32_t addr_be)
{
    /* addr_be is in network byte order in our struct (per benchmark.c). */
    uint8_t b[4];
    memcpy(b, &addr_be, 4);
    snprintf(buf, 16, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

/* Write IPv6 in lowercase, no leading zeros, double-colon-compressed.
 * Implementation: use inet_ntop(AF_INET6) — defined in <arpa/inet.h>. */
#include <arpa/inet.h>
static inline void parity_write_ipv6(char buf[40], const uint8_t addr[16])
{
    inet_ntop(AF_INET6, addr, buf, 40);
}

static inline void parity_write_mac(char buf[18], const uint8_t mac[6])
{
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Emit JSONL line. Returns the number of bytes written, negative on error. */
static inline int parity_record_emit_jsonl(FILE *fp, const struct parity_record *r)
{
    int n = 0, t;
    char buf[40];

    t = fprintf(fp, "{\"schema_version\":%d,\"pcap\":\"%s\",\"packet_index\":%u",
                PARITY_SCHEMA_VERSION, r->pcap ? r->pcap : "", r->packet_index);
    if (t < 0) return -1; n += t;
    t = fprintf(fp, ",\"parser_id\":\"%s\",\"parser_kind\":\"%s\"",
                r->parser_id ? r->parser_id : "?", r->parser_kind ? r->parser_kind : "?");
    if (t < 0) return -1; n += t;
    t = fprintf(fp, ",\"accepted\":%s", r->accepted ? "true" : "false");
    if (t < 0) return -1; n += t;
    if (r->accept_path) {
        t = fprintf(fp, ",\"accept_path\":\"%s\"", r->accept_path); if (t < 0) return -1; n += t;
    }
    if (r->reject_reason) {
        t = fprintf(fp, ",\"reject_reason\":\"%s\"", r->reject_reason); if (t < 0) return -1; n += t;
    }

    t = fprintf(fp, ",\"fields\":{");
    if (t < 0) return -1; n += t;
    int first = 1;
    #define EMIT_COMMA() do { if (!first) { fputc(',', fp); n++; } first = 0; } while (0)

    if (parity_has(r, PF_addr_type)) {
        EMIT_COMMA();
        const char *s = "null";
        switch (r->addr_type) {
            case PARITY_ADDR_IPV4: s = "ipv4"; break;
            case PARITY_ADDR_IPV6: s = "ipv6"; break;
            case PARITY_ADDR_TIPC: s = "tipc"; break;
            case PARITY_ADDR_SUNH: s = "sunh"; break;
            default: s = "null"; break;
        }
        t = fprintf(fp, "\"addr_type\":\"%s\"", s); if (t < 0) return -1; n += t;
    }
    if (parity_has(r, PF_ip_proto))   { EMIT_COMMA(); t = fprintf(fp, "\"ip_proto\":%u", r->ip_proto); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_ipv4_src))   { EMIT_COMMA(); parity_write_ipv4(buf, r->ipv4_src); t = fprintf(fp, "\"ipv4_src\":\"%s\"", buf); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_ipv4_dst))   { EMIT_COMMA(); parity_write_ipv4(buf, r->ipv4_dst); t = fprintf(fp, "\"ipv4_dst\":\"%s\"", buf); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_ipv6_src))   { EMIT_COMMA(); parity_write_ipv6(buf, r->ipv6_src); t = fprintf(fp, "\"ipv6_src\":\"%s\"", buf); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_ipv6_dst))   { EMIT_COMMA(); parity_write_ipv6(buf, r->ipv6_dst); t = fprintf(fp, "\"ipv6_dst\":\"%s\"", buf); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_tipc_key))   { EMIT_COMMA(); t = fprintf(fp, "\"tipc_key\":%" PRIu32, r->tipc_key); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_sport))      { EMIT_COMMA(); t = fprintf(fp, "\"sport\":%u", r->sport); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_dport))      { EMIT_COMMA(); t = fprintf(fp, "\"dport\":%u", r->dport); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_thoff))      { EMIT_COMMA(); t = fprintf(fp, "\"thoff\":%u", r->thoff); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_is_frag))    { EMIT_COMMA(); t = fprintf(fp, "\"is_frag\":%s", r->is_frag ? "true" : "false"); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_is_first_frag)) { EMIT_COMMA(); t = fprintf(fp, "\"is_first_frag\":%s", r->is_first_frag ? "true" : "false"); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_flow_label)) { EMIT_COMMA(); t = fprintf(fp, "\"flow_label\":%" PRIu32, r->flow_label); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_eth_proto))  { EMIT_COMMA(); t = fprintf(fp, "\"eth_proto\":%u", r->eth_proto); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_eth_dst))    { EMIT_COMMA(); parity_write_mac(buf, r->eth_dst); t = fprintf(fp, "\"eth_dst\":\"%s\"", buf); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_eth_src))    { EMIT_COMMA(); parity_write_mac(buf, r->eth_src); t = fprintf(fp, "\"eth_src\":\"%s\"", buf); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_ip_tos))     { EMIT_COMMA(); t = fprintf(fp, "\"ip_tos\":%u", r->ip_tos); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_ip_ttl))     { EMIT_COMMA(); t = fprintf(fp, "\"ip_ttl\":%u", r->ip_ttl); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_tcp_flags))  { EMIT_COMMA(); t = fprintf(fp, "\"tcp_flags\":%u", r->tcp_flags); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_vlan)) {
        EMIT_COMMA();
        t = fprintf(fp, "\"vlan\":["); if (t < 0) return -1; n += t;
        for (uint8_t i = 0; i < r->vlan_count; i++) {
            t = fprintf(fp, "%s{\"tci\":%u,\"tpid\":%u,\"vid\":%u}",
                        i ? "," : "", r->vlan[i].tci, r->vlan[i].tpid, r->vlan[i].vid);
            if (t < 0) return -1; n += t;
        }
        fputc(']', fp); n++;
    }
    if (parity_has(r, PF_mpls)) {
        EMIT_COMMA();
        t = fprintf(fp, "\"mpls\":["); if (t < 0) return -1; n += t;
        for (uint8_t i = 0; i < r->mpls_count; i++) {
            t = fprintf(fp, "%s{\"label\":%" PRIu32 ",\"tc\":%u,\"s\":%s,\"ttl\":%u}",
                        i ? "," : "", r->mpls[i].label, r->mpls[i].tc,
                        r->mpls[i].s ? "true" : "false", r->mpls[i].ttl);
            if (t < 0) return -1; n += t;
        }
        fputc(']', fp); n++;
    }
    if (parity_has(r, PF_arp_sip))     { EMIT_COMMA(); parity_write_ipv4(buf, r->arp_sip); t = fprintf(fp, "\"arp_sip\":\"%s\"", buf); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_arp_tip))     { EMIT_COMMA(); parity_write_ipv4(buf, r->arp_tip); t = fprintf(fp, "\"arp_tip\":\"%s\"", buf); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_arp_op))      { EMIT_COMMA(); t = fprintf(fp, "\"arp_op\":%u", r->arp_op); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_gre_proto))   { EMIT_COMMA(); t = fprintf(fp, "\"gre_proto\":%u", r->gre_proto); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_gre_keyid))   { EMIT_COMMA(); t = fprintf(fp, "\"gre_keyid\":%" PRIu32, r->gre_keyid); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_esp_spi))     { EMIT_COMMA(); t = fprintf(fp, "\"esp_spi\":%" PRIu32, r->esp_spi); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_ah_spi))      { EMIT_COMMA(); t = fprintf(fp, "\"ah_spi\":%" PRIu32, r->ah_spi); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_l2tp_session_id)) { EMIT_COMMA(); t = fprintf(fp, "\"l2tp_session_id\":%" PRIu32, r->l2tp_session_id); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_icmp_type))   { EMIT_COMMA(); t = fprintf(fp, "\"icmp_type\":%u", r->icmp_type); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_icmp_code))   { EMIT_COMMA(); t = fprintf(fp, "\"icmp_code\":%u", r->icmp_code); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_icmp_id))     { EMIT_COMMA(); t = fprintf(fp, "\"icmp_id\":%u", r->icmp_id); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_icmp_seq))    { EMIT_COMMA(); t = fprintf(fp, "\"icmp_seq\":%u", r->icmp_seq); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_l2_off))      { EMIT_COMMA(); t = fprintf(fp, "\"l2_off\":%u", r->l2_off); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_l3_off))      { EMIT_COMMA(); t = fprintf(fp, "\"l3_off\":%u", r->l3_off); if (t < 0) return -1; n += t; }
    if (parity_has(r, PF_l4_off))      { EMIT_COMMA(); t = fprintf(fp, "\"l4_off\":%u", r->l4_off); if (t < 0) return -1; n += t; }
    #undef EMIT_COMMA

    t = fprintf(fp, "}}\n");
    if (t < 0) return -1; n += t;
    return n;
}

#endif /* SAMPLES_FLOW_DISSECTOR_PARITY_SCHEMA_H */
