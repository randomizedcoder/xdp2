/* PCAP-driven microbench for libflowdis. Times __skb_flow_dissect_err
 * over the packets in a PCAP, cycling until a target call count is
 * reached. Reports aggregate ns/pkt + per-PCAP packet count.
 *
 * Sibling of perf-results/2026-06-04-series3-phase3-t/micro_flowdis.c
 * (single hardcoded eth+IPv4+TCP frame). This variant lets the same
 * bench drive the dissector against arbitrary traffic mixes from
 * data/pcaps/ — ICMP, fragmented IPv4, VLAN/QinQ, GRE/VXLAN/IPIP/L2TP
 * encap, IPv6 with extension headers, SRv6 — as well as the
 * mixed-traffic PCAPs produced by samples/flow_dissector/gen_workload_pcap.py.
 *
 * Used by nix/series3-pcap-microbench.nix and documented in the
 * series 3 non-fast-path / mixed-traffic A/B writeups under
 * perf-results/.
 *
 * Build: gcc -O3 -march=native -o micro_flowdis_pcap micro_flowdis_pcap.c \
 *           -I PFX/include -I PFX/include/flowdis \
 *           -L PFX/lib -lflowdis -lsiphash -lpcap
 *
 * Run:   LD_LIBRARY_PATH=PFX/lib ./micro_flowdis_pcap <pcap> [iter]
 */
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "flow_dissector.h"

extern struct flow_dissector flow_keys_dissector;

void skb_flow_dissector_init(struct flow_dissector *fd,
                              const struct flow_dissector_key *keys,
                              unsigned int n);
bool __skb_flow_dissect_err(const struct sk_buff *skb,
                             struct flow_dissector *fd,
                             void *target, void *data,
                             __be16 proto, int nhoff, int hlen,
                             unsigned int flags, const char **errmsg);

static const struct flow_dissector_key dk[] = {
    { .key_id = FLOW_DISSECTOR_KEY_CONTROL,    .offset = offsetof(struct flow_keys, control) },
    { .key_id = FLOW_DISSECTOR_KEY_BASIC,      .offset = offsetof(struct flow_keys, basic) },
    { .key_id = FLOW_DISSECTOR_KEY_IPV4_ADDRS, .offset = offsetof(struct flow_keys, addrs.v4addrs) },
    { .key_id = FLOW_DISSECTOR_KEY_IPV6_ADDRS, .offset = offsetof(struct flow_keys, addrs.v6addrs) },
    { .key_id = FLOW_DISSECTOR_KEY_PORTS,      .offset = offsetof(struct flow_keys, ports) },
    { .key_id = FLOW_DISSECTOR_KEY_VLAN,       .offset = offsetof(struct flow_keys, vlan) },
    { .key_id = FLOW_DISSECTOR_KEY_FLOW_LABEL, .offset = offsetof(struct flow_keys, tags) },
    { .key_id = FLOW_DISSECTOR_KEY_GRE_KEYID,  .offset = offsetof(struct flow_keys, keyid) },
};

/* Each cached packet: pointer past the 14-byte eth header, ethertype
 * read from the eth header, and the L3+ length. The bench feeds these
 * to __skb_flow_dissect_err — same shape as the single-shape sibling
 * which uses `data = pkt + 14; proto = htons(ETH_P_IP); nhoff = 0;`
 * for one packet.
 */
struct cached_pkt {
    const uint8_t *data;
    __be16         proto;
    int            hlen;
};

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <pcap> [iter]\n", argv[0]);
        return 64;
    }
    const char *pcap_path = argv[1];
    long iter = (argc > 2) ? atol(argv[2]) : 10000000;

    /* Open PCAP and cache every frame in memory. The bench loops over
     * the cached array; we don't pay PCAP read cost inside the timed
     * region.
     */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(pcap_path, errbuf);
    if (!p) {
        fprintf(stderr, "pcap_open_offline %s: %s\n", pcap_path, errbuf);
        return 1;
    }
    int dlt = pcap_datalink(p);
    if (dlt != DLT_EN10MB) {
        fprintf(stderr, "skip %s: non-Ethernet link-layer (DLT=%d, %s)\n",
                pcap_path, dlt,
                pcap_datalink_val_to_name(dlt) ?: "unknown");
        pcap_close(p);
        return 2;
    }

    /* Two-pass: count first to size the cache, then capture. PCAP API
     * doesn't give a packet count up front. Use a growable buffer
     * instead — simpler and still fast.
     */
    size_t cap = 256, n = 0;
    struct cached_pkt *pkts = malloc(cap * sizeof(*pkts));
    /* One big pool for all packet payloads. Packets in PCAPs are
     * typically < 9000 B; reserve a generous slab and grow if needed.
     */
    size_t pool_cap = 1 << 20, pool_used = 0;
    uint8_t *pool = malloc(pool_cap);
    if (!pkts || !pool) { fprintf(stderr, "oom\n"); return 1; }

    struct pcap_pkthdr *hdr;
    const uint8_t *raw;
    while (pcap_next_ex(p, &hdr, &raw) == 1) {
        if (hdr->caplen < 14)
            continue; /* not enough for an eth header; skip */
        size_t l3_len = hdr->caplen - 14;

        if (pool_used + l3_len > pool_cap) {
            while (pool_used + l3_len > pool_cap)
                pool_cap *= 2;
            uint8_t *new_pool = realloc(pool, pool_cap);
            if (!new_pool) { fprintf(stderr, "pool grow oom\n"); return 1; }
            /* Existing cached pointers reference the old pool. Rebase
             * them. Since pointers are recorded as offsets-from-base,
             * we have to update each one — store offsets and convert
             * to pointers after caching completes.
             */
            ptrdiff_t shift = new_pool - pool;
            for (size_t k = 0; k < n; k++)
                pkts[k].data = (const uint8_t *)((uintptr_t)pkts[k].data + shift);
            pool = new_pool;
        }
        uint8_t *dst = pool + pool_used;
        memcpy(dst, raw + 14, l3_len);
        if (n + 1 > cap) {
            cap *= 2;
            pkts = realloc(pkts, cap * sizeof(*pkts));
            if (!pkts) { fprintf(stderr, "pkts grow oom\n"); return 1; }
        }
        pkts[n].data  = dst;
        pkts[n].proto = (__be16)((raw[12] << 8) | raw[13]);
        pkts[n].hlen  = (int)l3_len;
        pool_used += l3_len;
        n++;
    }
    pcap_close(p);

    if (n == 0) {
        fprintf(stderr, "no usable packets in %s\n", pcap_path);
        return 1;
    }

    skb_flow_dissector_init(&flow_keys_dissector, dk,
                            sizeof(dk) / sizeof(dk[0]));

    const char *errmsg = NULL;
    struct flow_keys keys;

    /* Warm up: 100 k dispatches across the PCAP. */
    for (long i = 0; i < 100000; i++) {
        const struct cached_pkt *q = &pkts[i % n];
        memset(&keys, 0, sizeof(keys));
        __skb_flow_dissect_err(NULL, &flow_keys_dissector,
                                &keys, (void *)q->data, q->proto,
                                0, q->hlen, 0, &errmsg);
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC_RAW, &t0);

    long count = 0;
    while (count < iter) {
        const struct cached_pkt *q = &pkts[count % n];
        memset(&keys, 0, sizeof(keys));
        __skb_flow_dissect_err(NULL, &flow_keys_dissector,
                                &keys, (void *)q->data, q->proto,
                                0, q->hlen, 0, &errmsg);
        count++;
    }

    clock_gettime(CLOCK_MONOTONIC_RAW, &t1);

    long ns = (t1.tv_sec - t0.tv_sec) * 1000000000L
            + (t1.tv_nsec - t0.tv_nsec);
    double ns_per_pkt = (double)ns / count;
    printf("pcap=%s n_packets=%zu iter=%ld total=%ld ns ns_per_pkt=%.2f\n",
           pcap_path, n, count, ns, ns_per_pkt);

    free(pkts);
    free(pool);
    return 0;
}
