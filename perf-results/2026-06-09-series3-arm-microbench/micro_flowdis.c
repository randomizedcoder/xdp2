/* Minimal microbench for libflowdis. Times __skb_flow_dissect_err on a
 * synthetic eth+IPv4+TCP packet. Reports ns/pkt.
 *
 * Build: gcc -O3 -march=native -o micro_flowdis micro_flowdis.c \
 *           -I /home/das/Downloads/xdp2/src/include/flowdis \
 *           -L /home/das/Downloads/xdp2/result/lib -lflowdis
 *
 * Run: LD_LIBRARY_PATH=/home/das/Downloads/xdp2/result/lib ./micro_flowdis
 */
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "flow_dissector.h"

/* Build a synthetic eth+IPv4+TCP packet that hits the fast-path. */
static unsigned char pkt[64] = {
    /* Eth (14 bytes) */
    0x52, 0x54, 0x00, 0x12, 0x34, 0x56,  /* dst MAC */
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,  /* src MAC */
    0x08, 0x00,                            /* ethertype = ETH_P_IP */
    /* IPv4 (20 bytes) */
    0x45,                                  /* version 4, IHL 5 */
    0x00,                                  /* TOS */
    0x00, 0x32,                            /* total length 50 */
    0x00, 0x00,                            /* ID */
    0x40, 0x00,                            /* flags=DF, offset=0 */
    0x40,                                  /* TTL 64 */
    0x06,                                  /* protocol = TCP */
    0x00, 0x00,                            /* checksum */
    192, 168, 1, 100,                      /* src IP */
    10, 0, 0, 5,                           /* dst IP */
    /* TCP (20 bytes, ports we care about) */
    0xab, 0xcd,                            /* src port */
    0x00, 0x50,                            /* dst port = 80 */
    0x00, 0x00, 0x00, 0x00,                /* seq */
    0x00, 0x00, 0x00, 0x00,                /* ack */
    0x50, 0x10,                            /* doff=5 (20 bytes), flags=ACK */
    0xff, 0xff,                            /* window */
    0x00, 0x00, 0x00, 0x00,                /* checksum + urgent */
};

extern struct flow_dissector flow_keys_dissector;
extern bool flow_keys_dissector_initialized;

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

int main(int argc, char **argv) {
    /* Init the standard flow_keys dissector. */
    skb_flow_dissector_init(&flow_keys_dissector, dk,
                            sizeof(dk) / sizeof(dk[0]));

    long iter = (argc > 1) ? atol(argv[1]) : 10000000;
    const char *errmsg = NULL;

    struct flow_keys keys;
    void *data = pkt + 14;  /* point at IPv4 header */
    int nhoff = 0;
    int hlen = sizeof(pkt) - 14;
    __be16 proto = htons(ETH_P_IP);

    /* Warm up */
    for (int i = 0; i < 100000; i++) {
        memset(&keys, 0, sizeof(keys));
        __skb_flow_dissect_err(NULL, &flow_keys_dissector,
                                &keys, data, proto, nhoff, hlen, 0,
                                &errmsg);
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC_RAW, &t0);

    for (long i = 0; i < iter; i++) {
        memset(&keys, 0, sizeof(keys));
        __skb_flow_dissect_err(NULL, &flow_keys_dissector,
                                &keys, data, proto, nhoff, hlen, 0,
                                &errmsg);
    }

    clock_gettime(CLOCK_MONOTONIC_RAW, &t1);

    long ns = (t1.tv_sec - t0.tv_sec) * 1000000000L
            + (t1.tv_nsec - t0.tv_nsec);
    double ns_per_pkt = (double)ns / iter;
    printf("iter=%ld total=%ld ns ns_per_pkt=%.2f\n", iter, ns, ns_per_pkt);
    /* Sanity: print key contents to verify dissector worked */
    printf("addr_type=%d ip_proto=%d v4src=0x%x v4dst=0x%x sport=%d dport=%d\n",
           keys.control.addr_type,
           keys.basic.ip_proto,
           ntohl(keys.addrs.v4addrs.src),
           ntohl(keys.addrs.v4addrs.dst),
           ntohs(keys.ports.src),
           ntohs(keys.ports.dst));
    return 0;
}
