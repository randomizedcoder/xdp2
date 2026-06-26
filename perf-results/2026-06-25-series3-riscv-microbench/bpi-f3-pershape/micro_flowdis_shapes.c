/* Per-shape libflowdis microbench: eth_ip, vlan, qinq. Reports ns/pkt
 * per shape plus the dissected L3/L4 + vlan fields (so patched-vs-
 * baseline output can be diffed for byte-identical correctness). */
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "flow_dissector.h"

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

/* eth(14) + [tags] + IPv4(20) + TCP(20); data is taken at +14. */
static unsigned char pkt_ethip[80] = {
  0x52,0x54,0,0x12,0x34,0x56, 0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0x08,0x00,
  0x45,0x00,0x00,0x32,0,0,0x40,0,0x40,0x06,0,0, 192,168,1,100, 10,0,0,5,
  0xab,0xcd,0x00,0x50,0,0,0,0,0,0,0,0,0x50,0x10,0xff,0xff,0,0,0,0 };
static unsigned char pkt_vlan[80] = {
  0x52,0x54,0,0x12,0x34,0x56, 0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0x81,0x00,
  0x00,0x64,0x08,0x00,                                   /* vlan vid=100 -> IP */
  0x45,0x00,0x00,0x32,0,0,0x40,0,0x40,0x06,0,0, 192,168,1,100, 10,0,0,5,
  0xab,0xcd,0x00,0x50,0,0,0,0,0,0,0,0,0x50,0x10,0xff,0xff,0,0,0,0 };
static unsigned char pkt_qinq[80] = {
  0x52,0x54,0,0x12,0x34,0x56, 0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0x88,0xa8,
  0x00,0xc8,0x81,0x00,                                   /* outer 8021AD vid=200 -> 8021Q */
  0x00,0x64,0x08,0x00,                                   /* inner 8021Q vid=100 -> IP */
  0x45,0x00,0x00,0x32,0,0,0x40,0,0x40,0x06,0,0, 192,168,1,100, 10,0,0,5,
  0xab,0xcd,0x00,0x50,0,0,0,0,0,0,0,0,0x50,0x10,0xff,0xff,0,0,0,0 };

extern struct flow_dissector flow_keys_dissector;
void skb_flow_dissector_init(struct flow_dissector *, const struct flow_dissector_key *, unsigned int);
bool __skb_flow_dissect_err(const struct sk_buff *, struct flow_dissector *, void *, void *,
                            __be16, int, int, unsigned int, const char **);

static const struct flow_dissector_key dk[] = {
  { .key_id=FLOW_DISSECTOR_KEY_CONTROL,    .offset=offsetof(struct flow_keys, control) },
  { .key_id=FLOW_DISSECTOR_KEY_BASIC,      .offset=offsetof(struct flow_keys, basic) },
  { .key_id=FLOW_DISSECTOR_KEY_IPV4_ADDRS, .offset=offsetof(struct flow_keys, addrs.v4addrs) },
  { .key_id=FLOW_DISSECTOR_KEY_IPV6_ADDRS, .offset=offsetof(struct flow_keys, addrs.v6addrs) },
  { .key_id=FLOW_DISSECTOR_KEY_PORTS,      .offset=offsetof(struct flow_keys, ports) },
  { .key_id=FLOW_DISSECTOR_KEY_VLAN,       .offset=offsetof(struct flow_keys, vlan) },
  { .key_id=FLOW_DISSECTOR_KEY_CVLAN,      .offset=offsetof(struct flow_keys, cvlan) },
};

static void bench(const char *name, unsigned char *pkt, int len, __be16 proto, long iter) {
  const char *err=NULL; struct flow_keys keys;
  void *data = pkt + 14; int hlen = len - 14;
  for (int i=0;i<100000;i++){ memset(&keys,0,sizeof(keys));
    __skb_flow_dissect_err(NULL,&flow_keys_dissector,&keys,data,proto,0,hlen,0,&err); }
  struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC_RAW,&t0);
  for (long i=0;i<iter;i++){ memset(&keys,0,sizeof(keys));
    __skb_flow_dissect_err(NULL,&flow_keys_dissector,&keys,data,proto,0,hlen,0,&err); }
  clock_gettime(CLOCK_MONOTONIC_RAW,&t1);
  long ns=(t1.tv_sec-t0.tv_sec)*1000000000L+(t1.tv_nsec-t0.tv_nsec);
  printf("shape=%-6s ns_per_pkt=%.2f  addr_type=%d ip_proto=%d v4src=0x%x v4dst=0x%x sport=%d dport=%d vlan=%d cvlan=%d\n",
    name,(double)ns/iter,keys.control.addr_type,keys.basic.ip_proto,
    ntohl(keys.addrs.v4addrs.src),ntohl(keys.addrs.v4addrs.dst),
    ntohs(keys.ports.src),ntohs(keys.ports.dst),keys.vlan.vlan_id,keys.cvlan.vlan_id);
}

int main(int argc,char**argv){
  skb_flow_dissector_init(&flow_keys_dissector,dk,sizeof(dk)/sizeof(dk[0]));
  long iter=(argc>1)?atol(argv[1]):10000000;
  bench("eth_ip",pkt_ethip,sizeof(pkt_ethip),htons(ETH_P_IP),iter);
  bench("vlan",  pkt_vlan, sizeof(pkt_vlan), htons(ETH_P_8021Q),iter);
  bench("qinq",  pkt_qinq, sizeof(pkt_qinq), htons(ETH_P_8021AD),iter);
  return 0;
}
