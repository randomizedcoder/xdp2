/* 6-shape libflowdis microbench: eth_ip, vlan, qinq, pppoe, mpls, ipip. */
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
#ifndef ETH_P_PPP_SES
#define ETH_P_PPP_SES 0x8864
#endif
#ifndef ETH_P_MPLS_UC
#define ETH_P_MPLS_UC 0x8847
#endif
#define IP20(proto,a,b,c,d,e,f,g,h) 0x45,0,0,0x32,0,0,0x40,0,0x40,(proto),0,0, a,b,c,d, e,f,g,h
#define TCP20 0xab,0xcd,0x00,0x50,0,0,0,0,0,0,0,0,0x50,0x10,0xff,0xff,0,0,0,0
#define ETH14 0x52,0x54,0,0x12,0x34,0x56, 0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0,0
static unsigned char p_ethip[90]={ ETH14, IP20(0x06,192,168,1,100,10,0,0,5), TCP20 };
static unsigned char p_vlan[90] ={ ETH14, 0x00,0x64,0x08,0x00, IP20(0x06,192,168,1,100,10,0,0,5), TCP20 };
static unsigned char p_qinq[90] ={ ETH14, 0x00,0xc8,0x81,0x00, 0x00,0x64,0x08,0x00, IP20(0x06,192,168,1,100,10,0,0,5), TCP20 };
static unsigned char p_pppoe[90]={ ETH14, 0x11,0x00,0x00,0x01,0x00,0x2a,0x00,0x21, IP20(0x06,192,168,1,100,10,0,0,5), TCP20 };
static unsigned char p_mpls[90] ={ ETH14, 0x00,0x06,0x41,0x40, IP20(0x06,192,168,1,100,10,0,0,5), TCP20 };
static unsigned char p_ipip[90] ={ ETH14, IP20(0x04,172,16,0,1,172,16,0,2), IP20(0x06,192,168,1,100,10,0,0,5), TCP20 };

extern struct flow_dissector flow_keys_dissector;
void skb_flow_dissector_init(struct flow_dissector*,const struct flow_dissector_key*,unsigned int);
bool __skb_flow_dissect_err(const struct sk_buff*,struct flow_dissector*,void*,void*,__be16,int,int,unsigned int,const char**);
static const struct flow_dissector_key dk[]={
 {.key_id=FLOW_DISSECTOR_KEY_CONTROL,.offset=offsetof(struct flow_keys,control)},
 {.key_id=FLOW_DISSECTOR_KEY_BASIC,.offset=offsetof(struct flow_keys,basic)},
 {.key_id=FLOW_DISSECTOR_KEY_IPV4_ADDRS,.offset=offsetof(struct flow_keys,addrs.v4addrs)},
 {.key_id=FLOW_DISSECTOR_KEY_IPV6_ADDRS,.offset=offsetof(struct flow_keys,addrs.v6addrs)},
 {.key_id=FLOW_DISSECTOR_KEY_PORTS,.offset=offsetof(struct flow_keys,ports)},
 {.key_id=FLOW_DISSECTOR_KEY_VLAN,.offset=offsetof(struct flow_keys,vlan)},
 {.key_id=FLOW_DISSECTOR_KEY_CVLAN,.offset=offsetof(struct flow_keys,cvlan)},
};
static void bench(const char*name,unsigned char*pkt,__be16 proto,long iter){
 const char*e=NULL; struct flow_keys k; void*d=pkt+14; int hlen=90-14;
 for(int i=0;i<100000;i++){memset(&k,0,sizeof(k));__skb_flow_dissect_err(NULL,&flow_keys_dissector,&k,d,proto,0,hlen,0,&e);}
 struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC_RAW,&t0);
 for(long i=0;i<iter;i++){memset(&k,0,sizeof(k));__skb_flow_dissect_err(NULL,&flow_keys_dissector,&k,d,proto,0,hlen,0,&e);}
 clock_gettime(CLOCK_MONOTONIC_RAW,&t1);
 long ns=(t1.tv_sec-t0.tv_sec)*1000000000L+(t1.tv_nsec-t0.tv_nsec);
 printf("shape=%-6s ns_per_pkt=%.2f  at=%d ipp=%d src=0x%x dst=0x%x sp=%d dp=%d vlan=%d cvlan=%d encap=%d\n",
  name,(double)ns/iter,k.control.addr_type,k.basic.ip_proto,ntohl(k.addrs.v4addrs.src),ntohl(k.addrs.v4addrs.dst),
  ntohs(k.ports.src),ntohs(k.ports.dst),k.vlan.vlan_id,k.cvlan.vlan_id,(k.control.flags&FLOW_DIS_ENCAPSULATION)?1:0);
}
int main(int argc,char**argv){
 skb_flow_dissector_init(&flow_keys_dissector,dk,sizeof(dk)/sizeof(dk[0]));
 long it=(argc>1)?atol(argv[1]):10000000;
 bench("eth_ip",p_ethip,htons(ETH_P_IP),it);
 bench("vlan",p_vlan,htons(ETH_P_8021Q),it);
 bench("qinq",p_qinq,htons(ETH_P_8021AD),it);
 bench("pppoe",p_pppoe,htons(ETH_P_PPP_SES),it);
 bench("mpls",p_mpls,htons(ETH_P_MPLS_UC),it);
 bench("ipip",p_ipip,htons(ETH_P_IP),it);
 return 0;
}
