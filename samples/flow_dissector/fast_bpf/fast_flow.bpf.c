// SPDX-License-Identifier: GPL-2.0
//
// xdp2-flow-ebpf: high-performance BPF flow dissector built on
// xdp2-rs techniques (fixed-offset templates + fast-path top-N tail-call
// dispatch).
//
// See samples/flow_dissector/docs/super-flow-dissector-plan.md §5.
//
// Status: D1-D4 + D5 (minus §5a dynamic) + D6a. Entry program gates
// IPv4 (IHL=5, no fragmentation), pure IPv6 (no extension headers), and
// single-tagged 802.1Q VLAN over IPv4 (IHL=5, no fragmentation).
// Dispatches into seven specialised programs: ETH/IPv4/{TCP,UDP,ICMP},
// ETH/IPv6/{TCP,UDP}, ETH/VLAN/IPv4/{TCP,UDP}. Full slow-path tail call
// (D6) and dynamic socket-driven slot (§5a) are TODO. Slow-path
// fall-through returns BPF_FLOW_DISSECTOR_CONTINUE so the kernel's
// software dissector takes over — no packet drops on fast-path misses
// (D6a).
//

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* <linux/if_vlan.h> is kernel-internal; struct vlan_hdr isn't exported
 * to BPF builds. Declare the wire format inline — TCI + inner ethertype.
 */
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/* ─── Fast-path chain IDs ──────────────────────────────────────────────
 *
 * Keep in sync with super-flow-dissector-plan.md §5 ("Core design").
 * Slot 7 (CHAIN_DYNAMIC) is reserved for §5a listening-socket-driven
 * templates installed at runtime by xdp2-flow-loader.
 */
#define CHAIN_ETH_IPV4_TCP      0
#define CHAIN_ETH_IPV4_UDP      1
#define CHAIN_ETH_IPV6_TCP      2
#define CHAIN_ETH_IPV6_UDP      3
#define CHAIN_ETH_VLAN_IPV4_TCP 4
#define CHAIN_ETH_VLAN_IPV4_UDP 5
#define CHAIN_ETH_IPV4_ICMP     6
#define CHAIN_DYNAMIC           7  /* TODO §5a */
#define NUM_FAST_CHAINS         8

/* Mirror of net/ipv4/ip.h — the IPv4 frag_off field's M/F and offset
 * bits. We exclude any fragmented packet from the fast path. */
#define IP_MF       0x2000
#define IP_OFFSET   0x1FFF

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, NUM_FAST_CHAINS);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

/* ─── Entry program: signature match + tail-call dispatch ──────────────
 *
 * The kernel (or BPF_PROG_TEST_RUN) pre-sets keys->n_proto from the
 * Ethernet header and keys->nhoff = ETH_HLEN before calling us, so we
 * begin parsing at L3.
 *
 * Fast-path gate for IPv4: IHL=5 (no options) AND no fragmentation.
 * Anything else falls to slow path.
 */
SEC("flow_dissector")
int _dissect(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 nhoff = keys->nhoff;

	if (keys->n_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + nhoff;

		if ((void *)(iph + 1) > data_end)
			goto slowpath;

		/* Gate: no options, no fragmentation. */
		if (iph->ihl != 5)
			goto slowpath;
		if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
			goto slowpath;

		switch (iph->protocol) {
		case IPPROTO_TCP:
			bpf_tail_call_static(skb, &jmp_table,
					     CHAIN_ETH_IPV4_TCP);
			break;
		case IPPROTO_UDP:
			bpf_tail_call_static(skb, &jmp_table,
					     CHAIN_ETH_IPV4_UDP);
			break;
		case IPPROTO_ICMP:
			bpf_tail_call_static(skb, &jmp_table,
					     CHAIN_ETH_IPV4_ICMP);
			break;
		default:
			goto slowpath;
		}
		/* tail-call fall-through = slot empty; treat as slow path */
	} else if (keys->n_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = data + nhoff;

		if ((void *)(ip6h + 1) > data_end)
			goto slowpath;

		/* Gate: reject any IPv6 with extension headers. A real
		 * ext-hdr walk belongs in the slow path. */
		switch (ip6h->nexthdr) {
		case IPPROTO_TCP:
			bpf_tail_call_static(skb, &jmp_table,
					     CHAIN_ETH_IPV6_TCP);
			break;
		case IPPROTO_UDP:
			bpf_tail_call_static(skb, &jmp_table,
					     CHAIN_ETH_IPV6_UDP);
			break;
		default:
			goto slowpath;
		}
	} else if (keys->n_proto == bpf_htons(ETH_P_8021Q)) {
		/* Single-tagged 802.1Q over IPv4. QinQ and VLAN-over-IPv6
		 * are left for the slow path — the fast-path templates want
		 * a fixed L2 stride. */
		struct vlan_hdr *vlan = data + nhoff;
		struct iphdr *iph = data + nhoff + sizeof(*vlan);

		if ((void *)(vlan + 1) > data_end)
			goto slowpath;
		if (vlan->h_vlan_encapsulated_proto != bpf_htons(ETH_P_IP))
			goto slowpath;

		if ((void *)(iph + 1) > data_end)
			goto slowpath;
		if (iph->ihl != 5)
			goto slowpath;
		if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
			goto slowpath;

		switch (iph->protocol) {
		case IPPROTO_TCP:
			bpf_tail_call_static(skb, &jmp_table,
					     CHAIN_ETH_VLAN_IPV4_TCP);
			break;
		case IPPROTO_UDP:
			bpf_tail_call_static(skb, &jmp_table,
					     CHAIN_ETH_VLAN_IPV4_UDP);
			break;
		default:
			goto slowpath;
		}
	}

slowpath:
	/* D6a: hand the packet back to the kernel's software dissector.
	 * BPF_FLOW_DISSECTOR_CONTINUE preserves upstream coverage — no
	 * packet drops on fast-path misses. D6 will replace this with a
	 * direct tail call into an xdp2-compiler-generated slow path for
	 * reduced per-packet overhead. */
	return BPF_FLOW_DISSECTOR_CONTINUE;
}

/* ─── Specialised: ETH / IPv4 / TCP ────────────────────────────────────
 *
 * Preconditions from the entry gate: IPv4, IHL=5, not fragmented, proto
 * is TCP. No loops, no switch, fixed-offset reads only. Verifier-trivial.
 *
 * A tail-called program doesn't inherit verifier state from the caller,
 * so all packet-boundary checks are re-asserted here.
 */
SEC("flow_dissector")
int flow_dissector_eth_ipv4_tcp(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 nhoff = keys->nhoff;
	__u32 thoff = nhoff + 20;  /* IHL=5 guaranteed by entry gate */
	struct iphdr *iph = data + nhoff;
	__be16 *ports = data + thoff;

	if ((void *)(iph + 1) > data_end)
		return BPF_DROP;
	if ((void *)(ports + 2) > data_end)
		return BPF_DROP;

	keys->addr_proto = ETH_P_IP;
	keys->ipv4_src = iph->saddr;
	keys->ipv4_dst = iph->daddr;
	keys->ip_proto = IPPROTO_TCP;
	keys->sport = ports[0];
	keys->dport = ports[1];
	keys->thoff = thoff;
	keys->is_frag = 0;
	keys->is_first_frag = 0;

	return BPF_OK;
}

/* ─── Specialised: ETH / IPv4 / UDP ────────────────────────────────────
 *
 * UDP has the same src/dst-port layout as TCP at offsets 0/2, so this is
 * a literal mirror of the TCP extractor with ip_proto set to UDP.
 */
SEC("flow_dissector")
int flow_dissector_eth_ipv4_udp(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 nhoff = keys->nhoff;
	__u32 thoff = nhoff + 20;
	struct iphdr *iph = data + nhoff;
	__be16 *ports = data + thoff;

	if ((void *)(iph + 1) > data_end)
		return BPF_DROP;
	if ((void *)(ports + 2) > data_end)
		return BPF_DROP;

	keys->addr_proto = ETH_P_IP;
	keys->ipv4_src = iph->saddr;
	keys->ipv4_dst = iph->daddr;
	keys->ip_proto = IPPROTO_UDP;
	keys->sport = ports[0];
	keys->dport = ports[1];
	keys->thoff = thoff;
	keys->is_frag = 0;
	keys->is_first_frag = 0;

	return BPF_OK;
}

/* ─── Specialised: ETH / IPv6 / TCP ────────────────────────────────────
 *
 * Preconditions from the entry gate: IPv6, next-hdr = TCP (no extension
 * headers). Fixed IPv6 header size = 40 bytes.
 *
 * ipv6_src and ipv6_dst are contiguous in the header, so we read them
 * with one 32-byte memcpy. `flow_label` comes from the 20-bit field in
 * the first 4 bytes of the header (big-endian).
 */
SEC("flow_dissector")
int flow_dissector_eth_ipv6_tcp(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 nhoff = keys->nhoff;
	__u32 thoff = nhoff + sizeof(struct ipv6hdr);
	struct ipv6hdr *ip6h = data + nhoff;
	__be16 *ports = data + thoff;

	if ((void *)(ip6h + 1) > data_end)
		return BPF_DROP;
	if ((void *)(ports + 2) > data_end)
		return BPF_DROP;

	keys->addr_proto = ETH_P_IPV6;
	__builtin_memcpy(&keys->ipv6_src, &ip6h->saddr,
			 2 * sizeof(ip6h->saddr));
	keys->ip_proto = IPPROTO_TCP;
	keys->sport = ports[0];
	keys->dport = ports[1];
	keys->thoff = thoff;
	keys->flow_label = bpf_ntohl(*(__be32 *)ip6h) & 0x000FFFFF;
	keys->is_frag = 0;
	keys->is_first_frag = 0;

	return BPF_OK;
}

/* ─── Specialised: ETH / IPv6 / UDP ────────────────────────────────────
 *
 * Mirror of IPv6/TCP with ip_proto = UDP.
 */
SEC("flow_dissector")
int flow_dissector_eth_ipv6_udp(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 nhoff = keys->nhoff;
	__u32 thoff = nhoff + sizeof(struct ipv6hdr);
	struct ipv6hdr *ip6h = data + nhoff;
	__be16 *ports = data + thoff;

	if ((void *)(ip6h + 1) > data_end)
		return BPF_DROP;
	if ((void *)(ports + 2) > data_end)
		return BPF_DROP;

	keys->addr_proto = ETH_P_IPV6;
	__builtin_memcpy(&keys->ipv6_src, &ip6h->saddr,
			 2 * sizeof(ip6h->saddr));
	keys->ip_proto = IPPROTO_UDP;
	keys->sport = ports[0];
	keys->dport = ports[1];
	keys->thoff = thoff;
	keys->flow_label = bpf_ntohl(*(__be32 *)ip6h) & 0x000FFFFF;
	keys->is_frag = 0;
	keys->is_first_frag = 0;

	return BPF_OK;
}

/* ─── Specialised: ETH / VLAN / IPv4 / TCP ─────────────────────────────
 *
 * Preconditions from the entry gate: 802.1Q tag (single, not QinQ),
 * encapsulated ethertype = IPv4, IHL=5, not fragmented, proto=TCP.
 * Fixed L2 stride: vlan_hdr (4B) after the original ETH, so L3 starts
 * at nhoff + 4 and L4 at nhoff + 4 + 20.
 *
 * Upstream bpf_flow.kern.o unwraps the VLAN tag in-place: nhoff is
 * advanced past the tag and n_proto is rewritten to the inner ethertype
 * before the IPv4 handler runs. We mirror that so the oracle and fast
 * path produce identical bpf_flow_keys.
 */
SEC("flow_dissector")
int flow_dissector_eth_vlan_ipv4_tcp(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 nhoff = keys->nhoff + sizeof(struct vlan_hdr);
	__u32 thoff = nhoff + 20;
	struct iphdr *iph = data + nhoff;
	__be16 *ports = data + thoff;

	if ((void *)(iph + 1) > data_end)
		return BPF_DROP;
	if ((void *)(ports + 2) > data_end)
		return BPF_DROP;

	keys->nhoff = nhoff;
	keys->n_proto = bpf_htons(ETH_P_IP);
	keys->addr_proto = ETH_P_IP;
	keys->ipv4_src = iph->saddr;
	keys->ipv4_dst = iph->daddr;
	keys->ip_proto = IPPROTO_TCP;
	keys->sport = ports[0];
	keys->dport = ports[1];
	keys->thoff = thoff;
	keys->is_frag = 0;
	keys->is_first_frag = 0;

	return BPF_OK;
}

/* ─── Specialised: ETH / VLAN / IPv4 / UDP ─────────────────────────────
 *
 * Mirror of VLAN/IPv4/TCP with ip_proto = UDP.
 */
SEC("flow_dissector")
int flow_dissector_eth_vlan_ipv4_udp(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 nhoff = keys->nhoff + sizeof(struct vlan_hdr);
	__u32 thoff = nhoff + 20;
	struct iphdr *iph = data + nhoff;
	__be16 *ports = data + thoff;

	if ((void *)(iph + 1) > data_end)
		return BPF_DROP;
	if ((void *)(ports + 2) > data_end)
		return BPF_DROP;

	keys->nhoff = nhoff;
	keys->n_proto = bpf_htons(ETH_P_IP);
	keys->addr_proto = ETH_P_IP;
	keys->ipv4_src = iph->saddr;
	keys->ipv4_dst = iph->daddr;
	keys->ip_proto = IPPROTO_UDP;
	keys->sport = ports[0];
	keys->dport = ports[1];
	keys->thoff = thoff;
	keys->is_frag = 0;
	keys->is_first_frag = 0;

	return BPF_OK;
}

/* ─── Specialised: ETH / IPv4 / ICMP ───────────────────────────────────
 *
 * ICMP has no L4 port pair, so sport/dport stay at their zero default.
 * Upstream bpf_flow.kern.o validates sizeof(icmphdr) is present at thoff
 * and otherwise emits just the IP-level fields — this extractor mirrors
 * that exactly.
 */
SEC("flow_dissector")
int flow_dissector_eth_ipv4_icmp(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 nhoff = keys->nhoff;
	__u32 thoff = nhoff + 20;
	struct iphdr *iph = data + nhoff;
	struct icmphdr *icmp = data + thoff;

	if ((void *)(iph + 1) > data_end)
		return BPF_DROP;
	if ((void *)(icmp + 1) > data_end)
		return BPF_DROP;

	keys->addr_proto = ETH_P_IP;
	keys->ipv4_src = iph->saddr;
	keys->ipv4_dst = iph->daddr;
	keys->ip_proto = IPPROTO_ICMP;
	keys->thoff = thoff;
	keys->is_frag = 0;
	keys->is_first_frag = 0;

	return BPF_OK;
}

char _license[] SEC("license") = "GPL";
