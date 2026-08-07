/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fast_flow_inner.h — shared inner extractors for the per-encapsulation
 * xdp2-flow-ebpf menu (fast_flow_<encap>.bpf.c).
 *
 * Each per-encap object #includes this header to get the common
 * eth + IPv4/IPv6 + {TCP,UDP,ICMP} fixed-offset extractors as tail-call
 * targets, plus the jmp_table PROG_ARRAY and the CHAIN_* ids. The
 * per-encap .bpf.c defines only the `_dissect` entry: it recognises
 * plain IP and its own encapsulation, advances keys->nhoff past the
 * L2/encap stride (rewriting keys->n_proto — the kernel unwrap pattern),
 * then bpf_tail_call()s into these shared inner programs. One source of
 * truth for the inner 5-tuple; each encap shim stays tiny.
 *
 * See kernel-patches/series6-common-case/ebpf-menu.md and
 * samples/flow_dissector/docs/super-flow-dissector-plan.md §5.
 *
 * Portability / CO-RE rationale is identical to fast_flow.bpf.c — see the
 * header comment there (all accesses are BPF-uapi stable structs or
 * RFC-stable wire formats, so BPF_CORE_READ is intentionally not used).
 */
#ifndef XDP2_FAST_FLOW_INNER_H
#define XDP2_FAST_FLOW_INNER_H

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

/* Inner-chain tail-call slot ids. The programs below are declared in
 * exactly this order: the loaders (parity_test.c, benchmark_bpf.c,
 * xdp2-flow-loader) populate jmp_table with every non-entry program in
 * declaration order, so declaration order == CHAIN_* index. */
#define CHAIN_ETH_IPV4_TCP  0
#define CHAIN_ETH_IPV4_UDP  1
#define CHAIN_ETH_IPV6_TCP  2
#define CHAIN_ETH_IPV6_UDP  3
#define CHAIN_ETH_IPV4_ICMP 4
#define CHAIN_DYNAMIC       7  /* slow-path slot; matches xdp2-flow-loader */
#define NUM_FAST_CHAINS     8

/* IPv4 frag_off M/F + offset bits — fragmented packets defer. */
#define IP_MF     0x2000
#define IP_OFFSET 0x1FFF

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, NUM_FAST_CHAINS);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

/* ─── Specialised: ETH / IPv4 / TCP ────────────────────────────────────
 *
 * Preconditions asserted by the entry: keys->nhoff points at an IPv4
 * header with IHL=5, not fragmented, protocol == TCP. No loops, no
 * switch, fixed-offset reads only. A tail-called program doesn't inherit
 * verifier state from the caller, so packet-boundary checks are
 * re-asserted here.
 */
SEC("flow_dissector")
int flow_dissector_eth_ipv4_tcp(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 nhoff = keys->nhoff;
	__u32 thoff;
	struct iphdr *iph;

	if (nhoff > 128)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	thoff = nhoff + 20;  /* IHL=5 guaranteed by entry gate */
	iph = data + nhoff;
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
 * UDP shares the src/dst-port layout with TCP at offsets 0/2; a literal
 * mirror of the TCP extractor with ip_proto = UDP.
 */
SEC("flow_dissector")
int flow_dissector_eth_ipv4_udp(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 nhoff = keys->nhoff;
	__u32 thoff;
	struct iphdr *iph;

	if (nhoff > 128)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	thoff = nhoff + 20;
	iph = data + nhoff;
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
 * Preconditions: keys->nhoff at an IPv6 header, next-hdr == TCP (no
 * extension headers). Fixed 40-byte header. ipv6_src/ipv6_dst are
 * contiguous — one 32-byte memcpy. flow_label is the 20-bit field in the
 * first 4 bytes (big-endian).
 */
SEC("flow_dissector")
int flow_dissector_eth_ipv6_tcp(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 nhoff = keys->nhoff;
	__u32 thoff;
	struct ipv6hdr *ip6h;

	if (nhoff > 128)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	thoff = nhoff + sizeof(struct ipv6hdr);
	ip6h = data + nhoff;
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
	__u32 thoff;
	struct ipv6hdr *ip6h;

	if (nhoff > 128)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	thoff = nhoff + sizeof(struct ipv6hdr);
	ip6h = data + nhoff;
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

/* ─── Specialised: ETH / IPv4 / ICMP ───────────────────────────────────
 *
 * ICMP has no L4 port pair, so sport/dport keep their zero default.
 * Mirrors upstream bpf_flow.kern.o: validate sizeof(icmphdr) present at
 * thoff, emit IP-level fields only.
 */
SEC("flow_dissector")
int flow_dissector_eth_ipv4_icmp(struct __sk_buff *skb)
{
	struct bpf_flow_keys *keys = skb->flow_keys;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 nhoff = keys->nhoff;
	__u32 thoff;
	struct iphdr *iph;
	struct icmphdr *icmp;

	if (nhoff > 128)
		return BPF_FLOW_DISSECTOR_CONTINUE;

	thoff = nhoff + 20;
	iph = data + nhoff;
	icmp = data + thoff;

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

/* ─── Shared L3 dispatch ────────────────────────────────────────────────
 *
 * Given the (already-unwrapped) inner ethertype and the L3 offset in
 * keys->nhoff, gate on IPv4 (IHL=5, not fragmented) / IPv6 (no ext hdrs)
 * and tail-call the matching inner extractor. On any miss, returns
 * BPF_FLOW_DISSECTOR_CONTINUE so the kernel software dissector takes over.
 *
 * Every fast_flow_<encap>.bpf.c entry reduces to: bound nhoff, unwrap its
 * encapsulation into (nhoff, proto), then `return fast_dispatch_l3(...)`.
 * This is the single source of truth for the inner gate + dispatch, so the
 * per-encap shims carry no duplicated 5-tuple logic.
 *
 * Callers MUST set keys->nhoff to the L3 offset before calling (the inner
 * extractors read keys->nhoff and derive thoff from it); the encap entry
 * also rewrites keys->n_proto to the inner ethertype, mirroring the
 * kernel's in-place unwrap.
 */
static __always_inline int fast_dispatch_l3(struct __sk_buff *skb, void *data,
					    void *data_end, __u32 nhoff,
					    __be16 proto)
{
	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + nhoff;

		if ((void *)(iph + 1) > data_end)
			return BPF_FLOW_DISSECTOR_CONTINUE;
		if (iph->ihl != 5)
			return BPF_FLOW_DISSECTOR_CONTINUE;
		if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
			return BPF_FLOW_DISSECTOR_CONTINUE;

		switch (iph->protocol) {
		case IPPROTO_TCP:
			bpf_tail_call_static(skb, &jmp_table, CHAIN_ETH_IPV4_TCP);
			break;
		case IPPROTO_UDP:
			bpf_tail_call_static(skb, &jmp_table, CHAIN_ETH_IPV4_UDP);
			break;
		case IPPROTO_ICMP:
			bpf_tail_call_static(skb, &jmp_table, CHAIN_ETH_IPV4_ICMP);
			break;
		}
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = data + nhoff;

		if ((void *)(ip6h + 1) > data_end)
			return BPF_FLOW_DISSECTOR_CONTINUE;

		switch (ip6h->nexthdr) {
		case IPPROTO_TCP:
			bpf_tail_call_static(skb, &jmp_table, CHAIN_ETH_IPV6_TCP);
			break;
		case IPPROTO_UDP:
			bpf_tail_call_static(skb, &jmp_table, CHAIN_ETH_IPV6_UDP);
			break;
		}
	}

	/* tail-call fell through (empty slot / unsupported) or non-IP */
	return BPF_FLOW_DISSECTOR_CONTINUE;
}

/* ─── Shared outer eth+IP+UDP probe (UDP-tunnel menu objects) ────────────
 *
 * For a UDP-tunnel object (fast_flow_{vxlan,geneve,gtpu}), validate that
 * the outer is eth + IPv4 (IHL=5, not fragmented) / IPv6 (no ext hdrs) +
 * UDP, and return the outer UDP offset. Returns -1 if the outer isn't a
 * fast-pathable eth+IP+UDP shape — the caller then plain-dispatches the
 * outer (fast_dispatch_l3), which covers non-UDP (e.g. outer TCP) and
 * non-tunnel UDP alike.
 */
static __always_inline int fast_outer_udp_off(void *data, void *data_end,
					      __u32 nhoff, __be16 proto)
{
	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + nhoff;

		if ((void *)(iph + 1) > data_end)
			return -1;
		if (iph->ihl != 5)
			return -1;
		if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
			return -1;
		if (iph->protocol != IPPROTO_UDP)
			return -1;
		return (int)nhoff + 20;
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = data + nhoff;

		if ((void *)(ip6h + 1) > data_end)
			return -1;
		if (ip6h->nexthdr != IPPROTO_UDP)
			return -1;
		return (int)nhoff + 40;
	}
	return -1;
}

#endif /* XDP2_FAST_FLOW_INNER_H */
