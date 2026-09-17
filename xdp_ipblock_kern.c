// SPDX-License-Identifier: GPL-2.0
/* XDP kernel program: drop packets whose source IP is in the blocklist maps */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Map: blocked IPv4 addresses  key=__be32, value=__u8 (dummy) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key,   __u32);
    __type(value, __u8);
} blocked_v4 SEC(".maps");

/* Map: blocked IPv6 addresses  key=16 bytes, value=__u8 (dummy) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key,   struct in6_addr);
    __type(value, __u8);
} blocked_v6 SEC(".maps");

SEC("xdp")
int xdp_ipblock(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_type = bpf_ntohs(eth->h_proto);

    if (eth_type == ETH_P_IP) {
        /* IPv4 */
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;

        __u32 src = iph->saddr;   /* already in network byte order */
        if (bpf_map_lookup_elem(&blocked_v4, &src))
            return XDP_DROP;

    } else if (eth_type == ETH_P_IPV6) {
        /* IPv6 */
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;

        struct in6_addr src = ip6h->saddr;
        if (bpf_map_lookup_elem(&blocked_v6, &src))
            return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
