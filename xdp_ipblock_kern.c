// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_ipblock_kern.c
 *
 * XDP program: drop inbound packets whose source IP matches any entry
 * (host address or CIDR prefix) in the LPM trie blocklist maps.
 *
 * Maps use BPF_MAP_TYPE_LPM_TRIE for O(prefix-length) longest-prefix
 * matching – optimal for mixed single-host and CIDR entries.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * LPM trie key layout required by the kernel:
 *   [ prefixlen : u32 ][ data : N bytes ]
 * The kernel matches the most-specific prefix that covers the lookup key.
 * A host address is stored with prefixlen == 32 (IPv4) or 128 (IPv6).
 */

struct lpm_v4_key {
    __u32 prefixlen;   /* 0–32  */
    __u8  addr[4];     /* network byte order */
};

struct lpm_v6_key {
    __u32 prefixlen;   /* 0–128 */
    __u8  addr[16];    /* network byte order */
};

/* IPv4 LPM trie – supports both /32 host addresses and CIDR prefixes */
struct {
    __uint(type,        BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __type(key,         struct lpm_v4_key);
    __type(value,       __u8);
    __uint(map_flags,   BPF_F_NO_PREALLOC);
} blocked_v4 SEC(".maps");

/* IPv6 LPM trie – supports both /128 host addresses and CIDR prefixes */
struct {
    __uint(type,        BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __type(key,         struct lpm_v6_key);
    __type(value,       __u8);
    __uint(map_flags,   BPF_F_NO_PREALLOC);
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

        struct lpm_v4_key key;
        key.prefixlen = 32;
        /* saddr is already in network byte order; copy byte-by-byte */
        __u32 saddr = iph->saddr;
        key.addr[0] = (saddr)       & 0xff;
        key.addr[1] = (saddr >>  8) & 0xff;
        key.addr[2] = (saddr >> 16) & 0xff;
        key.addr[3] = (saddr >> 24) & 0xff;

        if (bpf_map_lookup_elem(&blocked_v4, &key))
            return XDP_DROP;

    } else if (eth_type == ETH_P_IPV6) {
        /* IPv6 */
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;

        struct lpm_v6_key key;
        key.prefixlen = 128;
        /* Copy all 16 bytes of source address */
        __builtin_memcpy(key.addr, &ip6h->saddr, 16);

        if (bpf_map_lookup_elem(&blocked_v6, &key))
            return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
