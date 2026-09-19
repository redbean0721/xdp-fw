// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_ipblock_kern.c
 *
 * Three-stage XDP pipeline per packet:
 *
 *  Stage 1 – Static whitelist (LPM trie)
 *    If the source IP matches any entry in whitelist_v4 / whitelist_v6,
 *    bypass all further checks and immediately XDP_PASS.
 *    Whitelisted sources are never rate-limited.
 *
 *  Stage 2 – Static blocklist (LPM trie)
 *    Drop if the source IP matches any entry in blocked_v4 / blocked_v6.
 *    Supports both host addresses (/32, /128) and CIDR prefixes.
 *
 *  Stage 3 – Per-source token-bucket rate limiter (LRU hash)
 *    Each unseen source IP gets a fresh bucket (burst tokens).
 *    On every packet:
 *      tokens += elapsed_ns * rate_pps / 1e9   (refill)
 *      tokens  = min(tokens, burst)
 *    If tokens >= 1 → consume 1 → XDP_PASS
 *    Else           → XDP_DROP  (DoS mitigation)
 *
 * Rate-limit parameters are read from a single-element ARRAY map
 * (rl_config) so they can be adjusted from user space without reloading
 * the program.
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

/*
 * Token-bucket state stored per source IP.
 * tokens is scaled by TOKEN_SCALE to avoid floating-point arithmetic.
 *
 * Effective tokens = tb_state.tokens / TOKEN_SCALE
 * A packet costs TOKEN_SCALE tokens.
 */
#define TOKEN_SCALE  1000ULL   /* sub-packet precision */

struct tb_state {
    __u64 tokens;      /* current tokens × TOKEN_SCALE          */
    __u64 last_ts_ns;  /* timestamp of last packet (bpf_ktime)  */
};

/*
 * Rate-limit configuration (written by user space, read by BPF).
 * Stored in a single-element ARRAY so updates are atomic and visible
 * to all CPUs without reloading the XDP program.
 */
struct rl_cfg {
    __u64 rate_pps;   /* allowed packets per second              */
    __u64 burst;      /* maximum burst (packets); bucket ceiling */
};

/* ===================================================================
 * Maps
 * =================================================================== */

/* Stage 1 – static whitelist (LPM trie): bypass all checks on match */
struct {
    __uint(type,        BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __type(key,         struct lpm_v4_key);
    __type(value,       __u8);
    __uint(map_flags,   BPF_F_NO_PREALLOC);
} whitelist_v4 SEC(".maps");

/* IPv6 whitelist LPM trie */
struct {
    __uint(type,        BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __type(key,         struct lpm_v6_key);
    __type(value,       __u8);
    __uint(map_flags,   BPF_F_NO_PREALLOC);
} whitelist_v6 SEC(".maps");

/* Stage 2 – static blocklist (LPM trie) */
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

/*
 * Stage 3 – per-source token-bucket state (LRU hash)
 *
 * BPF_MAP_TYPE_LRU_HASH:
 *   - O(1) lookup/update backed by a hash table
 *   - When the map is full the least-recently-used entry is evicted
 *     automatically – no user-space housekeeping required
 *   - Well-suited for tracking a large and dynamic set of source IPs
 */
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key,         __u32);          /* IPv4 src addr (network order) */
    __type(value,       struct tb_state);
} tb_v4 SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key,         __u8[16]);       /* IPv6 src addr (network order) */
    __type(value,       struct tb_state);
} tb_v6 SEC(".maps");

/* Rate-limit config – index 0 holds the active configuration */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,         __u32);
    __type(value,       struct rl_cfg);
} rl_config SEC(".maps");

/* ===================================================================
 * Token-bucket helper
 *
 * Called after whitelist/blocklist checks. Updates the per-IP bucket
 * and returns 1 (pass) or 0 (drop).
 *
 * Algorithm (all integer arithmetic):
 *
 *   Δt   = now_ns - last_ts_ns            (nanoseconds elapsed)
 *   add  = Δt * rate_pps / 1_000_000_000 (tokens to add, scaled)
 *   tokens = min(tokens + add, burst * TOKEN_SCALE)
 *
 *   if tokens >= TOKEN_SCALE:
 *       tokens -= TOKEN_SCALE  →  pass
 *   else:
 *       drop
 * =================================================================== */
static __always_inline int token_bucket_allow(void *map,
                                               void *key,
                                               __u64 rate_pps,
                                               __u64 burst_pkts)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 burst_tokens = burst_pkts * TOKEN_SCALE;

    struct tb_state *st = bpf_map_lookup_elem(map, key);
    if (!st) {
        /* First packet from this source: create a fresh bucket */
        struct tb_state init;
        /* Start with a full bucket minus the current packet */
        init.tokens     = burst_tokens - TOKEN_SCALE;
        init.last_ts_ns = now;
        bpf_map_update_elem(map, key, &init, BPF_ANY);
        return 1;   /* pass */
    }

    /* Refill: tokens earned since last packet */
    __u64 elapsed = now - st->last_ts_ns;
    /*
     * add = elapsed * rate_pps * TOKEN_SCALE / 1_000_000_000
     * Use 64-bit arithmetic; safe for rates up to ~18 Gpps and
     * elapsed times up to ~18 seconds before overflow.
     */
    __u64 add = (elapsed / 1000000000ULL) * rate_pps * TOKEN_SCALE
              + (elapsed % 1000000000ULL) * rate_pps * TOKEN_SCALE / 1000000000ULL;

    st->tokens += add;
    if (st->tokens > burst_tokens)
        st->tokens = burst_tokens;

    st->last_ts_ns = now;

    if (st->tokens >= TOKEN_SCALE) {
        st->tokens -= TOKEN_SCALE;
        return 1;   /* pass */
    }
    return 0;       /* drop – bucket empty */
}

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

    /* --- Load rate-limit config (index 0) --- */
    __u32 cfg_idx = 0;
    struct rl_cfg *cfg = bpf_map_lookup_elem(&rl_config, &cfg_idx);
    /* Use safe defaults if the map entry is missing */
    __u64 rate_pps  = cfg ? cfg->rate_pps : 1000ULL;
    __u64 burst     = cfg ? cfg->burst    : 2000ULL;

    if (eth_type == ETH_P_IP) {
        /* IPv4 */
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;

        __u32 saddr = iph->saddr;

        /* Build LPM key for this source address */
        struct lpm_v4_key lpm_key;
        lpm_key.prefixlen = 32;
        lpm_key.addr[0]   = (saddr)       & 0xff;
        lpm_key.addr[1]   = (saddr >>  8) & 0xff;
        lpm_key.addr[2]   = (saddr >> 16) & 0xff;
        lpm_key.addr[3]   = (saddr >> 24) & 0xff;

        /* Stage 1: whitelist – whitelisted sources bypass everything */
        if (bpf_map_lookup_elem(&whitelist_v4, &lpm_key))
            return XDP_PASS;

        /* Stage 2: static blocklist */
        if (bpf_map_lookup_elem(&blocked_v4, &lpm_key))
            return XDP_DROP;

        /* Stage 3: token-bucket rate limiter */
        if (!token_bucket_allow(&tb_v4, &saddr, rate_pps, burst))
            return XDP_DROP;

    } else if (eth_type == ETH_P_IPV6) {
        /* IPv6 */
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;

        /* Build LPM key for this source address */
        struct lpm_v6_key lpm_key;
        lpm_key.prefixlen = 128;
        __builtin_memcpy(lpm_key.addr, &ip6h->saddr, 16);

        /* Stage 1: whitelist – whitelisted sources bypass everything */
        if (bpf_map_lookup_elem(&whitelist_v6, &lpm_key))
            return XDP_PASS;

        /* Stage 2: static blocklist */
        if (bpf_map_lookup_elem(&blocked_v6, &lpm_key))
            return XDP_DROP;

        /* Stage 3: token-bucket rate limiter */
        __u8 saddr6[16];
        __builtin_memcpy(saddr6, &ip6h->saddr, 16);
        if (!token_bucket_allow(&tb_v6, saddr6, rate_pps, burst))
            return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
