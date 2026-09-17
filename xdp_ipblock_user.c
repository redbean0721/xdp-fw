// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_ipblock_user.c
 *
 * User-space loader for the XDP IP blocklist program.
 * Supports both single host addresses and CIDR prefixes in blocklist files.
 *
 * Usage:
 *   Load:   ./xdp_ipblock <ifname> [badip_v4.txt] [badip_v6.txt]
 *   Unload: ./xdp_ipblock <ifname> --unload
 *
 * File format (same for v4 and v6, one entry per line):
 *   192.168.1.0/24       <- CIDR prefix
 *   10.0.0.1             <- single host (treated as /32 or /128)
 *   2001:db8::/32        <- IPv6 CIDR
 *   fe80::1              <- single IPv6 host
 *   # comment lines and blank lines are ignored
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define XDP_OBJ    "xdp_ipblock_kern.o"
#define DEFAULT_V4 "badip_v4.txt"
#define DEFAULT_V6 "badip_v6.txt"

/* Must match the struct layout in the kernel program */
struct lpm_v4_key {
    __u32 prefixlen;
    __u8  addr[4];
};

struct lpm_v6_key {
    __u32 prefixlen;
    __u8  addr[16];
};

/* ------------------------------------------------------------------ */
/* Strip trailing newline and inline comments; trim leading whitespace */
static void clean_line(char *line)
{
    char *p;
    p = strchr(line, '#');  if (p) *p = '\0';
    p = strchr(line, '\n'); if (p) *p = '\0';
    p = strchr(line, '\r'); if (p) *p = '\0';
    /* ltrim */
    size_t off = strspn(line, " \t");
    if (off) memmove(line, line + off, strlen(line + off) + 1);
    /* rtrim */
    size_t len = strlen(line);
    while (len > 0 && (line[len-1] == ' ' || line[len-1] == '\t'))
        line[--len] = '\0';
}

/* ------------------------------------------------------------------ */
/*
 * Parse an IPv4 entry: either "a.b.c.d" or "a.b.c.d/prefix"
 * Stores the network address (host bits zeroed) in key->addr[].
 * Returns 0 on success, -1 on parse error.
 */
static int parse_v4_entry(const char *str, struct lpm_v4_key *key)
{
    char buf[64];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    int prefixlen = 32;   /* default: host address */
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        char *end;
        long pl = strtol(slash + 1, &end, 10);
        if (*end != '\0' || pl < 0 || pl > 32) {
            fprintf(stderr, "invalid IPv4 prefix length in: %s\n", str);
            return -1;
        }
        prefixlen = (int)pl;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) {
        fprintf(stderr, "invalid IPv4 address: %s\n", str);
        return -1;
    }

    /* Zero host bits so the trie key is canonical */
    __u32 mask = (prefixlen == 0) ? 0 : htonl(~((1u << (32 - prefixlen)) - 1));
    __u32 net  = addr.s_addr & mask;

    key->prefixlen = (__u32)prefixlen;
    key->addr[0]   = (net)       & 0xff;
    key->addr[1]   = (net >>  8) & 0xff;
    key->addr[2]   = (net >> 16) & 0xff;
    key->addr[3]   = (net >> 24) & 0xff;
    return 0;
}

/*
 * Parse an IPv6 entry: either "addr" or "addr/prefix"
 * Stores the network address (host bits zeroed) in key->addr[].
 * Returns 0 on success, -1 on parse error.
 */
static int parse_v6_entry(const char *str, struct lpm_v6_key *key)
{
    char buf[128];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    int prefixlen = 128;
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        char *end;
        long pl = strtol(slash + 1, &end, 10);
        if (*end != '\0' || pl < 0 || pl > 128) {
            fprintf(stderr, "invalid IPv6 prefix length in: %s\n", str);
            return -1;
        }
        prefixlen = (int)pl;
    }

    struct in6_addr addr;
    if (inet_pton(AF_INET6, buf, &addr) != 1) {
        fprintf(stderr, "invalid IPv6 address: %s\n", str);
        return -1;
    }

    /* Zero host bits byte-by-byte */
    __u8 tmp[16];
    memcpy(tmp, addr.s6_addr, 16);
    for (int i = 0; i < 16; i++) {
        int bit_start = i * 8;
        if (bit_start >= prefixlen) {
            tmp[i] = 0;
        } else if (bit_start + 8 > prefixlen) {
            int keep = prefixlen - bit_start;
            tmp[i] &= ((__u8)0xff << (8 - keep));
        }
    }

    key->prefixlen = (__u32)prefixlen;
    memcpy(key->addr, tmp, 16);
    return 0;
}

/* ------------------------------------------------------------------ */
static int load_v4(int map_fd, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) return 0;   /* file optional */
        perror(path);
        return -1;
    }

    char line[128];
    __u8 val = 1;
    int  cnt = 0;

    while (fgets(line, sizeof(line), f)) {
        clean_line(line);
        if (!*line) continue;

        struct lpm_v4_key key;
        if (parse_v4_entry(line, &key) < 0)
            continue;

        if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) < 0)
            perror("map_update v4");
        else
            cnt++;
    }
    fclose(f);
    fprintf(stderr, "[v4] loaded %d entries from %s\n", cnt, path);
    return 0;
}

static int load_v6(int map_fd, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) return 0;
        perror(path);
        return -1;
    }

    char line[256];
    __u8 val = 1;
    int  cnt = 0;

    while (fgets(line, sizeof(line), f)) {
        clean_line(line);
        if (!*line) continue;

        struct lpm_v6_key key;
        if (parse_v6_entry(line, &key) < 0)
            continue;

        if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) < 0)
            perror("map_update v6");
        else
            cnt++;
    }
    fclose(f);
    fprintf(stderr, "[v6] loaded %d entries from %s\n", cnt, path);
    return 0;
}

/* ------------------------------------------------------------------ */
static volatile int running = 1;
static void on_sig(int s) { (void)s; running = 0; }

/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "Usage:\n"
            "  %s <ifname> [badip_v4.txt] [badip_v6.txt]\n"
            "  %s <ifname> --unload\n", argv[0], argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "if_nametoindex(%s): %s\n", ifname, strerror(errno));
        return 1;
    }

    /* ---- unload mode ---- */
    if (argc >= 3 && strcmp(argv[2], "--unload") == 0) {
        if (bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL) < 0)
            /* try native then generic */
            bpf_xdp_detach(ifindex, 0, NULL);
        fprintf(stderr, "XDP detached from %s\n", ifname);
        return 0;
    }

    const char *v4_file = (argc >= 3) ? argv[2] : DEFAULT_V4;
    const char *v6_file = (argc >= 4) ? argv[3] : DEFAULT_V6;

    /* ---- open & load BPF object ---- */
    struct bpf_object *obj = bpf_object__open(XDP_OBJ);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "bpf_object__open(%s) failed\n", XDP_OBJ);
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "bpf_object__load failed\n");
        bpf_object__close(obj);
        return 1;
    }

    /* ---- find XDP program ---- */
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_ipblock");
    if (!prog) {
        fprintf(stderr, "program 'xdp_ipblock' not found\n");
        bpf_object__close(obj);
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);

    /* ---- find maps ---- */
    struct bpf_map *map_v4 = bpf_object__find_map_by_name(obj, "blocked_v4");
    struct bpf_map *map_v6 = bpf_object__find_map_by_name(obj, "blocked_v6");
    if (!map_v4 || !map_v6) {
        fprintf(stderr, "could not find maps\n");
        bpf_object__close(obj);
        return 1;
    }
    int fd_v4 = bpf_map__fd(map_v4);
    int fd_v6 = bpf_map__fd(map_v6);

    /* ---- populate maps ---- */
    if (load_v4(fd_v4, v4_file) < 0 || load_v6(fd_v6, v6_file) < 0) {
        bpf_object__close(obj);
        return 1;
    }

    /* ---- attach XDP (try native first, fall back to generic) ---- */
    int flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    if (bpf_xdp_attach(ifindex, prog_fd, flags | XDP_FLAGS_DRV_MODE, NULL) < 0) {
        fprintf(stderr, "native XDP failed, trying generic mode\n");
        if (bpf_xdp_attach(ifindex, prog_fd, flags | XDP_FLAGS_SKB_MODE, NULL) < 0) {
            perror("bpf_xdp_attach");
            bpf_object__close(obj);
            return 1;
        }
    }

    fprintf(stderr, "XDP attached to %s – press Ctrl-C to stop\n", ifname);

    signal(SIGINT,  on_sig);
    signal(SIGTERM, on_sig);
    while (running)
        pause();

    /* ---- detach ---- */
    bpf_xdp_detach(ifindex, 0, NULL);
    fprintf(stderr, "XDP detached from %s\n", ifname);

    bpf_object__close(obj);
    return 0;
}
