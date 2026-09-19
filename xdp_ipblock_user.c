#define _XOPEN_SOURCE 600

// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_ipblock_user.c
 *
 * User-space loader for the XDP IP whitelist/blocklist + rate-limiter program.
 *
 * Usage:
 *   Load:   ./xdp_ipblock <ifname> [--rate <pps>] [--burst <pkts>]
 *                                   [badip_v4.txt] [badip_v6.txt]
 *                                   [whitelist_v4.txt] [whitelist_v6.txt]
 *   Unload: ./xdp_ipblock <ifname> --unload
 *
 * Options:
 *   --rate    <pps>   Allowed packets per second per source IP (default: 1000)
 *   --burst   <pkts>  Burst capacity in packets (default: 2000)
 *   --wl-v4   <file>  IPv4 whitelist file (default: whitelist_v4.txt)
 *   --wl-v6   <file>  IPv6 whitelist file (default: whitelist_v6.txt)
 *   --bl-v4   <file>  IPv4 blocklist file (default: badip_v4.txt)
 *   --bl-v6   <file>  IPv6 blocklist file (default: badip_v6.txt)
 *
 * File format (one entry per line, shared by all list files):
 *   192.168.1.0/24    <- CIDR prefix
 *   10.0.0.1          <- single host (/32 or /128 implied)
 *   # comment / blank lines ignored
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <libgen.h>
#include <sys/inotify.h>
#include <sys/select.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/limits.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define XDP_OBJ        "xdp_ipblock_kern.o"
#define DEFAULT_BL_V4  "badip_v4.txt"
#define DEFAULT_BL_V6  "badip_v6.txt"
#define DEFAULT_WL_V4  "whitelist_v4.txt"
#define DEFAULT_WL_V6  "whitelist_v6.txt"

/* Default rate-limit parameters */
#define DEFAULT_RATE_PPS  1000ULL   /* packets/second per source */
#define DEFAULT_BURST     2000ULL   /* max burst packets          */

#define INOTIFY_BUFSZ  (32 * (sizeof(struct inotify_event) + NAME_MAX + 1))
#define ENTRY_MAXLEN   64

/* Must match kernel struct layout exactly */
struct lpm_v4_key {
    __u32 prefixlen;
    __u8  addr[4];
};

struct lpm_v6_key {
    __u32 prefixlen;
    __u8  addr[16];
};

struct rl_cfg {
    __u64 rate_pps;
    __u64 burst;
};

/* ------------------------------------------------------------------ */
/* Sorted string set for diffing list entries                           */
typedef struct {
    char   **data;
    size_t   count;
    size_t   cap;
} entry_set_t;

static int entry_cmp(const void *a, const void *b)
{
    return strcmp(*(const char **)a, *(const char **)b);
}

static void entry_set_init(entry_set_t *s)
{
    s->count = 0;
    s->cap   = 1024;
    s->data  = malloc(s->cap * sizeof(char *));
}

static void entry_set_free(entry_set_t *s)
{
    for (size_t i = 0; i < s->count; i++)
        free(s->data[i]);
    free(s->data);
    s->data  = NULL;
    s->count = 0;
    s->cap   = 0;
}

static void entry_set_insert(entry_set_t *s, char *str)
{
    if (s->count >= s->cap) {
        s->cap *= 2;
        s->data = realloc(s->data, s->cap * sizeof(char *));
    }
    s->data[s->count++] = str;
}

static void entry_set_sort(entry_set_t *s)
{
    qsort(s->data, s->count, sizeof(char *), entry_cmp);
}

static int entry_set_has(const entry_set_t *s, const char *str)
{
    if (!s->count) return 0;
    size_t lo = 0, hi = s->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(s->data[mid], str);
        if (c == 0) return 1;
        if (c < 0)  lo = mid + 1;
        else        hi = mid;
    }
    return 0;
}

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
 * Writes canonical "a.b.c.d/pl" into canon[ENTRY_MAXLEN] if non-NULL.
 * Returns 0 on success, -1 on parse error.
 */
static int parse_v4_entry(const char *str, struct lpm_v4_key *key,
                           char canon[ENTRY_MAXLEN])
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

    if (key) {
        key->prefixlen = (__u32)prefixlen;
        key->addr[0]   = (net)       & 0xff;
        key->addr[1]   = (net >>  8) & 0xff;
        key->addr[2]   = (net >> 16) & 0xff;
        key->addr[3]   = (net >> 24) & 0xff;
    }

    if (canon) {
        struct in_addr naddr = { .s_addr = net };
        char tmp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &naddr, tmp, sizeof(tmp));
        snprintf(canon, ENTRY_MAXLEN, "%s/%d", tmp, prefixlen);
    }
    return 0;
}

/*
 * Parse an IPv6 entry: either "addr" or "addr/prefix"
 * Stores the network address (host bits zeroed) in key->addr[].
 * Writes canonical "addr/pl" into canon[ENTRY_MAXLEN] if non-NULL.
 * Returns 0 on success, -1 on parse error.
 */
static int parse_v6_entry(const char *str, struct lpm_v6_key *key,
                           char canon[ENTRY_MAXLEN])
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

    if (key) {
        key->prefixlen = (__u32)prefixlen;
        memcpy(key->addr, tmp, 16);
    }

    if (canon) {
        struct in6_addr naddr;
        memcpy(naddr.s6_addr, tmp, 16);
        char ntop[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &naddr, ntop, sizeof(ntop));
        snprintf(canon, ENTRY_MAXLEN, "%s/%d", ntop, prefixlen);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Generic load: read a file of IPv4 entries into a BPF LPM trie map   */
static int load_v4(int map_fd, const char *path, entry_set_t *set,
                   const char *label)
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
        char canon[ENTRY_MAXLEN];
        if (parse_v4_entry(line, &key, canon) < 0)
            continue;

        if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) < 0)
            perror("map_update v4");
        else {
            entry_set_insert(set, strdup(canon));
            cnt++;
        }
    }
    fclose(f);
    entry_set_sort(set);
    fprintf(stderr, "[v4/%s] loaded %d entries from %s\n", label, cnt, path);
    return 0;
}

/* Generic load: read a file of IPv6 entries into a BPF LPM trie map   */
static int load_v6(int map_fd, const char *path, entry_set_t *set,
                   const char *label)
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
        char canon[ENTRY_MAXLEN];
        if (parse_v6_entry(line, &key, canon) < 0)
            continue;

        if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) < 0)
            perror("map_update v6");
        else {
            entry_set_insert(set, strdup(canon));
            cnt++;
        }
    }
    fclose(f);
    entry_set_sort(set);
    fprintf(stderr, "[v6/%s] loaded %d entries from %s\n", label, cnt, path);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Re-read a file, diff against old set, apply delta to BPF map        */
static void reload_v4(int map_fd, const char *path, entry_set_t *old,
                      const char *label)
{
    entry_set_t nw;
    entry_set_init(&nw);

    FILE *f = fopen(path, "r");
    if (!f) { if (errno != ENOENT) perror(path); return; }

    char line[128];
    while (fgets(line, sizeof(line), f)) {
        clean_line(line);
        if (!*line) continue;
        char canon[ENTRY_MAXLEN];
        if (parse_v4_entry(line, NULL, canon) < 0) continue;
        entry_set_insert(&nw, strdup(canon));
    }
    fclose(f);
    entry_set_sort(&nw);

    __u8 val = 1;
    int added = 0, removed = 0;

    for (size_t i = 0; i < nw.count; i++) {
        if (!entry_set_has(old, nw.data[i])) {
            struct lpm_v4_key key;
            if (parse_v4_entry(nw.data[i], &key, NULL) == 0) {
                bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
                added++;
            }
        }
    }
    for (size_t i = 0; i < old->count; i++) {
        if (!entry_set_has(&nw, old->data[i])) {
            struct lpm_v4_key key;
            if (parse_v4_entry(old->data[i], &key, NULL) == 0) {
                bpf_map_delete_elem(map_fd, &key);
                removed++;
            }
        }
    }

    fprintf(stderr, "[v4/%s] reload %s: +%d -%d (total %zu)\n",
            label, path, added, removed, nw.count);

    entry_set_free(old);
    *old = nw;
}

static void reload_v6(int map_fd, const char *path, entry_set_t *old,
                      const char *label)
{
    entry_set_t nw;
    entry_set_init(&nw);

    FILE *f = fopen(path, "r");
    if (!f) { if (errno != ENOENT) perror(path); return; }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        clean_line(line);
        if (!*line) continue;
        char canon[ENTRY_MAXLEN];
        if (parse_v6_entry(line, NULL, canon) < 0) continue;
        entry_set_insert(&nw, strdup(canon));
    }
    fclose(f);
    entry_set_sort(&nw);

    __u8 val = 1;
    int added = 0, removed = 0;

    for (size_t i = 0; i < nw.count; i++) {
        if (!entry_set_has(old, nw.data[i])) {
            struct lpm_v6_key key;
            if (parse_v6_entry(nw.data[i], &key, NULL) == 0) {
                bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
                added++;
            }
        }
    }
    for (size_t i = 0; i < old->count; i++) {
        if (!entry_set_has(&nw, old->data[i])) {
            struct lpm_v6_key key;
            if (parse_v6_entry(old->data[i], &key, NULL) == 0) {
                bpf_map_delete_elem(map_fd, &key);
                removed++;
            }
        }
    }

    fprintf(stderr, "[v6/%s] reload %s: +%d -%d (total %zu)\n",
            label, path, added, removed, nw.count);

    entry_set_free(old);
    *old = nw;
}

/* ------------------------------------------------------------------ */
/*
 * inotify watch descriptor with its associated directory path.
 * Multiple files may share the same wd (same directory).
 */
#define MAX_WATCHES 8

struct watch_file {
    const char *path;        /* full path of the list file              */
    const char *base;        /* basename (points into path string)      */
    int         map_fd;      /* BPF map fd for this file                */
    entry_set_t set;         /* in-memory canonical entry set           */
    const char *label;       /* "wl" or "bl", for log messages          */
    int         is_v6;       /* 0 = IPv4, 1 = IPv6                      */
    int         wd;          /* inotify watch descriptor for its dir    */
};

/* ------------------------------------------------------------------ */
static volatile sig_atomic_t running = 1;
static void on_sig(int s) { (void)s; running = 0; }

/* ------------------------------------------------------------------ */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s <ifname> [OPTIONS]\n"
        "  %s <ifname> --unload\n"
        "\n"
        "Options:\n"
        "  --rate   <pps>   Packets/sec per source IP (default: %llu)\n"
        "  --burst  <pkts>  Burst size in packets     (default: %llu)\n"
        "  --bl-v4  <file>  IPv4 blocklist  file      (default: %s)\n"
        "  --bl-v6  <file>  IPv6 blocklist  file      (default: %s)\n"
        "  --wl-v4  <file>  IPv4 whitelist  file      (default: %s)\n"
        "  --wl-v6  <file>  IPv6 whitelist  file      (default: %s)\n"
        "\n"
        "Positional fallback (legacy): [bl_v4] [bl_v6]\n",
        prog, prog,
        (unsigned long long)DEFAULT_RATE_PPS,
        (unsigned long long)DEFAULT_BURST,
        DEFAULT_BL_V4, DEFAULT_BL_V6,
        DEFAULT_WL_V4, DEFAULT_WL_V6);
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    if (argc < 2) { usage(argv[0]); return 1; }

    const char *ifname = argv[1];
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "if_nametoindex(%s): %s\n", ifname, strerror(errno));
        return 1;
    }

    /* ---- unload shortcut ---- */
    if (argc >= 3 && strcmp(argv[2], "--unload") == 0) {
        if (bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL) < 0)
            /* try native then generic */
            bpf_xdp_detach(ifindex, 0, NULL);
        fprintf(stderr, "XDP detached from %s\n", ifname);
        return 0;
    }

    /* ---- parse remaining options ---- */
    __u64 rate_pps  = DEFAULT_RATE_PPS;
    __u64 burst     = DEFAULT_BURST;
    const char *bl_v4_file = DEFAULT_BL_V4;
    const char *bl_v6_file = DEFAULT_BL_V6;
    const char *wl_v4_file = DEFAULT_WL_V4;
    const char *wl_v6_file = DEFAULT_WL_V6;

    int pos = 0;   /* positional argument counter (legacy bl_v4/bl_v6) */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--rate") == 0 && i + 1 < argc) {
            char *end;
            rate_pps = strtoull(argv[++i], &end, 10);
            if (*end || rate_pps == 0) {
                fprintf(stderr, "invalid --rate value\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--burst") == 0 && i + 1 < argc) {
            char *end;
            burst = strtoull(argv[++i], &end, 10);
            if (*end || burst == 0) {
                fprintf(stderr, "invalid --burst value\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--bl-v4") == 0 && i + 1 < argc) {
            bl_v4_file = argv[++i];
        } else if (strcmp(argv[i], "--bl-v6") == 0 && i + 1 < argc) {
            bl_v6_file = argv[++i];
        } else if (strcmp(argv[i], "--wl-v4") == 0 && i + 1 < argc) {
            wl_v4_file = argv[++i];
        } else if (strcmp(argv[i], "--wl-v6") == 0 && i + 1 < argc) {
            wl_v6_file = argv[++i];
        } else if (argv[i][0] != '-') {
            /* Legacy positional args: first = bl_v4, second = bl_v6 */
            if (pos == 0)      bl_v4_file = argv[i];
            else if (pos == 1) bl_v6_file = argv[i];
            pos++;
        } else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    fprintf(stderr, "rate-limit  : %llu pps / burst %llu pkts per source\n",
            (unsigned long long)rate_pps, (unsigned long long)burst);
    fprintf(stderr, "blocklist   : v4=%s  v6=%s\n", bl_v4_file, bl_v6_file);
    fprintf(stderr, "whitelist   : v4=%s  v6=%s\n", wl_v4_file, wl_v6_file);

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

    /* ---- find all maps ---- */
    struct bpf_map *map_wl_v4 = bpf_object__find_map_by_name(obj, "whitelist_v4");
    struct bpf_map *map_wl_v6 = bpf_object__find_map_by_name(obj, "whitelist_v6");
    struct bpf_map *map_bl_v4 = bpf_object__find_map_by_name(obj, "blocked_v4");
    struct bpf_map *map_bl_v6 = bpf_object__find_map_by_name(obj, "blocked_v6");
    struct bpf_map *map_cfg   = bpf_object__find_map_by_name(obj, "rl_config");

    if (!map_wl_v4 || !map_wl_v6 || !map_bl_v4 || !map_bl_v6 || !map_cfg) {
        fprintf(stderr, "could not find required maps\n");
        bpf_object__close(obj);
        return 1;
    }

    /* ---- write rate-limit config (index 0) ---- */
    struct rl_cfg cfg = { .rate_pps = rate_pps, .burst = burst };
    __u32 cfg_idx = 0;
    if (bpf_map_update_elem(bpf_map__fd(map_cfg), &cfg_idx, &cfg, BPF_ANY) < 0) {
        perror("rl_config update");
        bpf_object__close(obj);
        return 1;
    }

    /* ---- populate maps + build in-memory sets ---- */
    entry_set_t set_wl_v4, set_wl_v6, set_bl_v4, set_bl_v6;
    entry_set_init(&set_wl_v4);
    entry_set_init(&set_wl_v6);
    entry_set_init(&set_bl_v4);
    entry_set_init(&set_bl_v6);

    if (load_v4(bpf_map__fd(map_wl_v4), wl_v4_file, &set_wl_v4, "wl") < 0 ||
        load_v6(bpf_map__fd(map_wl_v6), wl_v6_file, &set_wl_v6, "wl") < 0 ||
        load_v4(bpf_map__fd(map_bl_v4), bl_v4_file, &set_bl_v4, "bl") < 0 ||
        load_v6(bpf_map__fd(map_bl_v6), bl_v6_file, &set_bl_v6, "bl") < 0) {
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

    /* ----------------------------------------------------------------
     * inotify: build watch_file table for all four list files.
     * We watch the containing directory (not the file inode) to handle
     * atomic saves (vim, sed -i, mv).  Multiple files in the same dir
     * share one watch descriptor.
     * ---------------------------------------------------------------- */
    struct watch_file wfiles[4] = {
        { wl_v4_file, NULL, bpf_map__fd(map_wl_v4), {0}, "wl", 0, -1 },
        { wl_v6_file, NULL, bpf_map__fd(map_wl_v6), {0}, "wl", 1, -1 },
        { bl_v4_file, NULL, bpf_map__fd(map_bl_v4), {0}, "bl", 0, -1 },
        { bl_v6_file, NULL, bpf_map__fd(map_bl_v6), {0}, "bl", 1, -1 },
    };

    /* Assign pre-built entry sets */
    wfiles[0].set = set_wl_v4;
    wfiles[1].set = set_wl_v6;
    wfiles[2].set = set_bl_v4;
    wfiles[3].set = set_bl_v6;

    /* Resolve basenames */
    for (int i = 0; i < 4; i++) {
        const char *b = strrchr(wfiles[i].path, '/');
        wfiles[i].base = b ? b + 1 : wfiles[i].path;
    }

    int ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ifd < 0) { perror("inotify_init1"); goto detach; }

    uint32_t watch_mask = IN_CLOSE_WRITE | IN_MOVED_TO;

    /*
     * For each file, get the directory path and add an inotify watch.
     * If another file already has a watch on the same directory,
     * reuse that wd.
     */
    for (int i = 0; i < 4; i++) {
        char dir_buf[PATH_MAX];
        strncpy(dir_buf, wfiles[i].path, PATH_MAX - 1);
        dir_buf[PATH_MAX - 1] = '\0';
        const char *dir = dirname(dir_buf);

        /* Check if a previous file already watches this directory */
        int found_wd = -1;
        for (int j = 0; j < i; j++) {
            char prev_dir[PATH_MAX];
            strncpy(prev_dir, wfiles[j].path, PATH_MAX - 1);
            prev_dir[PATH_MAX - 1] = '\0';
            if (strcmp(dirname(prev_dir), dir) == 0) {
                found_wd = wfiles[j].wd;
                break;
            }
        }

        if (found_wd >= 0) {
            wfiles[i].wd = found_wd;
        } else {
            wfiles[i].wd = inotify_add_watch(ifd, dir, watch_mask);
            if (wfiles[i].wd < 0) {
                fprintf(stderr, "inotify_add_watch(%s): %s\n",
                        dir, strerror(errno));
                goto detach;
            }
        }
    }

    signal(SIGINT,  on_sig);
    signal(SIGTERM, on_sig);

    /* Use pselect() to atomically wait on ifd and unblock signals */
    sigset_t mask_block, mask_orig;
    sigemptyset(&mask_block);
    sigaddset(&mask_block, SIGINT);
    sigaddset(&mask_block, SIGTERM);
    sigprocmask(SIG_BLOCK, &mask_block, &mask_orig);

    char ibuf[INOTIFY_BUFSZ]
        __attribute__((aligned(__alignof__(struct inotify_event))));

    while (running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ifd, &rfds);

        int ret = pselect(ifd + 1, &rfds, NULL, NULL, NULL, &mask_orig);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("pselect");
            break;
        }

        ssize_t len = read(ifd, ibuf, sizeof(ibuf));
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            perror("inotify read");
            break;
        }

        char *ptr = ibuf;
        while (ptr < ibuf + len) {
            struct inotify_event *ev = (struct inotify_event *)ptr;
            ptr += sizeof(*ev) + ev->len;
            if (!ev->len) continue;

            /* Wait for the filesystem to settle (editors may emit
             * multiple events in rapid succession) */
            usleep(50 * 1000);

            /* Match event against each watched file */
            for (int i = 0; i < 4; i++) {
                if (ev->wd != wfiles[i].wd) continue;
                if (strcmp(ev->name, wfiles[i].base) != 0) continue;

                if (wfiles[i].is_v6)
                    reload_v6(wfiles[i].map_fd, wfiles[i].path,
                              &wfiles[i].set, wfiles[i].label);
                else
                    reload_v4(wfiles[i].map_fd, wfiles[i].path,
                              &wfiles[i].set, wfiles[i].label);
            }
        }
    }

    close(ifd);
detach:
    /* ---- detach ---- */
    bpf_xdp_detach(ifindex, 0, NULL);
    fprintf(stderr, "XDP detached from %s\n", ifname);

    for (int i = 0; i < 4; i++)
        entry_set_free(&wfiles[i].set);
    bpf_object__close(obj);
    return 0;
}
