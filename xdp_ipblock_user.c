// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_ipblock_user.c
 *
 * Usage:
 *   Load:   ./xdp_ipblock <ifname> [badip_v4.txt] [badip_v6.txt]
 *   Unload: ./xdp_ipblock <ifname> --unload
 *
 * badip_v4.txt – one IPv4 address per line (e.g. 1.2.3.4)
 * badip_v6.txt – one IPv6 address per line (e.g. 2001:db8::1)
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

#define XDP_OBJ      "xdp_ipblock_kern.o"
#define DEFAULT_V4   "badip_v4.txt"
#define DEFAULT_V6   "badip_v6.txt"

/* ------------------------------------------------------------------ */
static int load_v4(int map_fd, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) return 0;   /* file optional */
        perror(path);
        return -1;
    }

    char line[64];
    __u8 val = 1;
    int  cnt = 0;

    while (fgets(line, sizeof(line), f)) {
        /* strip newline / comments */
        char *p = strchr(line, '\n'); if (p) *p = '\0';
        p = strchr(line, '#');        if (p) *p = '\0';
        while (*line == ' ' || *line == '\t') memmove(line, line+1, strlen(line));
        if (!*line) continue;

        struct in_addr addr;
        if (inet_pton(AF_INET, line, &addr) != 1) {
            fprintf(stderr, "bad IPv4: %s\n", line);
            continue;
        }
        __u32 key = addr.s_addr;   /* network byte order */
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

    char line[128];
    __u8 val = 1;
    int  cnt = 0;

    while (fgets(line, sizeof(line), f)) {
        char *p = strchr(line, '\n'); if (p) *p = '\0';
        p = strchr(line, '#');        if (p) *p = '\0';
        while (*line == ' ' || *line == '\t') memmove(line, line+1, strlen(line));
        if (!*line) continue;

        struct in6_addr addr;
        if (inet_pton(AF_INET6, line, &addr) != 1) {
            fprintf(stderr, "bad IPv6: %s\n", line);
            continue;
        }
        if (bpf_map_update_elem(map_fd, &addr, &val, BPF_ANY) < 0)
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
