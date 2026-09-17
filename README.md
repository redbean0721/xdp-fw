# xdp_ipblock

eBPF/XDP program that drops inbound packets whose **source IP** matches any
entry in a blocklist — single host addresses **or CIDR prefixes** — for both
IPv4 and IPv6.

## Files

| File | Role |
|------|------|
| `xdp_ipblock_kern.c` | BPF (kernel-side) XDP program |
| `xdp_ipblock_user.c` | User-space loader / lifecycle manager |
| `Makefile` | Build rules |
| `badip_v4.txt` | IPv4 blocklist (hosts and/or CIDRs) |
| `badip_v6.txt` | IPv6 blocklist (hosts and/or CIDRs) |

## Map type: `BPF_MAP_TYPE_LPM_TRIE`

Both maps use the kernel's built-in **Longest-Prefix Match trie**.

| Property | Detail |
|----------|--------|
| Lookup complexity | O(prefix length) — effectively O(32) v4 / O(128) v6 |
| CIDR matching | Native — a single trie entry covers an entire subnet |
| `max_entries` | **100 000** per map |
| Allocation | `BPF_F_NO_PREALLOC` — memory allocated per inserted entry |

A host address (`/32` or `/128`) is stored as a full-length prefix, so host
and CIDR entries coexist in the same trie with no performance penalty.

## Dependencies

```
# Debian / Ubuntu
sudo apt install clang llvm libelf-dev zlib1g-dev libbpf-dev

# RHEL / Fedora
sudo dnf install clang llvm elfutils-libelf-devel zlib-devel libbpf-devel
```

Kernel ≥ 5.1 recommended.

## Build

```bash
make
```

Produces:
- `xdp_ipblock_kern.o` – BPF bytecode (loaded at runtime by libbpf)
- `xdp_ipblock`        – user-space binary

## Usage

### Load

```bash
sudo ./xdp_ipblock <ifname> [badip_v4.txt] [badip_v6.txt]

# Examples
sudo ./xdp_ipblock eth0
sudo ./xdp_ipblock eth0 badip_v4.txt badip_v6.txt
```

Tries **native XDP** (driver-level, zero-copy) first; falls back to
**generic/SKB mode** automatically if the driver does not support it.

Press **Ctrl-C** or send `SIGTERM` to detach and exit cleanly.

### Unload manually

```bash
sudo ./xdp_ipblock eth0 --unload
```

## Blocklist file format

Both files accept the same format — one entry per line:

```
# comment lines start with '#'; blank lines are ignored

# Single host address (stored as /32 or /128)
1.2.3.4
fe80::bad:1

# CIDR prefix – entire subnet is blocked
192.168.0.0/16
10.0.0.0/8
2001:db8::/32
2400:cb00::/32
```

The user-space loader **zeroes host bits** before inserting, so
`192.168.1.5/24` is canonicalised to `192.168.1.0/24` automatically.

## How it works

```
Inbound packet
      │
  [XDP hook]  ← kernel-side BPF program (xdp_ipblock_kern.c)
      │
  parse ETH → IP / IPv6 header
      │
  build LPM key  { prefixlen=32/128, addr=src }
      │
  bpf_map_lookup_elem(&blocked_vX, &key)
      │              (LPM trie: finds longest matching prefix)
  hit? ──YES──► XDP_DROP   (dropped at driver level)
      │
     NO
      │
  XDP_PASS  (packet continues up the kernel stack)
```

### Key layout (kernel requirement)

```c
struct lpm_v4_key { __u32 prefixlen; __u8 addr[4];  };   // 8 bytes
struct lpm_v6_key { __u32 prefixlen; __u8 addr[16]; };   // 20 bytes
```

The kernel's LPM trie compares only the first `prefixlen` bits of `addr`,
so a stored prefix `/24` matches any lookup with the same top 24 bits.
