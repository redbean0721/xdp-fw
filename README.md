# xdp_ipblock

eBPF/XDP program that drops inbound packets whose **source IP** appears in a
blocklist file.  Supports both IPv4 and IPv6.

## Files

| File | Role |
|------|------|
| `xdp_ipblock_kern.c` | BPF (kernel-side) XDP program |
| `xdp_ipblock_user.c` | User-space loader / lifecycle manager |
| `Makefile` | Build rules |
| `badip_v4.txt` | One blocked IPv4 per line |
| `badip_v6.txt` | One blocked IPv6 per line |

## Dependencies

```
# Debian / Ubuntu
sudo apt install clang llvm libelf-dev zlib1g-dev libbpf-dev

# RHEL / Fedora
sudo dnf install clang llvm elfutils-libelf-devel zlib-devel libbpf-devel
```

Kernel ≥ 5.1 recommended (XDP native/generic support).

## Build

```bash
make
```

This produces:
- `xdp_ipblock_kern.o`  – BPF bytecode loaded at runtime
- `xdp_ipblock`         – user-space binary

## Usage

### Load (attach XDP and block IPs)

```bash
sudo ./xdp_ipblock <ifname> [badip_v4.txt] [badip_v6.txt]

# Examples
sudo ./xdp_ipblock eth0
sudo ./xdp_ipblock eth0 badip_v4.txt badip_v6.txt
```

The program tries **native XDP** first (driver support required); if that fails
it falls back to **generic/SKB mode** automatically.

Press **Ctrl-C** (or send SIGTERM) to detach and exit.

### Unload manually

```bash
sudo ./xdp_ipblock eth0 --unload
```

## IP list format

```
# comment lines start with '#'
1.2.3.4
192.0.2.1

2001:db8::1
fe80::bad:ip
```

Blank lines and `#` comments are skipped.  Both files are optional; if a file
is absent, that address family is simply not blocked.

## How it works

```
Inbound packet
      │
  [XDP hook]  ← kernel-side BPF program
      │
  parse ETH → IP/IPv6 header
      │
  lookup src addr in BPF hash map
      │
  found? ──YES──► XDP_DROP  (packet discarded in driver)
      │
     NO
      │
  XDP_PASS  (normal kernel stack)
```

Two `BPF_MAP_TYPE_HASH` maps are used:
- `blocked_v4`  – key: 4-byte `__be32` IPv4 address
- `blocked_v6`  – key: 16-byte `struct in6_addr` IPv6 address

The user-space program reads the text files, populates both maps, attaches the
XDP program to the requested interface, then waits for a signal.

## Map capacity

Default max entries per map: **100 000**.  Adjust `max_entries` in
`xdp_ipblock_kern.c` if a larger blocklist is needed.
