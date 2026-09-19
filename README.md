# xdp_ipblock

eBPF/XDP two-stage packet filter with **live blocklist hot-reload**:

1. **Static blocklist** – drops packets from IPs / CIDR prefixes listed in
   `badip_v4.txt` / `badip_v6.txt` (LPM trie, O(prefix-len) lookup).
2. **Per-source token-bucket rate limiter** – drops packets from any source
   that exceeds the configured rate, providing DoS mitigation for traffic
   not covered by the static list (LRU hash, O(1) lookup).
3. **inotify hot-reload** – the directory containing each blocklist file is
   watched; when a file changes only the diff (added/removed entries) is
   applied to the BPF map. No program reload, no traffic interruption.

## Files

| File | Role |
|------|------|
| `xdp_ipblock_kern.c` | BPF kernel-side XDP program |
| `xdp_ipblock_user.c` | User-space loader + inotify watcher |
| `Makefile` | Build rules |
| `badip_v4.txt` | IPv4 blocklist (hosts / CIDRs) |
| `badip_v6.txt` | IPv6 blocklist (hosts / CIDRs) |

## Map summary

| Map | Type | Key | Purpose |
|-----|------|-----|---------|
| `blocked_v4` | `LPM_TRIE` | `{prefixlen, addr[4]}` | Static IPv4 blocklist |
| `blocked_v6` | `LPM_TRIE` | `{prefixlen, addr[16]}` | Static IPv6 blocklist |
| `tb_v4` | `LRU_HASH` | `__u32` src addr | Token-bucket state per IPv4 source |
| `tb_v6` | `LRU_HASH` | `__u8[16]` src addr | Token-bucket state per IPv6 source |
| `rl_config` | `ARRAY` | `__u32` index 0 | `{rate_pps, burst}` – runtime tunable |

All maps have `max_entries = 100 000`. The LRU maps evict the
least-recently-used entry automatically when full.

## Dependencies

```
# Debian / Ubuntu
sudo apt install clang llvm libelf-dev zlib1g-dev libbpf-dev

# RHEL / Fedora
sudo dnf install clang llvm elfutils-libelf-devel zlib-devel libbpf-devel
```

Kernel ≥ 5.1 required; ≥ 5.4 recommended for `BPF_MAP_TYPE_LRU_HASH`.

## Build

```bash
make
```

## Usage

### Load

```bash
# Defaults: 1000 pps / burst 2000 pkts per source
sudo ./xdp_ipblock eth0

# Custom rate limits
sudo ./xdp_ipblock eth0 --rate 500 --burst 1000

# Custom blocklist files + rate limits
sudo ./xdp_ipblock eth0 --rate 200 --burst 400 myv4.txt myv6.txt
```

### Unload

```bash
sudo ./xdp_ipblock eth0 --unload
```

## Hot-reload mechanism

The directory containing each blocklist file is watched with inotify.
On `IN_CLOSE_WRITE` or `IN_MOVED_TO` (covers atomic editor writes / `sed -i`),
the changed file is re-parsed and diffed against the in-memory set.
Only added entries are inserted and removed entries are deleted from the
BPF LPM trie – no full-reload or map flush is performed.

```
Editor saves badip_v4.txt
        │
        │  IN_CLOSE_WRITE or IN_MOVED_TO on directory watch
        ▼
  check ev->name == basename(v4_file)
        │
        ▼
  re-read file → new_set (sorted canonical CIDR strings)
        │
        ├─ entries in new_set \ old_set  →  bpf_map_update_elem()
        └─ entries in old_set \ new_set  →  bpf_map_delete_elem()
        │
        ▼
  old_set = new_set
```

**Why watch the directory, not the file?**
Many editors and tools (`vim`, `sed -i`, `mv`) write atomically by creating
a temporary file and renaming it over the original. A watch on the original
inode is silently dropped after a rename. Watching the directory and
filtering by `ev->name` catches both `IN_CLOSE_WRITE` (in-place edit) and
`IN_MOVED_TO` (atomic replace).

If both files share the same directory, a single inotify watch descriptor
is reused and each event is matched against both basenames independently.

## Token-bucket algorithm

```
On each packet from source IP S:
  Δt     = now_ns − last_seen_ns[S]
  tokens[S] += Δt × rate_pps / 1_000_000_000
  tokens[S]  = min(tokens[S], burst)

  if tokens[S] ≥ 1:
      tokens[S] -= 1  →  XDP_PASS
  else:
      XDP_DROP           (DoS mitigation)
```

- **First packet** from a new source: bucket is initialised full → passes.
- **LRU eviction**: when `tb_v4` / `tb_v6` is full, the kernel evicts the
  least-recently-used entry, so stale sources never block new ones.
- **No user-space cleanup thread** is needed.
- **`TOKEN_SCALE = 1000`** provides sub-packet precision for low rates without
  floating-point arithmetic.
- Parameters (`rate_pps`, `burst`) live in the `rl_config` ARRAY map and can
  be updated at runtime without reloading the XDP program.

## Packet flow

```
Inbound packet
      │
  [XDP hook]
      │
  parse ETH → IP / IPv6
      │
  ┌── Stage 1: LPM trie lookup (blocked_v4 / blocked_v6)
  │       hit? ──YES──► XDP_DROP  (static blocklist)
  │
  └── Stage 2: token-bucket (tb_v4 / tb_v6)
          read rl_config → rate_pps, burst
          refill tokens from elapsed time
          tokens ≥ 1? ──NO──► XDP_DROP  (rate exceeded / DoS)
                │
               YES
                │
          tokens -= 1
                │
          XDP_PASS
```
