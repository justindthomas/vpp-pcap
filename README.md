# vpp-pcap

A tcpdump-style live packet-capture tool for [FD.io VPP][vpp]. Run a CLI,
supply a libpcap-syntax filter expression, and watch matched packets
stream in real time — across one interface or all of them, with the
interface name and direction visible per packet.

```
2026-05-05 00:05:34.720551787 wan    Inbound  44.215.74.30 → 23.177.24.9 TCP 66 443 → 33283 [ACK] Seq=1 Ack=1
2026-05-05 00:05:34.720567097 bvi100 Outbound 64:ff9b::2cd7:4a1e → 2602:f90e:10:0:18ff:7059:2bb8:3aac TCP 86 ...
```

The same packet captured 16µs apart on its way through the router —
ingress on `wan`, egress on `bvi100` — without leaving VPP for a kernel
TAP and without paying the file-based round-trip of `pcap trace`.

See [DESIGN.md](DESIGN.md) for architecture and rationale.

## Status

**Working** for live operator-facing capture. Loaded and tested daily
on a production VPP 25.10 router. Not wire-stable: still subject to
breaking control-protocol changes, no version commitment.

What's in:

- Live capture across one interface or all (`-i <iface>` or `-i any`)
- Libpcap-syntax filter expressions (`'tcp port 179'`, `'icmp6'`,
  `'net 2602:f90e::/32 and udp port 53'`, etc.)
- Per-packet interface name + direction in the wire format (pcap-ng
  IDB / EPB)
- File output (`-w cap.pcapng`), stdout pipe (`-w -`), human-readable
  decode (`--print` shells out to tshark)
- Auto-cleanup on consumer disconnect (no orphan sessions)
- Variable-stride per-(session, worker) SPSC rings sized to the
  operator's snaplen — typical session is ~1MB total memory at the
  default 4096 snaplen across 8 workers

What's not yet:

- `-d drop` mode — needs a small VPP patch (in `vpp-patches.disabled/`)
  to expose an error-drop callback hook; degrades to a silent no-op
  without it
- High-rate consumer path — Unix socket caps at ~50–100kpps streamed;
  fine for operator debugging, not for IDS-style wire-rate inspection
  (a memif sibling sink is the planned answer)
- Lazy-IDB emission for interfaces created mid-session
- VLAN-tagged packets need explicit `vlan` keyword in the filter
  expression (libpcap semantics)

## Why

VPP's existing capture story:

| Tool | Filter | Output | Live? |
|---|---|---|---|
| `pcap trace` | `bpf_trace_filter` | file | no |
| SPAN to tap + `tcpdump` | post-mirror | live | yes, but mirrors before filtering |
| `vpptrace.sh` | text grep on `show trace` | console | yes-ish |
| sFlow | random sample | Netlink | yes, statistical only |
| **vpp-pcap** | **libpcap BPF** | **live pcap-ng stream** | **yes** |

`bpf_trace_filter` already solved the predicate half (libpcap parses
your filter, compiles to BPF, runs per packet). vpp-pcap adds the
streaming half: per-(session, worker) SPSC rings, main-thread drain to
a Unix socket, pcap-ng wire format with per-packet interface metadata.

## Quickstart

Once the plugin is loaded into VPP and the CLI is on PATH:

```sh
# Watch BGP traffic on wan
vpp-pcap -i wan --print 'tcp port 179'

# Watch DNS through the router (both ingress and egress paths)
vpp-pcap -i any --print 'udp port 53'

# Inspect everything for an IPv6 client across interfaces
vpp-pcap -i any --print 'host 2602:f90e:10:0:18ff:7059:2bb8:3aac'

# Save 1000 packets to a pcap-ng file for Wireshark
vpp-pcap -i any -c 1000 -w incident.pcapng 'host 1.2.3.4'

# Pipe straight to wireshark
vpp-pcap -i wan -w - 'port 443' | wireshark -k -i -

# Pipe to tshark with iface column visible
vpp-pcap -i any -w - 'port 53' | tshark -r - -nl -t ad \
  -o 'gui.column.format:"Time","%t","Iface","%Cus:frame.interface_name:0:R","Source","%s","Destination","%d","Proto","%p","Info","%i"'
```

### Filter expressions

Standard libpcap syntax. A few notes for VPP-on-VLAN setups:

- VLAN-tagged frames need an explicit `vlan` keyword:
  `(udp port 53) or (vlan and udp port 53)` matches both untagged and
  tagged DNS. Without `vlan`, libpcap's offset arithmetic skips
  VLAN-tagged packets.
- IPv6 nets work the same as IPv4: `net 2602:f90e::/32`.
- Source/destination filters: `src host`, `dst host`, `src net`,
  `dst net`, `src port`, `dst port`.
- Combining: `and`, `or`, parentheses.

### Subcommands

```sh
vpp-pcap list            # list active sessions on the plugin
vpp-pcap stats <id>      # captured/dropped counters for a session
vpp-pcap kill <id>       # tear down a session by id
vpp-pcap inject <hex>    # test path: inject a hex-encoded packet
                         #   through every active session (no real
                         #   capture, just exercises the ring + socket)
```

## Wire format

pcap-ng over a Unix-domain SOCK_STREAM socket. Each session sends one
Section Header Block, one Interface Description Block per VPP
interface (carrying the operator-visible name like `bvi100` or
`lan.30`), and one Enhanced Packet Block per matched packet. Direction
(in/out) rides as an EPB option. Nanosecond timestamp resolution
(`if_tsresol = 9`).

Wireshark and tshark consume the stream natively and show the
interface name as a column. tcpdump 4.99 (Bookworm) decodes the
packets correctly but doesn't surface the interface column in default
output — patches landed upstream but aren't in 4.99 yet. Use the
`tshark` invocation above (or `--print`, which uses it under the hood)
to see the iface column on Bookworm.

## Layout

```
vpp-pcap/
├── DESIGN.md                   architecture sketch
├── README.md                   this file
├── LICENSE                     Apache-2.0
├── build.sh                    containerised plugin build (podman/docker)
├── Dockerfile                  Bookworm + VPP 25.10 dev packages + libpcap
├── plugin/                     C plugin (loads into VPP)
│   ├── CMakeLists.txt
│   ├── pcap_stream.api         binary API (placeholder; control is text-socket)
│   ├── pcap_stream.c           plugin registration, vppctl debug commands
│   ├── pcap_stream_session.c   create/destroy, refcount-driven feature-arc enable
│   ├── pcap_stream_ring.c      variable-stride SPSC ring allocator
│   ├── pcap_stream_drain.c     control socket + main-thread drain process
│   ├── pcap_stream_node.c      device-input + interface-output feature-arc nodes
│   ├── pcap_stream_drop.c      error-drop tap (requires VPP patch)
│   ├── pcap_stream_pcapng.c    pcap-ng SHB / IDB / EPB emission
│   ├── pcap_filter.c           libpcap wrapper (cached pcap_t per DLT)
│   └── pcap_stream_api.c       binary API stub
├── cli/                        Rust CLI binary `vpp-pcap`
│   ├── Cargo.toml
│   └── src/main.rs             clap argparse, control-socket client, splice
├── tests/                      integration tests
│   ├── README.md
│   ├── smoke_protocol.sh       CLI ↔ mock-server protocol shape
│   └── e2e_netns.sh            netns + VPP + veth, capture a known packet
└── vpp-patches.disabled/       optional VPP patches not yet upstream
    └── 0001-error-drop-callback-hook.patch.todo
```

## Building

Plugin builds inside a container so it links against VPP 25.10's
exact glibc + libvppinfra versions:

```sh
./build.sh           # podman or docker; produces output/pcap_stream_plugin.so
```

CLI is a normal cargo build, but on a target router running Debian
Bookworm you'll want to build inside a Bookworm container too (the
build host typically runs Trixie, glibc mismatch otherwise):

```sh
podman run --rm -v "$PWD/cli:/src" -v "$PWD/cli/target:/out" debian:bookworm \
  bash -c 'apt-get update -qq && apt-get install -y -qq curl build-essential pkg-config ca-certificates &&
           curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet --default-toolchain stable &&
           . ~/.cargo/env && cd /src && CARGO_TARGET_DIR=/out cargo build --release'
```

## Installing on a VPP router

```sh
# Plugin
install -m 644 output/pcap_stream_plugin.so /usr/lib/x86_64-linux-gnu/vpp_plugins/

# CLI
install -m 755 cli/target/release/vpp-pcap /usr/local/bin/

# Restart VPP to load the plugin (control-socket binds at start time)
service impd restart   # or however your install supervises VPP

# Verify
vppctl -s /run/vpp/core-cli.sock show plugins | grep pcap_stream
ls -la /run/vpp/pcap-stream.sock
vpp-pcap list
```

VPP's plugin block must not have `default { disable }`, or `pcap_stream`
needs an explicit `plugin pcap_stream_plugin.so { enable }`.

## Testing

```sh
./tests/smoke_protocol.sh       # CLI ↔ mock-server, host-side, no VPP needed
sudo ./tests/e2e_netns.sh       # spins up VPP in a netns, real capture
```

## Performance

At the default snaplen of 4096 with 256-deep rings × 8 workers, a
session holds ~8 MB of preallocated ring memory. At a smaller snaplen
(`-s 96`) it drops to ~256 KB. Per-packet cost in the feature-arc
nodes is ~1–2µs (BPF interpreter + memcpy of `min(packet_length,
snaplen)` bytes). Drain ticks every 1 ms.

The throughput ceiling is the SOCK_STREAM Unix socket — about 50–100
kpps streamed sustainably to a CPU-bound consumer. Operators
typically don't push it. For wire-rate consumers (IDS, telemetry),
the planned answer is a memif sibling sink — same plugin, different
data path.

## License

Apache-2.0 — see [LICENSE](LICENSE).

[vpp]: https://fd.io/
