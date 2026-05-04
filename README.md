# vpp-pcap

A tcpdump-style live packet-capture tool for [FD.io VPP][vpp]. Run a CLI,
supply a libpcap-syntax filter expression, and watch matched packets stream
in real time. Pipe-friendly:

```sh
vpp-pcap -i wan 'tcp port 179'                    # bgp on the wire
vpp-pcap -i lan 'icmp6'                           # ping/NDP
vpp-pcap -d drop 'host 8.8.8.8'                   # why is google getting dropped
vpp-pcap -i any 'host 1.1.1.1' | tshark -r -      # decode with wireshark
vpp-pcap -i wan -w cap.pcap 'port 53' &           # save to file
```

See [DESIGN.md](DESIGN.md) for architecture and rationale.

## Status

Pre-alpha — actively under construction. Nothing here is wire-stable yet.

## Why

VPP's existing capture story is file-based (`pcap trace`), text-scraped
(`vpptrace.sh`), or sample-only (sFlow). None of them give you "live
tcpdump" inside a vector-processing dataplane. This plugin closes that
gap by reusing the upstream `bpf_trace_filter` libpcap-compile path for
the predicate and adding a per-worker SPSC ring + main-thread drain that
ships matched packets to a Unix-socket consumer in real time.

## Layout

```
vpp-pcap/
├── DESIGN.md                       architecture sketch
├── plugin/                         C plugin, builds against installed VPP
│   ├── CMakeLists.txt
│   ├── pcap_stream.api             binary API
│   └── *.c, *.h
├── cli/                            Rust CLI binary `vpp-pcap`
│   ├── Cargo.toml
│   └── src/
├── docs/
└── tests/                          integration tests (netns'd VPP)
```

## Building

Plugin builds against VPP 25.10 dev packages in a containerised toolchain
(matches the [sfw build flow][sfw]):

```sh
./build.sh                # produces output/pcap_stream_plugin.so
```

CLI is a standard cargo build:

```sh
cd cli && cargo build --release
```

## License

Apache-2.0 — see [LICENSE](LICENSE).

[vpp]: https://fd.io/
[sfw]: https://github.com/justindthomas/sfw
