# vpp-pcap tests

Two tiers:

## 1. CLI smoke test (host, no VPP)

`smoke_protocol.sh` spins up a tiny netcat-based mock of the
plugin's control socket, runs the CLI against it, and verifies
the wire protocol is well-formed. Catches CLI regressions
without needing a built plugin.

```sh
./smoke_protocol.sh
```

## 2. End-to-end against real VPP (build host)

`e2e_netns.sh` does the real thing on a Linux host with VPP
installed:

1. Starts VPP in a fresh netns with two veth pairs (`pcap-a`, `pcap-b`).
2. Loads the built `pcap_stream_plugin.so`.
3. Runs `vpp-pcap -i pcap-a 'icmp'` in the background, writing
   to a temporary pcap file.
4. Sends a known ICMP echo through the dataplane via the host
   side of the veth.
5. Stops the capture and verifies the resulting pcap file
   contains the expected bytes.

Required only on the build host; not part of host-side CI.

```sh
./e2e_netns.sh
```

The expected output is "OK: 1 ICMP packet captured" or similar.
Failures dump the captured pcap and the VPP log.
