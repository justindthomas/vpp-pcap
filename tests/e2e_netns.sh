#!/bin/bash
#
# End-to-end test: spin up VPP in a netns, capture a known packet,
# verify it ended up in the output pcap. Run on the build host.
#
# Requirements (build host):
#   - vpp + vpp-plugin-core installed (or VPP source checkout buildable)
#   - pcap_stream_plugin.so built and installed in /usr/lib/vpp_plugins
#     (or pointed to via VPP_PLUGIN_PATH)
#   - vpp-pcap CLI built (cargo build --release)
#   - root (or CAP_NET_ADMIN + CAP_SYS_ADMIN for netns)
#
# Usage:
#   sudo ./e2e_netns.sh
#   sudo ./e2e_netns.sh --keep      # leave the netns + VPP running on exit

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
CLI="$REPO/cli/target/release/vpp-pcap"
PLUGIN="${PLUGIN:-$REPO/output/pcap_stream_plugin.so}"

NS="pcap-test-$$"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

log() { printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }

cleanup() {
    if [ "$KEEP" -eq 1 ]; then
        log "leaving netns $NS and VPP running for inspection"
        return
    fi
    log "cleaning up"
    kill $(jobs -p) 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    ip link del veth-host 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

if [ ! -x "$CLI" ]; then
    log "building CLI"
    (cd "$REPO/cli" && cargo build --release >/dev/null)
fi
if [ ! -f "$PLUGIN" ]; then
    log "ERROR: pcap_stream_plugin.so not found at $PLUGIN"
    log "       run ./build.sh from the repo root first"
    exit 2
fi

WORK=$(mktemp -d)
log "workdir: $WORK"

# 1. Create netns + veth pair
log "setting up netns $NS + veth"
ip netns add "$NS"
ip link add veth-host type veth peer name veth-vpp
ip link set veth-vpp netns "$NS"
ip addr add 10.42.0.1/24 dev veth-host
ip link set veth-host up
ip -n "$NS" addr add 10.42.0.2/24 dev veth-vpp
ip -n "$NS" link set veth-vpp up
ip -n "$NS" link set lo up

# 2. Start VPP in the netns
log "starting VPP"
cat >"$WORK/vpp.conf" <<EOF
unix {
  log $WORK/vpp.log
  cli-listen $WORK/vpp.sock
  full-coredump
  nodaemon
}
api-segment {
  prefix vpp-pcap-test
}
plugins {
  plugin default { disable }
  plugin pcap_stream_plugin.so { enable }
  plugin af_packet_plugin.so { enable }
}
EOF

ip netns exec "$NS" vpp -c "$WORK/vpp.conf" >"$WORK/vpp.stdout" 2>&1 &
VPP_PID=$!
sleep 2

# 3. Bring up the veth in VPP
VPPCTL="ip netns exec $NS vppctl -s $WORK/vpp.sock"
log "creating af_packet host-interface for veth-vpp"
$VPPCTL create host-interface name veth-vpp >/dev/null
$VPPCTL set interface state host-veth-vpp up >/dev/null
$VPPCTL set interface ip address host-veth-vpp 10.42.0.2/24 >/dev/null

# 4. Start the capture
SOCK="/run/vpp/pcap-stream.sock"
# pcap_stream listens at the default path inside the netns
log "starting capture: vpp-pcap -i host-veth-vpp 'icmp' -w cap.pcap"
ip netns exec "$NS" "$CLI" -i host-veth-vpp -d any -w "$WORK/cap.pcap" 'icmp' &
CAP_PID=$!
sleep 0.5

# 5. Send a known ICMP packet
log "sending ICMP echo from host into netns"
ping -c 1 -W 2 10.42.0.2 >/dev/null || true
sleep 1

# 6. Stop the capture and check
kill $CAP_PID 2>/dev/null || true
wait $CAP_PID 2>/dev/null || true

if [ ! -s "$WORK/cap.pcap" ]; then
    log "FAIL: cap.pcap is empty"
    exit 1
fi

# 7. Decode and verify
COUNT=$(tcpdump -r "$WORK/cap.pcap" -nn 2>/dev/null | grep -c ICMP || true)
if [ "$COUNT" -ge 1 ]; then
    log "PASS: $COUNT ICMP packet(s) captured"
    exit 0
else
    log "FAIL: no ICMP packets in cap.pcap"
    log "tcpdump output:"
    tcpdump -r "$WORK/cap.pcap" -nn 2>&1 | head -20
    exit 1
fi
