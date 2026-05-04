#!/bin/bash
# Mock the pcap_stream control socket using `socat`/`nc`, run the
# CLI against it, verify the request lines look right.
#
# Doesn't validate the data-stream path (no real pcap bytes flow),
# just that the CLI emits the expected text protocol.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
CLI="$REPO/cli/target/release/vpp-pcap"

if [ ! -x "$CLI" ]; then
    echo "[!] CLI not built; running cargo build --release" >&2
    (cd "$REPO/cli" && cargo build --release >/dev/null)
fi

if ! command -v socat >/dev/null 2>&1; then
    echo "[!] socat required" >&2
    exit 2
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; jobs -p | xargs -r kill 2>/dev/null || true' EXIT
SOCK="$WORK/pcap.sock"

# Test 1: list — server replies with two sessions
( socat -u UNIX-LISTEN:"$SOCK",fork,reuseaddr - <<EOF
ok sessions=2
session id=1 dir=0x7 snaplen=262144 captured=0 dropped=0 filter=tcp
session id=2 dir=0x1 snaplen=96 captured=10 dropped=0 filter=icmp
EOF
) &
sleep 0.2

OUT=$("$CLI" --server "$SOCK" list)
echo "$OUT" | grep -q "id=1" || { echo "FAIL: list response missing id=1"; exit 1; }
echo "$OUT" | grep -q "id=2" || { echo "FAIL: list response missing id=2"; exit 1; }
echo "PASS: list"

wait || true

# Test 2: capture create — verify the request line shape
REQ_LOG="$WORK/req.log"
( socat -u UNIX-LISTEN:"$SOCK",fork,reuseaddr SYSTEM:"tee $REQ_LOG; printf 'ok id=42\n'" ) &
sleep 0.2

# CLI hangs reading the data stream after `ok id=42`, so background it
# and kill after a second.
"$CLI" --server "$SOCK" -i wan -d any -s 96 'tcp port 179' >/dev/null 2>&1 &
CLI_PID=$!
sleep 0.5
kill $CLI_PID 2>/dev/null || true
wait $CLI_PID 2>/dev/null || true

if grep -q "create iface=wan dir=any snaplen=96 max=0 filter='tcp port 179'" "$REQ_LOG"; then
    echo "PASS: capture request"
else
    echo "FAIL: capture request line did not match expected shape:"
    cat "$REQ_LOG"
    exit 1
fi

echo "all CLI protocol smoke tests passed"
