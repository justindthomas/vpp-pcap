#!/usr/bin/env bash
# build.sh — compile pcap_stream_node v2 chassis libFuzzer harnesses
# inside the audit-tools:vpp-fuzz container.  Mirrors
# sfw/fuzz/sfw_node/build.sh.
#
# v2.0 scope (this script): every TU compiles, every symbol resolves
# at link time, and each harness drives pcap_stream_{rx,tx}_node_fn
# against fuzzer-supplied bytes loaded into a 4-vector frame.  No
# bihash instantiation needed (vpp-pcap uses no bihash).
#
# Usage:  build.sh [output-dir]
#         (default output-dir: /src/fuzz/pcap_stream_node/out)
set -euo pipefail

OUT="${1:-/src/fuzz/pcap_stream_node/out}"
SRC=/src
HERE="$SRC/fuzz/pcap_stream_node"
mkdir -p "$OUT"

SAN_LINK_FLAGS="-fsanitize=address,undefined,fuzzer"
SAN_OBJ_FLAGS="-fsanitize=address,undefined,fuzzer-no-link"
COMMON_CFLAGS="-O1 -g -Wall -fno-omit-frame-pointer"

# pcap_stream .c files use `#include <pcap_stream/pcap_stream.h>`;
# mirror that include layout without polluting the tree.
mkdir -p "$OUT/include/pcap_stream"
ln -sf "$SRC/plugin/pcap_stream.h" "$OUT/include/pcap_stream/pcap_stream.h"
ln -sf "$SRC/plugin/pcap_filter.h" "$OUT/include/pcap_stream/pcap_filter.h"

INCLUDES="-I/usr/include -I$OUT/include -I$HERE -I$SRC/plugin"

##############################################################################
# Step 1: compile the pcap_stream .c files we need at the per-packet
# layer.  We skip pcap_stream.c (VLIB_INIT_FUNCTION + drain socket),
# pcap_filter.c (libpcap), pcap_stream_drain.c, pcap_stream_drop.c,
# pcap_stream_session.c, pcap_stream_pcapng.c, pcap_stream_api.c —
# none reached from the rx/tx node body.
##############################################################################
echo "--- compile pcap_stream .c files ---"
for f in pcap_stream_node.c pcap_stream_ring.c; do
    echo "    $f"
    clang $COMMON_CFLAGS $SAN_OBJ_FLAGS $INCLUDES \
        -c "$SRC/plugin/$f" -o "$OUT/${f%.c}.o"
done

##############################################################################
# Step 2: chassis glue (VPP runtime globals + function stubs +
# pcap-pcap shims + per-call fixture).
##############################################################################
echo "--- compile harness_glue.o ---"
clang $COMMON_CFLAGS $SAN_OBJ_FLAGS $INCLUDES \
    -c "$HERE/harness_glue.c" -o "$OUT/harness_glue.o"

##############################################################################
# Step 3: each harness — link with sanitiser + libfuzzer entry, the
# pcap_stream .o files, harness_glue.o, libvppinfra.
##############################################################################
build_harness() {
    local target=$1
    echo "--- $target ---"
    clang $COMMON_CFLAGS $SAN_LINK_FLAGS $INCLUDES \
        "$HERE/$target.c" \
        "$OUT/pcap_stream_node.o" \
        "$OUT/pcap_stream_ring.o" \
        "$OUT/harness_glue.o" \
        -lvppinfra \
        -o "$OUT/$target"
    echo "  -> $OUT/$target"
}

build_harness fuzz_pcap_stream_rx_node
build_harness fuzz_pcap_stream_tx_node

echo
echo "=== artefacts in $OUT ==="
ls -la "$OUT"
