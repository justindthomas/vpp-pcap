#!/bin/bash
#
# Containerised build for the pcap_stream VPP plugin.
#
# Builds a small Debian image with VPP 25.10 dev packages + libpcap-dev,
# then compiles the plugin against this checkout and drops
# pcap_stream_plugin.so into ./output/.
#
# Mirrors the sfw build flow exactly — same toolchain image is fine if
# you've already built it.
#
# Environment overrides:
#   CONTAINER_ENGINE  podman | docker     (default: auto-detect)
#   IMAGE_TAG         image tag to build  (default: vpp-pcap-build:25.10)
#   VPP_BRANCH        VPP branch to clone (default: v25.10)
#   BUILD_TYPE        CMake build type    (default: Release)
#   JOBS              parallel make jobs  (default: container's nproc)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"

IMAGE_TAG="${IMAGE_TAG:-vpp-pcap-build:25.10}"
VPP_BRANCH="${VPP_BRANCH:-v25.10}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
JOBS="${JOBS:-}"

if [ -z "${CONTAINER_ENGINE:-}" ]; then
    if command -v podman >/dev/null 2>&1; then
        CONTAINER_ENGINE=podman
    elif command -v docker >/dev/null 2>&1; then
        CONTAINER_ENGINE=docker
    else
        echo "[-] Neither podman nor docker found in PATH" >&2
        exit 1
    fi
fi
echo "[+] Using container engine: $CONTAINER_ENGINE"

mkdir -p "$OUTPUT_DIR"

echo "[+] Building image $IMAGE_TAG..."
"$CONTAINER_ENGINE" build -t "$IMAGE_TAG" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR"

VOL_OPTS=""
if [ "$CONTAINER_ENGINE" = "podman" ]; then
    VOL_OPTS=":Z"
fi

echo "[+] Running build inside container..."
"$CONTAINER_ENGINE" run --rm \
    -v "$SCRIPT_DIR:/src${VOL_OPTS}" \
    -v "$OUTPUT_DIR:/out${VOL_OPTS}" \
    -e VPP_BRANCH="$VPP_BRANCH" \
    -e BUILD_TYPE="$BUILD_TYPE" \
    -e JOBS="$JOBS" \
    "$IMAGE_TAG" bash -euo pipefail -c '
        JOBS="${JOBS:-$(nproc)}"
        echo "[+] Cloning VPP $VPP_BRANCH..."
        git clone --depth 1 --branch "$VPP_BRANCH" \
            https://github.com/FDio/vpp.git /tmp/vpp-src 2>&1 | tail -3

        # VPP patches required for "-d drop" capture mode. The
        # plugin pcap_stream_drop.c declares the drop-callback
        # symbols extern; this patch exposes them in libvlib.so.
        # Without the patch (i.e. against vanilla VPP), the symbols
        # resolve to the weak no-op stubs and drop-mode silently
        # degrades; you still need this patch on the plugin build
        # itself to get the matching header declarations.
        if [ -d /src/vpp-patches ] && compgen -G "/src/vpp-patches/*.patch" > /dev/null; then
            echo "[+] Applying VPP patches..."
            for p in /src/vpp-patches/*.patch; do
                echo "  applying $(basename "$p")"
                (cd /tmp/vpp-src && patch -p1 --forward < "$p")
            done
        fi

        echo "[+] Installing pcap_stream plugin source..."
        mkdir -p /tmp/vpp-src/src/plugins/pcap_stream
        for f in /src/plugin/*.c /src/plugin/*.h /src/plugin/*.api /src/plugin/CMakeLists.txt; do
            [ -e "$f" ] && cp "$f" /tmp/vpp-src/src/plugins/pcap_stream/
        done

        echo "[+] Configuring ($BUILD_TYPE)..."
        mkdir -p /tmp/vpp-src/build && cd /tmp/vpp-src/build
        cmake ../src \
            -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
            -DVPP_BUILD_TESTS=OFF \
            -DCMAKE_C_FLAGS="-Werror" \
            2>&1 | tail -5

        echo "[+] Building pcap_stream_plugin (-j$JOBS)..."
        make -j"$JOBS" pcap_stream_plugin 2>&1 | tail -10

        PLUGIN=$(find . -name pcap_stream_plugin.so -type f | head -1)
        if [ -z "$PLUGIN" ]; then
            echo "[-] Build failed: pcap_stream_plugin.so not found" >&2
            exit 1
        fi
        cp "$PLUGIN" /out/pcap_stream_plugin.so

        APIJSON=$(find . -path "*/plugins/pcap_stream/pcap_stream.api.json" -type f | head -1)
        if [ -n "$APIJSON" ]; then
            cp "$APIJSON" /out/pcap_stream.api.json
            echo "[+] API JSON exported: /out/pcap_stream.api.json"
        fi

        echo "[+] Build successful: /out/pcap_stream_plugin.so"
        ls -la /out/
    '

echo "[+] Done: $OUTPUT_DIR/pcap_stream_plugin.so"
