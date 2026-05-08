# vpp-pcap pcap_stream_node v2 chassis — extends audit-tools:vpp-fuzz
# so the layered base (clang + libfuzzer + ASan/UBSan + libclang-rt-
# dev + vpp-dev) carries over.  Mirrors sfw/fuzz/sfw_node/Dockerfile.
FROM localhost/audit-tools:vpp-fuzz

WORKDIR /src
ENTRYPOINT ["/bin/bash"]
