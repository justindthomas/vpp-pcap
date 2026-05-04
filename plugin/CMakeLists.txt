# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Justin Thomas

add_vpp_plugin(pcap_stream
  SOURCES
  pcap_stream.c
  pcap_stream_session.c
  pcap_stream_ring.c
  pcap_stream_drain.c
  pcap_stream_node.c
  pcap_stream_drop.c
  pcap_stream_api.c
  pcap_filter.c
  pcap_stream.h
  pcap_filter.h

  MULTIARCH_SOURCES
  pcap_stream_node.c

  API_FILES
  pcap_stream.api

  LINK_LIBRARIES
  pcap
)
