/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 *
 * fuzz_pcap_stream_tx_node.c — mirror of fuzz_pcap_stream_rx_node.c
 * against the tx-direction entrypoint.  See that file's header.
 */

#include <stdint.h>
#include <stddef.h>

#include <vlib/vlib.h>
#include "harness_init.h"

extern uword pcap_stream_tx_node_fn (vlib_main_t *, vlib_node_runtime_t *,
				     vlib_frame_t *);

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;
  harness_init_once ();
  return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size == 0)
    return 0;

  harness_load_packet (data, size);
  pcap_stream_tx_node_fn (fuzz_get_main (), fuzz_get_node_runtime (),
			  fuzz_get_frame ());
  return 0;
}
