/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 *
 * fuzz_pcap_stream_rx_node.c — drives pcap_stream_rx_node_fn
 * against fuzzer-supplied bytes loaded into a 4-buffer frame.
 *
 * Coverage targets: pcap_stream_match_and_enqueue (filter NULL =
 * always match), pcap_stream_ring_reserve / commit, the
 * snaplen-bounded record copy (sfw v1's F8 was a bounds bug at
 * exactly this kind of copy), the per-direction sw_if_index check.
 *
 * Audit reference: F2 (use-after-free candidate in
 * pcap_stream_session_destroy / hot-path race) is *not* triggerable
 * by single-thread libfuzzer; it needs a concurrent destroy mid-
 * iteration.  This harness establishes ASan-clean coverage of the
 * non-race path and provides the chassis a future stress harness
 * can extend.
 */

#include <stdint.h>
#include <stddef.h>

#include <vlib/vlib.h>
#include "harness_init.h"

extern uword pcap_stream_rx_node_fn (vlib_main_t *, vlib_node_runtime_t *,
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
  pcap_stream_rx_node_fn (fuzz_get_main (), fuzz_get_node_runtime (),
			  fuzz_get_frame ());
  return 0;
}
