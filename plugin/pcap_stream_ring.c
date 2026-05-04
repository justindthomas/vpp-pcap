/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 */

/* pcap_stream_ring.c — SPSC ring allocator. The hot-path reserve/
 * commit/peek/advance helpers are inlined in the header; this file
 * only owns alloc/free since they touch vec_ headers and tend to
 * pull in extra includes. */

#include <pcap_stream/pcap_stream.h>

pcap_stream_ring_t *
pcap_stream_ring_alloc (void)
{
  pcap_stream_ring_t *r;
  /* Aligned alloc so the cache-line padding in the struct actually
   * lands on a cache-line boundary. */
  r = clib_mem_alloc_aligned (sizeof (*r), CLIB_CACHE_LINE_BYTES);
  if (!r)
    return 0;
  clib_memset (r, 0, sizeof (*r));
  return r;
}

void
pcap_stream_ring_free (pcap_stream_ring_t *r)
{
  if (r)
    clib_mem_free (r);
}
