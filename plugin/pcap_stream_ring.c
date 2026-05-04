/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 */

/* pcap_stream_ring.c — SPSC ring allocator. Variable-stride records
 * sized at session-create from the operator's snaplen. The records
 * buffer is a flexible array member of the ring struct, so the
 * whole thing is one allocation.
 *
 * Memory budget: PCAP_STREAM_RING_SIZE (256) × (record_hdr +
 * snaplen). At the default snaplen of 4096 that's about 1MB per
 * ring per worker — N workers per session, so a few MB per
 * session. The earlier crash on jt-router was a fixed 64KB
 * inline payload with depth 1024 (= 64MB per ring), which
 * exhausted VPP's heap. Don't go back. */

#include <pcap_stream/pcap_stream.h>

pcap_stream_ring_t *
pcap_stream_ring_alloc (u32 snaplen)
{
  pcap_stream_ring_t *r;

  if (snaplen == 0 || snaplen > PCAP_STREAM_MAX_SNAPLEN)
    snaplen = PCAP_STREAM_MAX_SNAPLEN;

  u32 stride = sizeof (pcap_stream_record_hdr_t) + snaplen;
  /* Align stride to 8 bytes so the next record's u64 timestamp is
   * naturally aligned. */
  stride = (stride + 7) & ~7u;

  size_t bytes = sizeof (*r) + (size_t) stride * PCAP_STREAM_RING_SIZE;

  /* Use the regular vppinfra allocator. Returning NULL on failure
   * lets session_create surface the error to the operator instead
   * of panicking VPP — clib_mem_alloc_aligned os_panic'd us last
   * time when the heap was exhausted. */
  r = clib_mem_alloc_aligned_or_null (bytes, CLIB_CACHE_LINE_BYTES);
  if (!r)
    return 0;
  clib_memset (r, 0, sizeof (*r));
  r->record_stride = stride;
  return r;
}

void
pcap_stream_ring_free (pcap_stream_ring_t *r)
{
  if (r)
    clib_mem_free (r);
}
