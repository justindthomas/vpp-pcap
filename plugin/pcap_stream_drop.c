/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 */

/* pcap_stream_drop.c — error-drop capture path.
 *
 * Hooks the vlib drop callback exposed by our small VPP patch
 * (see vpp-patches/0001-error-drop-callback-hook.patch). The
 * callback fires inside error-drop on every dropped buffer; we
 * filter against PCAP_STREAM_DIR_DROP sessions and enqueue.
 *
 * If the patch hasn't been applied, the symbol resolves at link
 * time to the weak no-op stub at the bottom of this file and drop
 * capture silently degrades to a no-op (rest of the plugin still
 * works). Same shape as how sfw handles its optional vpp-patch
 * extensions.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <pcap_stream/pcap_stream.h>

#ifdef HAVE_VLIB_DROP_CALLBACK
extern void vlib_drop_callback_register (
    void (*fn) (vlib_main_t *, vlib_buffer_t *, u64));
extern void vlib_drop_callback_unregister (
    void (*fn) (vlib_main_t *, vlib_buffer_t *, u64));
#else
/* Weak no-op fallbacks so the build works against an unpatched VPP.
 * The drop tap is silently a no-op in that case — sessions with
 * direction=drop will appear active but never receive packets. */
__attribute__ ((weak)) void
vlib_drop_callback_register (void (*fn) (vlib_main_t *, vlib_buffer_t *, u64))
{
  (void) fn;
}

__attribute__ ((weak)) void
vlib_drop_callback_unregister (
    void (*fn) (vlib_main_t *, vlib_buffer_t *, u64))
{
  (void) fn;
}
#endif

static void
pcap_stream_drop_callback (vlib_main_t *vm, vlib_buffer_t *b, u64 e0)
{
  pcap_stream_main_t *psm = &pcap_stream_main;
  u32 thread_index = vm->thread_index;
  u32 orig_len = vlib_buffer_length_in_chain (vm, b);
  u32 first_seg_len = b->current_length;
  u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];

  /* error-drop runs after the packet has progressed through some
   * fraction of the L3/L4 pipeline, so b->current_data may not
   * point at the ethernet header anymore. Use DLT_RAW for the
   * filter — most drop reasons are L3+ anyway. */
  const u8 *pkt = vlib_buffer_get_current (b);

  struct timespec ts;
  clock_gettime (CLOCK_REALTIME, &ts);
  u64 ts_ns = (u64) ts.tv_sec * 1000000000ULL + (u64) ts.tv_nsec;

  for (u32 i = 0; i < PCAP_STREAM_MAX_SESSIONS; i++)
    {
      pcap_stream_session_t *s = &psm->sessions[i];
      if (!s->active)
	continue;
      if (!(s->direction & PCAP_STREAM_DIR_DROP))
	continue;
      /* Drop-mode sessions can't filter by sw_if_index reliably
       * (some drop sources don't carry it). If the operator
       * specified an interface, only match when it's set. */
      if (s->sw_if_index != ~0 && s->sw_if_index != sw_if_index)
	continue;

      if (!pcap_filter_run (s->bpf_raw, pkt, first_seg_len, orig_len))
	continue;

      pcap_stream_ring_t *r = s->rings[thread_index];
      pcap_stream_record_hdr_t *rec = pcap_stream_ring_reserve (r);
      if (!rec)
	{
	  __atomic_fetch_add (&s->dropped, 1, __ATOMIC_RELAXED);
	  continue;
	}
      rec->ts_ns = ts_ns;
      rec->sw_if_index = sw_if_index;
      rec->orig_len = orig_len;
      rec->len = first_seg_len < s->snaplen ? first_seg_len : s->snaplen;
      rec->direction = PCAP_STREAM_DIR_DROP;
      clib_memcpy_fast (pcap_stream_record_data (rec), pkt, rec->len);
      pcap_stream_ring_commit (r);
    }
  (void) e0; /* error code is logged by error-drop itself; we don't
		surface it through the pcap stream for v1. */
}

void
pcap_stream_drop_enable (int enable)
{
  if (enable)
    vlib_drop_callback_register (pcap_stream_drop_callback);
  else
    vlib_drop_callback_unregister (pcap_stream_drop_callback);
}
