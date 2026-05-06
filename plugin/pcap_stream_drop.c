/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 */

/* pcap_stream_drop.c — error-drop capture path.
 *
 * Hooks the vlib drop callback added by our patch in
 * vpp-patches/0001-error-drop-callback-hook.patch. Per-buffer
 * callback fires inside error-drop just before vlib_buffer_free;
 * we filter against PCAP_STREAM_DIR_DROP sessions and enqueue the
 * matched packets, attaching the drop reason (e.g.
 * "ip6-input.no-route") as a pcap-ng EPB comment so it surfaces in
 * the operator's output.
 *
 * The patched libvlib.so is a hard requirement — we don't ship
 * weak no-op fallbacks. The earlier attempt did that and it
 * silently broke at static link time: GCC resolved the call to the
 * weak local stub before dlopen could redirect it to libvlib's
 * strong symbol, so drop-mode looked alive but captured nothing.
 * Now: if the symbol is missing at plugin load time, VPP fails to
 * load the plugin (clear failure mode, easy to debug).
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <pcap_stream/pcap_stream.h>

/* Decoded drop info: node + counter strings plus a flag indicating
 * which feature arc the drop fired on. Output-arc drops want the
 * tx-side iface + an Outbound EPB flag; everything else gets the
 * rx-side iface + Inbound. */
typedef struct
{
  const char *node_name;	/* borrowed pointer into vlib_node_t */
  const char *code_desc;	/* borrowed pointer into counters_heap */
  int is_output_arc;
} drop_info_t;

/* Suffix-match against the set of node names that fire on output
 * feature arcs / TX path. Conservative: matches only nodes where
 * the buffer was being sent OUT a different interface than it came
 * IN on. Common cases:
 *   sfw-ip4-out, sfw-ip6-out      — sfw output feature arc
 *   ip4-output, ip6-output        — pre-rewrite output node
 *   ip4-rewrite, ip6-rewrite      — header rewrite (TTL, MTU drops)
 *   ip4-arp, ip6-discover-neighbor — neighbour resolution drops
 *   interface-output, *-tx        — final TX nodes (rare at error-
 *                                   drop but covered for safety) */
static int
node_is_output_arc (const char *name)
{
  if (!name)
    return 0;
  size_t n = strlen (name);
  /* Suffix helpers — only match if name is at least suffix length
   * AND tail equals suffix. */
#define ENDS(s)                                                               \
  (n >= sizeof (s) - 1 && memcmp (name + n - (sizeof (s) - 1), (s),           \
				  sizeof (s) - 1) == 0)
  if (ENDS ("-out"))
    return 1;
  if (ENDS ("-output"))
    return 1;
  if (ENDS ("-rewrite"))
    return 1;
  if (ENDS ("-tx"))
    return 1;
#undef ENDS
  if (strcmp (name, "ip4-arp") == 0)
    return 1;
  if (strcmp (name, "ip6-discover-neighbor") == 0)
    return 1;
  return 0;
}

/* Decode the encoded error into node + counter strings + arc hint.
 * Returns 1 on success, 0 if the error can't be decoded (caller
 * should skip the comment + leave direction as DROP-only). */
static int
decode_drop (vlib_main_t *vm, u32 error_index, drop_info_t *out)
{
  vlib_error_main_t *em = &vm->error_main;
  uword node_index = vlib_error_get_node (&vm->node_main, error_index);
  uword code = vlib_error_get_code (&vm->node_main, error_index);

  if (node_index >= vec_len (vm->node_main.nodes))
    return 0;
  vlib_node_t *n = vlib_get_node (vm, node_index);
  if (code >= n->n_errors)
    return 0;

  uword counter_idx = n->error_heap_index + code;
  if (counter_idx >= vec_len (em->counters_heap))
    return 0;

  out->node_name = (const char *) n->name;
  out->code_desc = em->counters_heap[counter_idx].desc;
  if (!out->node_name || !out->code_desc)
    return 0;
  out->is_output_arc = node_is_output_arc (out->node_name);
  return 1;
}

static void
pcap_stream_drop_callback (vlib_main_t *vm, vlib_buffer_t *b, u32 error_index)
{
  pcap_stream_main_t *psm = &pcap_stream_main;
  u32 thread_index = vm->thread_index;
  u32 orig_len = vlib_buffer_length_in_chain (vm, b);

  /* Decode the drop reason first — its node-name suffix tells us
   * whether to attribute the drop to the rx-side interface (input
   * arc) or the tx-side (output arc). Output-arc drops use VLIB_TX
   * if it's been populated; otherwise fall back to VLIB_RX so we
   * always emit a usable iface. */
  drop_info_t di;
  int decoded = decode_drop (vm, error_index, &di);

  u32 sw_if_index;
  u8 epb_dir_bit;
  if (decoded && di.is_output_arc)
    {
      u32 tx = vnet_buffer (b)->sw_if_index[VLIB_TX];
      if (tx != ~0u && tx != 0)
	{
	  sw_if_index = tx;
	  epb_dir_bit = PCAP_STREAM_DIR_TX;
	}
      else
	{
	  /* Output-arc drop but TX iface not set yet (e.g. rewrite
	   * fired before the FIB lookup populated VLIB_TX) — fall back
	   * to RX + Inbound. */
	  sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
	  epb_dir_bit = PCAP_STREAM_DIR_RX;
	}
    }
  else
    {
      sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
      epb_dir_bit = PCAP_STREAM_DIR_RX;
    }

  /* Rewind to the L2 header so the captured frame is decodable
   * against the DLT_EN10MB IDB. Three cases:
   *
   * 1. L2_HDR_OFFSET flag set — vnet_buffer(b)->l2_hdr_offset is
   *    the absolute offset from b->data to the start of the L2
   *    header. This is precise: ethernet-input stamps it and
   *    every downstream node that advances past L2 leaves it
   *    alone. Use it when available.
   *
   * 2. No flag, current_data > 0 — fall back to assuming a
   *    14-byte Ethernet header sits immediately before
   *    current_data. Not perfect (misses VLAN tags and over-
   *    reads if multiple headers were stripped), but better
   *    than rewinding by current_data which lands in unused
   *    headroom for ip4-input drops (cd==34, real L2 is 20
   *    bytes inside that range).
   *
   * 3. current_data <= 0 — header was prepended (TX path,
   *    unusual at error-drop). vlib_buffer_get_current is the
   *    frame start. */
  const u8 *pkt;
  u32 first_seg_len;
  if (b->flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID)
    {
      i16 l2_off = vnet_buffer (b)->l2_hdr_offset;
      pkt = b->data + l2_off;
      i32 stripped = (i32) b->current_data - (i32) l2_off;
      if (stripped < 0)
	stripped = 0;
      first_seg_len = (u32) stripped + b->current_length;
      orig_len += (u32) stripped;
    }
  else if (b->current_data > 0)
    {
      const u32 ETH_HLEN = 14;
      u32 rewind = (u32) b->current_data < ETH_HLEN
		     ? (u32) b->current_data
		     : ETH_HLEN;
      pkt = vlib_buffer_get_current (b) - rewind;
      first_seg_len = rewind + b->current_length;
      orig_len += rewind;
    }
  else
    {
      pkt = vlib_buffer_get_current (b);
      first_seg_len = b->current_length;
    }

  /* Format reason once per drop, regardless of how many sessions
   * match. Borrowed pointers in di are stable for the life of the
   * vlib registration so it's safe to read them across the loop. */
  char reason_buf[96];
  char *reason = NULL;
  if (decoded)
    {
      snprintf (reason_buf, sizeof (reason_buf), "%s.%s", di.node_name,
		di.code_desc);
      reason = reason_buf;
    }

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
      if (s->sw_if_index != ~0 && s->sw_if_index != sw_if_index)
	continue;

      /* Filter against bpf_eth — we capture from b->data which
       * includes the original L2, so the filter sees a normal
       * Ethernet frame. (Pre-fix this used bpf_raw because
       * current_data had already skipped L2.) */
      if (!pcap_filter_run (s->bpf_eth, pkt, first_seg_len, orig_len))
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
      /* DROP bit drives session-direction filtering; the RX/TX bit
       * tells the pcap-ng EPB encoder whether to mark Inbound or
       * Outbound. */
      rec->direction = PCAP_STREAM_DIR_DROP | epb_dir_bit;
      /* Stash drop reason in the record's reserved area so the
       * drain can emit it as a pcap-ng EPB comment. We bound the
       * length to keep records uniform — most drop reasons are
       * <60 chars (longest is around "ip6-input.frag-internet-header-overflow"
       * at ~40). Truncated reasons still attach a useful prefix. */
      if (reason)
	{
	  size_t rl = strlen (reason);
	  if (rl >= sizeof (rec->reason))
	    rl = sizeof (rec->reason) - 1;
	  memcpy (rec->reason, reason, rl);
	  rec->reason[rl] = 0;
	}
      else
	{
	  rec->reason[0] = 0;
	}
      clib_memcpy_fast (pcap_stream_record_data (rec), pkt, rec->len);
      pcap_stream_ring_commit (r);
    }
}

void
pcap_stream_drop_enable (int enable)
{
  if (enable)
    vlib_drop_callback_register (pcap_stream_drop_callback);
  else
    vlib_drop_callback_unregister (pcap_stream_drop_callback);
}
