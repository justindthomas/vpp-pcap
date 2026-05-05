/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 */

/* pcap_stream_node.c — feature-arc nodes that filter + enqueue.
 *
 * Two nodes register on two arcs:
 *
 *   pcap-stream-rx  on  "device-input"      (before ethernet-input)
 *   pcap-stream-tx  on  "interface-output"  (just before tx)
 *
 * Both see the ethernet-framed packet, so we filter against each
 * session's DLT_EN10MB libpcap program. Buffers traverse the node
 * unmodified — we always send them to the next feature in the arc.
 *
 * The hot-path scan is O(active_sessions) per buffer per node.
 * With the recommended cap (PCAP_STREAM_MAX_SESSIONS = 64) and
 * sessions only existing while operators are watching, the typical
 * cost on an idle dataplane is zero (feature arc disabled) and the
 * worst case is one BPF-interpreter invocation per active session
 * per packet.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/devices/devices.h>
#include <pcap_stream/pcap_stream.h>

typedef struct
{
  u32 sw_if_index;
  u32 sessions_matched;
  u32 packet_len;
} pcap_stream_trace_t;

#ifndef CLIB_MARCH_VARIANT

static u8 *
format_pcap_stream_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pcap_stream_trace_t *t = va_arg (*args, pcap_stream_trace_t *);

  s = format (s, "pcap-stream: sw_if=%u len=%u matched=%u",
	      t->sw_if_index, t->packet_len, t->sessions_matched);
  return s;
}

vlib_node_registration_t pcap_stream_rx_node;
vlib_node_registration_t pcap_stream_tx_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_pcap_stream_error                                             \
  _ (PROCESSED, "pcap_stream packets seen")                                   \
  _ (MATCHED, "pcap_stream packets matched a session filter")                 \
  _ (DROPPED, "pcap_stream records dropped (ring full)")

typedef enum
{
#define _(sym, str) PCAP_STREAM_ERROR_##sym,
  foreach_pcap_stream_error
#undef _
      PCAP_STREAM_N_ERROR,
} pcap_stream_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *pcap_stream_error_strings[] = {
#define _(sym, string) string,
  foreach_pcap_stream_error
#undef _
};
#endif

/* Feature-arc next-node enum: only ever a single next ("the next
 * feature on the arc"), but VPP requires a node next-table so we
 * declare it. */
typedef enum
{
  PCAP_STREAM_NEXT_NORMAL,
  PCAP_STREAM_N_NEXT,
} pcap_stream_next_t;

/* --- the inner work: try to match this packet against each active
 *     session and enqueue if it matches. Inlined into both rx/tx
 *     wrappers via the `direction` constant so the per-direction
 *     branch is constant-folded. */
static_always_inline u32
pcap_stream_match_and_enqueue (vlib_main_t *vm, vlib_buffer_t *b,
			       u8 direction, u64 ts_ns, u32 thread_index)
{
  pcap_stream_main_t *psm = &pcap_stream_main;
  u32 matched = 0;
  u32 orig_len = vlib_buffer_length_in_chain (vm, b);
  /* For multi-buffer chains we only see the first segment via
   * b->current_data + b->current_length. Truncating is fine for
   * snaplen-limited capture; full reassembly would mean walking
   * the chain which we skip in v1. */
  u32 first_seg_len = b->current_length;
  const u8 *eth = vlib_buffer_get_current (b);

  for (u32 i = 0; i < PCAP_STREAM_MAX_SESSIONS; i++)
    {
      pcap_stream_session_t *s = &psm->sessions[i];
      if (!s->active)
	continue;
      if (!(s->direction & direction))
	continue;
      /* Per-interface filter: only match if either the session is
       * "any" (~0) OR the interface matches. */
      u32 iface = (direction == PCAP_STREAM_DIR_RX)
		      ? vnet_buffer (b)->sw_if_index[VLIB_RX]
		      : vnet_buffer (b)->sw_if_index[VLIB_TX];
      if (s->sw_if_index != ~0 && s->sw_if_index != iface)
	continue;

      /* libpcap filter — NULL filter (no expression) always matches. */
      if (!pcap_filter_run (s->bpf_eth, eth, first_seg_len, orig_len))
	continue;

      pcap_stream_ring_t *r = s->rings[thread_index];
      pcap_stream_record_hdr_t *rec = pcap_stream_ring_reserve (r);
      if (!rec)
	{
	  __atomic_fetch_add (&s->dropped, 1, __ATOMIC_RELAXED);
	  continue;
	}
      rec->ts_ns = ts_ns;
      rec->sw_if_index = iface;
      rec->orig_len = orig_len;
      rec->len = first_seg_len < s->snaplen ? first_seg_len : s->snaplen;
      rec->direction = direction;
      rec->reason[0] = 0; /* rx/tx — only drop-mode sets this */
      clib_memcpy_fast (pcap_stream_record_data (rec), eth, rec->len);
      pcap_stream_ring_commit (r);
      matched++;
    }
  return matched;
}

/* The per-direction node body. We intentionally keep this simple
 * — buffer-at-a-time, no quad-loop, no SIMD. The hot path's cost
 * is dominated by the libpcap interpreter, so loop unrolling won't
 * move the needle materially. Optimise later if benchmarks say so.
 */
static_always_inline uword
pcap_stream_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, u8 direction)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 nexts[VLIB_FRAME_SIZE];
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u32 thread_index = vm->thread_index;
  u32 matched_total = 0;

  /* Wall-clock timestamp once per vector; intra-vector skew is sub-
   * microsecond and not worth the per-packet syscall. The BPF
   * filter doesn't depend on this — only the saved record does. */
  struct timespec ts;
  clock_gettime (CLOCK_REALTIME, &ts);
  u64 ts_ns = (u64) ts.tv_sec * 1000000000ULL + (u64) ts.tv_nsec;

  vlib_get_buffers (vm, from, bufs, n_left);

  for (u32 i = 0; i < n_left; i++)
    {
      nexts[i] = PCAP_STREAM_NEXT_NORMAL;

      vnet_feature_next_u16 (&nexts[i], bufs[i]);
      matched_total +=
	  pcap_stream_match_and_enqueue (vm, bufs[i], direction, ts_ns,
					 thread_index);

      if (PREDICT_FALSE (bufs[i]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  pcap_stream_trace_t *t =
	      vlib_add_trace (vm, node, bufs[i], sizeof (*t));
	  t->sw_if_index = (direction == PCAP_STREAM_DIR_RX)
			       ? vnet_buffer (bufs[i])->sw_if_index[VLIB_RX]
			       : vnet_buffer (bufs[i])->sw_if_index[VLIB_TX];
	  t->packet_len = vlib_buffer_length_in_chain (vm, bufs[i]);
	  t->sessions_matched = matched_total;
	}
    }

  vlib_node_increment_counter (vm, node->node_index, PCAP_STREAM_ERROR_PROCESSED,
			       n_left);
  if (matched_total)
    vlib_node_increment_counter (vm, node->node_index, PCAP_STREAM_ERROR_MATCHED,
				 matched_total);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_left);
  return n_left;
}

VLIB_NODE_FN (pcap_stream_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return pcap_stream_node_inline (vm, node, frame, PCAP_STREAM_DIR_RX);
}

VLIB_NODE_FN (pcap_stream_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return pcap_stream_node_inline (vm, node, frame, PCAP_STREAM_DIR_TX);
}

#ifndef CLIB_MARCH_VARIANT

VLIB_REGISTER_NODE (pcap_stream_rx_node) = {
  .name = "pcap-stream-rx",
  .vector_size = sizeof (u32),
  .format_trace = format_pcap_stream_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (pcap_stream_error_strings),
  .error_strings = pcap_stream_error_strings,
  .n_next_nodes = PCAP_STREAM_N_NEXT,
  .next_nodes = {
    [PCAP_STREAM_NEXT_NORMAL] = "ethernet-input",
  },
};

VLIB_REGISTER_NODE (pcap_stream_tx_node) = {
  .name = "pcap-stream-tx",
  .vector_size = sizeof (u32),
  .format_trace = format_pcap_stream_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (pcap_stream_error_strings),
  .error_strings = pcap_stream_error_strings,
  .n_next_nodes = PCAP_STREAM_N_NEXT,
  .next_nodes = {
    [PCAP_STREAM_NEXT_NORMAL] = "interface-output",
  },
};

VNET_FEATURE_INIT (pcap_stream_rx_feat, static) = {
  .arc_name = "device-input",
  .node_name = "pcap-stream-rx",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (pcap_stream_tx_feat, static) = {
  .arc_name = "interface-output",
  .node_name = "pcap-stream-tx",
};

void
pcap_stream_node_enable_iface (u32 sw_if_index, u8 direction, int enable)
{
  if (direction & PCAP_STREAM_DIR_RX)
    vnet_feature_enable_disable ("device-input", "pcap-stream-rx",
				 sw_if_index, enable, 0, 0);
  if (direction & PCAP_STREAM_DIR_TX)
    vnet_feature_enable_disable ("interface-output", "pcap-stream-tx",
				 sw_if_index, enable, 0, 0);
}

/* Enable/disable the feature arcs on every currently-known sw
 * interface. Used for "any" mode where the operator hasn't named
 * a specific interface. New interfaces created after enable
 * won't pick this up automatically — registering an interface-
 * add callback is a v2 nice-to-have. */
void
pcap_stream_node_enable_all (u8 direction, int enable)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *si;
  pool_foreach (si, vnm->interface_main.sw_interfaces)
    {
      if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE &&
	  si->type != VNET_SW_INTERFACE_TYPE_SUB)
	continue;
      pcap_stream_node_enable_iface (si->sw_if_index, direction, enable);
    }
}

#endif /* CLIB_MARCH_VARIANT */
