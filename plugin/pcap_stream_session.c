/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 */

/* pcap_stream_session.c — session create/destroy + BPF compile.
 *
 * Sessions live in a fixed-size array indexed by slot, with the
 * monotonically-incrementing session_id stored alongside so the
 * external id never collides with a freshly-reused slot.
 */

#include <pcap_stream/pcap_stream.h>

/* Compile both DLT_EN10MB and DLT_RAW programs so we can dispatch
 * on the buffer's effective offset at filter time — same trick
 * `bpf_trace_filter` uses upstream. Returns 0 on success, -1 on
 * compile failure (with *err_msg set). */
static int
compile_filter (pcap_stream_session_t *s, const char *expr, char **err_msg)
{
  pcap_t *eth_dummy = pcap_open_dead (DLT_EN10MB, PCAP_STREAM_MAX_SNAPLEN);
  pcap_t *raw_dummy = pcap_open_dead (DLT_RAW, PCAP_STREAM_MAX_SNAPLEN);
  if (!eth_dummy || !raw_dummy)
    {
      if (eth_dummy)
	pcap_close (eth_dummy);
      if (raw_dummy)
	pcap_close (raw_dummy);
      *err_msg = strdup ("pcap_open_dead failed");
      return -1;
    }

  if (pcap_compile (eth_dummy, &s->bpf_eth, expr, 1, PCAP_NETMASK_UNKNOWN) <
      0)
    {
      *err_msg = strdup (pcap_geterr (eth_dummy));
      pcap_close (eth_dummy);
      pcap_close (raw_dummy);
      return -1;
    }
  if (pcap_compile (raw_dummy, &s->bpf_raw, expr, 1, PCAP_NETMASK_UNKNOWN) <
      0)
    {
      *err_msg = strdup (pcap_geterr (raw_dummy));
      pcap_freecode (&s->bpf_eth);
      pcap_close (eth_dummy);
      pcap_close (raw_dummy);
      return -1;
    }

  pcap_close (eth_dummy);
  pcap_close (raw_dummy);
  s->bpf_compiled = 1;
  return 0;
}

/* Adjust feature-arc refcounts when sessions appear/disappear. The
 * actual vnet_feature_enable_disable call is in node.c (task #3);
 * here we just bump the counters and call the stubs. */
static void
adjust_refcounts (pcap_stream_session_t *s, int delta)
{
  pcap_stream_main_t *psm = &pcap_stream_main;
  u32 idx = s->sw_if_index;

  if (idx == ~0)
    {
      /* "any" interface — bump the global rx/tx counters and let
       * the node layer handle "enable on every interface" semantics
       * lazily as packets arrive. */
      if (s->direction & PCAP_STREAM_DIR_RX)
	psm->any_iface_rx_refcnt += delta;
      if (s->direction & PCAP_STREAM_DIR_TX)
	psm->any_iface_tx_refcnt += delta;
    }
  else
    {
      if (s->direction & PCAP_STREAM_DIR_RX)
	{
	  vec_validate (psm->rx_refcnt, idx);
	  psm->rx_refcnt[idx] += delta;
	  if (delta > 0 && psm->rx_refcnt[idx] == 1)
	    pcap_stream_node_enable_iface (idx, PCAP_STREAM_DIR_RX, 1);
	  else if (delta < 0 && psm->rx_refcnt[idx] == 0)
	    pcap_stream_node_enable_iface (idx, PCAP_STREAM_DIR_RX, 0);
	}
      if (s->direction & PCAP_STREAM_DIR_TX)
	{
	  vec_validate (psm->tx_refcnt, idx);
	  psm->tx_refcnt[idx] += delta;
	  if (delta > 0 && psm->tx_refcnt[idx] == 1)
	    pcap_stream_node_enable_iface (idx, PCAP_STREAM_DIR_TX, 1);
	  else if (delta < 0 && psm->tx_refcnt[idx] == 0)
	    pcap_stream_node_enable_iface (idx, PCAP_STREAM_DIR_TX, 0);
	}
    }

  if (s->direction & PCAP_STREAM_DIR_DROP)
    {
      psm->drop_refcnt += delta;
      if (delta > 0 && psm->drop_refcnt == 1)
	pcap_stream_drop_enable (1);
      else if (delta < 0 && psm->drop_refcnt == 0)
	pcap_stream_drop_enable (0);
    }
}

pcap_stream_session_t *
pcap_stream_session_create (const char *filter_expr, u32 sw_if_index,
			    u8 direction, u32 snaplen, u64 max_packets,
			    char **error_msg)
{
  pcap_stream_main_t *psm = &pcap_stream_main;
  pcap_stream_session_t *s = 0;
  u32 nthreads = vlib_get_n_threads ();

  *error_msg = 0;

  if (snaplen == 0 || snaplen > PCAP_STREAM_MAX_SNAPLEN)
    snaplen = PCAP_STREAM_MAX_SNAPLEN;

  /* Find a free slot. */
  for (u32 i = 0; i < PCAP_STREAM_MAX_SESSIONS; i++)
    if (!psm->sessions[i].active)
      {
	s = &psm->sessions[i];
	break;
      }
  if (!s)
    {
      *error_msg = strdup ("session table full");
      return 0;
    }

  clib_memset (s, 0, sizeof (*s));
  s->session_id = psm->next_session_id++;
  s->sw_if_index = sw_if_index;
  s->direction = direction;
  s->snaplen = snaplen;
  s->max_packets = max_packets;
  s->data_fd = -1;
  s->created_at = vlib_time_now (psm->vlib_main);
  s->filter_expr = strdup (filter_expr ? filter_expr : "");

  if (filter_expr && filter_expr[0] != 0 &&
      compile_filter (s, filter_expr, error_msg) < 0)
    {
      free (s->filter_expr);
      clib_memset (s, 0, sizeof (*s));
      return 0;
    }

  /* Allocate per-thread rings. We allocate one for every thread
   * including main, so the worker threads can blindly index by
   * vm->thread_index without a bounds check. */
  vec_validate (s->rings, nthreads - 1);
  for (u32 i = 0; i < nthreads; i++)
    s->rings[i] = pcap_stream_ring_alloc ();

  s->active = 1;
  adjust_refcounts (s, 1);
  return s;
}

void
pcap_stream_session_destroy (pcap_stream_session_t *s)
{
  if (!s || !s->active)
    return;

  adjust_refcounts (s, -1);

  if (s->data_file)
    {
      clib_file_del (&file_main, s->data_file);
      s->data_file = 0;
    }
  if (s->data_fd >= 0)
    {
      close (s->data_fd);
      s->data_fd = -1;
    }

  if (s->bpf_compiled)
    {
      pcap_freecode (&s->bpf_eth);
      pcap_freecode (&s->bpf_raw);
      s->bpf_compiled = 0;
    }

  for (u32 i = 0; i < vec_len (s->rings); i++)
    pcap_stream_ring_free (s->rings[i]);
  vec_free (s->rings);

  if (s->filter_expr)
    {
      free (s->filter_expr);
      s->filter_expr = 0;
    }

  s->active = 0;
}
