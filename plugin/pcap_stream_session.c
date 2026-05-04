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
#include <vlib/file.h>
#include <unistd.h>

/* Compile both DLT_EN10MB and DLT_RAW programs so we can dispatch
 * on the buffer's effective offset at filter time — same trick
 * `bpf_trace_filter` uses upstream. The eth side is required (the
 * RX/TX feature-arc nodes always have ethernet-framed buffers);
 * the raw side is optional because expressions like `arp` and
 * `ether host ..` are eth-only and libpcap rejects them with
 * "expression rejects all packets" when compiled against DLT_RAW
 * — which would mean the drop tap (DLT_RAW) just never matches,
 * which is the correct behaviour anyway.
 *
 * Returns 0 on success, -1 on eth-side compile failure (with
 * *err_msg set). Raw-side failure leaves bpf_raw NULL and
 * silently disables drop-mode matching for this session. */
static int
compile_filter (pcap_stream_session_t *s, const char *expr, char **err_msg)
{
  /* Compile both DLT_EN10MB and DLT_RAW programs (eth required,
   * raw best-effort for the future drop tap). Both go through
   * pcap_compile_nopcap which doesn't have the pcap_t lifecycle
   * issue that crashed VPP on the second compile in the
   * pcap_open_dead/pcap_close pattern. */
  s->bpf_eth = pcap_filter_compile (expr, PCAP_FILTER_DLT_EN10MB,
				    PCAP_STREAM_MAX_SNAPLEN, err_msg);
  if (!s->bpf_eth)
    return -1;
  /* Best-effort raw-side compile. Discard any error — eth-only
   * filters like `arp` and `ether host ..` can't compile against
   * DLT_RAW, which just means drop-mode matching is silently
   * disabled for that session. */
  char *raw_err = NULL;
  s->bpf_raw = pcap_filter_compile (expr, PCAP_FILTER_DLT_RAW,
				    PCAP_STREAM_MAX_SNAPLEN, &raw_err);
  if (raw_err)
    free (raw_err);
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
      /* "any" interface — bump global counter; on the first
       * "any" session for each direction, enable the feature
       * arc on every existing interface. New interfaces created
       * after this won't auto-pick up; v2 nice-to-have. */
      if (s->direction & PCAP_STREAM_DIR_RX)
	{
	  psm->any_iface_rx_refcnt += delta;
	  if (delta > 0 && psm->any_iface_rx_refcnt == 1)
	    pcap_stream_node_enable_all (PCAP_STREAM_DIR_RX, 1);
	  else if (delta < 0 && psm->any_iface_rx_refcnt == 0)
	    pcap_stream_node_enable_all (PCAP_STREAM_DIR_RX, 0);
	}
      if (s->direction & PCAP_STREAM_DIR_TX)
	{
	  psm->any_iface_tx_refcnt += delta;
	  if (delta > 0 && psm->any_iface_tx_refcnt == 1)
	    pcap_stream_node_enable_all (PCAP_STREAM_DIR_TX, 1);
	  else if (delta < 0 && psm->any_iface_tx_refcnt == 0)
	    pcap_stream_node_enable_all (PCAP_STREAM_DIR_TX, 0);
	}
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

  /* Clamp snaplen — 0 means "use default", > MAX is an over-ask
   * we silently cap. The default (4096) covers the 99% case
   * (DNS payloads, BGP UPDATEs, OSPF LSAs) without burning the
   * memory that a full 65535-byte snaplen would. Operators who
   * need full payloads can request up to PCAP_STREAM_MAX_SNAPLEN
   * explicitly. */
  if (snaplen == 0)
    snaplen = PCAP_STREAM_DEFAULT_SNAPLEN;
  if (snaplen > PCAP_STREAM_MAX_SNAPLEN)
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
  s->data_file_index = ~0;
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
   * vm->thread_index without a bounds check. The ring is sized
   * for the operator's snaplen — see pcap_stream_ring_alloc.
   * If any allocation fails (heap exhausted), tear down what we
   * built and surface an error to the operator rather than
   * panicking VPP. */
  vec_validate (s->rings, nthreads - 1);
  for (u32 i = 0; i < nthreads; i++)
    {
      s->rings[i] = pcap_stream_ring_alloc (snaplen);
      if (!s->rings[i])
	{
	  *error_msg = strdup ("ring allocation failed (VPP heap exhausted)");
	  /* Free what we managed before bailing. */
	  for (u32 j = 0; j < i; j++)
	    pcap_stream_ring_free (s->rings[j]);
	  vec_free (s->rings);
	  if (s->bpf_eth) pcap_filter_free (s->bpf_eth);
	  if (s->bpf_raw) pcap_filter_free (s->bpf_raw);
	  free (s->filter_expr);
	  clib_memset (s, 0, sizeof (*s));
	  return 0;
	}
    }

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

  /* clib_file_del closes the underlying fd (dont_close=0 default),
   * so when a file_index is registered we must NOT close
   * data_fd ourselves — that would double-close, and if the
   * kernel has reused the fd for a new client connection in
   * between, we'd close the new client's fd by accident. Only
   * close data_fd directly when no file is registered (the
   * unhandover-fast-path case that doesn't currently exist but
   * is here for symmetry). */
  if (s->data_file_index != ~0u)
    {
      clib_file_del_by_index (&file_main, s->data_file_index);
      s->data_file_index = ~0;
      s->data_fd = -1;
    }
  else if (s->data_fd >= 0)
    {
      close (s->data_fd);
      s->data_fd = -1;
    }

  if (s->bpf_eth)
    {
      pcap_filter_free (s->bpf_eth);
      s->bpf_eth = NULL;
    }
  if (s->bpf_raw)
    {
      pcap_filter_free (s->bpf_raw);
      s->bpf_raw = NULL;
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
