/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 *
 * harness_glue.c — extern symbols pcap_stream_node.c (and its sole
 * sibling pcap_stream_ring.c) reach for that aren't present in
 * libvppinfra.  Modeled on sfw/fuzz/sfw_node/harness_glue.c — same
 * shape, no bihash (vpp-pcap doesn't use it), plus a pcap_stream
 * fixture with one always-match session.
 *
 * Three categories:
 *   1. **VPP runtime data** — vlib_global_main, vlib_thread_main,
 *      ip4_main, ip6_main, feature_main, FIB pools, etc.  Storage
 *      provided here, populated in harness_init_once().
 *   2. **VPP runtime functions** — vlib_*, vnet_*, format_*, etc.
 *      Stubs return harmless defaults.
 *   3. **vpp-pcap shims** — pcap_filter_run stub (always match,
 *      avoids linking libpcap), pcap_stream_main BSS storage that
 *      pcap_stream.c would otherwise own.
 *
 * The harness body invokes VLIB_NODE_FN-emitted entrypoints
 * (pcap_stream_rx_node_fn / pcap_stream_tx_node_fn) against the
 * fixture; the audit's F2 candidate is a session-destroy / hot-path
 * race that needs concurrency to fire — single-thread libfuzzer
 * doesn't trigger it but provides ASan-clean coverage of the
 * non-race paths and lays the groundwork for a multi-thread
 * race-stress harness later.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/feature/feature.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip4_fib_16.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip4_mtrie.h>
#include <vnet/ip/ip_packet.h>
#include <vppinfra/time.h>
#include <vppinfra/vec.h>
#include <vppinfra/pool.h>
#include <vppinfra/bihash_24_8.h>
#include <pcap_stream/pcap_stream.h>

#include "harness_init.h"

/* ============================================================ */
/*  Category 1: VPP runtime globals                              */
/* ============================================================ */

vlib_global_main_t vlib_global_main;
vlib_thread_main_t vlib_thread_main;
vlib_buffer_func_main_t vlib_buffer_func_main;
u8 **vlib_thread_stacks;

vnet_feature_main_t feature_main;

ip4_main_t ip4_main;
ip6_main_t ip6_main;
ip4_fib_16_t *ip4_fib_16s;
ip4_mtrie_8_ply_t *ip4_ply_pool;
ip6_fib_fwding_table_instance_t ip6_fib_fwding_table;
load_balance_t *load_balance_pool;

/* pcap_stream_main is normally defined in pcap_stream.c (which we
 * don't compile in — it pulls VLIB_INIT_FUNCTION + drain_init that
 * touch the control socket).  Hand-define it here. */
pcap_stream_main_t pcap_stream_main;

/* CPU-feature-detected SIMD checksum that VPP swaps in at vlib_init
 * time.  Portable RFC-1071 fallback works on any host. */
static ip_csum_t
fuzz_incremental_checksum_portable (ip_csum_t csum, void *data_arg,
				    uword n_bytes)
{
  uint8_t *p = data_arg;
  while (n_bytes >= sizeof (uint32_t))
    {
      uint32_t w;
      __builtin_memcpy (&w, p, sizeof (w));
      csum = ip_csum_with_carry (csum, w);
      p += sizeof (uint32_t);
      n_bytes -= sizeof (uint32_t);
    }
  if (n_bytes > 0)
    {
      uint32_t tmp = 0;
      __builtin_memcpy (&tmp, p, n_bytes);
      csum = ip_csum_with_carry (csum, tmp);
    }
  return csum;
}

ip_csum_t (*vnet_incremental_checksum_fp) (ip_csum_t, void *, uword) =
  fuzz_incremental_checksum_portable;

/* ============================================================ */
/*  Category 2: VPP runtime function stubs                       */
/* ============================================================ */

static vnet_main_t fuzz_vnet_main;

vnet_main_t *
vnet_get_main (void)
{
  return &fuzz_vnet_main;
}

int
vnet_feature_enable_disable (const char *arc_name, const char *node_name,
			     u32 sw_if_index, int enable_disable,
			     void *feature_config,
			     u32 n_feature_config_bytes)
{
  (void) arc_name;
  (void) node_name;
  (void) sw_if_index;
  (void) enable_disable;
  (void) feature_config;
  (void) n_feature_config_bytes;
  return 0;
}

uword
vlib_buffer_length_in_chain_slow_path (vlib_main_t *vm, vlib_buffer_t *b)
{
  (void) vm;
  return b ? b->current_length : 0;
}

void
vlib_cli_output (vlib_main_t *vm, char *fmt, ...)
{
  (void) vm;
  (void) fmt;
}

void *
vlib_add_trace (vlib_main_t *vm, vlib_node_runtime_t *r, vlib_buffer_t *b,
		u32 n_data_bytes)
{
  (void) vm;
  (void) r;
  (void) b;
  (void) n_data_bytes;
  return NULL;
}

void
vlib_worker_thread_barrier_sync_int (vlib_main_t *vm, const char *func_name)
{
  (void) vm;
  (void) func_name;
}

void
vlib_worker_thread_barrier_release (vlib_main_t *vm)
{
  (void) vm;
}

u8 *
format_vnet_sw_if_index_name (u8 *s, va_list *args)
{
  (void) args;
  return s;
}

uword
unformat_vnet_sw_interface (unformat_input_t *input, va_list *args)
{
  (void) input;
  (void) args;
  return 0;
}

/* ============================================================ */
/*  Category 3: vpp-pcap shims                                   */
/* ============================================================ */

/* pcap_filter_run stub.  The real implementation in pcap_filter.c
 * pulls libpcap and BSD packet-filter VM internals that aren't worth
 * fuzzing through this harness (filter compilation is a one-shot at
 * session-create, not in the per-packet hot path).  NULL filter is
 * the fast path the production code returns 1 (match) for; we
 * always present a NULL session->bpf_eth so this stub is the only
 * implementation the harness touches.
 *
 * pcap_filter_compile / pcap_filter_free are linker satisfiers —
 * neither is reachable from the hot path. */
typedef struct pcap_filter_s pcap_filter_t;

int
pcap_filter_run (const pcap_filter_t *f, const uint8_t *pkt,
		 uint32_t caplen, uint32_t orig_len)
{
  (void) f;
  (void) pkt;
  (void) caplen;
  (void) orig_len;
  return 1; /* match; the harness keeps bpf_eth = NULL anyway */
}

pcap_filter_t *
pcap_filter_compile (const char *expr, int dlt, int snaplen, char **err)
{
  (void) expr;
  (void) dlt;
  (void) snaplen;
  if (err)
    *err = NULL;
  return NULL;
}

void
pcap_filter_free (pcap_filter_t *f)
{
  (void) f;
}

/* ============================================================ */
/*  v2.0: chassis fixture (driveable harness)                   */
/* ============================================================ */

#define FUZZ_BUFFER_DATA_SIZE 2048
#define FUZZ_BUFFER_SLOT_SIZE \
  (sizeof (vlib_buffer_t) + FUZZ_BUFFER_DATA_SIZE)
#define FUZZ_N_BUFFERS 4
#define FUZZ_BUFFER_SLOT_STRIDE_INDEX 36
#define FUZZ_BUFFER_SLOT_STRIDE_BYTES \
  (FUZZ_BUFFER_SLOT_STRIDE_INDEX * 64)

static u8 fuzz_buffer_storage[FUZZ_N_BUFFERS * FUZZ_BUFFER_SLOT_STRIDE_BYTES]
  __attribute__ ((aligned (64)));

static const u32 fuzz_buffer_indices[FUZZ_N_BUFFERS] = {
  0 * FUZZ_BUFFER_SLOT_STRIDE_INDEX,
  1 * FUZZ_BUFFER_SLOT_STRIDE_INDEX,
  2 * FUZZ_BUFFER_SLOT_STRIDE_INDEX,
  3 * FUZZ_BUFFER_SLOT_STRIDE_INDEX,
};

static inline vlib_buffer_t *
fuzz_buffer_at (u32 i)
{
  return (vlib_buffer_t *) (fuzz_buffer_storage +
			    i * FUZZ_BUFFER_SLOT_STRIDE_BYTES);
}

static vlib_main_t fuzz_vm;
static vlib_buffer_main_t fuzz_bm;
static vlib_buffer_pool_t *fuzz_buffer_pools_vec;

#define N_PCAP_COUNTERS 16
static vlib_node_t fuzz_node;
static vlib_node_runtime_t fuzz_node_runtime;
static vlib_error_t fuzz_node_errors[N_PCAP_COUNTERS];

#define FUZZ_FRAME_STORAGE_SIZE 256
static u8 fuzz_frame_storage[FUZZ_FRAME_STORAGE_SIZE]
  __attribute__ ((aligned (16)));

static u32 *fuzz_config_string_heap;

static int fuzz_initialized = 0;

vlib_main_t *
fuzz_get_main (void)
{
  return &fuzz_vm;
}

vlib_node_runtime_t *
fuzz_get_node_runtime (void)
{
  return &fuzz_node_runtime;
}

vlib_frame_t *
fuzz_get_frame (void)
{
  return (vlib_frame_t *) fuzz_frame_storage;
}

static void
fuzz_buffer_enqueue_to_next_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
				u32 *buffers, u16 *nexts, uword count)
{
  (void) vm;
  (void) node;
  (void) buffers;
  (void) nexts;
  (void) count;
}

void
harness_init_once (void)
{
  if (fuzz_initialized)
    return;

  /* 0. vppinfra main heap. */
  clib_mem_init_thread_safe (0, 64ULL << 20);

  /* 1. clib_time + thread index. */
  clib_time_init (&fuzz_vm.clib_time);
  fuzz_vm.thread_index = 0;

  /* 2. Buffer arena (4 slots, 36 cache lines apart). */
  fuzz_vm.buffer_main = &fuzz_bm;
  fuzz_bm.buffer_mem_start = (uword) fuzz_buffer_storage;
  fuzz_bm.buffer_mem_size = sizeof (fuzz_buffer_storage);
  fuzz_bm.default_data_size = FUZZ_BUFFER_DATA_SIZE;
  vec_validate (fuzz_buffer_pools_vec, 0);
  fuzz_buffer_pools_vec[0].start = (uword) fuzz_buffer_storage;
  fuzz_buffer_pools_vec[0].size = sizeof (fuzz_buffer_storage);
  fuzz_buffer_pools_vec[0].data_size = FUZZ_BUFFER_DATA_SIZE;
  fuzz_buffer_pools_vec[0].alloc_size = sizeof (fuzz_buffer_storage);
  fuzz_buffer_pools_vec[0].n_buffers = FUZZ_N_BUFFERS;
  fuzz_bm.buffer_pools = fuzz_buffer_pools_vec;

  /* 3. vlib_thread_main: vlib_num_workers() = 0. */
  vlib_thread_main.n_vlib_mains = 1;

  /* 4. node_main + error_main for vlib_node_increment_counter. */
  fuzz_node.error_heap_index = 0;
  vec_add1 (fuzz_vm.node_main.nodes, &fuzz_node);
  vec_validate (fuzz_vm.error_main.counters, N_PCAP_COUNTERS - 1);

  /* 5. node_runtime.errors[]. */
  for (u32 i = 0; i < N_PCAP_COUNTERS; i++)
    fuzz_node_errors[i] = i;
  fuzz_node_runtime.errors = fuzz_node_errors;
  fuzz_node_runtime.node_index = 0;
  fuzz_node_runtime.flags = 0;

  /* 6. Frame: n_vectors=4, vector_offset just past the header. */
  vlib_frame_t *frame = (vlib_frame_t *) fuzz_frame_storage;
  memset (frame, 0, FUZZ_FRAME_STORAGE_SIZE);
  frame->vector_offset = sizeof (vlib_frame_t);
  if (frame->vector_offset & 3)
    frame->vector_offset = (frame->vector_offset + 3) & ~3u;
  frame->n_vectors = FUZZ_N_BUFFERS;
  u32 *vec_args = (u32 *) ((u8 *) frame + frame->vector_offset);
  for (u32 i = 0; i < FUZZ_N_BUFFERS; i++)
    vec_args[i] = fuzz_buffer_indices[i];

  /* 7. buffer_func_main stub. */
  vlib_buffer_func_main.buffer_enqueue_to_next_fn =
    fuzz_buffer_enqueue_to_next_fn;

  /* 8. feature_main with one valid arc.  vnet_feature_next_u16 reads
   *    feature_arc_index from vnet_buffer(b) (=0) and indexes
   *    feature_config_mains[0]. */
  vec_validate (feature_main.feature_config_mains, 0);
  vec_validate (fuzz_config_string_heap, 0);
  fuzz_config_string_heap[0] = 0; /* PCAP_STREAM_NEXT_NORMAL */
  feature_main.feature_config_mains[0].config_main.config_string_heap =
    fuzz_config_string_heap;

  /* 9. ip4_main / ip6_main fib_index_by_sw_if_index — pcap_stream
   *    doesn't use these directly, but vnet_feature_next_u16's
   *    config-walk code path is shared with sfw and may read them. */
  vec_validate (ip4_main.fib_index_by_sw_if_index, 0);
  ip4_main.fib_index_by_sw_if_index[0] = 0;
  vec_validate (ip6_main.fib_index_by_sw_if_index, 0);
  ip6_main.fib_index_by_sw_if_index[0] = 0;

  /* 10. pcap_stream fixture: one always-match session.
   *     - active = 1
   *     - direction = RX|TX (covers both rx_node and tx_node)
   *     - sw_if_index = ~0 ("any interface")
   *     - snaplen = small enough that records fit in cache, big
   *       enough to copy realistic Ethernet+IP+L4 prefixes
   *     - bpf_eth = NULL (filter stub returns match)
   *     - rings[0] = pre-allocated SPSC ring sized for our snaplen
   */
  pcap_stream_main.vlib_main = &fuzz_vm;
  pcap_stream_main.vnet_main = &fuzz_vnet_main;
  pcap_stream_main.initialized = 1;
  pcap_stream_main.next_session_id = 1;

  pcap_stream_session_t *s = &pcap_stream_main.sessions[0];
  s->session_id = 1;
  s->sw_if_index = (u32) ~0;
  s->direction = PCAP_STREAM_DIR_RX | PCAP_STREAM_DIR_TX;
  s->snaplen = 256;
  s->bpf_eth = NULL;
  s->bpf_raw = NULL;
  s->filter_expr = NULL;
  s->data_file_index = (u32) ~0;
  s->data_fd = -1;
  s->pcap_header_sent = 0;
  vec_validate (s->rings, 0);
  s->rings[0] = pcap_stream_ring_alloc (s->snaplen);
  /* Last to be set so the hot path's `if (!s->active) continue` is
   * resolved against fully-initialised storage. */
  s->active = 1;

  fuzz_initialized = 1;
}

void
harness_load_packet (const uint8_t *data, size_t size)
{
  /* 4-vector frame: slice the fuzzer's bytes across N=4 buffers via
   * a 1-byte length prefix per slice.  Same shape as sfw_node v2.4.
   *
   * Per-buffer state: current_data=0, current_length=N, flags=0,
   * ref_count=1, sw_if_index[VLIB_RX]=0 (so PCAP_STREAM_DIR_RX is
   * default-targeted; the harness picks rx vs tx node body by
   * which entrypoint it calls). */
  size_t cap = FUZZ_BUFFER_DATA_SIZE;
  const u8 *p = data;
  size_t remaining = size;

  for (u32 i = 0; i < FUZZ_N_BUFFERS; i++)
    {
      vlib_buffer_t *b = fuzz_buffer_at (i);

      size_t slice_len = 0;
      if (remaining > 0)
	{
	  slice_len = (size_t) p[0];
	  p++;
	  remaining--;
	  if (slice_len > remaining)
	    slice_len = remaining;
	  if (slice_len > cap)
	    slice_len = cap;
	}

      memset (b, 0, sizeof (*b));
      if (slice_len > 0)
	memcpy (b->data, p, slice_len);
      b->current_data = 0;
      b->current_length = (u16) slice_len;
      b->flags = 0;
      b->ref_count = 1;
      b->buffer_pool_index = 0;
      b->error = 0;
      b->current_config_index = 0;

      vnet_buffer_opaque_t *vb = vnet_buffer (b);
      vb->sw_if_index[VLIB_RX] = 0;
      vb->sw_if_index[VLIB_TX] = 0;
      vb->feature_arc_index = 0;

      p += slice_len;
      remaining -= slice_len;
    }

  vlib_frame_t *frame = (vlib_frame_t *) fuzz_frame_storage;
  frame->n_vectors = FUZZ_N_BUFFERS;
  frame->frame_flags = 0;
  frame->flags = 0;
  u32 *vec_args = (u32 *) ((u8 *) frame + frame->vector_offset);
  for (u32 i = 0; i < FUZZ_N_BUFFERS; i++)
    vec_args[i] = fuzz_buffer_indices[i];
}
