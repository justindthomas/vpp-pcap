/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 */

/* pcap_stream.h — live tcpdump-style packet capture over Unix sockets.
 *
 * Operator runs the `vpp-pcap` CLI; CLI talks to /run/vpp/pcap-stream.sock,
 * gets a session id and a per-session data socket path, then reads pcap
 * savefile-formatted bytes off the data socket. See DESIGN.md.
 */

#ifndef __included_pcap_stream_h__
#define __included_pcap_stream_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vlib/vlib.h>
#include <vppinfra/clib.h>
#include <vppinfra/file.h>

#include <pcap/pcap.h>

#define PCAP_STREAM_PLUGIN_VERSION_MAJOR 0
#define PCAP_STREAM_PLUGIN_VERSION_MINOR 1

/* Default control socket path. Override via plugin CLI:
 *   pcap stream control-socket /custom/path.sock
 */
#define PCAP_STREAM_CONTROL_SOCK_DEFAULT "/run/vpp/pcap-stream.sock"

/* Per-session data socket path template — %u is the session id. */
#define PCAP_STREAM_DATA_SOCK_FMT "/run/vpp/pcap-stream-%u.sock"

/* Maximum number of concurrent sessions. Sessions are cheap (small
 * struct + per-worker rings) but we cap to keep the linear hot-path
 * scan bounded. */
#define PCAP_STREAM_MAX_SESSIONS 64

/* Per-(session, worker) ring depth in records. SPSC, power of two.
 * 1024 records × ~1.5KB worst case = ~1.5MB per ring × 64 sessions ×
 * N workers worst case. Tune later if needed. */
#define PCAP_STREAM_RING_LOG2_SIZE 10
#define PCAP_STREAM_RING_SIZE	  (1u << PCAP_STREAM_RING_LOG2_SIZE)
#define PCAP_STREAM_RING_MASK	  (PCAP_STREAM_RING_SIZE - 1)

/* Per-record max captured bytes. Records are fixed-size so the ring
 * stays cache-friendly; matches the libpcap savefile snaplen ceiling
 * for a "watch a wire" tool. Actual stored length is record->len. */
#define PCAP_STREAM_MAX_SNAPLEN 65535

/* Direction filter — what the operator's `-d` argument selects. */
typedef enum
{
  PCAP_STREAM_DIR_RX = 1 << 0,
  PCAP_STREAM_DIR_TX = 1 << 1,
  PCAP_STREAM_DIR_DROP = 1 << 2,
  PCAP_STREAM_DIR_ANY = PCAP_STREAM_DIR_RX | PCAP_STREAM_DIR_TX |
			PCAP_STREAM_DIR_DROP,
} pcap_stream_direction_t;

/* One captured-packet record sitting in a ring. The payload is
 * inline so the ring is one contiguous allocation per (session,
 * worker). `len` may be < snaplen if the original packet was
 * shorter; `orig_len` is the on-the-wire length so the consumer
 * can render the truncation indicator. */
typedef struct
{
  u64 ts_ns;	      /* CLOCK_REALTIME in ns */
  u32 sw_if_index;    /* original VLIB_RX/TX iface */
  u32 orig_len;	      /* full packet length pre-snap */
  u32 len;	      /* bytes actually copied */
  u8 direction;	      /* pcap_stream_direction_t single bit */
  u8 _pad[3];
  u8 data[PCAP_STREAM_MAX_SNAPLEN];
} pcap_stream_record_t;

/* SPSC ring — one writer (a single VPP worker), one reader (the
 * main thread drain). head/tail are monotonically increasing
 * 64-bit counters; modulo masks them at access time. */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (head_pad);
  volatile u64 head; /* next slot the writer will fill */

  CLIB_CACHE_LINE_ALIGN_MARK (tail_pad);
  volatile u64 tail; /* next slot the reader will consume */

  CLIB_CACHE_LINE_ALIGN_MARK (data_pad);
  pcap_stream_record_t records[PCAP_STREAM_RING_SIZE];
} pcap_stream_ring_t;

/* One capture session. Holds the compiled BPF program, per-worker
 * rings, and the data socket fd that the main-thread drain is
 * writing into. */
typedef struct
{
  u32 session_id;     /* allocator handle, also wire id */
  u8 active;	      /* 0 = free slot in the pool */

  /* Filter spec */
  u32 sw_if_index;    /* ~0 = any */
  u8 direction;	      /* mask of pcap_stream_direction_t */
  u32 snaplen;	      /* bytes to copy per packet */
  u64 max_packets;    /* 0 = unlimited */

  /* Compiled libpcap programs. The bpf_trace_filter trick: keep
   * one program compiled against DLT_EN10MB and one against
   * DLT_RAW so we can dispatch based on whether the buffer is
   * pre- or post-ethernet. */
  struct bpf_program bpf_eth;
  struct bpf_program bpf_raw;
  u8 bpf_compiled;
  char *filter_expr;	  /* operator's original string */

  /* Per-worker rings. Indexed by vlib_thread_index — vec length
   * equals total threads (main + workers). Worker writes; main
   * thread drains. */
  pcap_stream_ring_t **rings;	   /* vec[nthreads] */

  /* Data socket — main-thread end. The CLI connects, we write
   * pcap file header + records. -1 until CLI connects. */
  clib_file_t *data_file;	   /* registered with file_main */
  int data_fd;
  u8 pcap_header_sent;

  /* Stats */
  u64 captured;	      /* records written to socket */
  u64 dropped;	      /* records lost to ring-full */
  f64 created_at;     /* vlib_time_now at session create */
} pcap_stream_session_t;

/* One control-socket client connection. Multiple may be open at
 * the same time (e.g. a CLI that sent `list` while another is
 * streaming a session). */
typedef struct
{
  clib_file_t *file;
  int fd;
  u8 *rx_buf;	      /* accumulated bytes, line-delimited messages */
} pcap_stream_control_client_t;

/* Plugin-wide state. Singleton, lives in BSS. */
typedef struct
{
  /* VPP handles */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* Initialization */
  u8 initialized;

  /* Sessions — fixed-size table for cheap linear scan in the hot
   * path. Holes are marked with active=0. */
  pcap_stream_session_t sessions[PCAP_STREAM_MAX_SESSIONS];
  u32 next_session_id;	  /* monotonic, never reused */

  /* Reference counts of how many sessions are listening to each
   * (sw_if_index, direction) so we know when to enable/disable
   * the feature arc. -1 indices are reserved for the "any"
   * sw_if_index sentinel. */
  u32 *rx_refcnt; /* vec[sw_if_index] */
  u32 *tx_refcnt; /* vec[sw_if_index] */
  u32 drop_refcnt;
  u32 any_iface_rx_refcnt;
  u32 any_iface_tx_refcnt;

  /* Control socket */
  char *control_socket_path;
  int control_listen_fd;
  clib_file_t *control_listen_file;
  pcap_stream_control_client_t *control_clients; /* pool */

  /* Drain process — wakes periodically + on data-socket-writable */
  uword drain_process_node_index;
} pcap_stream_main_t;

extern pcap_stream_main_t pcap_stream_main;

/* --- session.c --- */

/* Allocate + initialise a new session. Returns NULL on failure
 * (e.g. table full, BPF compile error). filter_expr is copied. */
pcap_stream_session_t *pcap_stream_session_create (
    const char *filter_expr, u32 sw_if_index, u8 direction, u32 snaplen,
    u64 max_packets, char **error_msg);

/* Tear down a session: free BPF, free rings, close data fd, drop
 * feature-arc refcounts. */
void pcap_stream_session_destroy (pcap_stream_session_t *s);

/* Fast O(N) iteration over active sessions. Inline so the hot
 * path doesn't pay a function-call cost. */
static_always_inline pcap_stream_session_t *
pcap_stream_session_first_active (pcap_stream_main_t *psm)
{
  for (u32 i = 0; i < PCAP_STREAM_MAX_SESSIONS; i++)
    if (psm->sessions[i].active)
      return &psm->sessions[i];
  return 0;
}

/* --- ring.c --- */

pcap_stream_ring_t *pcap_stream_ring_alloc (void);
void pcap_stream_ring_free (pcap_stream_ring_t *r);

/* Producer — return pointer to the next writable record, or NULL
 * if the ring is full. Caller fills the record then calls commit.
 * Single-writer per ring; no atomics on head besides the release-
 * store at commit time. */
static_always_inline pcap_stream_record_t *
pcap_stream_ring_reserve (pcap_stream_ring_t *r)
{
  u64 head = r->head;
  u64 tail = __atomic_load_n (&r->tail, __ATOMIC_ACQUIRE);
  if (head - tail >= PCAP_STREAM_RING_SIZE)
    return 0;
  return &r->records[head & PCAP_STREAM_RING_MASK];
}

static_always_inline void
pcap_stream_ring_commit (pcap_stream_ring_t *r)
{
  __atomic_store_n (&r->head, r->head + 1, __ATOMIC_RELEASE);
}

/* Consumer — main thread. Returns pointer to next-readable record
 * or NULL if empty. Caller copies out then calls advance. */
static_always_inline pcap_stream_record_t *
pcap_stream_ring_peek (pcap_stream_ring_t *r)
{
  u64 tail = r->tail;
  u64 head = __atomic_load_n (&r->head, __ATOMIC_ACQUIRE);
  if (tail == head)
    return 0;
  return &r->records[tail & PCAP_STREAM_RING_MASK];
}

static_always_inline void
pcap_stream_ring_advance (pcap_stream_ring_t *r)
{
  __atomic_store_n (&r->tail, r->tail + 1, __ATOMIC_RELEASE);
}

/* --- drain.c --- */

/* Set up the control socket listener and the drain process. Called
 * once at plugin init. */
clib_error_t *pcap_stream_drain_init (vlib_main_t *vm);

/* Wake the drain process — used after a session ring has had data
 * appended, or when a new client connects. */
void pcap_stream_drain_wake (void);

/* --- node.c (task #3) --- */

void pcap_stream_node_enable_iface (u32 sw_if_index, u8 direction,
				    int enable);

/* --- drop.c (task #4) --- */

void pcap_stream_drop_enable (int enable);

/* --- shared utility --- */

/* libpcap savefile header. Written once at the start of every
 * data-socket stream. Layout per the de-facto pcap format. */
typedef struct
{
  u32 magic;	   /* 0xa1b2c3d4 = us, 0xa1b23c4d = ns */
  u16 version_major;
  u16 version_minor;
  i32 thiszone;
  u32 sigfigs;
  u32 snaplen;
  u32 network;	   /* DLT — 1 = EN10MB */
} pcap_stream_file_header_t;

#define PCAP_STREAM_MAGIC_NS 0xa1b23c4d

typedef struct
{
  u32 ts_sec;
  u32 ts_nsec;
  u32 incl_len;	   /* bytes in this record */
  u32 orig_len;	   /* on-the-wire length */
} pcap_stream_pkt_header_t;

#endif /* __included_pcap_stream_h__ */
