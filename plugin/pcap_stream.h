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

#include "pcap_filter.h"

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
 * Was 1024 originally — combined with a fixed 64KB inline payload
 * per record, that meant ~64MB per ring per worker. With multiple
 * workers and a couple of sessions we exhausted VPP's heap and
 * crashed (clib_mem_alloc_aligned → os_panic). 256 is plenty for
 * operator-rate debugging; the drain runs every 1ms so we can
 * absorb 256 packets between drains, well above the per-session
 * stream rate the Unix socket can sustain. */
#define PCAP_STREAM_RING_LOG2_SIZE 8
#define PCAP_STREAM_RING_SIZE	  (1u << PCAP_STREAM_RING_LOG2_SIZE)
#define PCAP_STREAM_RING_MASK	  (PCAP_STREAM_RING_SIZE - 1)

/* Per-record max captured bytes. Records are *variable*-size — the
 * payload buffer is allocated at session-create from the actual
 * operator-requested snaplen, not this ceiling. This is a hard
 * upper bound that bounds a single session's memory footprint
 * even if the operator asks for something silly. 65535 is the
 * libpcap savefile snaplen ceiling, so clipping here is no UX
 * loss. */
#define PCAP_STREAM_MAX_SNAPLEN 65535

/* Default cap when the operator doesn't override. CLI default is
 * "full packet" (262144) which gets clamped here. 4096 covers the
 * 99% case (DNS payload, BGP UPDATE, OSPF LSA) without burning
 * memory. Operator can request more via `-s <bytes>`. */
#define PCAP_STREAM_DEFAULT_SNAPLEN 4096

/* Direction filter — what the operator's `-d` argument selects. */
typedef enum
{
  PCAP_STREAM_DIR_RX = 1 << 0,
  PCAP_STREAM_DIR_TX = 1 << 1,
  PCAP_STREAM_DIR_DROP = 1 << 2,
  PCAP_STREAM_DIR_ANY = PCAP_STREAM_DIR_RX | PCAP_STREAM_DIR_TX |
			PCAP_STREAM_DIR_DROP,
} pcap_stream_direction_t;

/* Captured-packet record header. The payload immediately follows
 * the header in memory, sized at session-create from the operator's
 * snaplen — see pcap_stream_record_data() to walk to it. `len` may
 * be < snaplen if the original packet was shorter; `orig_len` is
 * the on-the-wire length so the consumer can render the truncation
 * indicator.
 *
 * `reason[]` is non-empty only for drop-mode captures — carries the
 * encoded drop reason (e.g. "ip6-input.no-route") which the drain
 * attaches to the EPB as a pcap-ng comment option. 64 bytes covers
 * every drop reason vlib emits today. Empty string for rx/tx
 * captures. */
typedef struct
{
  u64 ts_ns;	      /* CLOCK_REALTIME in ns */
  u32 sw_if_index;    /* original VLIB_RX/TX iface */
  u32 orig_len;	      /* full packet length pre-snap */
  u32 len;	      /* bytes actually copied */
  u8 direction;	      /* pcap_stream_direction_t single bit */
  u8 _pad[3];
  char reason[64];    /* drop reason for DIR_DROP; empty otherwise */
  /* u8 payload[snaplen] follows immediately — access via
   * pcap_stream_record_data(). */
} pcap_stream_record_hdr_t;

/* SPSC ring — one writer (a single VPP worker), one reader (the
 * main thread drain). head/tail are monotonically increasing
 * 64-bit counters; modulo masks them at access time.
 *
 * Records are variable-stride: `record_stride` = sizeof(hdr) +
 * snaplen, set at session-create. The records buffer follows the
 * ring struct in memory (flexible array member) so the entire
 * thing is one allocation. */
typedef struct
{
  u32 record_stride; /* hdr + snaplen, bytes per slot */
  u32 _pad0;

  CLIB_CACHE_LINE_ALIGN_MARK (head_pad);
  volatile u64 head; /* next slot the writer will fill */

  CLIB_CACHE_LINE_ALIGN_MARK (tail_pad);
  volatile u64 tail; /* next slot the reader will consume */

  CLIB_CACHE_LINE_ALIGN_MARK (data_pad);
  u8 records[]; /* PCAP_STREAM_RING_SIZE * record_stride bytes */
} pcap_stream_ring_t;

static_always_inline pcap_stream_record_hdr_t *
pcap_stream_record_at (pcap_stream_ring_t *r, u64 seq)
{
  return (pcap_stream_record_hdr_t *) (r->records +
				       (seq & PCAP_STREAM_RING_MASK) *
					   r->record_stride);
}

static_always_inline u8 *
pcap_stream_record_data (pcap_stream_record_hdr_t *rec)
{
  return (u8 *) (rec + 1);
}

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
   * one program compiled against DLT_EN10MB (for pre-strip RX/TX
   * captures where the ethernet header is intact) and one against
   * DLT_RAW (for the drop tap, where the buffer's current_data
   * may have advanced past L2). NULL if no filter expression. */
  pcap_filter_t *bpf_eth;
  pcap_filter_t *bpf_raw;
  char *filter_expr;	  /* operator's original string */

  /* Per-worker rings. Indexed by vlib_thread_index — vec length
   * equals total threads (main + workers). Worker writes; main
   * thread drains. */
  pcap_stream_ring_t **rings;	   /* vec[nthreads] */

  /* Data socket — main-thread end. The CLI connects, we write
   * pcap-ng SHB + IDBs at session start, then EPB per matched
   * packet. ~0 until CLI connects. */
  u32 data_file_index;	   /* clib_file_add return; ~0 = unset */
  int data_fd;
  u8 pcap_header_sent;

  /* pcap-ng interface map. iface_id_to_sw is the IDB sequence we
   * sent (vec[iface_id] = sw_if_index); sw_to_iface_id is the
   * reverse for fast O(1) lookup at drain time
   * (vec[sw_if_index] = iface_id, ~0 means "no IDB sent for this
   * interface — packet dropped from output rather than emitted
   * with a bad ID"). Built once at session start from the
   * snapshot of vnm->interface_main.sw_interfaces. */
  u32 *iface_id_to_sw;
  u32 *sw_to_iface_id;

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
  u32 file_index;     /* ~0 if the fd has been handed off to a session */
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
  u32 control_listen_file_index;
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

/* Allocate a ring sized for the operator's snaplen. Returns NULL
 * on alloc failure (caller must handle gracefully — don't panic
 * VPP). */
pcap_stream_ring_t *pcap_stream_ring_alloc (u32 snaplen);
void pcap_stream_ring_free (pcap_stream_ring_t *r);

/* Producer — return pointer to the next writable record, or NULL
 * if the ring is full. Caller fills the record then calls commit.
 * Single-writer per ring; no atomics on head besides the release-
 * store at commit time. */
static_always_inline pcap_stream_record_hdr_t *
pcap_stream_ring_reserve (pcap_stream_ring_t *r)
{
  u64 head = r->head;
  u64 tail = __atomic_load_n (&r->tail, __ATOMIC_ACQUIRE);
  if (head - tail >= PCAP_STREAM_RING_SIZE)
    return 0;
  return pcap_stream_record_at (r, head);
}

static_always_inline void
pcap_stream_ring_commit (pcap_stream_ring_t *r)
{
  __atomic_store_n (&r->head, r->head + 1, __ATOMIC_RELEASE);
}

/* Consumer — main thread. Returns pointer to next-readable record
 * or NULL if empty. Caller copies out then calls advance. */
static_always_inline pcap_stream_record_hdr_t *
pcap_stream_ring_peek (pcap_stream_ring_t *r)
{
  u64 tail = r->tail;
  u64 head = __atomic_load_n (&r->head, __ATOMIC_ACQUIRE);
  if (tail == head)
    return 0;
  return pcap_stream_record_at (r, tail);
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
void pcap_stream_node_enable_all (u8 direction, int enable);

/* --- drop.c (task #4) --- */

void pcap_stream_drop_enable (int enable);

/* --- pcap-ng wire format --- */

/* Block types (RFC draft-tuexen-opsawg-pcapng-02 / current
 * pcap-ng spec). We only emit SHB, IDB, and EPB. */
#define PCAPNG_BT_SHB 0x0a0d0d0a
#define PCAPNG_BT_IDB 0x00000001
#define PCAPNG_BT_EPB 0x00000006

#define PCAPNG_SHB_BYTE_ORDER_MAGIC 0x1a2b3c4d
#define PCAPNG_VERSION_MAJOR 1
#define PCAPNG_VERSION_MINOR 0

/* Option codes */
#define PCAPNG_OPT_COMMENT 1 /* free-form comment string */
#define PCAPNG_OPT_ENDOFOPT 0
#define PCAPNG_IDB_OPT_NAME 2 /* if_name string */
#define PCAPNG_IDB_OPT_TSRESOL 9 /* timestamp resolution */
#define PCAPNG_EPB_OPT_FLAGS 2 /* direction + reception type */

/* EPB flags: bits 0-1 = direction, 1=in, 2=out */
#define PCAPNG_EPB_FLAGS_IN  0x00000001
#define PCAPNG_EPB_FLAGS_OUT 0x00000002

/* Emit pcap-ng prelude (SHB + one IDB per interface) on the
 * session's data fd. Builds s->iface_id_to_sw / sw_to_iface_id
 * tables. Returns 0 on success, -1 if any write fails. */
int pcap_stream_pcapng_emit_prelude (pcap_stream_session_t *s,
				     vnet_main_t *vnm);

/* Emit one EPB. Header + packet bytes + options + trailer go out
 * atomically via sendmsg. iface_id is looked up from
 * s->sw_to_iface_id; if not present, the EPB is skipped (caller
 * decides to drop or fall back). `comment` is optional; when
 * non-NULL and non-empty, attached as an opt_comment EPB option
 * and surfaces in tcpdump/Wireshark output (used to carry the drop
 * reason for `-d drop` mode captures). */
int pcap_stream_pcapng_emit_epb (pcap_stream_session_t *s, u32 sw_if_index,
				 u8 direction, u64 ts_ns, u32 caplen,
				 u32 orig_len, const u8 *pkt,
				 const char *comment);

#endif /* __included_pcap_stream_h__ */
