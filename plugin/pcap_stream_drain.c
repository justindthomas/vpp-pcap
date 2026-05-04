/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 */

/* Need _GNU_SOURCE for accept4(). VPP's build doesn't define it
 * by default for plugin TUs. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* pcap_stream_drain.c — control socket + main-thread drain process.
 *
 * Wire protocol (text, line-delimited, one message per request):
 *
 *   create iface=NAME dir=any|rx|tx|drop snaplen=N max=N filter='EXPR'
 *     -> ok id=N (then connection becomes pcap data stream:
 *        pcap_file_header + pcap_record per matched packet)
 *
 *   list           -> ok sessions=N then one `session id=...` line per
 *   delete id=N    -> ok captured=N dropped=N
 *   stats  id=N    -> ok captured=N dropped=N since=secs
 *
 *   error reason=...   on any failure
 *
 * A connection is in MANAGEMENT mode by default; a successful
 * `create` flips it into STREAMING mode and no further requests are
 * read on that fd. Closing the fd tears the session down.
 */

#include <pcap_stream/pcap_stream.h>
#include <vppinfra/file.h>
#include <vlib/file.h>
#include <vlib/unix/unix.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#define DRAIN_TICK_INTERVAL 0.001 /* 1ms */
#define DRAIN_WAKE_EVENT    1

static uword pcap_stream_drain_process (vlib_main_t *vm,
					vlib_node_runtime_t *rt,
					vlib_frame_t *f);

VLIB_REGISTER_NODE (pcap_stream_drain_node, static) = {
  .function = pcap_stream_drain_process,
  .name = "pcap-stream-drain",
  .type = VLIB_NODE_TYPE_PROCESS,
};

/* Forward decls */
static clib_error_t *control_listen_read (clib_file_t *uf);
static clib_error_t *control_client_read (clib_file_t *uf);
static clib_error_t *control_client_error (clib_file_t *uf);
static clib_error_t *data_socket_eof (clib_file_t *uf);
static clib_error_t *data_socket_error (clib_file_t *uf);
static void control_client_close (pcap_stream_control_client_t *c);
static void send_pcap_file_header (pcap_stream_session_t *s);
static int parse_and_dispatch (pcap_stream_control_client_t *c, char *line);

/* --- init --- */

static int
control_listen_setup (pcap_stream_main_t *psm)
{
  struct sockaddr_un addr;
  int fd;

  /* Best-effort unlink any stale socket from a prior crash. */
  unlink (psm->control_socket_path);

  fd = socket (AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0)
    {
      clib_warning ("pcap_stream: socket() failed: %s", strerror (errno));
      return -1;
    }

  clib_memset (&addr, 0, sizeof (addr));
  addr.sun_family = AF_UNIX;
  strncpy (addr.sun_path, psm->control_socket_path,
	   sizeof (addr.sun_path) - 1);

  if (bind (fd, (struct sockaddr *) &addr, sizeof (addr)) < 0)
    {
      clib_warning ("pcap_stream: bind(%s) failed: %s",
		    psm->control_socket_path, strerror (errno));
      close (fd);
      return -1;
    }
  if (listen (fd, 16) < 0)
    {
      clib_warning ("pcap_stream: listen() failed: %s", strerror (errno));
      close (fd);
      return -1;
    }
  /* World-writable so unprivileged operators can talk to it; same
   * model as `vppctl`'s socket. Tighten via the socket-path option
   * if the deployment cares. */
  chmod (psm->control_socket_path, 0666);

  psm->control_listen_fd = fd;

  clib_file_t t = { 0 };
  t.read_function = control_listen_read;
  t.file_descriptor = fd;
  t.description = format (0, "pcap-stream control listener");
  psm->control_listen_file_index = clib_file_add (&file_main, &t);

  clib_warning ("pcap_stream: listening on %s", psm->control_socket_path);
  return 0;
}

clib_error_t *
pcap_stream_drain_init (vlib_main_t *vm)
{
  pcap_stream_main_t *psm = &pcap_stream_main;

  if (control_listen_setup (psm) < 0)
    return clib_error_return (0, "control socket setup failed");

  /* Cache the drain process node index so worker threads can wake
   * us by signalling an event. */
  vlib_node_t *n = vlib_get_node_by_name (vm, (u8 *) "pcap-stream-drain");
  psm->drain_process_node_index = n->index;

  return 0;
}

void
pcap_stream_drain_wake (void)
{
  pcap_stream_main_t *psm = &pcap_stream_main;
  vlib_process_signal_event_mt (psm->vlib_main,
				psm->drain_process_node_index,
				DRAIN_WAKE_EVENT, 0);
}

/* --- listener: accept + register new client --- */

static clib_error_t *
control_listen_read (clib_file_t *uf)
{
  pcap_stream_main_t *psm = &pcap_stream_main;
  int cfd;

  for (;;)
    {
      cfd = accept4 (uf->file_descriptor, 0, 0,
		     SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (cfd < 0)
	{
	  if (errno == EAGAIN || errno == EWOULDBLOCK)
	    return 0;
	  clib_warning ("pcap_stream: accept() failed: %s", strerror (errno));
	  return 0;
	}

      pcap_stream_control_client_t *c;
      pool_get_zero (psm->control_clients, c);
      c->fd = cfd;
      c->file_index = ~0;

      clib_file_t t = { 0 };
      t.read_function = control_client_read;
      t.error_function = control_client_error;
      t.file_descriptor = cfd;
      t.private_data = c - psm->control_clients;
      t.description = format (0, "pcap-stream client fd=%d", cfd);
      c->file_index = clib_file_add (&file_main, &t);
    }
}

static void
control_client_close (pcap_stream_control_client_t *c)
{
  pcap_stream_main_t *psm = &pcap_stream_main;

  if (!c)
    return;

  /* If this client owns a session via streaming mode, the session's
   * data_file shares the fd with c->file. Closing the data_file
   * closes the fd; we must not double-close. The session destroy
   * path detects this by clearing data_file/data_fd before
   * returning here. */
  /* Same double-close avoidance as session_destroy — clib_file_del
   * closes the fd, don't close again. */
  if (c->file_index != ~0u)
    {
      clib_file_del_by_index (&file_main, c->file_index);
      c->file_index = ~0;
      c->fd = -1;
    }
  else if (c->fd >= 0)
    {
      close (c->fd);
      c->fd = -1;
    }
  vec_free (c->rx_buf);
  pool_put (psm->control_clients, c);
}

static clib_error_t *
control_client_error (clib_file_t *uf)
{
  pcap_stream_main_t *psm = &pcap_stream_main;
  pcap_stream_control_client_t *c =
      pool_elt_at_index (psm->control_clients, uf->private_data);
  control_client_close (c);
  return 0;
}

/* --- client read: accumulate to '\n', then dispatch --- */

static clib_error_t *
control_client_read (clib_file_t *uf)
{
  pcap_stream_main_t *psm = &pcap_stream_main;
  pcap_stream_control_client_t *c =
      pool_elt_at_index (psm->control_clients, uf->private_data);
  u8 buf[4096];
  ssize_t n;

  for (;;)
    {
      n = read (c->fd, buf, sizeof (buf));
      if (n > 0)
	{
	  vec_add (c->rx_buf, buf, n);
	  /* Cap accumulated buffer to avoid unbounded growth on a
	   * misbehaving client. 64KB is plenty for one filter. */
	  if (vec_len (c->rx_buf) > 65536)
	    {
	      control_client_close (c);
	      return 0;
	    }
	}
      else if (n == 0)
	{
	  /* EOF — peer closed. */
	  control_client_close (c);
	  return 0;
	}
      else
	{
	  if (errno == EAGAIN || errno == EWOULDBLOCK)
	    break;
	  control_client_close (c);
	  return 0;
	}
    }

  /* Process complete lines. */
  while (1)
    {
      u8 *nl = 0;
      for (u32 i = 0; i < vec_len (c->rx_buf); i++)
	if (c->rx_buf[i] == '\n')
	  {
	    nl = &c->rx_buf[i];
	    break;
	  }
      if (!nl)
	break;

      *nl = 0;
      /* parse_and_dispatch returns 1 if the connection has flipped
       * to streaming mode (no more reads expected). */
      int streaming = parse_and_dispatch (c, (char *) c->rx_buf);
      vec_delete (c->rx_buf, (nl - c->rx_buf) + 1, 0);

      if (streaming)
	{
	  /* Tear down the control-client handle. The session has its
	   * own dup'd fd for the data path, so this clib_file_del
	   * closing c->fd is fine (and necessary — otherwise we
	   * leak the kernel-side accept fd). */
	  if (c->file_index != ~0u)
	    {
	      clib_file_del_by_index (&file_main, c->file_index);
	      c->file_index = ~0;
	      c->fd = -1;
	    }
	  vec_free (c->rx_buf);
	  pool_put (psm->control_clients, c);
	  return 0;
	}
    }
  return 0;
}

/* --- response helpers --- */

static void
write_all (int fd, const void *buf, size_t len)
{
  /* Best-effort blocking write for small control messages. The fd
   * is non-blocking, so we loop on EAGAIN with a tiny spin. For
   * the ~100-byte control responses this is plenty. */
  const u8 *p = buf;
  size_t left = len;
  while (left)
    {
      ssize_t n = write (fd, p, left);
      if (n > 0)
	{
	  p += n;
	  left -= n;
	}
      else if (n < 0 && (errno == EAGAIN || errno == EINTR))
	{
	  continue;
	}
      else
	return;
    }
}

static void
respond (pcap_stream_control_client_t *c, const char *fmt, ...)
{
  va_list ap;
  u8 *line = 0;
  va_start (ap, fmt);
  line = va_format (line, fmt, &ap);
  va_end (ap);
  vec_add1 (line, '\n');
  write_all (c->fd, line, vec_len (line));
  vec_free (line);
}

/* --- minimal arg parser for "key=value key='quoted value' ..." --- */

/* Returns a freshly malloc'd copy of the value for `key`, or NULL
 * if the key isn't present. Caller MUST free.
 *
 * This used to mutate the input string by null-terminating at the
 * value's end and returning an interior pointer, but that broke
 * subsequent arg_get calls — they hit the embedded null and
 * stopped scanning. Always allocating a new string is the simple
 * correct fix; control messages are tiny and infrequent so the
 * malloc cost is irrelevant. */
static char *
arg_get (const char *line, const char *key)
{
  size_t klen = strlen (key);
  const char *p = line;
  while (*p)
    {
      while (*p == ' ' || *p == '\t')
	p++;
      const char *kstart = p;
      while (*p && *p != '=' && *p != ' ' && *p != '\t')
	p++;
      size_t kl = p - kstart;
      if (*p != '=')
	{
	  while (*p && *p != ' ' && *p != '\t')
	    p++;
	  continue;
	}
      p++; /* skip = */
      const char *vstart;
      const char *vend;
      if (*p == '\'' || *p == '"')
	{
	  char quote = *p++;
	  vstart = p;
	  while (*p && *p != quote)
	    p++;
	  vend = p;
	  if (*p == quote)
	    p++;
	}
      else
	{
	  vstart = p;
	  while (*p && *p != ' ' && *p != '\t')
	    p++;
	  vend = p;
	}
      if (kl == klen && memcmp (kstart, key, klen) == 0)
	{
	  size_t vl = vend - vstart;
	  char *out = malloc (vl + 1);
	  if (!out)
	    return NULL;
	  memcpy (out, vstart, vl);
	  out[vl] = 0;
	  return out;
	}
    }
  return NULL;
}

/* --- dispatch --- */

static pcap_stream_session_t *
session_lookup (u32 id)
{
  pcap_stream_main_t *psm = &pcap_stream_main;
  for (u32 i = 0; i < PCAP_STREAM_MAX_SESSIONS; i++)
    if (psm->sessions[i].active && psm->sessions[i].session_id == id)
      return &psm->sessions[i];
  return 0;
}

static u8
parse_direction (const char *s)
{
  if (!s)
    return PCAP_STREAM_DIR_ANY;
  if (!strcmp (s, "rx"))
    return PCAP_STREAM_DIR_RX;
  if (!strcmp (s, "tx"))
    return PCAP_STREAM_DIR_TX;
  if (!strcmp (s, "drop"))
    return PCAP_STREAM_DIR_DROP;
  return PCAP_STREAM_DIR_ANY;
}

static int
parse_and_dispatch (pcap_stream_control_client_t *c, char *line)
{
  pcap_stream_main_t *psm = &pcap_stream_main;

  /* Skip leading whitespace, capture verb. */
  while (*line == ' ' || *line == '\t')
    line++;
  char *verb = line;
  char *rest = line;
  while (*rest && *rest != ' ' && *rest != '\t')
    rest++;
  if (*rest)
    {
      *rest = 0;
      rest++;
    }

  if (!strcmp (verb, "create"))
    {
      char *iface_name = arg_get (rest, "iface");
      char *dir_str = arg_get (rest, "dir");
      char *snap_str = arg_get (rest, "snaplen");
      char *max_str = arg_get (rest, "max");
      char *filter_expr = arg_get (rest, "filter");

      u32 sw_if_index = ~0;
      if (iface_name && strcmp (iface_name, "any") != 0)
	{
	  /* Use unformat_vnet_sw_interface so we accept ALL interface
	   * kinds: hardware, sub-interfaces (lan.110), loop, BVI,
	   * tap, etc. The hw_interface_by_name hash only catches
	   * hardware interfaces and misses sub-ifs. */
	  vnet_main_t *vnm = psm->vnet_main;
	  unformat_input_t in;
	  unformat_init_string (&in, iface_name, strlen (iface_name));
	  if (!unformat (&in, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	    {
	      unformat_free (&in);
	      respond (c, "error reason=unknown_interface name=%s",
		       iface_name);
	      free (iface_name); free (dir_str); free (snap_str);
	      free (max_str); free (filter_expr);
	      return 0;
	    }
	  unformat_free (&in);
	}

      u8 direction = parse_direction (dir_str);
      u32 snaplen =
	  snap_str ? (u32) strtoul (snap_str, 0, 10) : PCAP_STREAM_MAX_SNAPLEN;
      u64 max_packets = max_str ? strtoull (max_str, 0, 10) : 0;

      char *err = 0;
      pcap_stream_session_t *s = pcap_stream_session_create (
	  filter_expr ? filter_expr : "", sw_if_index, direction, snaplen,
	  max_packets, &err);
      free (iface_name); free (dir_str); free (snap_str); free (max_str);
      free (filter_expr);
      if (!s)
	{
	  respond (c, "error reason=%s", err ? err : "create_failed");
	  if (err)
	    free (err);
	  return 0;
	}

      respond (c, "ok id=%u", s->session_id);

      /* Dup the fd so the data session has its own. The control
       * client's clib_file_del (in the streaming-mode handoff
       * below) will close c->fd; we don't want that to also close
       * what the data session is reading from. With dup, both
       * clib_file_del calls (control client, then session
       * destroy) close their own fd cleanly with no race against
       * fd reuse. */
      int dup_fd = dup (c->fd);
      if (dup_fd < 0)
	{
	  respond (c, "error reason=dup_failed");
	  pcap_stream_session_destroy (s);
	  return 0;
	}
      s->data_fd = dup_fd;
      /* Force the data socket BLOCKING (the dup inherits O_NONBLOCK
       * from the accept). Two reasons:
       *
       * 1) writev() of header+payload must be atomic on the wire so
       *    tcpdump and friends never see a per-packet header
       *    without its bytes following — non-blocking would split.
       *
       * 2) When the consumer can't keep up (e.g. tcpdump -A -vvv at
       *    1500-byte packets is CPU-bound), backpressure should
       *    accumulate as drops on the per-worker ring, not as
       *    truncated pcap streams.
       *
       * The cost is that a slow consumer can briefly stall the
       * vlib_process drain — bounded by the kernel socket buffer
       * and our drain tick, both fast. */
      int flags = fcntl (dup_fd, F_GETFL, 0);
      if (flags >= 0)
	(void) fcntl (dup_fd, F_SETFL, flags & ~O_NONBLOCK);
      clib_file_t t = { 0 };
      t.read_function = data_socket_eof;
      t.error_function = data_socket_error;
      t.file_descriptor = dup_fd;
      t.private_data = s->session_id;
      t.description = format (0, "pcap-stream data session=%u", s->session_id);
      s->data_file_index = clib_file_add (&file_main, &t);
      send_pcap_file_header (s);
      return 1; /* streaming */
    }

  if (!strcmp (verb, "list"))
    {
      u32 n = 0;
      for (u32 i = 0; i < PCAP_STREAM_MAX_SESSIONS; i++)
	if (psm->sessions[i].active)
	  n++;
      respond (c, "ok sessions=%u", n);
      for (u32 i = 0; i < PCAP_STREAM_MAX_SESSIONS; i++)
	{
	  pcap_stream_session_t *s = &psm->sessions[i];
	  if (!s->active)
	    continue;
	  respond (c,
		   "session id=%u dir=0x%x snaplen=%u captured=%llu "
		   "dropped=%llu filter=%s",
		   s->session_id, s->direction, s->snaplen, s->captured,
		   s->dropped, s->filter_expr);
	}
      return 0;
    }

  if (!strcmp (verb, "delete"))
    {
      char *id_str = arg_get (rest, "id");
      if (!id_str)
	{
	  respond (c, "error reason=missing_id");
	  return 0;
	}
      u32 id = strtoul (id_str, 0, 10);
      free (id_str);
      pcap_stream_session_t *s = session_lookup (id);
      if (!s)
	{
	  respond (c, "error reason=no_such_session");
	  return 0;
	}
      u64 cap = s->captured, drp = s->dropped;
      /* Respond BEFORE destroy — destroy may take a moment as it
       * tears down per-worker rings and the data socket, and we
       * don't want the response delayed past the client's read
       * timeout. */
      respond (c, "ok captured=%llu dropped=%llu", cap, drp);
      pcap_stream_session_destroy (s);
      return 0;
    }

  if (!strcmp (verb, "inject"))
    {
      /* Test verb: push raw hex bytes through every active session
       * as if they arrived from the dataplane. Used by task #6's
       * integration test to validate the ring + drain + socket path
       * without standing up the real feature-arc node. */
      char *hex = arg_get (rest, "hex");
      if (!hex)
	{
	  respond (c, "error reason=missing_hex");
	  return 0;
	}
      size_t hl = strlen (hex);
      if (hl == 0 || (hl & 1))
	{
	  free (hex);
	  respond (c, "error reason=bad_hex");
	  return 0;
	}
      size_t pl = hl / 2;
      if (pl > PCAP_STREAM_MAX_SNAPLEN)
	{
	  free (hex);
	  respond (c, "error reason=too_long");
	  return 0;
	}
      u8 *payload = clib_mem_alloc (pl);
      for (size_t i = 0; i < pl; i++)
	{
	  unsigned int b;
	  if (sscanf (hex + (i * 2), "%2x", &b) != 1)
	    {
	      clib_mem_free (payload);
	      respond (c, "error reason=bad_hex");
	      return 0;
	    }
	  payload[i] = (u8) b;
	}

      f64 now = vlib_time_now (psm->vlib_main);
      u64 ts_ns =
	  (u64) (now) * 1000000000ULL + (u64) ((now - (u64) now) * 1e9);
      u32 injected = 0;
      for (u32 i = 0; i < PCAP_STREAM_MAX_SESSIONS; i++)
	{
	  pcap_stream_session_t *s = &psm->sessions[i];
	  if (!s->active)
	    continue;
	  /* Filter against the ethernet program (DLT_EN10MB) — inject
	   * always assumes ethernet-framed input. */
	  if (!pcap_filter_run (s->bpf_eth, payload, pl, pl))
	    continue;
	  pcap_stream_ring_t *r = s->rings[0]; /* main thread */
	  pcap_stream_record_hdr_t *rec = pcap_stream_ring_reserve (r);
	  if (!rec)
	    {
	      __atomic_fetch_add (&s->dropped, 1, __ATOMIC_RELAXED);
	      continue;
	    }
	  rec->ts_ns = ts_ns;
	  rec->sw_if_index = ~0;
	  rec->orig_len = pl;
	  rec->len = pl < s->snaplen ? pl : s->snaplen;
	  rec->direction = PCAP_STREAM_DIR_RX;
	  clib_memcpy_fast (pcap_stream_record_data (rec), payload, rec->len);
	  pcap_stream_ring_commit (r);
	  injected++;
	}
      clib_mem_free (payload);
      free (hex);
      pcap_stream_drain_wake ();
      respond (c, "ok injected=%u", injected);
      return 0;
    }

  if (!strcmp (verb, "stats"))
    {
      char *id_str = arg_get (rest, "id");
      if (!id_str)
	{
	  respond (c, "error reason=missing_id");
	  return 0;
	}
      u32 id = strtoul (id_str, 0, 10);
      free (id_str);
      pcap_stream_session_t *s = session_lookup (id);
      if (!s)
	{
	  respond (c, "error reason=no_such_session");
	  return 0;
	}
      f64 since = vlib_time_now (psm->vlib_main) - s->created_at;
      respond (c, "ok captured=%llu dropped=%llu since=%.3f", s->captured,
	       s->dropped, since);
      return 0;
    }

  respond (c, "error reason=unknown_verb verb=%s", verb);
  return 0;
}

/* --- pcap-ng prelude --- */

static void
send_pcap_file_header (pcap_stream_session_t *s)
{
  /* Emit pcap-ng SHB followed by one IDB per HW/SUB interface.
   * On error we leave pcap_header_sent = 0 and the drain loop
   * skips this session — eventually the consumer will EOF and
   * we tear down. */
  pcap_stream_main_t *psm = &pcap_stream_main;
  if (pcap_stream_pcapng_emit_prelude (s, psm->vnet_main) == 0)
    s->pcap_header_sent = 1;
}

/* On data-socket EOF/error: tear the session down.
 *
 * We register both read_function and error_function on the data
 * socket. The read_function is needed because VPP's epoll wiring
 * only watches an fd for EPOLLIN events when read_function is set
 * — without it, a client disconnect never triggers our cleanup
 * and the orphaned fd hangs around until the kernel reuses its
 * number for a new accept(), which then races against
 * session_destroy's clib_file_del. Detecting the EOF eagerly
 * avoids that.
 *
 * The CLI never actually sends bytes on the data socket — it's
 * one-way pcap from server to client — so the only thing read()
 * ever returns here is 0 (EOF) or -1 (broken pipe). Both mean
 * "tear down". */
static clib_error_t *
data_socket_eof (clib_file_t *uf)
{
  /* Drain any pending bytes from the socket. The CLI doesn't send
   * data, so the only thing we ever see is EOF (read returns 0)
   * or EAGAIN. EAGAIN means epoll fired spuriously (or there were
   * a few stray bytes from a busted client); just return and let
   * the next event re-trigger us. */
  u32 sid = uf->private_data;
  u8 buf[256];
  ssize_t n = read (uf->file_descriptor, buf, sizeof (buf));
  if (n > 0)
    {
      /* Unexpected — protocol says client doesn't write. Discard
       * and continue. */
      clib_warning (
	  "pcap_stream: %zd unexpected bytes from data-socket consumer for "
	  "session %u (discarded)",
	  n, sid);
      return 0;
    }
  if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK))
    {
      pcap_stream_session_t *s = session_lookup (sid);
      if (s)
	pcap_stream_session_destroy (s);
    }
  return 0;
}

static clib_error_t *
data_socket_error (clib_file_t *uf)
{
  return data_socket_eof (uf);
}

/* --- per-tick drain: ring -> data fd --- */

static void
drain_one_session (pcap_stream_session_t *s)
{
  if (!s->active || s->data_fd < 0 || !s->pcap_header_sent)
    return;

  for (u32 wi = 0; wi < vec_len (s->rings); wi++)
    {
      pcap_stream_ring_t *r = s->rings[wi];
      if (!r)
	continue;

      while (1)
	{
	  pcap_stream_record_hdr_t *rec = pcap_stream_ring_peek (r);
	  if (!rec)
	    break;

	  /* Emit one pcap-ng EPB tagged with the interface ID for
	   * rec->sw_if_index. The pcap-ng emitter handles atomic
	   * sendmsg + drop-on-no-IDB internally. EPIPE / short
	   * write tears down the session. */
	  if (pcap_stream_pcapng_emit_epb (s, rec->sw_if_index, rec->direction,
					   rec->ts_ns, rec->len, rec->orig_len,
					   pcap_stream_record_data (rec)) < 0)
	    {
	      pcap_stream_session_destroy (s);
	      return;
	    }
	  s->captured++;
	  pcap_stream_ring_advance (r);
	}
    }
}

static uword
pcap_stream_drain_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
			   vlib_frame_t *f)
{
  pcap_stream_main_t *psm = &pcap_stream_main;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, DRAIN_TICK_INTERVAL);
      uword *event_data = 0;
      vlib_process_get_events (vm, &event_data);
      vec_free (event_data);

      for (u32 i = 0; i < PCAP_STREAM_MAX_SESSIONS; i++)
	drain_one_session (&psm->sessions[i]);
    }
  return 0;
}
