/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 */

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
#include <vlib/unix/unix.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
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
  psm->control_listen_file = clib_file_add (&file_main, &t);

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

      clib_file_t t = { 0 };
      t.read_function = control_client_read;
      t.error_function = control_client_error;
      t.file_descriptor = cfd;
      t.private_data = c - psm->control_clients;
      t.description = format (0, "pcap-stream client fd=%d", cfd);
      c->file = clib_file_add (&file_main, &t);
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
  if (c->file)
    {
      clib_file_del (&file_main, c->file);
      c->file = 0;
    }
  if (c->fd >= 0)
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
	  /* Take this fd off the control-client read path; it's now
	   * owned by the session's data_file. */
	  if (c->file)
	    {
	      clib_file_del (&file_main, c->file);
	      c->file = 0;
	    }
	  /* Don't close the fd — the session owns it now. */
	  c->fd = -1;
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

/* Returns pointer to value (mutated in-place — quotes stripped) or
 * NULL if the key isn't present. Caller does not free. */
static char *
arg_get (char *line, const char *key)
{
  size_t klen = strlen (key);
  char *p = line;
  while (*p)
    {
      while (*p == ' ' || *p == '\t')
	p++;
      char *kstart = p;
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
      char *vstart;
      char *vend;
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
	  *vend = 0;
	  return vstart;
	}
    }
  return 0;
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
      const char *iface_name = arg_get (rest, "iface");
      const char *dir_str = arg_get (rest, "dir");
      const char *snap_str = arg_get (rest, "snaplen");
      const char *max_str = arg_get (rest, "max");
      const char *filter_expr = arg_get (rest, "filter");

      u32 sw_if_index = ~0;
      if (iface_name && strcmp (iface_name, "any") != 0)
	{
	  vnet_main_t *vnm = psm->vnet_main;
	  vnet_sw_interface_t *si;
	  uword *p = hash_get_mem (vnm->interface_main.hw_interface_by_name,
				   iface_name);
	  if (!p)
	    {
	      respond (c, "error reason=unknown_interface name=%s", iface_name);
	      return 0;
	    }
	  vnet_hw_interface_t *hi =
	      vnet_get_hw_interface (vnm, p[0]);
	  si = vnet_get_sw_interface (vnm, hi->sw_if_index);
	  sw_if_index = si->sw_if_index;
	}

      u8 direction = parse_direction (dir_str);
      u32 snaplen =
	  snap_str ? (u32) strtoul (snap_str, 0, 10) : PCAP_STREAM_MAX_SNAPLEN;
      u64 max_packets = max_str ? strtoull (max_str, 0, 10) : 0;

      char *err = 0;
      pcap_stream_session_t *s = pcap_stream_session_create (
	  filter_expr ? filter_expr : "", sw_if_index, direction, snaplen,
	  max_packets, &err);
      if (!s)
	{
	  respond (c, "error reason=%s", err ? err : "create_failed");
	  if (err)
	    free (err);
	  return 0;
	}

      respond (c, "ok id=%u", s->session_id);

      /* Take ownership of the fd, send pcap file header, register
       * for write-error tracking. */
      s->data_fd = c->fd;
      clib_file_t t = { 0 };
      t.error_function = data_socket_error;
      t.file_descriptor = c->fd;
      t.private_data = s->session_id;
      t.description = format (0, "pcap-stream data session=%u", s->session_id);
      s->data_file = clib_file_add (&file_main, &t);
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
      const char *id_str = arg_get (rest, "id");
      if (!id_str)
	{
	  respond (c, "error reason=missing_id");
	  return 0;
	}
      pcap_stream_session_t *s = session_lookup (strtoul (id_str, 0, 10));
      if (!s)
	{
	  respond (c, "error reason=no_such_session");
	  return 0;
	}
      u64 cap = s->captured, drp = s->dropped;
      pcap_stream_session_destroy (s);
      respond (c, "ok captured=%llu dropped=%llu", cap, drp);
      return 0;
    }

  if (!strcmp (verb, "inject"))
    {
      /* Test verb: push raw hex bytes through every active session
       * as if they arrived from the dataplane. Used by task #6's
       * integration test to validate the ring + drain + socket path
       * without standing up the real feature-arc node. */
      const char *hex = arg_get (rest, "hex");
      if (!hex)
	{
	  respond (c, "error reason=missing_hex");
	  return 0;
	}
      size_t hl = strlen (hex);
      if (hl == 0 || (hl & 1))
	{
	  respond (c, "error reason=bad_hex");
	  return 0;
	}
      size_t pl = hl / 2;
      if (pl > PCAP_STREAM_MAX_SNAPLEN)
	{
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
	  if (s->bpf_compiled)
	    {
	      struct pcap_pkthdr ph = {
		.caplen = pl,
		.len = pl,
	      };
	      if (!pcap_offline_filter (&s->bpf_eth, &ph, payload))
		continue;
	    }
	  pcap_stream_ring_t *r = s->rings[0]; /* main thread */
	  pcap_stream_record_t *rec = pcap_stream_ring_reserve (r);
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
	  clib_memcpy_fast (rec->data, payload, rec->len);
	  pcap_stream_ring_commit (r);
	  injected++;
	}
      clib_mem_free (payload);
      pcap_stream_drain_wake ();
      respond (c, "ok injected=%u", injected);
      return 0;
    }

  if (!strcmp (verb, "stats"))
    {
      const char *id_str = arg_get (rest, "id");
      if (!id_str)
	{
	  respond (c, "error reason=missing_id");
	  return 0;
	}
      pcap_stream_session_t *s = session_lookup (strtoul (id_str, 0, 10));
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

/* --- pcap framing --- */

static void
send_pcap_file_header (pcap_stream_session_t *s)
{
  pcap_stream_file_header_t h = {
    .magic = PCAP_STREAM_MAGIC_NS,
    .version_major = 2,
    .version_minor = 4,
    .thiszone = 0,
    .sigfigs = 0,
    .snaplen = s->snaplen,
    .network = 1, /* DLT_EN10MB */
  };
  write_all (s->data_fd, &h, sizeof (h));
  s->pcap_header_sent = 1;
}

/* On data-socket EOF/error: tear the session down. */
static clib_error_t *
data_socket_error (clib_file_t *uf)
{
  u32 sid = uf->private_data;
  pcap_stream_session_t *s = session_lookup (sid);
  if (s)
    pcap_stream_session_destroy (s);
  return 0;
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
	  pcap_stream_record_t *rec = pcap_stream_ring_peek (r);
	  if (!rec)
	    break;

	  pcap_stream_pkt_header_t h = {
	    .ts_sec = (u32) (rec->ts_ns / 1000000000ULL),
	    .ts_nsec = (u32) (rec->ts_ns % 1000000000ULL),
	    .incl_len = rec->len,
	    .orig_len = rec->orig_len,
	  };

	  /* Two writes (header + payload). On EAGAIN we leave the
	   * record in the ring and try again next tick. We must not
	   * advance until both writes succeed atomically — but with
	   * MSG_DONTWAIT a partial header write would corrupt the
	   * pcap stream, so we use blocking writes here. The CLI
	   * consumer is supposed to be a fast pipe; a stalled CLI
	   * just slows the worker via ring backpressure (drops). */
	  ssize_t n1 = send (s->data_fd, &h, sizeof (h), MSG_NOSIGNAL);
	  if (n1 != (ssize_t) sizeof (h))
	    {
	      /* Connection broken — destroy session. */
	      pcap_stream_session_destroy (s);
	      return;
	    }
	  ssize_t n2 = send (s->data_fd, rec->data, rec->len, MSG_NOSIGNAL);
	  if (n2 != (ssize_t) rec->len)
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
