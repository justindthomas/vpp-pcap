/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 */

/* pcap_stream_pcapng.c — pcap-ng wire format (SHB + IDBs + EPB).
 *
 * Pcap-ng was chosen over the classic pcap savefile format so the
 * stream can carry per-interface metadata: each Interface
 * Description Block declares one VPP interface (name, link layer,
 * timestamp resolution), and every Enhanced Packet Block tags its
 * bytes with the interface ID. tcpdump and Wireshark both consume
 * pcap-ng natively and print "lan.30 Out IP ..." style lines without
 * any post-processing. Direction (in/out) rides as an EPB option.
 *
 * Endianness: all multi-byte fields are emitted in HOST byte order.
 * The SHB's byte-order-magic field tells the consumer which it is;
 * little-endian (0x1a2b3c4d) on x86_64 is what every consumer
 * defaults to, so this is fine.
 *
 * Padding: every block's payload is 32-bit aligned; option values
 * are too. Block-total-length appears at both the start and the end
 * of each block to allow reverse traversal.
 */

#include <pcap_stream/pcap_stream.h>

#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>
#include <string.h>

/* Round x up to next multiple of 4 (32-bit alignment). */
#define PCAPNG_PAD4(x) (((x) + 3) & ~3u)

/* --- low-level send helpers --- */

/* Atomic-write a fully-formed buffer to the data fd. Loops on
 * EINTR; on EPIPE/short returns -1 so caller can tear down. */
static int
pcapng_write_all (int fd, const void *buf, size_t len)
{
  const u8 *p = buf;
  size_t left = len;
  while (left)
    {
      ssize_t n = send (fd, p, left, MSG_NOSIGNAL);
      if (n > 0)
	{
	  p += n;
	  left -= n;
	}
      else if (n < 0 && errno == EINTR)
	continue;
      else
	return -1;
    }
  return 0;
}

/* --- SHB --- */

static int
emit_shb (int fd)
{
  /* Section Header Block, no options. Total length = 28 bytes:
   *   block_type(4) + block_total_length(4) + magic(4) + version(4)
   *   + section_length(8) + block_total_length(4)
   */
  u8 buf[28];
  u32 *p = (u32 *) buf;
  *p++ = PCAPNG_BT_SHB;
  *p++ = 28;
  *p++ = PCAPNG_SHB_BYTE_ORDER_MAGIC;
  *p++ = ((u32) PCAPNG_VERSION_MAJOR) | ((u32) PCAPNG_VERSION_MINOR << 16);
  /* section_length = -1 (unknown) */
  *p++ = 0xffffffff;
  *p++ = 0xffffffff;
  *p++ = 28;
  return pcapng_write_all (fd, buf, sizeof (buf));
}

/* --- IDB --- */

/* Emit one IDB declaring an interface. link_type is the DLT
 * (1 = EN10MB). name is the operator-visible interface name, e.g.
 * "lan.30" or "bvi100". Returns 0 on success, -1 on write fail. */
static int
emit_idb (int fd, u32 link_type, u32 snaplen, const char *name)
{
  size_t name_len = name ? strlen (name) : 0;
  size_t name_padded = PCAPNG_PAD4 (name_len);

  /* Layout (all multiples of 4):
   *   header:        block_type(4) + total_len(4) = 8
   *   fixed body:    link_type(2)+reserved(2) + snaplen(4) = 8
   *   if_name opt:   code(2)+len(2) + name_padded
   *   tsresol opt:   code(2)+len(2) + 1byte+3pad = 8
   *   end opt:       code(2)+len(2) = 4
   *   trailer:       total_len(4) = 4
   */
  u32 total_len = 8 + 8 + 4 + (u32) name_padded + 8 + 4 + 4;

  u8 buf[256]; /* worst case interface name fits */
  if (total_len > sizeof (buf))
    return -1;

  u32 *hdr = (u32 *) buf;
  hdr[0] = PCAPNG_BT_IDB;
  hdr[1] = total_len;
  /* link_type (u16) + reserved (u16) */
  ((u16 *) (buf + 8))[0] = (u16) link_type;
  ((u16 *) (buf + 8))[1] = 0;
  ((u32 *) (buf + 12))[0] = snaplen;

  size_t off = 16;

  if (name_len > 0)
    {
      ((u16 *) (buf + off))[0] = PCAPNG_IDB_OPT_NAME;
      ((u16 *) (buf + off))[1] = (u16) name_len;
      off += 4;
      memcpy (buf + off, name, name_len);
      /* zero the padding bytes if any */
      if (name_padded > name_len)
	memset (buf + off + name_len, 0, name_padded - name_len);
      off += name_padded;
    }

  /* if_tsresol = 9 (nanoseconds, base-10). Length is 1, padded to 4. */
  ((u16 *) (buf + off))[0] = PCAPNG_IDB_OPT_TSRESOL;
  ((u16 *) (buf + off))[1] = 1;
  off += 4;
  buf[off] = 9;
  buf[off + 1] = 0;
  buf[off + 2] = 0;
  buf[off + 3] = 0;
  off += 4;

  /* end-of-options */
  ((u16 *) (buf + off))[0] = PCAPNG_OPT_ENDOFOPT;
  ((u16 *) (buf + off))[1] = 0;
  off += 4;

  /* trailing block_total_length */
  ((u32 *) (buf + off))[0] = total_len;
  off += 4;

  return pcapng_write_all (fd, buf, off);
}

/* --- prelude: SHB + walk-and-emit-IDB-per-interface --- */

int
pcap_stream_pcapng_emit_prelude (pcap_stream_session_t *s, vnet_main_t *vnm)
{
  if (emit_shb (s->data_fd) < 0)
    return -1;

  vnet_sw_interface_t *si;
  u32 next_iface_id = 0;

  /* Snapshot every hardware/sub interface. We send one IDB each;
   * the position in the IDB stream becomes the iface_id used by
   * EPBs. Both maps grow together. */
  pool_foreach (si, vnm->interface_main.sw_interfaces)
    {
      if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE &&
	  si->type != VNET_SW_INTERFACE_TYPE_SUB)
	continue;

      u8 *name = format (0, "%U%c", format_vnet_sw_if_index_name, vnm,
			 si->sw_if_index, 0);
      if (emit_idb (s->data_fd, 1 /* DLT_EN10MB */, s->snaplen,
		    (const char *) name) < 0)
	{
	  vec_free (name);
	  return -1;
	}
      vec_free (name);

      vec_validate_init_empty (s->sw_to_iface_id, si->sw_if_index, ~0u);
      s->sw_to_iface_id[si->sw_if_index] = next_iface_id;
      vec_add1 (s->iface_id_to_sw, si->sw_if_index);
      next_iface_id++;
    }

  return 0;
}

/* --- EPB --- */

int
pcap_stream_pcapng_emit_epb (pcap_stream_session_t *s, u32 sw_if_index,
			     u8 direction, u64 ts_ns, u32 caplen,
			     u32 orig_len, const u8 *pkt, const char *comment)
{
  /* Look up iface_id. Drop quietly if we don't have an IDB for this
   * sw_if_index (e.g. a loopback or interface added after session
   * start). v2: lazily emit an IDB on first sight. */
  u32 iface_id = ~0u;
  if (sw_if_index < vec_len (s->sw_to_iface_id))
    iface_id = s->sw_to_iface_id[sw_if_index];
  if (iface_id == ~0u)
    return 0;

  /* Optional opt_comment for drop-reason etc. */
  size_t comment_len = (comment && comment[0]) ? strlen (comment) : 0;
  size_t comment_padded = PCAPNG_PAD4 (comment_len);
  u32 comment_block = comment_len ? (u32) (4 + comment_padded) : 0;

  /* EPB layout:
   *   header:        block_type(4) + total_len(4) = 8
   *   fixed body:    iface_id(4) + ts_high(4) + ts_low(4)
   *                  + cap_len(4) + orig_len(4) = 20
   *   pkt data:      caplen bytes, padded to 4
   *   comment opt:   code(2)+len(2) + N + pad (if comment present)
   *   flags opt:     code(2)+len(2) + flags(4) = 8
   *   end opt:       code(2)+len(2) = 4
   *   trailer:       total_len(4) = 4
   */
  u32 cap_padded = PCAPNG_PAD4 (caplen);
  u32 pkt_pad = cap_padded - caplen;
  u32 total_len = 8 + 20 + cap_padded + comment_block + 8 + 4 + 4;

  u8 prefix[28];
  u32 *p = (u32 *) prefix;
  *p++ = PCAPNG_BT_EPB;
  *p++ = total_len;
  *p++ = iface_id;
  *p++ = (u32) (ts_ns >> 32);
  *p++ = (u32) (ts_ns & 0xffffffff);
  *p++ = caplen;
  *p++ = orig_len;

  /* Trailer: padding + flags option + end-of-opt + block_total_length. */
  /* Trailer holds: pkt-padding + optional comment opt + flags opt
   * + end-of-opt + total_len. Worst-case sizing: 3 (max pkt pad) +
   * 4 + 64 (comment header + truncated comment) + 8 + 4 + 4 = 87.
   * 256 leaves headroom. */
  u8 trailer[256];
  size_t toff = 0;
  for (u32 i = 0; i < pkt_pad; i++)
    trailer[toff++] = 0;

  /* opt_comment, if present */
  if (comment_len)
    {
      ((u16 *) (trailer + toff))[0] = PCAPNG_OPT_COMMENT;
      ((u16 *) (trailer + toff))[1] = (u16) comment_len;
      toff += 4;
      memcpy (trailer + toff, comment, comment_len);
      if (comment_padded > comment_len)
	memset (trailer + toff + comment_len, 0,
		comment_padded - comment_len);
      toff += comment_padded;
    }

  /* flags option */
  ((u16 *) (trailer + toff))[0] = PCAPNG_EPB_OPT_FLAGS;
  ((u16 *) (trailer + toff))[1] = 4;
  toff += 4;
  /* direction is a bitmask in the per-record header — for live rx/tx
   * it's a single bit (RX or TX); for drops it's DIR_DROP, optionally
   * combined with RX or TX to encode which feature arc the drop fired
   * on. Test the bits in priority order: TX wins (output-arc drop is
   * an outbound observation), then RX, otherwise unknown. */
  u32 flags = 0;
  if (direction & PCAP_STREAM_DIR_TX)
    flags = PCAPNG_EPB_FLAGS_OUT;
  else if (direction & PCAP_STREAM_DIR_RX)
    flags = PCAPNG_EPB_FLAGS_IN;
  *((u32 *) (trailer + toff)) = flags;
  toff += 4;
  /* end-of-opt */
  ((u16 *) (trailer + toff))[0] = PCAPNG_OPT_ENDOFOPT;
  ((u16 *) (trailer + toff))[1] = 0;
  toff += 4;
  /* trailing total_len */
  *((u32 *) (trailer + toff)) = total_len;
  toff += 4;

  /* Emit atomically via sendmsg + 3 iovecs (prefix, payload, trailer). */
  struct iovec iov[3] = {
    { .iov_base = prefix, .iov_len = sizeof (prefix) },
    { .iov_base = (void *) pkt, .iov_len = caplen },
    { .iov_base = trailer, .iov_len = toff },
  };
  struct msghdr mh = {
    .msg_iov = iov,
    .msg_iovlen = 3,
  };
  ssize_t want = (ssize_t) (sizeof (prefix) + caplen + toff);
  ssize_t got;
  do
    {
      got = sendmsg (s->data_fd, &mh, MSG_NOSIGNAL);
    }
  while (got < 0 && errno == EINTR);
  if (got != want)
    return -1;
  return 0;
}
