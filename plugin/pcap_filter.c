/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 */

/* pcap_filter.c — libpcap-isolated wrapper. Only file that includes
 * <pcap/pcap.h>; everything else uses the opaque pcap_filter_t. */

#include "pcap_filter.h"

#include <pcap/pcap.h>

#include <stdlib.h>
#include <string.h>

struct pcap_filter_s
{
  struct bpf_program prog;
};

pcap_filter_t *
pcap_filter_compile (const char *expr, int dlt, int snaplen, char **err)
{
  /* Translate our portable PCAP_FILTER_DLT_* sentinels to whatever
   * the linked libpcap thinks DLT_EN10MB / DLT_RAW are. Hardcoding
   * the wire values (1, 101) breaks because some libpcap builds
   * remap DLT_RAW to a different number to deconflict the
   * historic Linux-vs-BSD divergence (we hit "unknown data link
   * type 101" on Bookworm's libpcap1.10). */
  int real_dlt;
  switch (dlt)
    {
    case PCAP_FILTER_DLT_EN10MB:
      real_dlt = DLT_EN10MB;
      break;
    case PCAP_FILTER_DLT_RAW:
      real_dlt = DLT_RAW;
      break;
    default:
      real_dlt = dlt;
      break;
    }
  pcap_t *dummy = pcap_open_dead (real_dlt, snaplen);
  if (!dummy)
    {
      if (err)
	*err = strdup ("pcap_open_dead failed");
      return NULL;
    }

  pcap_filter_t *f = calloc (1, sizeof (*f));
  if (!f)
    {
      pcap_close (dummy);
      if (err)
	*err = strdup ("calloc failed");
      return NULL;
    }

  if (pcap_compile (dummy, &f->prog, expr, 1, PCAP_NETMASK_UNKNOWN) < 0)
    {
      if (err)
	*err = strdup (pcap_geterr (dummy));
      pcap_close (dummy);
      free (f);
      return NULL;
    }

  pcap_close (dummy);
  return f;
}

void
pcap_filter_free (pcap_filter_t *f)
{
  if (!f)
    return;
  pcap_freecode (&f->prog);
  free (f);
}

int
pcap_filter_run (const pcap_filter_t *f, const uint8_t *pkt, uint32_t caplen,
		 uint32_t orig_len)
{
  if (!f)
    return 1; /* no filter = always match */
  struct pcap_pkthdr ph = { .caplen = caplen, .len = orig_len };
  return pcap_offline_filter (&f->prog, &ph, pkt);
}
