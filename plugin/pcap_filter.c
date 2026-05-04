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

/* Long-lived dummy pcap_t handles, one per DLT. Created lazily on
 * first compile, never closed. Reusing the same handle across
 * compiles avoids the open/close cycle that breaks libpcap's
 * internal state on Bookworm — pcap_compile() on the same handle
 * works repeatedly; what fails is repeatedly opening and closing.
 *
 * Memory leak is bounded (one pcap_t per DLT, 2 DLTs total). */
static pcap_t *g_pcap_eth = NULL;
static pcap_t *g_pcap_raw = NULL;

pcap_filter_t *
pcap_filter_compile (const char *expr, int dlt, int snaplen, char **err)
{
  /* Translate our portable PCAP_FILTER_DLT_* sentinels to libpcap's
   * actual DLT_EN10MB / DLT_RAW values, and pick the matching
   * cached handle. */
  int real_dlt;
  pcap_t **slot;
  switch (dlt)
    {
    case PCAP_FILTER_DLT_EN10MB:
      real_dlt = DLT_EN10MB;
      slot = &g_pcap_eth;
      break;
    case PCAP_FILTER_DLT_RAW:
      real_dlt = DLT_RAW;
      slot = &g_pcap_raw;
      break;
    default:
      if (err)
	*err = strdup ("unknown DLT");
      return NULL;
    }

  if (*slot == NULL)
    {
      *slot = pcap_open_dead (real_dlt, PCAP_FILTER_MAX_SNAPLEN);
      if (*slot == NULL)
	{
	  if (err)
	    *err = strdup ("pcap_open_dead failed");
	  return NULL;
	}
    }

  pcap_filter_t *f = calloc (1, sizeof (*f));
  if (!f)
    {
      if (err)
	*err = strdup ("calloc failed");
      return NULL;
    }

  /* Compile against the long-lived handle. Calling pcap_compile()
   * many times on the SAME pcap_t works fine — what crashed VPP
   * was repeatedly pcap_open_dead/pcap_close cycling. */
  if (pcap_compile (*slot, &f->prog, expr, 1, PCAP_NETMASK_UNKNOWN) < 0)
    {
      if (err)
	*err = strdup (pcap_geterr (*slot));
      free (f);
      return NULL;
    }
  (void) snaplen; /* baked into the cached handle */
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
