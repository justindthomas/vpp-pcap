/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 */

/* pcap_filter.h — thin libpcap wrapper.
 *
 * Exists to isolate the libpcap symbol surface from the rest of
 * the plugin. VPP's vppinfra/pcap_funcs.h declares its own
 * `pcap_close` with an incompatible signature (clib_error_t * vs.
 * libpcap's void return), so any TU that pulls in both headers
 * fails to compile. Restricting libpcap to this single .c file
 * sidesteps the collision.
 */

#ifndef __included_pcap_filter_h__
#define __included_pcap_filter_h__

#include <stdint.h>
#include <stddef.h>

/* Opaque BPF program handle. Internally this is a libpcap
 * `struct bpf_program *` but the rest of the plugin doesn't need
 * to know that. */
typedef struct pcap_filter_s pcap_filter_t;

/* DLT identifiers, mirrored from <pcap/dlt.h>. */
#define PCAP_FILTER_DLT_EN10MB 1
#define PCAP_FILTER_DLT_RAW    101

/* Snaplen baked into the cached long-lived dummy pcap_t. Ceiling
 * for the libpcap savefile format. We always compile against this
 * max — actual per-session snaplen is enforced by the ring/copy
 * code, not the BPF program. */
#define PCAP_FILTER_MAX_SNAPLEN 65535

/* Compile `expr` for the given DLT. Returns NULL on failure with
 * `*err` set to a malloc'd error string the caller must free. */
pcap_filter_t *pcap_filter_compile (const char *expr, int dlt, int snaplen,
				    char **err);

/* Free a compiled filter. */
void pcap_filter_free (pcap_filter_t *f);

/* Run a packet through the filter. Returns non-zero on match. */
int pcap_filter_run (const pcap_filter_t *f, const uint8_t *pkt,
		     uint32_t caplen, uint32_t orig_len);

#endif /* __included_pcap_filter_h__ */
