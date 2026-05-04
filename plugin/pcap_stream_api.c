/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 */

/* pcap_stream_api.c — binary API stub.
 *
 * v0.1 has no binary API messages (the control socket is the
 * primary interface). Keeping this file present so the
 * pcap_stream.api plumbing has a destination once we add messages.
 *
 * The cmake build references this file in CMakeLists; it would be
 * empty-translation-unit otherwise, which gcc tolerates but is
 * confusing — leave a single static const so something is here.
 */

#include <pcap_stream/pcap_stream.h>

static const char pcap_stream_api_placeholder[] __attribute__ ((unused)) =
    "pcap_stream binary API (placeholder)";
