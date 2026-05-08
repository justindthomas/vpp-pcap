/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 *
 * harness_init.h — public surface of the vpp-pcap v2 chassis fixture.
 * Mirrors sfw/fuzz/sfw_node/harness_init.h.
 *
 * harness_init_once() runs the one-time setup of the synthesised
 * vlib runtime: vm->buffer_main + buffer arena (4 slots),
 * vm->node_main / error_main, vlib_buffer_func_main stub,
 * feature_main config arc 0, ip{4,6}_main FIB index vec, plus the
 * pcap_stream_main fixture (one active session with NULL filter +
 * per-thread ring).  Idempotent.
 *
 * harness_load_packet(data, size) slices the fuzzer-provided bytes
 * across N=4 buffers in one frame via a 1-byte length prefix per
 * slice, leaving each buffer's vlib_buffer_t header in the canonical
 * "fresh from the pool" state.
 *
 * fuzz_get_main / fuzz_get_node_runtime / fuzz_get_frame are thin
 * accessors so the harness body stays free of file-scoped statics.
 */

#ifndef HARNESS_INIT_H
#define HARNESS_INIT_H

#include <stdint.h>
#include <stddef.h>
#include <vlib/vlib.h>

void harness_init_once (void);
void harness_load_packet (const uint8_t *data, size_t size);

vlib_main_t *fuzz_get_main (void);
vlib_node_runtime_t *fuzz_get_node_runtime (void);
vlib_frame_t *fuzz_get_frame (void);

#endif /* HARNESS_INIT_H */
