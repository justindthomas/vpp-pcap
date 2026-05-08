# vpp-pcap fuzz harnesses (v2 — pcap_stream_node body)

libFuzzer harnesses for the **pcap_stream rx / tx node bodies** —
`pcap_stream_node_inline` in `plugin/pcap_stream_node.c`.  The chassis
is a direct port of sfw's v2 chassis (`~/code/sfw/fuzz/sfw_node/`),
adapted for vpp-pcap's smaller hot path.

## Status

**v2.0: driveable — pcap_stream_{rx,tx}_node_fn run against fuzzer
input.**

The hot-path TUs (`pcap_stream_node.c`, `pcap_stream_ring.c`) compile
with `-fsanitize=address,undefined,fuzzer-no-link`; the chassis
(`harness_glue.c` + `harness_init.h`) brings up the synthesised vlib
runtime — buffer arena (4 slots), `vm->buffer_main`, `node_main` /
`error_main` for `vlib_node_increment_counter`, no-op
`buffer_enqueue_to_next_fn`, `feature_main.feature_config_mains[0]`
for `vnet_feature_next_u16`, plus the pcap_stream fixture (one
session with NULL filter and a per-thread ring).

```
$ ./out/fuzz_pcap_stream_rx_node -max_total_time=8
#3394675  DONE  cov: 175 ft: 196  exec/s: 377186
$ ./out/fuzz_pcap_stream_tx_node -max_total_time=8
#3387169  DONE  cov: 176 ft: 197  exec/s: 376352
```

vpp-pcap's hot path is a fraction of sfw's surface (one inline body,
one ring writer, no policy/NAT/FIB), so absolute coverage numbers are
lower than sfw_node v2.4's 569/499.  What matters is the *path*
covered: parser (none — pcap_stream is L2-agnostic, copies
ethernet+IP raw), filter dispatch (NULL-filter fast path),
ring-reserve/commit, snaplen-bounded record copy.

## Audit reference: F2 candidate

The 2026-05-08 audit (`audit-tools/reports/vpp-pcap-2026-05-08.md`)
flagged F2 — a candidate use-after-free where
`pcap_stream_session_destroy` frees `s->bpf_eth` and `s->rings[]`
*before* clearing `s->active`, racing the worker hot path's
`if (s->active) ... access s->bpf_eth` window.

This v2.0 single-thread harness **cannot trigger F2** — it needs
concurrency between a destroy on the main thread and a node
invocation on a worker thread.  What this harness *does* establish:

- ASan-clean coverage of the non-race hot path (no UAF in the
  steady-state flow).
- A chassis a future stress harness can extend by spawning a
  destroy thread that interleaves with `LLVMFuzzerTestOneInput`
  invocations.

If F2 is triaged as fix-without-PoC (vpp-pcap is a low-volume
plugin and the operator-driven race is rare in production), this
harness becomes the regression-defence — the closed-corpus seed
for F2's fix would be a packet that exercises the post-fix
ordering's `s->active = 0; barrier; free(...)` path.

## Layout

```
fuzz/pcap_stream_node/
├── Dockerfile                      # FROM audit-tools:vpp-fuzz
├── build.sh                        # compile pcap_stream .c + chassis + harnesses
├── harness_glue.c                  # VPP runtime globals + stubs + v2.0 fixture
├── harness_init.h                  # public surface: harness_init_once,
│                                   # harness_load_packet, fuzz_get_main, ...
├── fuzz_pcap_stream_rx_node.c      # drives pcap_stream_rx_node_fn
├── fuzz_pcap_stream_tx_node.c      # drives pcap_stream_tx_node_fn
├── corpus/
│   └── <harness>/closed/<id>.bin   # closed-finding regression seeds
└── README.md                       # this file
```

## Build

On the IMP build host, inside `audit-tools:vpp-fuzz`:

```bash
podman run --rm -v ~/code/vpp-pcap:/src:Z \
    localhost/audit-tools:vpp-fuzz \
    -c "/src/fuzz/pcap_stream_node/build.sh"

ls fuzz/pcap_stream_node/out
```

## Architecture

v2 compiles the per-packet TUs (`pcap_stream_node.c`,
`pcap_stream_ring.c`) with sanitisers and links each harness against:

- `pcap_stream_node.o`, `pcap_stream_ring.o` — sanitised plugin code
- `harness_glue.o` — chassis layer:
    1. **Runtime data globals**: `vlib_global_main`,
       `vlib_thread_main`, `vlib_buffer_func_main`,
       `vlib_thread_stacks`, `feature_main`, `ip4_main`, `ip6_main`,
       `ip4_fib_16s`, `ip4_ply_pool`, `ip6_fib_fwding_table`,
       `load_balance_pool`, plus `pcap_stream_main` (which the
       skipped `pcap_stream.c` would normally own) and the portable
       `vnet_incremental_checksum_fp`.
    2. **Function stubs**: `vnet_get_main`,
       `vnet_feature_enable_disable`,
       `vlib_buffer_length_in_chain_slow_path`, `vlib_cli_output`,
       `vlib_add_trace`, `vlib_worker_thread_barrier_*`,
       `format_vnet_sw_if_index_name`, `unformat_vnet_sw_interface`,
       and the `pcap_filter_*` shims (always-match,
       libpcap-isolation-free).
    3. **Per-call fixture**:
       - `harness_init_once`: brings up the vppinfra heap, the
         buffer arena, frame, node runtime, error counters, and
         `pcap_stream_main.sessions[0]` with `active=1`,
         `direction=RX|TX`, `sw_if_index=~0`,
         `snaplen=256`, NULL filter, and a 256-slot SPSC ring.
       - `harness_load_packet`: slices the fuzzer input across N=4
         buffers in one frame via a 1-byte length prefix per
         slice, leaving each `vlib_buffer_t` in canonical "fresh
         from pool" state.

- `libvppinfra` — vec / bitmap / mem allocator used by the ring
  alloc and node-runtime counter machinery.

The build skips:

- `pcap_stream.c` — pulls VLIB_INIT_FUNCTION + drain socket.
  `pcap_stream_main` is hand-defined in `harness_glue.c` instead.
- `pcap_filter.c` — pulls libpcap; `pcap_filter_run` is stubbed
  to always-match in the chassis.
- `pcap_stream_drain.c`, `pcap_stream_drop.c`,
  `pcap_stream_session.c`, `pcap_stream_pcapng.c`,
  `pcap_stream_api.c` — none reached from the rx/tx node body.

## What's covered vs. not

| Path                                    | Covered (v2.0) |
|-----------------------------------------|----------------|
| `pcap_stream_match_and_enqueue` body    | yes            |
| Per-direction sw_if_index check         | yes            |
| `pcap_filter_run` (NULL filter path)    | yes (stubbed)  |
| Ring `reserve` / `commit` / overflow    | yes            |
| Snaplen-bounded record copy             | yes            |
| Trace path (`vlib_add_trace`)           | no (stubbed)   |
| Multi-segment chain handling            | no             |
| F2 destroy/hot-path race                | no — needs concurrency (see "Audit reference" above) |
| Drop tap (`pcap_stream_drop_callback`)  | no — separate path |
| Drain process (sockets, pcap-ng emit)   | no — out of node-fuzz scope |

## Roadmap

1. **Multi-thread stress harness for F2.** Spawn a destroy thread
   that calls into a synthesised `pcap_stream_session_destroy`
   while the main thread runs `pcap_stream_*_node_fn` in a tight
   loop.  ASan should surface F2's UAF if the race fires.  This is
   structurally different from libfuzzer's single-shot model — a
   custom main() driving randomised destroy timing.

2. **Multi-segment chain handling.** Build a fixture where
   `b->flags & VLIB_BUFFER_NEXT_PRESENT` and `b->next_buffer`
   chains across multiple slots, so
   `vlib_buffer_length_in_chain_slow_path` runs.  Surfaces
   chain-walk bugs that single-segment fuzzing misses.

3. **Drop tap harness.**  `pcap_stream_drop_callback` has a
   different argument shape (no `vlib_buffer_t`, just a raw
   pointer + reason string).  Distinct harness; the chassis
   transplants but the driver doesn't.
