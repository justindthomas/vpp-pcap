# vpp-pcap — Design Sketch

A tcpdump-style live packet-capture tool for FD.io VPP. Operator
runs a CLI, supplies a libpcap-syntax filter expression, and
watches matched packets stream in real time. Pipe-friendly
(`vpp-pcap -i internet 'tcp port 179' | tshark -r -`).

This is a sketch — pre-implementation. Open questions in the last
section; nothing here is committed.

---

## Why this needs to exist

VPP's existing capture story:

| Tool                        | Filter           | Output      | Live? |
|-----------------------------|------------------|-------------|-------|
| `pcap trace`                | `bpf_trace_filter` (libpcap) | `/tmp/*.pcap` file | no — flushes on rollover |
| `pcap dispatch trace`       | classifier       | file        | no |
| `trace add` / `show trace`  | `bpf_trace_filter` | text in console | no — manual ring scrape |
| SPAN to TAP + `tcpdump`     | post-mirror      | live        | yes, but mirrors everything before filtering |
| `vpptrace.sh` (contiv)      | text grep        | console     | yes-ish — polls `show trace` |
| sFlow plugin                | random sample    | Netlink PSAMPLE → hsflowd | yes, statistical only |

What we want: file-less, live, libpcap-filtered, multi-session,
cheap when nobody's watching.

The BPF half is already solved upstream (`bpf_trace_filter`
plugin uses `pcap_compile()` + `pcap_offline_filter()`). We're
building the **streaming half** that nobody has shipped.

---

## High-level architecture

```
┌──────────────────────────── VPP process ────────────────────────────┐
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │ vpp-pcap-input node (per direction: rx, tx, drop)               │ │
│  │ ─ runs as feature on ip4-unicast/ip4-output/etc.                │ │
│  │ ─ disabled (zero-cost) when no sessions are attached            │ │
│  │ ─ for each buffer in vector:                                    │ │
│  │     for each active session matching this iface+dir:            │ │
│  │       if pcap_offline_filter(s->bpf_prog, eth_hdr, len):        │ │
│  │         enqueue (ts, iface, snaplen, payload[snaplen]) into     │ │
│  │           per-(session,worker) SPSC ring                        │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                              │                                       │
│                              ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │ vpp-pcap-drain (main thread, vlib process)                      │ │
│  │ ─ wakes on socket-writable + 1ms tick                           │ │
│  │ ─ round-robin drain worker rings → per-session output queue     │ │
│  │ ─ writes pcap-record-framed bytes to session's Unix socket      │ │
│  │ ─ on EAGAIN: stop draining that session, count drops on ring    │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                              │                                       │
│  control socket: /run/vpp/vpp-pcap.sock                              │
│  data sockets:   /run/vpp/vpp-pcap-N.sock (one per session)          │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
                       ┌───────┴────────┐
                       │  vpp-pcap CLI  │
                       └────────────────┘
```

**Two sockets per session** (control + data) keeps the framing
clean: control speaks length-prefixed JSON, data is raw pcap
bytes consumable by `tshark -r -`. CLI does the splice.

Alternative considered: single SOCK_SEQPACKET socket with
typed messages (control + data interleaved). Rejected — breaks
`vpp-pcap | tshark -r -` without a CLI splice. Two sockets is
simpler.

---

## Hot path detail

Per-buffer cost when at least one session is active:

```
for s in active_sessions[iface_dir]:
    eth = vlib_buffer_get_current(b)
    if pcap_offline_filter(s->prog, eth, b->current_length):
        ring_t *r = s->worker_rings[vm->thread_index]
        if ring_full(r): __atomic_inc(&s->drops); continue
        rec = ring_reserve(r)
        rec->ts_ns = clib_cpu_time_now_to_ns()
        rec->iface = vnet_buffer(b)->sw_if_index[VLIB_RX]
        rec->len = min(s->snaplen, b->current_length)
        clib_memcpy_fast(rec->data, eth, rec->len)
        ring_commit(r)
```

Key properties:

- **Zero work when no sessions** — feature arc disabled, plugin
  hot path never enters. `vnet_feature_enable_disable()` toggles
  on first session create / last session delete.
- **No locks on the worker side** — SPSC ring (one writer per
  worker, one reader = main thread).
- **Bounded backpressure** — ring full → drop + counter, never
  block the worker. Operator sees drop count in session summary
  on close.
- **Per-session BPF program** — compiled once at session create,
  freed at session destroy. `bpf_trace_filter` already does the
  raw-vs-ethernet detection trick we should copy verbatim.

Estimated cost per matched packet: ~50–100 cycles for the BPF
interpreter + ~30 cycles for the ring enqueue + memcpy of
`snaplen` bytes (default 96, configurable). At 1Mpps with 1%
match rate that's ~10kpps streamed — well under the
psample-pattern ceiling of ~50–100kpps.

---

## Wire format

### Control socket (`/run/vpp/vpp-pcap.sock`, SOCK_STREAM)

Length-prefixed JSON, one message per request/response:

```
[u32 le length][JSON body]
```

Requests:

```json
{"op": "create_session",
 "interface": "GigabitEthernet0/0/0",   // or "any"
 "direction": "rx",                     // rx | tx | drop | any
 "filter": "tcp port 179",              // libpcap syntax
 "snaplen": 96,                         // bytes per packet, 0 = full
 "max_packets": 0}                      // 0 = unlimited
```

Responses:

```json
{"ok": true, "session_id": 7,
 "data_socket": "/run/vpp/vpp-pcap-7.sock",
 "compiled_filter_bytes": 240}
```

```json
{"op": "list_sessions"} → {"ok": true, "sessions": [...]}
{"op": "delete_session", "id": 7} → {"ok": true, "captured": 1234, "dropped": 12}
{"op": "stats", "id": 7} → {"ok": true, "captured": ..., "dropped": ..., "since": ...}
```

### Data socket (`/run/vpp/vpp-pcap-N.sock`, SOCK_STREAM)

Raw pcap-savefile format (RFC-de-facto):

```
[pcap_file_hdr — 24 bytes, sent once on connect]
[pcap_pkthdr][packet bytes]
[pcap_pkthdr][packet bytes]
...
```

This means the operator can do:

```sh
vpp-pcap -i internet 'tcp port 179' > capture.pcap
vpp-pcap -i internet 'tcp port 179' | tshark -r -
vpp-pcap -i internet 'tcp port 179' | wireshark -k -i -
```

…without any framing fixup. CLI just splices control-socket setup
+ data-socket bytes to stdout (or to `-w` file).

---

## CLI surface

```
vpp-pcap [-i <iface>|any] [-d rx|tx|drop|any] [-s snaplen]
         [-c count] [-w outfile.pcap] [--server SOCK]
         '<bpf expression>'

vpp-pcap list                # list active sessions
vpp-pcap kill <id>           # delete a session by id
vpp-pcap stats <id>          # current capture/drop counters
```

Examples:

```sh
# Watch BGP sessions on the internet-facing interface
vpp-pcap -i internet 'tcp port 179'

# Capture all dropped packets system-wide
vpp-pcap -d drop 'ip6'

# Save first 10 NDP packets to a file
vpp-pcap -i lan -c 10 -w ndp.pcap 'icmp6 and (ip6[40] = 135 or ip6[40] = 136)'

# Pipe to wireshark
vpp-pcap -i wan 'host 1.1.1.1' | wireshark -k -i -

# Print decoded summary in tcpdump style (CLI does its own libpcap-printer)
vpp-pcap --print -i lan 'arp'
```

The CLI is dumb-ish: it talks to the control socket, gets back
the data-socket path, opens it, and either dumps to stdout or
formats with libpcap's printer. Most of the interesting code is
on the plugin side.

`--print` mode shells out to `tcpdump -nn -r -` rather than
embedding libpcap's printer (avoids reimplementing the universe).

---

## Repo layout

```
vpp-pcap/
├── README.md
├── DESIGN.md                       (this file)
├── LICENSE                         (Apache-2.0, matches VPP)
├── plugin/
│   ├── CMakeLists.txt              builds against installed VPP
│   ├── vpp_pcap.api                binary API (control plane)
│   ├── plugin.c                    init / VLIB_PLUGIN_REGISTER
│   ├── session.{c,h}               session table, BPF compile, ring alloc
│   ├── node.{c,h}                  feature-arc graph node (filter + enqueue)
│   ├── drain.{c,h}                 main-thread vlib_process: socket I/O
│   ├── ring.h                      SPSC ring inline header
│   └── pcap_format.h               libpcap-savefile header layout
├── cli/
│   ├── Cargo.toml                  Rust binary
│   └── src/
│       ├── main.rs                 arg parse, control-socket setup
│       ├── control.rs              JSON-over-Unix protocol client
│       └── stream.rs               data-socket → stdout/-w/--print pipeline
├── docs/
│   ├── architecture.md             expanded design
│   ├── wire-format.md              control + data protocol spec
│   └── performance.md              benchmark methodology + results
└── tests/
    ├── integration/                spin up VPP in netns, run capture, verify
    └── unit/                       libpcap interop, ring SPSC race
```

CLI in Rust because that matches the rest of the imp ecosystem
and we can lift the existing socket/JSON helpers; nothing
language-specific about it. C plugin because it lives inside
VPP's vlib and uses `clib_*` / `vlib_*` directly.

---

## Session lifecycle

```
CLI                               vpp-pcap plugin
 │                                       │
 │── connect /run/vpp/vpp-pcap.sock ────▶│
 │── {op: create_session, ...} ─────────▶│  pcap_compile(filter)
 │                                       │  alloc session struct
 │                                       │  alloc per-worker rings
 │                                       │  if first session for this
 │                                       │    iface+dir: enable feature arc
 │◀─ {ok, id, data_socket} ──────────────│
 │                                       │
 │── connect /run/vpp/vpp-pcap-N.sock ──▶│  send pcap file header
 │◀─ pcap file header ───────────────────│
 │                                       │
 │◀─ pcap pkthdr + bytes ────────────────│  drain loop sends as ring fills
 │◀─ pcap pkthdr + bytes ────────────────│
 │   ...                                 │
 │                                       │
 │── close data socket ─────────────────▶│  mark session for teardown
 │── close control socket ──────────────▶│  on next drain tick:
 │                                       │    free BPF program
 │                                       │    free rings
 │                                       │    if last session for arc:
 │                                       │      disable feature arc
```

Crash-safety: control-socket `EOF` → tear down session.
Operator's `Ctrl-C` cleans up automatically. No leaked sessions
when CLI dies.

---

## Things explicitly out of scope (v1)

- **No memif fast-path**. Adding one later is straightforward
  (swap the per-session output from Unix socket to libmemif ring),
  but the SOCK_STREAM path is enough for any operator-driven
  debugging and is much easier to integrate with.
- **No filter on metadata** like sw_if_index name (only matched
  by the `-i` arg, not within the BPF expression). Could add
  custom BPF extensions later.
- **No persistent sessions across VPP restarts**. Session table
  is in-memory; restart wipes it.
- **No multi-tenant auth**. Anyone with read access to
  `/run/vpp/vpp-pcap.sock` can capture anything. Match VPP's
  permission model — same as `vppctl`.
- **No NAT-aware "before/after" tap markers**. sfw integration
  comes later if useful (`-z internet:lan` zone-pair filter).

---

## Open questions for you

1. **Plugin name in VPP**: `vpp_pcap` or `pcap_stream` or
   something else? Affects `VLIB_PLUGIN_REGISTER`, CLI command
   names (`pcap stream session add ...`), and the binary API
   prefix. I lean `vpp_pcap` for symmetry with `bpf_trace_filter`
   et al.

2. **Where to hook in the graph**:
   - (a) Feature-arc node on every interface direction (rx, tx)
     — flexible, "any" gets natural coverage.
   - (b) Wrap `interface-output` and `device-input` only —
     simpler, misses internal redirects (drop, punt, lookup).
   - (c) Both: feature-arc for rx/tx, separate hook on
     `error-drop` for `-d drop` mode.

   I lean (c) — matches `pcap trace` semantics.

3. **Direction model**: tcpdump conflates rx/tx ("any direction
   on this interface"). VPP separates them cleanly. Default to
   `any` and let `-d` filter? Or default to `rx` (tcpdump-ish)?

4. **Snaplen default**: tcpdump defaults to 262144 (effectively
   full packet); old default was 68. We probably want 96 so the
   typical low-throughput operator session doesn't burn cycles
   memcpying full payloads. Configurable per session.

5. **CLI binary name in our install**: `vpp-pcap` (generic) or
   `imp-pcap` (matches our `imp-` prefix convention for the
   shipping binary in imp installs)? Probably ship as
   `vpp-pcap` upstream and symlink/wrap as `imp-pcap` in our
   build, similar to how `imp-ospfd` is the install name for
   `ospfd`.

6. **Build integration with imp**: add to
   `scripts/external-daemon-versions.txt` and
   `tests/integration/infra/build-impd.sh`? The plugin needs to
   land in `/usr/lib/vpp_plugins/`; the CLI in `/usr/local/bin/`.

7. **Should we contribute upstream**? FD.io has a contribution
   path; this is the kind of thing that would benefit the wider
   community. Probably worth keeping in our repo first, then
   submit to upstream once it stabilises.

---

## Estimated effort

- Plugin C code: ~600 LOC (session table, ring, drain, node,
  CLI). About 2 days for v1.
- CLI Rust code: ~300 LOC. Half a day.
- Tests + docs: 1 day.
- Integration with imp build: half a day.

Total: ~4 days for a usable v1.
