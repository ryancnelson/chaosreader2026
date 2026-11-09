# chaosreader2026 - Feature Backlog

**Purpose:** Capture and prioritize incremental, TDD-verified improvements for `chaosreader2026`.

**Project:** `chaosreader2026` (Rust)
**Description:** Modern single-binary packet-capture object carver, conversational transcript compiler, and safe session-replay generator.

**Last Updated:** 2026-11-09 (Post-Iteration 1 Landscape Alignment)

---

## Strategic Positioning (from [`docs/2026-landscape-and-positioning.md`](docs/2026-landscape-and-positioning.md))

- **Don't reinvent `libwireshark` or `dreadl0ck/netcap`:** Delegate heavy TLS 1.3 / `pcapng` `DSB` / HTTP/2 / QUIC decryption and complex stream reassembly to `tshark` when available on `PATH`, while keeping `[iter-1]`'s native Rust `pcap`/`pcapng` reader as a fast zero-dependency fallback.
- **Own the unoccupied 2026 gap:** Zero-server portable static HTML + `sessions.sqlite` (FTS5) case bundles, **SSE (`text/event-stream`) / LLM / MCP & WebSocket** conversation reconstructors, **`206 Partial Content` range stitching** + `br`/`zstd` object carving, inline **asciinema `.cast` v2** replays, and Tulip-style **`curl` request reproducers**.

---

## How to Use This Backlog

- **Adding ideas:** Add new items under **Ideas Inbox** or the appropriate priority section with `[IDEA]` tag.
- **Prioritizing:** Keep **Priority 1** scoped to single 30–45 minute vertical TDD slices.
- **Implementing:** Change `[IDEA]` → `[IN PROGRESS]` when starting `./scripts/next-iteration.sh <slug>`, then move to **Completed** with `[DONE]` and commit hash when merged.
- **Reviewing:** Re-prioritize during strategic reviews every 8 iterations (`STRATEGIC-REVIEW-CHECKLIST.md`).

---

## Priority 1: High Impact, Small Scope (30-45 min)

- [ ] **[FOCUS] [IDEA] `tshark` stream & TLS decryption backend (`SSLKEYLOGFILE` + `pcapng` `DSB`)** — Detect `tshark` on `PATH` (with fallback to native Rust reader) to ingest decrypted TLS 1.2/1.3, HTTP/1.x, HTTP/2, and QUIC streams without reinventing AEAD/HPACK/QUIC state machines.
- [ ] **[FOCUS] [IDEA] Content-Length & chunked HTTP object carver (`gzip`/`deflate`/`br`/`zstd` + magic-byte fallback)** — Carve exact HTTP request/response bodies, decompress modern encodings, sniff magic headers (`png`, `jpeg`, `gif`, `webp`, `avif`, `pdf`, `zip`, `wasm`, `woff2`, `sqlite`, `parquet`), emit SHA-256 deduplicated files + `image.html` gallery, and generate sanitized `curl` reproducers.
- [ ] **[FOCUS] [IDEA] SSE (`text/event-stream`) & NDJSON stream transcript reconstructor** — Reassemble streamed HTTP/1.1 & HTTP/2 responses (OpenAI/Anthropic/Gemini/Ollama/MCP event streams) into clean prompt/tool-call/completion transcripts with inter-event timing stats.
- [ ] **[FOCUS] [IDEA] Safe asciinema v2 (`.cast`) replay compiler & inline HTML player** — Replace raw PTY-injecting Perl `.replay` scripts with `.cast` v2 recordings for interactive text sessions (Telnet, IRC, Redis, SMTP) playable safely inside `index.html`.
- [ ] **[FOCUS] [IDEA] Queryable SQLite + FTS5 case manifest (`sessions.sqlite`)** — Emit a single-file SQLite database alongside `index.html` indexing flows, passive DNS/SNI names, HTTP requests, carved SHA-256 artifacts, and full-text searchable transcripts for humans and AI agents.
- [ ] **[IDEA] WebSocket frame unmasker & bidirectional message timeline** — Detect `101 Switching Protocols` upgrades, unmask client->server frames, reassemble fragmented continuations + `permessage-deflate`, and render 2-way message transcripts.
- [ ] **[IDEA] Passive hostname resolver (DNS `A`/`AAAA`/`CNAME` + mDNS + TLS `SNI`)** — Unroll CNAME chains from captured UDP/53 & mDNS 5353 packets plus plaintext TLS ClientHello `SNI` extensions to annotate IP endpoints across `index.html`, `sessions.jsonl`, and `sessions.sqlite`.
- [ ] **[IDEA] Payload-first L7 protocol classifier (DPI over port numbers)** — Sniff initial stream bytes (`HTTP/1.`, HTTP/2 preface, TLS ClientHello, `SSH-`, Redis RESP, Postgres startup, MQTT `CONNECT`, WebSocket) for native-fallback flows instead of trusting `min(src_port, dst_port)`.

---

## Priority 2: High Impact, Medium Scope (60-90 min)

- [ ] **[IDEA] HTTP `206 Partial Content` byte-range stitcher & `multipart/form-data` extractor** — Reconstruct complete files from multi-connection or ranged `Content-Range: bytes start-end/total` transfers and carve uploaded files/fields out of `multipart/form-data` POSTs.
- [ ] **[IDEA] Native fallback: overlap-trimmed TCP sequence reassembler & connection splitter** — Upgrade the zero-dependency Rust fallback path to handle out-of-order segments, partial-overlap retransmissions, 32-bit `seq` wraparound, and `SYN`/`FIN`/`RST` 4-tuple reuse when `tshark` is unavailable.
- [ ] **[IDEA] Schema-less gRPC & Protobuf wire decoder** — Unpack length-prefixed gRPC frames (including compressed flags) and render schema-less Protobuf wire tags/varints/strings into structured JSON/HTML views.
- [ ] **[IDEA] Native fallback: IPv4 & IPv6 fragment reassembly** — Reassemble fragmented IPv4 packets and IPv6 Fragment Extension Headers (`next_header = 44`) in pure-Rust mode.

---

## Priority 3: Medium Impact (East-West, Homelab & IoT Protocols)

- [ ] **[IDEA] MQTT session & topic-tree reconstructor** — Decode `CONNECT`, `SUBSCRIBE`, and `PUBLISH` packets into a browsable topic hierarchy with retained-message state and payload timeline.
- [ ] **[IDEA] Redis (`RESP2`/`RESP3`) & PostgreSQL (`pgwire`) command-response timelines** — Pair east-west cache and SQL queries with latency and row/reply summaries.
- [ ] **[IDEA] SMTP/IMF email & MIME attachment carver** — Extract RFC 5322 messages from SMTP `DATA` commands and unpack base64/quoted-printable MIME attachments into `carved/`.
- [ ] **[IDEA] TLS handshake metadata & JA4-style fingerprint summary (when keys are absent)** — Extract TLS version, cipher suites, ALPN (`h2`, `http/1.1`), SNI, and server certificates for encrypted sessions that cannot be decrypted.

---

## Priority 4: Low Priority / Future / Research Needed

- [ ] **[IDEA] Bounded-memory streaming mode for multi-GB captures** — Evict idle/closed TCP flows to disk incrementally so memory scales with concurrent active flows rather than capture file size.
- [ ] **[IDEA] VNC / RFB keystroke & modern web-canvas replay** — Modernize Chaosreader's RFB session capture into a browser-viewable timeline without requiring a local `vncviewer` binary.
- [ ] **[IDEA] Linux eBPF `ecapture` / `pcapng` `DSB` live-capture helper recipe** — Document and test zero-config plaintext TLS capture workflows feeding directly into `chaosreader2026`.

---

## Completed (Archive)

Track completed items here to celebrate progress and inform strategic reviews.

### Iteration 1 (2026-11-09)
- [DONE] ✅ **Vertical tracer bullet: `pcap` + `pcapng` ingestion & session index CLI** — Implemented `ingest_capture_bytes` and `generate_case_dir` supporting microsecond/nanosecond `pcap` and `pcapng` (`EnhancedPacketBlock` + `SimplePacketBlock`) across `ETHERNET`, `802.1Q VLAN`, `LINUX_SLL`, `LINUX_SLL2`, `RAW`, and `NULL`/`LOOP` (`IPv4` + `IPv6`), preserving same-timestamp packet order and emitting `sessions.jsonl` + strict-CSP, HTML-escaped `index.html` and `session_NNNN.html` transcripts.

### Iteration 0 (2026-11-09)
- [DONE] ✅ Initialized repository, upstream Chaosreader 2026 source review (`docs/chaosreader-2026-review.md`), public-safety git hooks, and `iterate-bot` + TDD + Gilfoyle scaffolding.

---

## Ideas Inbox (Unsorted)

- [ ] **[IDEA] `LaxSlicedPacket` fallback for snaplen-cut frames** — When `data.len() < original_len` cuts mid-IP payload so IP `total_len` exceeds captured slice length, fall back to `etherparse::LaxSlicedPacket` so partial L4 headers and truncated bytes are still recovered and flagged `partial: true`.
