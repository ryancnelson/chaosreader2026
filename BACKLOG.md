# chaosreader2026 - Feature Backlog

**Purpose:** Capture and prioritize incremental, TDD-verified improvements for `chaosreader2026`.

**Project:** `chaosreader2026` (Rust)
**Description:** Modern single-binary packet-capture object carver, conversational transcript compiler, and safe session-replay generator.

**Last Updated:** 2026-11-09 (Iteration 0 - Initialization)

---

## How to Use This Backlog

- **Adding ideas:** Add new items under **Ideas Inbox** or the appropriate priority section with `[IDEA]` tag.
- **Prioritizing:** Keep **Priority 1** scoped to single 30–45 minute vertical TDD slices.
- **Implementing:** Change `[IDEA]` → `[IN PROGRESS]` when starting `./scripts/next-iteration.sh <slug>`, then move to **Completed** with `[DONE]` and commit hash when merged.
- **Reviewing:** Re-prioritize during strategic reviews every 8 iterations (`STRATEGIC-REVIEW-CHECKLIST.md`).

---

## Priority 1: High Impact, Small Scope (30-45 min)

- [ ] **[FOCUS] [IDEA] Vertical tracer bullet: `pcap` + `pcapng` ingestion & session index CLI** — Decode legacy `pcap` (usec/nsec) and `pcapng` (`Ethernet`, `802.1Q VLAN`, `SLL`, `SLL2`, `DLT_NULL`, IPv4 & IPv6) with monotonic `(packet_index, timestamp_ns)` ordering (fixing Chaosreader's timestamp-collision bug) and emit `sessions.jsonl` + strict HTML-escaped `index.html`.
- [ ] **[FOCUS] [IDEA] Overlap-trimmed TCP sequence reassembler & connection-lifecycle splitter** — Reassemble unidirectional (`client->server`, `server->client`) and time-ordered bidirectional streams handling out-of-order segments, partial-overlap retransmissions, 32-bit `seq` wraparound, and `SYN`/`FIN`/`RST` 4-tuple reuse.
- [ ] **[FOCUS] [IDEA] Payload-first L7 protocol classifier (DPI over port numbers)** — Sniff initial stream bytes (`HTTP/1.`, HTTP/2 preface `PRI * HTTP/2.0`, TLS ClientHello, `SSH-`, Redis RESP, Postgres startup, MQTT `CONNECT`, WebSocket upgrade) instead of trusting `min(src_port, dst_port)`.
- [ ] **[FOCUS] [IDEA] Content-Length & chunked HTTP/1.x object carver with magic-byte fallback** — Carve exact HTTP request/response bodies without regex stream-splitting bugs, decompress `gzip`/`deflate`/`br`/`zstd`, sniff magic headers (`png`, `jpeg`, `gif`, `webp`, `avif`, `pdf`, `zip`, `wasm`, `woff2`, `sqlite`, `parquet`), and emit SHA-256 deduplicated files + `image.html` gallery.
- [ ] **[FOCUS] [IDEA] Safe asciinema v2 (`.cast`) replay compiler & sandboxed HTML viewer** — Replace raw PTY-injecting Perl `.replay` scripts with `.cast` v2 recordings for interactive TCP/UDP text sessions (Telnet, IRC, Redis, SMTP) with sanitized control-sequence rendering in `index.html`.
- [ ] **[IDEA] Passive hostname resolver (DNS `A`/`AAAA`/`CNAME` + mDNS + TLS `SNI`)** — Unroll CNAME chains from captured UDP/53 & mDNS 5353 packets plus plaintext TLS ClientHello `SNI` extensions to annotate IP endpoints across `index.html` and `sessions.jsonl` with zero live network queries.
- [ ] **[IDEA] SSE (`text/event-stream`) & NDJSON stream transcript reconstructor** — Reassemble streamed HTTP responses (OpenAI/Anthropic/Gemini/Ollama/MCP event streams) into clean, human-readable prompt/tool-call/completion transcripts with inter-token latency stats.
- [ ] **[IDEA] WebSocket frame unmasker & message timeline builder** — Detect HTTP `101 Switching Protocols` upgrades, unmask client->server frames, reassemble fragmented continuations + `permessage-deflate`, and render 2-way message transcripts.

---

## Priority 2: High Impact, Medium Scope (60-90 min)

- [ ] **[IDEA] `tshark` decryption bridge for TLS 1.3, HTTP/2 & QUIC (`SSLKEYLOGFILE` + `pcapng` `DSB`)** — Optional backend adapter invoking `tshark` when keylogs or embedded `pcapng` Decryption Secrets Blocks (`DSB`) are present, feeding decrypted HTTP/2 and QUIC streams into the L7 carvers.
- [ ] **[IDEA] HTTP `206 Partial Content` byte-range stitcher & `multipart/form-data` extractor** — Reconstruct complete files from multi-connection or ranged `Content-Range: bytes start-end/total` transfers and carve uploaded files/fields out of `multipart/form-data` POSTs.
- [ ] **[IDEA] Queryable SQLite session & artifact manifest (`sessions.sqlite`)** — Emit a structured SQLite database alongside `index.html` indexing flows, DNS/SNI names, HTTP transactions, carved SHA-256 objects, and transcript full-text search (FTS5).
- [ ] **[IDEA] IPv4 & IPv6 fragment reassembly engine** — Reassemble fragmented IPv4 packets and IPv6 Fragment Extension Headers (`next_header = 44`) with proper per-`(src, dst, proto, id)` completion cleanup (fixing Chaosreader's `L1104` hash-path bug).
- [ ] **[IDEA] Schema-less gRPC & Protobuf wire decoder** — Unpack length-prefixed gRPC frames (including compressed flags) and render schema-less Protobuf wire tags/varints/strings into structured JSON/HTML views.

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

### Iteration 0 (2026-11-09)
- [DONE] ✅ Initialized repository, upstream Chaosreader 2026 source review (`docs/chaosreader-2026-review.md`), public-safety git hooks, and `iterate-bot` + TDD + Gilfoyle scaffolding.

---

## Ideas Inbox (Unsorted)

New ideas discovered mid-iteration go here instead of expanding current iteration scope.
