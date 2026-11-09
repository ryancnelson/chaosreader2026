# 2026 Landscape Survey: Existing Tools & Where `chaosreader2026` Fits

**Verified:** 2026-11-09 (live GitHub repository metadata, upstream documentation, and protocol-support inventories).

Before investing multiple iterations into rebuilding low-level packet and TLS dissection from scratch, we surveyed active open-source tools across forensic CLI carvers, Attack/Defense CTF stream analyzers, eBPF capture producers, and desktop/WASM viewers to answer one question: **does "Chaosreader for 2026" already exist?**

**Short answer:** Mature tools cover major pieces—especially **`dreadl0ck/netcap`** (structured audit records + local React UI) and **`tshark` 4.6** (TLS 1.3/QUIC/HTTP2 decryption)—while **Tulip / pkappa2 / Shovel** modernized Chaosreader's red/blue conversation view for live CTFs. However, **nobody ships a single-command, zero-server static "case bundle" generator** that combines decrypted modern web/API stream reconstruction (SSE/LLM/MCP, WebSockets, HTTP/2–3, `206` byte-range stitching) with portable HTML reports, queryable SQLite/FTS5 manifests, and safe inline `.cast` / `curl` session replays.

---

## 1. Existing Open-Source Landscape (Verified 2026-11-09)

| Project | Stack & Activity | What It Already Solves Well | Where It Stops Short of Chaosreader 2026 |
| :--- | :--- | :--- | :--- |
| **[`dreadl0ck/netcap`](https://github.com/dreadl0ck/netcap)** | Go · **~1.8k★** · active (`v0.16.3`, 2026-11) | Closest single-binary forensic framework. Full TCP/UDP stream reassembly; carves files from HTTP/1, FTP, SMTP, SMB, POP3, IMAP, and IRC with SHA-256 + Google **Magika** file classification + YARA; decrypts **`pcapng` `TLSK` (`DSB`) TLS 1.2/1.3 HTTP/1**; decodes cleartext `h2c` HTTP/2; JA4 fingerprinting; built-in service-mode React dashboard (`-http 127.0.0.1:8080`). | Built around **Protobuf security audit records (`.ncap.gz`) + a running local server UI**, not a self-contained static HTML directory. Per upstream `docs/protocol-support.md`: opaque TLS/QUIC do not feed the HTTP/2 decoder, no arbitrary HTTP/3 plaintext, no generic gRPC message decoding, no SSE/WebSocket conversation transcripts, and no `.replay`/`.cast` session playback. |
| **[`simsong/tcpflow`](https://github.com/simsong/tcpflow)** | C++ · **~1.8k★** · active (2026-11) | Closest classic Unix CLI cousin (`tcpflow -r cap.pcap -a -o out/`). Fast TCP flow demultiplexer, carves HTTP/1.x response bodies, decompresses `gzip`, and writes DFXML (`report.xml`). | Cleartext HTTP/1.x only. No TLS keylog/`DSB` support, no HTTP/2 or QUIC, no Brotli/Zstd, no human-browsable HTML index or image gallery, and no session replay generation. |
| **`tshark` (Wireshark 4.6+)** | C · active | Gold-standard **TLS 1.3 + QUIC + HTTP/2 + HTTP/3 decryption** (`-o tls.keylog_file:...` and embedded `pcapng` `DSB`) plus `--export-objects http,smb,imf,tftp,dicom` and `-z follow,{tcp,tls,http,http2,quic}`. | Exports an unindexed flat folder of files with **no** static HTML report, no red/blue conversational HTML views, no `206 Partial Content` range stitching, no SSE/WebSocket transcript assembly, and no replay scripts. |
| **`Zeek` & `Suricata filestore`** | C++ / Rust · active | Battle-tested headless TCP reassembly, file carving (`extract-all-files.zeek` / Suricata `filestore` v2), and structured JSON logs (`conn.log`, `http.log`, `files.log`). | Designed to feed SIEM/log pipelines rather than humans—no static HTML case folder, awkward TLS keylog decryption story, no conversational transcripts, and no session replays. |
| **[`OpenAttackDefenseTools/tulip`](https://github.com/OpenAttackDefenseTools/tulip)**, **[`spq/pkappa2`](https://github.com/spq/pkappa2)**, **[`FCSC-FR/shovel`](https://github.com/FCSC-FR/shovel)** | Go / Suricata + Web UI · ~500★ / ~150★ (active 2026-11) / ~100★ (2026-09) | **Spiritual heirs to Chaosreader's conversation UX:** red/blue bidirectional stream views, HTTP decompression, regex hunting, and **"Copy as `curl` / Python `pwntools`"** exploit/request reproducers (the modern descendant of `.replay`). *(Supersede older unmaintained `eciavatta/caronte`, ~654★, 2022.)* | Multi-container **Docker Compose web stacks** (ingestion daemon + DB + frontend server) tailored to live cleartext Attack/Defense CTF flag traffic—not a single CLI binary producing a portable static artifact directory, and minimal TLS/file-carving focus. |
| **[`gojue/ecapture`](https://github.com/gojue/ecapture)** & **[`mozillazg/ptcpdump`](https://github.com/mozillazg/ptcpdump)** | C / Go eBPF · **~15.5k★** & **~1.3k★** · active (2026-11) | Solve the **2026 capture problem** on Linux: hook OpenSSL/BoringSSL/Go TLS via eBPF uprobes without MITM CAs and emit **`pcapng` files with embedded `DSB` TLS secrets** and process/container metadata. | Upstream **producers** of enriched `pcapng` captures, not offline object-carving or HTML report compilers. They create the exact inputs a modern Chaosreader should consume. |
| **[`kubeshark/kubeshark`](https://github.com/kubeshark/kubeshark)** & **[`subtrace/subtrace`](https://github.com/subtrace/subtrace)** | Go · **~12.1k★** & **~3.1k★** · active (2026) | Live eBPF/syscall traffic inspectors for Kubernetes and backend services with web dashboards (Kubeshark also exposes live traffic to AI agents via MCP). | Live cluster/process observability daemons, not offline `.pcap`/`.pcapng` forensic carvers. |
| **`NetworkMiner`** & **[`odedshimon/BruteShark`](https://github.com/odedshimon/BruteShark)** | C# Mono / .NET · BruteShark ~3.4k★ (last push 2023-04) | Desktop GUI host/file/credential extractors for HTTP/SMB/FTP captures. | Windows/Mono desktop workflow (`BruteShark` is unmaintained); no static HTML case bundle, HTTP/2–3, SSE/WebSocket transcripts, or terminal/API replays. |
| **`wiregasm` / `webshark`** | C++ → WASM · active | Compiles `libwireshark` to WebAssembly so packet trees and display filters run client-side in a browser tab. | Packet-dissector UI in the browser rather than pre-assembled objects, galleries, transcripts, and replays. |

*(Note on search-engine noise: generic web searches surface small or experimental repos such as `bidhata/PCaptor` [~8★ as of 2026-11] as "Chaosreader replacements." Always verify live repository maturity and test coverage before adopting dependencies or benchmarks.)*

---

## 2. Strategic Takeaways for `chaosreader2026`

### A. What We Should *Not* Reinvent
Re-implementing every edge case of TCP overlap trimming, IPv6 extension/fragment chains, TLS 1.3 AEAD record decryption, HPACK state tables, and QUIC packet coalescing from scratch in Rust duplicates years of work already maintained inside **`tshark` (`libwireshark`)** and **`dreadl0ck/netcap`**.

### B. The Unoccupied Niche Worth Building
`chaosreader2026` should own the **last-mile forensic & developer UX layer** that none of the tools above provide out of the box:

1. **One Command → Portable, Zero-Server Static Case Bundle:**
   - Input: `.pcap` or `.pcapng` (including `ecapture`/`ptcpdump`/`editcap` captures with embedded `DSB` TLS secrets, or an external `-k sslkeylog.log`).
   - Output: A self-contained directory (`index.html`, `image.html`, `session_*.html`, `carved/`, `replays/*.cast`, `sessions.jsonl`, `sessions.sqlite`) with strict CSP and HTML escaping—safe to open directly via `file://`, host on any static file server, render on an ambient status display, attach to an incident ticket, or query from SQL/LLM agents without running Docker or a web server.
2. **Delegate Heavy L2–L6 + TLS/H2/QUIC Decryption to `tshark` (Keep Native Rust Reader as Zero-Dep Fallback):**
   - When `tshark` is on `PATH` (especially when TLS keys / `DSB` / HTTP/2 / QUIC are present), use `tshark` as the battle-tested stream-reassembly and TLS/QUIC decryption backend.
   - Retain `[iter-1]`'s native Rust `pcap`/`pcapng` engine as a fast, zero-external-dependency path for environments without Wireshark installed.
3. **First-Class 2026 Stream & AI/API Protocol Reconstructors:**
   - **`text/event-stream` (SSE) & NDJSON Transcripts:** Reassemble chunked/H2 streamed LLM and MCP responses (OpenAI, Anthropic, Gemini, Ollama, JSON-RPC over SSE) into readable prompt/tool-call/response timelines with token-latency metrics.
   - **WebSockets & gRPC:** Unmask and stitch fragmented WebSocket conversations; render schema-less Protobuf/gRPC wire messages.
   - **HTTP `206 Partial Content` Stitcher & Modern Encodings:** Reassemble multi-range file transfers (`Content-Range`) and decode `br` (Brotli) and `zstd` alongside `gzip`/`deflate`.
4. **Modernized Replays (`.cast` + `curl` / Python Reproducers):**
   - Emit **asciinema v2 (`.cast`)** recordings for interactive text/terminal protocols (playable safely inside `index.html` without exposing the analyst's PTY to raw ANSI/OSC escape injection).
   - Borrow Tulip/Caronte's best CTF feature: generate sanitized **"Copy as `curl`"** (or Python `httpx`) reproducer snippets for reconstructed HTTP/API requests.
