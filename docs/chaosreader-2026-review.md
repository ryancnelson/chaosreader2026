# Chaosreader in 2026: Source Review, Broken Assumptions & Redesign

**Upstream reviewed:** [`brendangregg/Chaosreader`](https://github.com/brendangregg/Chaosreader) (`chaosreader` v0.96, 15-Jun-2014; 7,597 lines of Perl 5, originally written 2003–2004 by Brendan Gregg with 2008–2014 HTTP/MIME/DNS/deflate patches by Indian Larry, Jens Lechtenbörger, Pavel Hančar, and Pex).

Chaosreader's enduring value is not its packet parser—which is brittle on modern captures—but its **output paradigm**: turning a raw packet capture into a zero-dependency directory of carved application objects, visual contact sheets, conversational HTML transcripts, and self-executing time-accurate `.replay` programs without clicking through a GUI.

---

## 1. The Goldmine of Tricks (What's Worth Stealing)

1. **Dual-Indexed TCP Payload Storage with Zero-Copy Scalar References ([`Process_TCP_Packet`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L1329-L1378), [`TCP_Follow_RawA`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L5800-L5815)):**
   - Interactive sessions (Telnet, IRC, SMTP) read best in **arrival-time order** across both directions so conversational turn-taking stays intact; file transfers (HTTP, FTP, NFS) require **TCP sequence-number order** in one direction for byte-exact reconstruction.
   - Chaosreader stores each segment's payload once in `%TCP{id}{$session_id}{time}{$time}{data}` and stores **Perl scalar references (`\$...`)** to those buffers inside `%TCP{id}{$session_id}{Aseq}{$tcp_seq}` and `Bseq`. When a retransmission lands on an existing `$tcp_seq`, it keeps whichever payload is longer (`length($$existing) < length($tcp_data)`).

2. **Self-Contained Executable `.replay` Generators ([`Save_Session_Replay`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L3853-L3948), [`Save_Stream_Replay`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L4486-L4577)):**
   - Rather than requiring a dedicated player binary, Chaosreader compiles each interactive session into a standalone executable Perl script consisting of `print '...'` statements separated by `select(undef, undef, undef, $ms / $factor)` sub-second sleeps—delivering `ttyrec`/`asciinema`-style variable-speed (`2x`, `0.5x`) playback with zero external dependencies.

3. **Live X11 Resource-ID Bitmask Transposition & Screen-Scraping ([`Save_Session_XReplay`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L4584-L5142), [`Generate_X11_HTML`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L3435-L3581)):**
   - Raw X11 client streams cannot simply be replayed to a new X server because `ridbase`, `ridmask`, `rootid`, and default `colormap` are dynamically assigned per connection during `xConnSetup`.
   - Chaosreader unpacks the captured `xConnSetup` reply (auto-detecting MSB vs. LSB endianness), disassembles every X11 request opcode against a 32-bit word-map table ([`Set_X11_Codes`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L6234-L6372)), and emits Perl replay code interspersed with inline `R($xw)`, `D($xw)`, `C($xw)`, and `M($xw)` calls ([L4746–L4817](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L4746-L4817)) that bitmask-rewrite old resource IDs onto the analyst's live X server at playback time.
   - For static HTML transcripts (`textX11`), it fingerprints the wire `xmodmap` table (`/q...Q.*w...W.../` at [L3470–L3475](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L3470-L3475) to distinguish Linux vs. Sun keycodes) to decode `KeyPress` events (opcode 2), scrapes rendered strings out of `ImageText8`/`ImageText16` (opcodes 76/77), and injects `\n` whenever the Y-coordinate changes or `CopyArea` (opcode 62 = terminal scroll) fires ([L3529–L3565](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L3529-L3565)).

4. **Fake-Server VNC Playback ([`Save_Session_VNCReplay_andHTML`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L5151-L5522)):**
   - Avoids implementing VNC's Hextile/Raw/ZRLE framebuffer encodings by generating a minimal TCP socket server that waits for a real `vncviewer -viewonly` client to connect, then streams the captured server-to-client RFB bytes at original inter-packet intervals—while separately unpacking client RFB opcode 4 (`KeyEvent`) key-downs into a HTML keystroke report.

5. **Stateless XDR/NFS File Carving ([`Save_NFS_File`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L5728-L5770)):**
   - Instead of tracking stateful SunRPC XIDs and NFS file handles, it spots RPC/NFS streams by signature (`^\200\0\0p0\211` at [L1871](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L1871)), unpacks the 32-bit big-endian file size at byte offset 56, splits on the repeated XDR `$nfs_size....$nfs_size` pattern, and slices out `$nfs_sizeint` bytes.

6. **Passive DNS Harvesting + CNAME Chain Unrolling ([`Process_DNS`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L2275-L2295), [`Get_Name_For_IP`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L5878-L5888)):**
   - Parses UDP/53 replies inside the capture into `%DNS`, recording both `A` (`IP -> name`) and `CNAME` (`cname -> origin_name`) mappings, then walks CNAME chains backward so CDN/alias IPs in `index.html` label sessions with the original hostname queried—without issuing live reverse-DNS queries.

7. **MIME-Type + Magic-Byte Fallback Disambiguation ([`Save_HTTP_Files`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L5628-L5706), [`File_Type`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L3228-L3256)):**
   - Trusts specific HTTP `Content-Type` headers, overrides generic `application/octet-stream` and `text/plain` headers with magic-byte detection (`GIF8`, `JFIF`, `.PNG`, `PK\x03\x04`, `%PDF`, `\x1f\x8b`, `BZh`, `\x7fELF`), auto-decompresses `gzip` and `deflate`, and cross-links extracted assets into `image.html` (visual gallery), `getpost.html` (URL-decoded query/POST tables), and Squid-format proxy logs.

8. **Encrypted SSH Traffic-Analysis State Machine ([`Save_Session_textSSH_files`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L3962-L4332)):**
   - Infers cipher/MAC minimum packet size dynamically by frequency-counting small client-to-server packets (`%PacketSize`), detects PuTTY's doubled keystroke packets via banner matching, and segments encrypted flows into `(inter-keystroke delay, command-execution pause, response byte count)` records for `sshkeydata`.

---

## 2. Assumptions That Break Now (Verified in Source)

1. **Classic `libpcap` v2.4 Only — Fails on `pcapng` and Nanosecond Captures ([`Open_Input_File`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L756-L799)):**
   - Only recognizes classic microsecond `pcap` magic numbers (`0xa1b2c3d4`, modified `0xa1b2cd34`, and byte-swapped variants) plus Solaris `snoop`.
   - Immediately aborts with `ERROR10` on **`pcapng` (`0x0a0d0d0a`)**—the default format in Wireshark, `dumpcap`, `tshark`, and modern macOS `tcpdump`—as well as nanosecond-resolution `pcap` (`0xa1b23c4d`).
   - On macOS (`darwin`), standalone mode runs `tcpdump -s0 -w` ([`Check_Command`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L6996-L6997)), which writes `pcapng`/`PKTAP` by default unless `-P -i <iface>` is passed, causing Chaosreader to reject the file it just captured.

2. **Microsecond Timestamp Used as a Unique Packet Key ([`Read_Input_File`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L1075-L1080), [`Process_TCP_Packet`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L1334-L1377)):**
   - Pass 1 stores every IP packet in `$IP{time}{$packet_timefull}` where `$packet_timefull = $seconds + $msecs/1_000_000`. On 10/25/100GbE NICs, loopback interfaces, virtual switches, or GRO/LRO/TSO bursts, multiple packets routinely share the exact same microsecond timestamp—**silently overwriting** earlier packets in `%IP`.
   - In `%TCP`, `$TCP{id}{$session_id}{time}{$time}{data} .= $tcp_data` has no direction subkey, while `Aseq{$tcp_seq}` holds a reference (`\$...`) to that time-bucket scalar. Two segments in the same session arriving in the same microsecond (even in opposite directions) concatenate into the same scalar, corrupting sequence-reassembled files.

3. **Link-Layer & Encapsulation Blindness ([`Read_Input_File`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L868-L966)):**
   - `tcpdump -i any` on modern Linux (`libpcap` ≥ 1.10) emits **Linux Cooked v2 (`SLL2`, DLT 276, 20-byte header)**; Chaosreader only attempts 16-byte `SLL` v1, and even on `SLL` v1 drops all IPv6 traffic (`if ($ether_type ne "0800") { next; }` at [L963](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L963)).
   - Fails on Radiotap + 802.11n/ac/ax/be QoS data frames, BSD/macOS loopback (`DLT_NULL`), macOS `PKTAP`, QinQ (`0x88a8`), VXLAN, Geneve, MPLS, and WireGuard/VPN `utun` captures.
   - Single-VLAN (`0x8100`) handling at [L953–L956](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L953-L956) unpacks `$orig_ether_type` and never checks it, falling straight into IPv4/v6 header parsing even on ARP/non-IP frames.

4. **Broken IPv6 Formatting & Fragment-Cleanup Typo ([`Read_Input_File`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L1020-L1106)):**
   - Formats 16-byte IPv6 addresses via `sprintf("%x%x:...", @ip_src)` ([L1027](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L1027)) instead of `%02x%02x`, turning byte pair `(0x01, 0x02)` into `12` instead of `102`, and ignores IPv6 extension headers other than Fragment (`44`).
   - Typo at [L1104](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L1104): executes `undef $IP{ident}{StartTime}{$ip_id}` instead of `$IP{id}{$ip_id}{StartTime}`, so completed fragmented IP IDs never clear their `StartTime` pointer.

5. **Naive TCP Reassembly (No Overlap Trimming, Port-Reuse Splitting, or Seq Wraparound) ([`Process_TCP_Packet`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L1255-L1276), [`TCP_Follow_RawA`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L5809-L5812)):**
   - Unpacks `$tcp_fin` and `$tcp_rst` at [L1255–L1257](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L1255-L1257) and never uses them (silenced via [`Touch_Vars`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L6973)). When clients, NAT gateways, or service-mesh proxies reuse an ephemeral `(src_ip, src_port, dst_ip, dst_port)` 4-tuple across sequential connections, Chaosreader mashes all connections into one `session_id`.
   - `sort { $a <=> $b } @Seqs` fails when 32-bit TCP sequence numbers wrap around `2^32` (transfers > 4 GiB or random ISNs near `0xffffffff`), and partially overlapping TCP retransmissions duplicate the overlapping byte range in carved files.

6. **Service Identification by Port Number ([`Pick_Service_Port`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L5845-L5873), [`Load_Etc_Services`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L6101-L6125)):**
   - Assumes `min(src_port, dst_port)` identifies the application protocol when mid-stream.
   - Hardcodes modern application ports `5000`, `7000`, `8000`, and `9000` as IRC (`irc5000`, `irc8000`, `irc9000`), and checks `$service == 3127` instead of Squid's `3128` at [L1853](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L1853).

7. **Regex-Based HTTP Stream Splitting ([`Save_HTTP_Files`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L5588), [`Process_HTTP`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L2346-L2357)):**
   - Splits the entire reassembled server stream on `/HTTP\/[0-9.]* /` rather than tracking `Content-Length` / chunk boundaries—so any downloaded JS bundle, HTML page, or archive containing the literal ASCII substring `HTTP/1.1 ` is sliced into corrupt fragments.
   - Pairs HTTP requests with responses by scanning only `1..16` packet timestamps ahead, desynchronizing on large uploads or pipelined connections.

8. **OpenSSH 9.5+ Keystroke Timing Obfuscation:**
   - OpenSSH 9.5 (2023) introduced `ObscureKeystrokeTiming` (fixed ~20ms chaff intervals and synthetic ping traffic) specifically to break the 1-packet-per-keystroke cadence assumptions in [`Save_Session_textSSH_files`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L4093-L4269).

9. **Analyst Security Footguns (Stored XSS, Live Beaconing & Terminal Escape Injection):**
   - Unescaped packet strings (`$site` and `$var` in [`Process_HTTP`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L2470-L2483), DNS answers in [`Get_Name_For_IP`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L5878-L5888)) are interpolated directly into HTML reports (stored XSS when opening `index.html` or `getpost.html`).
   - `extimage.html` embeds `<img src="http://...">` tags pointing at live remote servers, leaking analyst IP/User-Agent on report view.
   - Generated `.replay` scripts write raw captured bytes directly to the analyst's PTY, exposing modern terminals to ANSI/OSC escape-sequence injection (e.g., OSC 52 clipboard manipulation or title/macro injection).

---

## 3. What Chaosreader Is Missing in 2026

1. **TLS 1.3 & QUIC Decryption Inputs (`SSLKEYLOGFILE` & `pcapng` `DSB`):**
   - Cannot ingest NSS TLS key logs (`SSLKEYLOGFILE`) or `pcapng` Decryption Secrets Blocks (`DSB`, e.g., produced by `editcap --inject-secrets` or Linux eBPF TLS uprobes like `ecapture`).
   - Extracts zero TLS handshake metadata (SNI, ALPN, certificate chains, JA4 fingerprints) when keys are unavailable.

2. **Modern Web, Streaming & API Framing:**
   - No **HTTP/2** (binary framing + HPACK header compression + multiplexed streams) or **HTTP/3** (QUIC over UDP + QPACK).
   - No **WebSocket** frame unmasking/reassembly, **`multipart/form-data`** upload file extraction, or **`206 Partial Content`** byte-range stitching.
   - No **Server-Sent Events (`text/event-stream`)** or **NDJSON** stream assembly—now the universal wire format for LLM token streams and MCP HTTP transports.

3. **Modern Compression & Object Formats:**
   - Missing **Brotli (`br`)** and **Zstandard (`zstd`)** content-encoding decompression.
   - Magic-byte sniffer ([`File_Type`](https://github.com/brendangregg/Chaosreader/blob/master/chaosreader#L3228-L3256)) predates `webp`, `avif`, `heic`, `woff2`, `wasm`, `mp4`/`fmp4` CMAF media segments, `zst`, SQLite, and Parquet.

4. **2026 Cleartext East-West, Localhost & IoT Protocols:**
   - Cleartext traffic moved off public WANs onto loopback, container/pod networks, and IoT segments: **gRPC / Protobuf**, **Redis (`RESP`)**, **PostgreSQL (`pgwire`)**, **MySQL**, **MQTT**, **mDNS / SSDP**, **SMB2/3**, and **RTSP/RTP**.

5. **Bounded-Memory Streaming Architecture:**
   - Holding full packet payloads in Perl hashes consumes ~5–10x the capture file size in RAM, preventing multi-gigabyte trace processing.

---

## 4. What We Can Do With It

### Path A: Zero-Code Legacy Compatibility Pipeline
When analyzing small legacy, lab, or CTF captures with classic `chaosreader`, normalize `pcapng` and modern `SLL2`/`PKTAP` link headers into legacy Ethernet `pcap` v2.4 first:

```sh
tshark -r capture.pcapng -F pcap -w - \
  | tcprewrite --dlt=enet --infile=- --outfile=normalized.pcap
chaosreader -vde -D report_out normalized.pcap
```

### Path B: "Chaosreader 2026" Architecture

Preserve Chaosreader's **zero-click static case-folder UX** while replacing the L2–L6 stack:

```
pcap / pcapng (+ DSB or SSLKEYLOGFILE) / eBPF plaintext capture
        │
        ▼
[1. L2–L6 + TLS Stream Engine]  (tshark backend or Rust/Go stream reassembler)
   - pcapng, SLL2, VLAN/VXLAN, IPv6 extensions
   - SYN/FIN/RST connection splitting, overlap-trimmed TCP seq reassembly, QUIC/H2
   - TLS 1.3 + QUIC decryption via DSB / keylog + passive DNS/mDNS/SNI map
        │
        ▼
[2. Payload-First Protocol Classifier (DPI, not port numbers)]
   - HTTP/1.x, HTTP/2, HTTP/3, WebSocket, SSE/NDJSON, gRPC/Protobuf
   - Redis RESP, Postgres pgwire, MQTT, SMTP, FTP, SSH, Telnet, VNC
        │
        ▼
[3. Object Carvers & Transcript Compilers]
   - HTTP object carver: br/zstd/gzip decode + multipart/form-data + 206 Range stitcher
   - Stream transcriptor: SSE / LLM / MCP / WebSocket message timelines
   - Wire decoders: schema-less Protobuf, SQL/Redis query-result pairs, MQTT topic tree
   - Safe replay compiler: asciinema v2 (.cast) instead of raw PTY Perl scripts
        │
        ▼
[4. Static Case Directory Output]
   - index.html (CSP-sandboxed, strict HTML-escaped, embedded .cast web player, offline-safe)
   - carved/ (deduplicated SHA-256 content-addressed objects + human symlinks)
   - sessions.sqlite or sessions.duckdb + sessions.jsonl (SQL- and agent-queryable index)
```

### High-Value First Milestones

1. **Core CLI (`chaosreader2026 <capture.pcapng> [-k sslkeylog.log] -o <dir>`):**
   - Ingest `pcap` and `pcapng` (including embedded `DSB` TLS secrets) via `tshark` JSON/follow streams or a native Rust/Go reassembler.
   - Passive hostname resolution combining DNS (`A`/`AAAA`/`CNAME`), mDNS, and TLS `SNI`.
2. **Modern Web, API & AI-Stream Reconstruction:**
   - Carve HTTP/1.1, HTTP/2, and HTTP/3 objects with `gzip`/`deflate`/`br`/`zstd` decoding, `multipart/form-data` extraction, and `206 Partial Content` range reassembly.
   - Reconstruct `text/event-stream` (SSE), NDJSON, and WebSocket conversations into readable timelines.
3. **Safe Replays & Queryable Index:**
   - Emit `.cast` (asciinema v2) terminal recordings rendered via a browser player in a strict-CSP `index.html` alongside a `sessions.sqlite` manifest.
