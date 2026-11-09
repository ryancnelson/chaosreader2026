# Chaosreader 2026

Design notes and prototype workspace for a modern successor to Brendan Gregg's [Chaosreader](https://github.com/brendangregg/Chaosreader) (2003–2014)—preserving its core workflow (**one capture in → one static, browsable directory of reconstructed files, transcripts, and replays out**) while replacing its 2004-era L2–L7 assumptions for 2026 network traffic.

## Documentation & Workflow

- **[Feature Backlog (`BACKLOG.md`)](BACKLOG.md)** — Prioritized single-iteration tasks (`the-iterate-bot` methodology).
- **[Development & TDD Guide (`CLAUDE.md`)](CLAUDE.md)** — Strict `RED → GREEN → REFACTOR` TDD workflow, hypothesis-driven debugging discipline, and iteration scripts (`./scripts/next-iteration.sh`).
- **[Strategic Review Checklist (`STRATEGIC-REVIEW-CHECKLIST.md`)](STRATEGIC-REVIEW-CHECKLIST.md)** — 8-iteration direction and health checkpoint.
- **[Chaosreader in 2026: Source Review, Broken Assumptions & Redesign](docs/chaosreader-2026-review.md)** — Line-by-line review of the original 7,597-line Perl implementation:
  1. **The Goldmine of Tricks:** Dual-indexed TCP payload storage, self-executing `.replay` generators, live X11 resource-ID bitmask transposition & screen-scraping, fake-server VNC playback, stateless XDR/NFS carving, and passive DNS CNAME unrolling.
  2. **Assumptions That Break Now:** `pcapng` & nanosecond headers, microsecond-timestamp hash collisions on fast links/GRO, `SLL2`/`PKTAP`/overlay link layers, IPv6 formatting & fragment-tracking bugs, 4-tuple reuse & TCP overlap edge cases, port-based service guessing, OpenSSH 9.5+ keystroke chaffing, and XSS / terminal-escape footguns.
  3. **What's Missing in 2026:** TLS 1.3 & QUIC decryption (`SSLKEYLOGFILE` / `pcapng` `DSB`), HTTP/2 & HTTP/3 framing, SSE (`text/event-stream`) / LLM stream & WebSocket reassembly, Brotli & Zstandard decompression, `206 Partial Content` range stitching, and modern east-west/IoT cleartext protocols (gRPC/Protobuf, Redis, Postgres, MQTT, mDNS).
  4. **Architecture Direction:** Delegating L2–L6 + TLS decryption to `tshark` or a memory-safe stream engine while emitting CSP-sandboxed static HTML reports, asciinema `.cast` terminal replays, and a queryable SQLite/DuckDB session manifest.

## Public-Repo Safety Guardrails

Packet captures and local environments frequently contain credentials, session cookies, internal hostnames, and private IPs. Before committing in a fresh clone, install the repository git hooks:

```sh
./scripts/install-hooks.sh
```

This wires [`scripts/check-public-safety.sh`](scripts/check-public-safety.sh) into `.git/hooks/pre-commit` and `.git/hooks/pre-push` to reject:
- Packet captures (`*.pcap`, `*.pcapng`, `*.snoop`, `*.har`) and TLS keylogs/keys
- Machine-generated git author emails (e.g. `*.local`, `*.lan`, `*.ts.net`)
- Local home-directory paths, local hostnames, `.local` / `.ts.net` domains, and CGNAT/VPN IP literals
- API tokens and private keys (plus `gitleaks` staged scanning when installed)
