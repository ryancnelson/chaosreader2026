//! chaosreader2026 — packet-capture ingestion, session indexing, and safe HTML reporting.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Cursor;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use etherparse::{EtherType, NetSlice, SlicedPacket, TransportSlice};
use pcap_file::DataLink;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::{Block, PcapNgReader};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported or corrupt capture format: {0}")]
    Format(String),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TransportKind {
    Tcp,
    Udp,
    Icmp,
}

impl TransportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TransportKind::Tcp => "TCP",
            TransportKind::Udp => "UDP",
            TransportKind::Icmp => "ICMP",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPacket {
    pub index: u64,
    pub timestamp: Duration,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub transport: TransportKind,
    pub payload: Vec<u8>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_num: usize,
    pub transport: TransportKind,
    pub client: String,
    pub server: String,
    pub packet_count: usize,
    pub payload_bytes: usize,
    pub first_seen_ns: u128,
    pub last_seen_ns: u128,
    pub partial: bool,
    pub transcript_file: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Endpoint {
    ip: IpAddr,
    port: Option<u16>,
}

impl Endpoint {
    fn display(&self) -> String {
        match (self.ip, self.port) {
            (IpAddr::V4(v4), Some(p)) => format!("{v4}:{p}"),
            (IpAddr::V6(v6), Some(p)) => format!("[{v6}]:{p}"),
            (ip, None) => ip.to_string(),
        }
    }

    fn sort_key(&self) -> (u8, Vec<u8>, u16) {
        match self.ip {
            IpAddr::V4(v4) => (4, v4.octets().to_vec(), self.port.unwrap_or(0)),
            IpAddr::V6(v6) => (6, v6.octets().to_vec(), self.port.unwrap_or(0)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CanonicalFlowKey {
    transport: TransportKind,
    low: Endpoint,
    high: Endpoint,
}

struct SessionAccum {
    transport: TransportKind,
    client: Endpoint,
    server: Endpoint,
    packet_count: usize,
    payload_bytes: usize,
    first_seen: Duration,
    last_seen: Duration,
    partial: bool,
    chunks: Vec<(bool, Vec<u8>)>,
}

const PCAPNG_SHB_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];
const STRICT_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'";

/// Escape untrusted text for safe inclusion in HTML elements and attributes.
pub fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

fn sanitize_payload_for_html(bytes: &[u8]) -> String {
    let mut ascii = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'\n' | b'\r' | b'\t' | 0x20..=0x7e => ascii.push(b as char),
            _ => ascii.push('.'),
        }
    }
    escape_html(&ascii)
}

/// Process a capture file and emit `index.html`, `sessions.jsonl`, and session transcripts.
pub fn generate_case_dir(
    input: &Path,
    output_dir: &Path,
) -> Result<Vec<SessionSummary>, CaptureError> {
    let raw = fs::read(input)?;
    let packets = ingest_capture_bytes(&raw)?;
    fs::create_dir_all(output_dir)?;

    let mut flow_index: HashMap<CanonicalFlowKey, usize> = HashMap::new();
    let mut flows: Vec<SessionAccum> = Vec::new();

    for pkt in packets {
        let src = Endpoint {
            ip: pkt.src_ip,
            port: pkt.src_port,
        };
        let dst = Endpoint {
            ip: pkt.dst_ip,
            port: pkt.dst_port,
        };
        let (low, high) = if src.sort_key() <= dst.sort_key() {
            (src.clone(), dst.clone())
        } else {
            (dst.clone(), src.clone())
        };
        let key = CanonicalFlowKey {
            transport: pkt.transport,
            low,
            high,
        };

        let idx = match flow_index.get(&key).copied() {
            Some(existing) => existing,
            None => {
                let new_idx = flows.len();
                flows.push(SessionAccum {
                    transport: pkt.transport,
                    client: src.clone(),
                    server: dst.clone(),
                    packet_count: 0,
                    payload_bytes: 0,
                    first_seen: pkt.timestamp,
                    last_seen: pkt.timestamp,
                    partial: false,
                    chunks: Vec::new(),
                });
                flow_index.insert(key, new_idx);
                new_idx
            }
        };

        let flow = &mut flows[idx];
        flow.packet_count += 1;
        flow.payload_bytes += pkt.payload.len();
        if pkt.timestamp < flow.first_seen {
            flow.first_seen = pkt.timestamp;
        }
        if pkt.timestamp > flow.last_seen {
            flow.last_seen = pkt.timestamp;
        }
        flow.partial |= pkt.truncated;
        if !pkt.payload.is_empty() {
            let from_client = src == flow.client;
            flow.chunks.push((from_client, pkt.payload));
        }
    }

    let mut summaries = Vec::with_capacity(flows.len());
    let mut jsonl_buf = String::new();

    for (i, flow) in flows.iter().enumerate() {
        let session_num = i + 1;
        let transcript_file = if !flow.chunks.is_empty() {
            let fname = format!("session_{session_num:04}.html");
            let html = render_transcript_html(session_num, flow);
            fs::write(output_dir.join(&fname), html)?;
            Some(fname)
        } else {
            None
        };

        let summary = SessionSummary {
            session_num,
            transport: flow.transport,
            client: flow.client.display(),
            server: flow.server.display(),
            packet_count: flow.packet_count,
            payload_bytes: flow.payload_bytes,
            first_seen_ns: flow.first_seen.as_nanos(),
            last_seen_ns: flow.last_seen.as_nanos(),
            partial: flow.partial,
            transcript_file,
        };

        jsonl_buf.push_str(&serde_json::to_string(&summary)?);
        jsonl_buf.push('\n');
        summaries.push(summary);
    }

    fs::write(output_dir.join("sessions.jsonl"), jsonl_buf)?;
    let capture_label = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("capture");
    fs::write(
        output_dir.join("index.html"),
        render_index_html(capture_label, &summaries),
    )?;

    Ok(summaries)
}

fn render_transcript_html(session_num: usize, flow: &SessionAccum) -> String {
    let client = escape_html(&flow.client.display());
    let server = escape_html(&flow.server.display());
    let proto = flow.transport.as_str();

    let mut body = String::new();
    for (from_client, bytes) in &flow.chunks {
        let cls = if *from_client { "c2s" } else { "s2c" };
        let escaped = sanitize_payload_for_html(bytes);
        let _ = write!(body, "<span class=\"{cls}\">{escaped}</span>");
    }

    format!(
        "<!DOCTYPE html>\n\
         <html lang=\"en\">\n\
         <head>\n\
         <meta charset=\"utf-8\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"{STRICT_CSP}\">\n\
         <title>Session {session_num:04} ({proto})</title>\n\
         <style>\
         body{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#0f172a;color:#e2e8f0;padding:1.5rem}}\
         a{{color:#38bdf8}}\
         pre{{white-space:pre-wrap;word-break:break-word;background:#1e293b;padding:1rem;border-radius:6px}}\
         .c2s{{color:#f87171}}\
         .s2c{{color:#60a5fa}}\
         </style>\n\
         </head>\n\
         <body>\n\
         <p><a href=\"index.html\">&larr; Back to index</a></p>\n\
         <h1>Session {session_num:04} &mdash; {proto}: {client} &rarr; {server}</h1>\n\
         <pre>{body}</pre>\n\
         </body>\n\
         </html>\n"
    )
}

fn render_index_html(capture_label: &str, summaries: &[SessionSummary]) -> String {
    let label = escape_html(capture_label);
    let mut rows = String::new();
    for s in summaries {
        let client = escape_html(&s.client);
        let server = escape_html(&s.server);
        let proto = s.transport.as_str();
        let link = match &s.transcript_file {
            Some(f) => {
                let ef = escape_html(f);
                format!("<a href=\"{ef}\">transcript</a>")
            }
            None => String::from("&mdash;"),
        };
        let _ = writeln!(
            rows,
            "<tr><td>{}</td><td>{}</td><td>{} &rarr; {}</td><td>{}</td><td>{} B</td><td>{}</td></tr>",
            s.session_num, proto, client, server, s.packet_count, s.payload_bytes, link
        );
    }

    format!(
        "<!DOCTYPE html>\n\
         <html lang=\"en\">\n\
         <head>\n\
         <meta charset=\"utf-8\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"{STRICT_CSP}\">\n\
         <title>chaosreader2026 &mdash; {label}</title>\n\
         <style>\
         body{{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;padding:1.5rem}}\
         a{{color:#38bdf8}}\
         table{{border-collapse:collapse;width:100%;margin-top:1rem}}\
         th,td{{border:1px solid #334155;padding:0.5rem 0.75rem;text-align:left;font-family:ui-monospace,monospace}}\
         th{{background:#1e293b}}\
         </style>\n\
         </head>\n\
         <body>\n\
         <h1>chaosreader2026 Report: {label}</h1>\n\
         <p>Sessions reconstructed: <strong>{}</strong> &middot; <a href=\"sessions.jsonl\">sessions.jsonl</a></p>\n\
         <table>\n\
         <thead><tr><th>#</th><th>Proto</th><th>Flow</th><th>Packets</th><th>Payload</th><th>Artifacts</th></tr></thead>\n\
         <tbody>\n{rows}</tbody>\n\
         </table>\n\
         </body>\n\
         </html>\n",
        summaries.len()
    )
}

/// Ingest a `pcap` or `pcapng` byte buffer and decode network/transport frames.
pub fn ingest_capture_bytes(bytes: &[u8]) -> Result<Vec<DecodedPacket>, CaptureError> {
    if bytes.len() < 4 {
        return Err(CaptureError::Format("capture shorter than 4 bytes".into()));
    }

    if bytes[..4] == PCAPNG_SHB_MAGIC {
        ingest_pcapng(bytes)
    } else {
        ingest_pcap(bytes)
    }
}

fn ingest_pcap(bytes: &[u8]) -> Result<Vec<DecodedPacket>, CaptureError> {
    let mut reader =
        PcapReader::new(Cursor::new(bytes)).map_err(|e| CaptureError::Format(e.to_string()))?;
    let datalink = reader.header().datalink;
    let mut out = Vec::new();
    let mut index = 0u64;

    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt.map_err(|e| CaptureError::Format(e.to_string()))?;
        let truncated = (pkt.data.len() as u32) < pkt.orig_len;
        if let Some(decoded) = decode_frame(index, pkt.timestamp, datalink, &pkt.data, truncated) {
            out.push(decoded);
        }
        index += 1;
    }

    Ok(out)
}

fn ingest_pcapng(bytes: &[u8]) -> Result<Vec<DecodedPacket>, CaptureError> {
    let mut reader =
        PcapNgReader::new(Cursor::new(bytes)).map_err(|e| CaptureError::Format(e.to_string()))?;
    let mut interfaces: Vec<DataLink> = Vec::new();
    let mut out = Vec::new();
    let mut index = 0u64;

    while let Some(block) = reader.next_block() {
        let block = block.map_err(|e| CaptureError::Format(e.to_string()))?;
        match block {
            Block::SectionHeader(_) => interfaces.clear(),
            Block::InterfaceDescription(idb) => interfaces.push(idb.linktype),
            Block::EnhancedPacket(epb) => {
                let datalink = interfaces
                    .get(epb.interface_id as usize)
                    .copied()
                    .unwrap_or(DataLink::ETHERNET);
                let truncated = (epb.data.len() as u32) < epb.original_len;
                if let Some(decoded) =
                    decode_frame(index, epb.timestamp, datalink, &epb.data, truncated)
                {
                    out.push(decoded);
                }
                index += 1;
            }
            Block::SimplePacket(spb) => {
                // RFC / pcapng spec: SimplePacketBlock implicitly belongs to interface 0 and has no timestamp.
                let datalink = interfaces.first().copied().unwrap_or(DataLink::ETHERNET);
                let truncated = (spb.data.len() as u32) < spb.original_len;
                if let Some(decoded) =
                    decode_frame(index, Duration::ZERO, datalink, &spb.data, truncated)
                {
                    out.push(decoded);
                }
                index += 1;
            }
            _ => {}
        }
    }

    Ok(out)
}

fn decode_frame(
    index: u64,
    timestamp: Duration,
    datalink: DataLink,
    data: &[u8],
    truncated: bool,
) -> Option<DecodedPacket> {
    let sliced = match datalink {
        DataLink::ETHERNET => SlicedPacket::from_ethernet(data).ok()?,
        DataLink::LINUX_SLL => SlicedPacket::from_linux_sll(data).ok()?,
        DataLink::LINUX_SLL2 => {
            if data.len() < 20 {
                return None;
            }
            let proto = u16::from_be_bytes([data[0], data[1]]);
            SlicedPacket::from_ether_type(EtherType(proto), &data[20..]).ok()?
        }
        DataLink::RAW => SlicedPacket::from_ip(data).ok()?,
        DataLink::NULL | DataLink::LOOP => {
            if data.len() < 4 {
                return None;
            }
            let af_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let af_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            let is_ip =
                matches!(af_le, 2 | 10 | 24 | 28 | 30) || matches!(af_be, 2 | 10 | 24 | 28 | 30);
            if !is_ip {
                return None;
            }
            SlicedPacket::from_ip(&data[4..]).ok()?
        }
        _ => return None,
    };

    let (src_ip, dst_ip) = match sliced.net? {
        NetSlice::Ipv4(v4) => (
            IpAddr::V4(v4.header().source_addr()),
            IpAddr::V4(v4.header().destination_addr()),
        ),
        NetSlice::Ipv6(v6) => (
            IpAddr::V6(v6.header().source_addr()),
            IpAddr::V6(v6.header().destination_addr()),
        ),
        NetSlice::Arp(_) => return None,
    };

    let (transport, src_port, dst_port, payload) = match sliced.transport? {
        TransportSlice::Tcp(tcp) => (
            TransportKind::Tcp,
            Some(tcp.source_port()),
            Some(tcp.destination_port()),
            tcp.payload().to_vec(),
        ),
        TransportSlice::Udp(udp) => (
            TransportKind::Udp,
            Some(udp.source_port()),
            Some(udp.destination_port()),
            udp.payload().to_vec(),
        ),
        TransportSlice::Icmpv4(icmp) => (TransportKind::Icmp, None, None, icmp.payload().to_vec()),
        TransportSlice::Icmpv6(icmp) => (TransportKind::Icmp, None, None, icmp.payload().to_vec()),
    };

    Some(DecodedPacket {
        index,
        timestamp,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        transport,
        payload,
        truncated,
    })
}
