use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use chaosreader2026::{TransportKind, ingest_capture_bytes};
use etherparse::PacketBuilder;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::{PcapNgBlock, PcapNgWriter};
use pcap_file::{DataLink, Endianness, TsResolution};

fn ethernet_ipv4_tcp_frame(
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    seq: u32,
    payload: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2])
        .ipv4(src_ip, dst_ip, 64)
        .tcp(src_port, dst_port, seq, 65535);
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, payload).expect("build tcp frame");
    buf
}

#[test]
fn ingests_pcap_and_pcapng_preserving_same_timestamp_packets() {
    let ts = Duration::from_micros(1_700_000_000_123_456);
    let frame_a = ethernet_ipv4_tcp_frame(
        [10, 0, 0, 2],
        51234,
        [10, 0, 0, 1],
        80,
        1000,
        b"GET / HTTP/1.1\r\n\r\n",
    );
    let frame_b = ethernet_ipv4_tcp_frame(
        [10, 0, 0, 1],
        80,
        [10, 0, 0, 2],
        51234,
        2000,
        b"HTTP/1.1 200 OK\r\n\r\nhi",
    );

    // 1. Classic nanosecond-resolution pcap with two packets at the exact same timestamp.
    let mut pcap_bytes = Vec::new();
    {
        let header = PcapHeader {
            datalink: DataLink::ETHERNET,
            ts_resolution: TsResolution::NanoSecond,
            endianness: Endianness::Big,
            ..Default::default()
        };
        let mut writer = PcapWriter::with_header(&mut pcap_bytes, header).unwrap();
        writer
            .write_packet(&PcapPacket::new(ts, frame_a.len() as u32, &frame_a))
            .unwrap();
        writer
            .write_packet(&PcapPacket::new(ts, frame_b.len() as u32, &frame_b))
            .unwrap();
    }

    let pcap_pkts = ingest_capture_bytes(&pcap_bytes).expect("parse nanosecond pcap");
    assert_eq!(
        pcap_pkts.len(),
        2,
        "must not overwrite colliding timestamps"
    );
    assert_eq!(pcap_pkts[0].index, 0);
    assert_eq!(pcap_pkts[1].index, 1);
    assert_eq!(pcap_pkts[0].payload, b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(pcap_pkts[1].payload, b"HTTP/1.1 200 OK\r\n\r\nhi");
    assert_eq!(pcap_pkts[0].transport, TransportKind::Tcp);
    assert_eq!(pcap_pkts[0].src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(pcap_pkts[0].dst_port, Some(80));

    // 2. Modern pcapng with the same colliding-timestamp pair.
    let mut pcapng_bytes = Vec::new();
    {
        let mut writer = PcapNgWriter::new(&mut pcapng_bytes).unwrap();
        let iface = InterfaceDescriptionBlock {
            linktype: DataLink::ETHERNET,
            snaplen: 65535,
            options: vec![],
        };
        writer.write_block(&iface.into_block()).unwrap();
        for frame in [&frame_a, &frame_b] {
            let epb = EnhancedPacketBlock {
                interface_id: 0,
                timestamp: ts,
                original_len: frame.len() as u32,
                data: Cow::Borrowed(frame),
                options: vec![],
            };
            writer.write_block(&epb.into_block()).unwrap();
        }
    }

    let ng_pkts = ingest_capture_bytes(&pcapng_bytes).expect("parse pcapng");
    assert_eq!(ng_pkts.len(), 2);
    assert_eq!(ng_pkts[0].payload, b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(ng_pkts[1].payload, b"HTTP/1.1 200 OK\r\n\r\nhi");
}

#[test]
fn decodes_linux_sll2_ipv6_bsd_null_raw_and_vlan_frames() {
    let ts = Duration::from_secs(1_700_000_100);

    // Build an IPv6 UDP payload whose address has a leading-zero byte (0x01, 0x02 -> :102:)
    // that upstream Chaosreader L1027 misformatted as :12:.
    let src_v6 = [
        0x20, 0x01, 0x0d, 0xb8, 0x01, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];
    let dst_v6 = [
        0x20, 0x01, 0x0d, 0xb8, 0x01, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    ];
    let v6_builder = PacketBuilder::ipv6(src_v6, dst_v6, 64).udp(5353, 5353);
    let mut raw_ipv6 = Vec::new();
    v6_builder
        .write(&mut raw_ipv6, b"mdns-probe")
        .expect("build ipv6 udp");

    // Wrap raw_ipv6 inside a 20-byte Linux Cooked v2 (SLL2, DLT 276) header:
    // bytes 0..2 = protocol type 0x86dd (IPv6), bytes 2..20 = reserved/ifindex/arphrd/pkt_type/lladdr.
    let mut sll2_frame = vec![0u8; 20];
    sll2_frame[0..2].copy_from_slice(&0x86dd_u16.to_be_bytes());
    sll2_frame[4..8].copy_from_slice(&1u32.to_be_bytes()); // ifindex = 1
    sll2_frame.extend_from_slice(&raw_ipv6);

    // Build BSD/macOS DLT_NULL loopback IPv4 UDP frame (4-byte host-endian AF_INET = 2).
    let v4_builder = PacketBuilder::ipv4([127, 0, 0, 1], [127, 0, 0, 1], 64).udp(54321, 53);
    let mut raw_ipv4 = Vec::new();
    v4_builder
        .write(&mut raw_ipv4, b"dns-query")
        .expect("build ipv4 udp");
    let mut null_frame = Vec::new();
    null_frame.extend_from_slice(&2u32.to_ne_bytes());
    null_frame.extend_from_slice(&raw_ipv4);

    // Build 802.1Q VLAN-tagged ARP frame (must be skipped cleanly) + VLAN-tagged IPv4 UDP frame.
    let mut vlan_arp = Vec::new();
    vlan_arp.extend_from_slice(&[0xff; 6]); // dst mac
    vlan_arp.extend_from_slice(&[0x02, 0, 0, 0, 0, 9]); // src mac
    vlan_arp.extend_from_slice(&0x8100_u16.to_be_bytes()); // 802.1Q TPID
    vlan_arp.extend_from_slice(&100_u16.to_be_bytes()); // VLAN 100
    vlan_arp.extend_from_slice(&0x0806_u16.to_be_bytes()); // ARP EtherType
    vlan_arp.extend_from_slice(&[0u8; 28]); // dummy ARP body

    let vlan_ip_builder = PacketBuilder::ethernet2([0x02; 6], [0x06; 6])
        .single_vlan(etherparse::VlanId::try_new(100).unwrap())
        .ipv4([192, 168, 10, 5], [192, 168, 10, 1], 64)
        .udp(40000, 514);
    let mut vlan_ip = Vec::new();
    vlan_ip_builder
        .write(&mut vlan_ip, b"syslog-line")
        .expect("build vlan ipv4");

    // Multi-interface pcapng combining SLL2, DLT_NULL, RAW, and VLAN Ethernet!
    let mut pcapng_bytes = Vec::new();
    {
        let mut writer = PcapNgWriter::new(&mut pcapng_bytes).unwrap();
        for linktype in [
            DataLink::LINUX_SLL2,
            DataLink::NULL,
            DataLink::RAW,
            DataLink::ETHERNET,
        ] {
            writer
                .write_block(
                    &InterfaceDescriptionBlock {
                        linktype,
                        snaplen: 65535,
                        options: vec![],
                    }
                    .into_block(),
                )
                .unwrap();
        }

        let frames: &[(u32, &[u8])] = &[
            (0, &sll2_frame),
            (1, &null_frame),
            (2, &raw_ipv6),
            (3, &vlan_arp),
            (3, &vlan_ip),
        ];
        for (idx, (if_id, frame)) in frames.iter().enumerate() {
            writer
                .write_block(
                    &EnhancedPacketBlock {
                        interface_id: *if_id,
                        timestamp: ts + Duration::from_millis(idx as u64),
                        original_len: frame.len() as u32,
                        data: Cow::Borrowed(frame),
                        options: vec![],
                    }
                    .into_block(),
                )
                .unwrap();
        }
    }

    let decoded = ingest_capture_bytes(&pcapng_bytes).expect("decode multi-dlt pcapng");
    assert_eq!(decoded.len(), 4, "4 IP packets decoded, 1 VLAN ARP skipped");
    assert_eq!(decoded[0].src_ip.to_string(), "2001:db8:102::1");
    assert_eq!(decoded[0].payload, b"mdns-probe");
    assert_eq!(decoded[1].src_ip.to_string(), "127.0.0.1");
    assert_eq!(decoded[1].payload, b"dns-query");
    assert_eq!(decoded[2].dst_ip.to_string(), "2001:db8:102::2");
    assert_eq!(decoded[3].payload, b"syslog-line");
}

#[test]
fn cli_generates_escaped_html_report_and_sessions_jsonl() {
    use chaosreader2026::SessionSummary;
    use std::process::Command;

    let tmp = tempfile::tempdir().expect("tempdir");
    let capture_path = tmp.path().join("xss_sample.pcapng");
    let out_dir = tmp.path().join("case_out");

    let ts0 = Duration::from_secs(1_700_000_200);
    let req = ethernet_ipv4_tcp_frame(
        [10, 1, 1, 50],
        55000,
        [10, 1, 1, 10],
        80,
        100,
        b"GET /?q=<script>alert('xss')</script> HTTP/1.1\r\nHost: example.test\r\n\r\n",
    );
    let resp = ethernet_ipv4_tcp_frame(
        [10, 1, 1, 10],
        80,
        [10, 1, 1, 50],
        55000,
        500,
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<b>ok</b>",
    );

    let mut pcapng_bytes = Vec::new();
    {
        let mut writer = PcapNgWriter::new(&mut pcapng_bytes).unwrap();
        writer
            .write_block(
                &InterfaceDescriptionBlock {
                    linktype: DataLink::ETHERNET,
                    snaplen: 65535,
                    options: vec![],
                }
                .into_block(),
            )
            .unwrap();
        for (idx, frame) in [&req, &resp].iter().enumerate() {
            writer
                .write_block(
                    &EnhancedPacketBlock {
                        interface_id: 0,
                        timestamp: ts0 + Duration::from_millis((idx * 25) as u64),
                        original_len: frame.len() as u32,
                        data: Cow::Borrowed(frame),
                        options: vec![],
                    }
                    .into_block(),
                )
                .unwrap();
        }
    }
    std::fs::write(&capture_path, &pcapng_bytes).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_chaosreader2026"))
        .arg(&capture_path)
        .arg("-o")
        .arg(&out_dir)
        .status()
        .expect("run chaosreader2026 binary");
    assert!(status.success(), "CLI exited non-zero");

    let jsonl_raw =
        std::fs::read_to_string(out_dir.join("sessions.jsonl")).expect("sessions.jsonl must exist");
    let lines: Vec<&str> = jsonl_raw.lines().collect();
    assert_eq!(lines.len(), 1, "bidirectional flow grouped into 1 session");
    let summary: SessionSummary =
        serde_json::from_str(lines[0]).expect("valid SessionSummary JSON");
    assert_eq!(summary.session_num, 1);
    assert_eq!(summary.packet_count, 2);
    assert_eq!(summary.client, "10.1.1.50:55000");
    assert_eq!(summary.server, "10.1.1.10:80");

    let index_html =
        std::fs::read_to_string(out_dir.join("index.html")).expect("index.html must exist");
    assert!(
        index_html.contains("Content-Security-Policy"),
        "index.html must include strict CSP meta tag"
    );
    assert!(index_html.contains("10.1.1.50:55000"));
    assert!(index_html.contains("10.1.1.10:80"));

    let transcript_name = summary
        .transcript_file
        .expect("session with payload should emit transcript file");
    let transcript_html = std::fs::read_to_string(out_dir.join(&transcript_name))
        .expect("session transcript must exist");
    assert!(
        !transcript_html.contains("<script>"),
        "raw <script> tag must never appear unescaped in transcript HTML"
    );
    assert!(
        transcript_html.contains("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"),
        "payload must be HTML-escaped in transcript"
    );
}

#[test]
fn handles_simple_packet_blocks_snaplen_truncation_and_corrupt_inputs() {
    use pcap_file::pcapng::blocks::simple_packet::SimplePacketBlock;

    // Corrupt inputs must return an error cleanly without panicking.
    assert!(ingest_capture_bytes(b"").is_err());
    assert!(ingest_capture_bytes(b"not-a-valid-pcap-header-at-all").is_err());

    // SimplePacketBlock (pcapng block 0x00000003) with original_len > captured len (snaplen truncation).
    let frame = ethernet_ipv4_tcp_frame([192, 0, 2, 1], 44444, [192, 0, 2, 2], 8080, 1, b"ping");
    let mut pcapng_bytes = Vec::new();
    {
        let mut writer = PcapNgWriter::new(&mut pcapng_bytes).unwrap();
        writer
            .write_block(
                &InterfaceDescriptionBlock {
                    linktype: DataLink::ETHERNET,
                    snaplen: 64,
                    options: vec![],
                }
                .into_block(),
            )
            .unwrap();
        writer
            .write_block(
                &SimplePacketBlock {
                    original_len: (frame.len() + 128) as u32,
                    data: Cow::Borrowed(&frame),
                }
                .into_block(),
            )
            .unwrap();
    }

    let pkts = ingest_capture_bytes(&pcapng_bytes).expect("decode SimplePacketBlock");
    assert_eq!(pkts.len(), 1);
    assert!(
        pkts[0].truncated,
        "original_len > data.len() must set truncated=true"
    );
    assert_eq!(pkts[0].payload, b"ping");
}
