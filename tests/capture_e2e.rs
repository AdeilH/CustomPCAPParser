//! End-to-end test against the real capture in `data/`.
//!
//! `data/` holds ~3.8 GB of NYSE Pillar captures and is gitignored, so this
//! test skips itself when the file is not present (e.g. fresh clone).

use pcap_parser::feeds::{self, PacketParser};
use pcap_parser::pcap::{timestamp_string, GlobalHeader, LinkType, PcapMagic};
use pcap_parser::feeds::xdp;
use pcap_parser::zstd::frame;
use std::collections::HashMap;

const CAPTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/ny4-xase-pillar-a-20230822T002000.pcap.zst"
);

#[test]
fn decompresses_real_capture_with_checksum() {
    let raw = match std::fs::read(CAPTURE) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("skipping: {CAPTURE} not present");
            return;
        }
    };

    // The frame carries an XXH64 checksum; frame::decompress verifies it, so
    // reaching Ok already proves the decoded content hashed correctly.
    let out = frame::decompress(&raw).expect("decompression + checksum");

    // Known content size from the frame header (4-byte FCS = 135,304) — the
    // value the zstd CLI also reports for this file.
    assert_eq!(out.len(), 135_304);

    // Classic pcap magic in the little-endian nanosecond variant
    // (0xa1b23c4d stored LE) — sanity-check the start of the capture.
    assert_eq!(&out[..4], &[0x4d, 0x3c, 0xb2, 0xa1]);

    // Global header of this capture.
    let header = GlobalHeader::parse(&out).expect("global header");
    assert_eq!(header.magic, PcapMagic::NanosecondsLe);
    assert_eq!((header.version_major, header.version_minor), (2, 4));
    assert_eq!(header.snaplen, 262_144);
    assert_eq!(header.network, LinkType::ETHERNET);

    // Walk every packet record.
    let mut count: u64 = 0;
    let mut captured: u64 = 0;
    let mut first: Option<(u32, u32)> = None;
    let mut last: Option<(u32, u32)> = None;
    for rec in header.records(&out) {
        let rec = rec.expect("record");
        assert!(rec.header.incl_len <= rec.header.orig_len);
        assert_eq!(rec.data.len() as u32, rec.header.incl_len);
        assert!(rec.header.ts_frac < 1_000_000_000);
        first.get_or_insert((rec.header.ts_sec, rec.header.ts_frac));
        last = Some((rec.header.ts_sec, rec.header.ts_frac));
        captured += rec.header.incl_len as u64;
        count += 1;
    }
    // Every byte after the global header is accounted for: record headers
    // (16 bytes each) plus their captured payloads.
    assert_eq!(
        captured + 16 * count,
        out.len() as u64 - GlobalHeader::SIZE as u64
    );
    assert!(count > 0);

    // The capture name (T002000) matches the first record's timestamp.
    let (ts_sec, ts_frac) = first.unwrap();
    assert_eq!(
        timestamp_string(ts_sec, ts_frac, header.magic),
        "2023-08-22 00:20:00.027865639 UTC"
    );
    // Records span more than the file name suggests: this capture runs
    // ~94 seconds (00:20:00 .. 00:21:34 observed), not just 10.
    let (last_sec, _) = last.unwrap();
    assert!(last_sec >= ts_sec);
    assert!(last_sec - ts_sec < 120, "unexpectedly large capture span");

    // Pre-market (00:20 UTC): every packet in this file is an XDP
    // heartbeat — 16-byte packet header, zero messages.
    let h = GlobalHeader::parse(&out).unwrap();
    let mut heartbeats = 0u64;
    for rec in h.records(&out) {
        let payload = xdp::udp_payload_of(rec.unwrap().data).unwrap();
        let (pkt, mut msgs) = xdp::PacketHeader::parse(payload).unwrap();
        assert_eq!(pkt.delivery_flag, xdp::DELIVERY_HEARTBEAT);
        assert_eq!(pkt.num_msgs, 0);
        assert!(msgs.next().is_none());
        heartbeats += 1;
    }
    assert_eq!(heartbeats, count);
}

/// The market-hours capture (13:00-13:10 UTC) carries the full feed:
/// original stream + refresh sequence + heartbeats on ~18 channels.
#[test]
fn dissects_market_hours_capture() {
    const CAPTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/data/ny4-xase-pillar-b-20230822T130000.pcap.zst"
    );
    let raw = match std::fs::read(CAPTURE) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("skipping: {CAPTURE} not present");
            return;
        }
    };
    let out = frame::decompress(&raw).unwrap();
    let header = GlobalHeader::parse(&out).unwrap();

    let mut packets = 0u64;
    let mut messages = 0u64;
    let mut delivery: HashMap<u8, u64> = HashMap::new();
    let mut types: HashMap<u16, u64> = HashMap::new();
    let mut first_add_order: Option<u32> = None;
    for rec in header.records(&out) {
        let payload = xdp::udp_payload_of(rec.unwrap().data).unwrap();
        let (pkt, msgs) = xdp::PacketHeader::parse(payload).unwrap();
        assert_eq!(pkt.pkt_size as usize, payload.len());
        *delivery.entry(pkt.delivery_flag).or_default() += 1;
        let mut n = 0u8;
        for m in msgs {
            let (hdr, body) = m.unwrap();
            let msg = xdp::decode(hdr, body).unwrap();
            if first_add_order.is_none() {
                if let xdp::Message::AddOrder { price, .. } = &msg {
                    first_add_order = Some(*price);
                }
            }
            *types.entry(msg.msg_type()).or_default() += 1;
            n += 1;
        }
        assert_eq!(n, pkt.num_msgs);
        messages += n as u64;
        packets += 1;
    }
    assert_eq!(packets, 112_354);
    assert_eq!(messages, 240_671);

    // Delivery flags (values observed in this capture).
    assert_eq!(delivery.get(&xdp::DELIVERY_HEARTBEAT), Some(&7_451));
    assert_eq!(delivery.get(&xdp::DELIVERY_ORIGINAL), Some(&46_990));
    assert_eq!(delivery.get(&xdp::DELIVERY_REFRESH_START), Some(&30));
    assert_eq!(delivery.get(&xdp::DELIVERY_REFRESH_PART), Some(&57_853));
    assert_eq!(delivery.get(&xdp::DELIVERY_REFRESH_END), Some(&30));

    // Message types (values observed in this capture).
    let expect: [(u16, u64); 12] = [
        (xdp::msg_type::SOURCE_TIME_REFERENCE, 3_331),
        (xdp::msg_type::SYMBOL_INDEX_MAPPING, 57_749),
        (xdp::msg_type::SECURITY_STATUS, 57_750),
        (xdp::msg_type::REFRESH_HEADER, 57_913),
        (xdp::msg_type::ADD_ORDER, 24_337),
        (xdp::msg_type::MODIFY_ORDER, 170),
        (xdp::msg_type::DELETE_ORDER, 24_074),
        (xdp::msg_type::ORDER_EXECUTION, 97),
        (xdp::msg_type::REPLACE_ORDER, 7),
        (xdp::msg_type::IMBALANCE, 2_407),
        (xdp::msg_type::ADD_ORDER_REFRESH, 12_825),
        (xdp::msg_type::NON_DISPLAYED_TRADE, 11),
    ];
    let total: u64 = expect.iter().map(|(_, n)| n).sum();
    assert_eq!(total, messages);
    for (t, n) in expect {
        assert_eq!(types.get(&t), Some(&n), "type {t}");
    }
    assert!(first_add_order.is_some());
}

/// The pipeline exercised exactly the way an external consumer would:
/// decompress -> parse pcap records -> run a registry-selected parser as a
/// trait object, without knowing the concrete feed type.
#[test]
fn feed_pipeline_through_trait_object() {
    const MARKET_CAPTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/data/ny4-xase-pillar-b-20230822T130000.pcap.zst"
    );
    let raw = match std::fs::read(MARKET_CAPTURE) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("skipping: {MARKET_CAPTURE} not present");
            return;
        }
    };
    let out = frame::decompress(&raw).unwrap();
    let header = GlobalHeader::parse(&out).unwrap();

    // Registry selection, run as `dyn PacketParser`.
    let mut parser = feeds::parser_by_name("xdp").unwrap();
    assert_eq!(parser.name(), "xdp");
    parser.begin(&header);

    let mut events = 0u64;
    let mut records = 0u64;
    for rec in header.records(&out) {
        events += parser.parse_packet(rec.unwrap().data).unwrap().len() as u64;
        records += 1;
    }
    assert_eq!(records, 112_354);
    assert_eq!(events, 240_671); // every message surfaces as an event

    let summary = parser.summarize();
    assert!(summary.contains("packets:  112354 (0 non-feed frames)"), "{summary}");
    assert!(summary.contains("messages: 240671"), "{summary}");
    assert!(summary.contains("100 Add Order                24337"), "{summary}");
    assert!(summary.contains("first market message:"), "{summary}");

    // The "none" parser handles the same capture untouched.
    let mut none = feeds::parser_by_name("none").unwrap();
    for rec in header.records(&out) {
        none.parse_packet(rec.unwrap().data).unwrap();
    }
    assert_eq!(none.summarize(), "packets: 112354");
}
