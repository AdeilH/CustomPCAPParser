//! End-to-end test against the real capture in `data/`.
//!
//! `data/` holds ~3.8 GB of NYSE Pillar captures and is gitignored, so this
//! test skips itself when the file is not present (e.g. fresh clone).

use pcap_parser::pcap::{timestamp_string, GlobalHeader, LinkType, PcapMagic};
use pcap_parser::zstd::frame;

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
}
