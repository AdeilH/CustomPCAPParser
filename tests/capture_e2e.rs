//! End-to-end test against the real capture in `data/`.
//!
//! `data/` holds ~3.8 GB of NYSE Pillar captures and is gitignored, so this
//! test skips itself when the file is not present (e.g. fresh clone).

use pcap_parser::pcap::{GlobalHeader, LinkType, PcapMagic};
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
}
